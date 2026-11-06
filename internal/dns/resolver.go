package dns

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"naive-client/internal/dns/ipcache"
	"naive-client/internal/routing"
)

var (
	DefaultBootstrapDoH = []string{
		"https://dns.alidns.com/dns-query",
		"https://doh.pub/dns-query",
	}
	DefaultRemoteDoH = []string{
		"https://1.1.1.1/dns-query",
		"https://dns.google/dns-query",
	}
)

type Blocker interface {
	Match(domain string) (blocked bool, rule string)
}

type ResolverOptions struct {
	Hosts            map[string]string
	MagicDNSEndpoint string
	Blocker          Blocker
	BootstrapDomains []string
	Router           *routing.Router
	BootstrapDoH     []string
	RemoteDoH        []string
	DialDirect       func(ctx context.Context, network, addr string) (net.Conn, error)
	DialProxy        func(ctx context.Context, network, addr string) (net.Conn, error)
	IPCache          *ipcache.Cache
}

type cacheEntry struct {
	msg         *dns.Msg
	cachedAt    time.Time
	expiresAt   time.Time
	staleUntil  time.Time
	refreshing  atomic.Bool
	minTTL      uint32
}

type Resolver struct {
	opts             ResolverOptions
	bootstrapSet     map[string]struct{}
	mu               sync.RWMutex
	cache            map[string]*cacheEntry
	cacheMu          sync.RWMutex
	directHTTPClient *http.Client
	proxyHTTPClient  *http.Client
	dnsClient        *dns.Client
}

func NewResolver(opts ResolverOptions) *Resolver {
	if len(opts.BootstrapDoH) == 0 {
		opts.BootstrapDoH = DefaultBootstrapDoH
	}
	if len(opts.RemoteDoH) == 0 {
		opts.RemoteDoH = DefaultRemoteDoH
	}
	if opts.IPCache == nil {
		opts.IPCache = ipcache.New(10000)
	}

	bootSet := make(map[string]struct{})
	for _, d := range opts.BootstrapDomains {
		clean := strings.ToLower(strings.Trim(d, "."))
		if clean != "" {
			bootSet[clean] = struct{}{}
		}
	}
	opts.IPCache.SetBootstrapDomains(opts.BootstrapDomains)

	directDialer := opts.DialDirect
	if directDialer == nil {
		netDialer := &net.Dialer{Timeout: 5 * time.Second}
		directDialer = netDialer.DialContext
	}

	proxyDialer := opts.DialProxy
	if proxyDialer == nil {
		proxyDialer = directDialer
	}

	directClient := &http.Client{
		Transport: &http.Transport{
			DialContext:         directDialer,
			MaxIdleConns:        50,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 5 * time.Second,
		},
		Timeout: 6 * time.Second,
	}

	proxyClient := &http.Client{
		Transport: &http.Transport{
			DialContext:         proxyDialer,
			MaxIdleConns:        50,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 6 * time.Second,
		},
		Timeout: 8 * time.Second,
	}

	return &Resolver{
		opts:             opts,
		bootstrapSet:     bootSet,
		cache:            make(map[string]*cacheEntry),
		directHTTPClient: directClient,
		proxyHTTPClient:  proxyClient,
		dnsClient:        &dns.Client{Timeout: 4 * time.Second},
	}
}

func (r *Resolver) SetBootstrapDomains(domains []string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.opts.BootstrapDomains = domains
	r.bootstrapSet = make(map[string]struct{}, len(domains))
	for _, d := range domains {
		clean := strings.ToLower(strings.Trim(d, "."))
		if clean != "" {
			r.bootstrapSet[clean] = struct{}{}
		}
	}
	if r.opts.IPCache != nil {
		r.opts.IPCache.SetBootstrapDomains(domains)
	}
}

func (r *Resolver) SetRouter(router *routing.Router) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.opts.Router = router
}

func (r *Resolver) SetBlocker(blocker Blocker) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.opts.Blocker = blocker
}

func (r *Resolver) IPCache() *ipcache.Cache {
	return r.opts.IPCache
}

func (r *Resolver) Resolve(ctx context.Context, domain string, qtype uint16) (*dns.Msg, error) {
	cleanDomain := strings.Trim(domain, ".")
	if cleanDomain == "" {
		return nil, errors.New("empty domain")
	}

	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(cleanDomain), qtype)
	return r.ResolveMsg(ctx, req)
}

func (r *Resolver) ResolveMsg(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if req == nil || len(req.Question) == 0 {
		return nil, errors.New("invalid dns question")
	}

	q := req.Question[0]
	domain := strings.ToLower(strings.Trim(q.Name, "."))
	qtype := q.Qtype

	// 1. Stage 1: Tailnet MagicDNS and Custom Hosts
	if resp := r.checkHosts(req, domain, qtype); resp != nil {
		return resp, nil
	}
	if r.isMagicDNS(domain) {
		if resp, err := r.queryMagicDNS(ctx, req); err == nil && resp != nil {
			r.recordIPs(resp, domain)
			return resp, nil
		}
	}

	// 2. Stage 2: Blocker
	if r.opts.Blocker != nil {
		if blocked, _ := r.opts.Blocker.Match(domain); blocked {
			resp := new(dns.Msg)
			resp.SetReply(req)
			resp.RecursionAvailable = true
			if qtype == dns.TypeA {
				rr, _ := dns.NewRR(fmt.Sprintf("%s 60 IN A 0.0.0.0", req.Question[0].Name))
				resp.Answer = append(resp.Answer, rr)
			} else if qtype == dns.TypeAAAA {
				rr, _ := dns.NewRR(fmt.Sprintf("%s 60 IN AAAA ::", req.Question[0].Name))
				resp.Answer = append(resp.Answer, rr)
			} else {
				resp.Rcode = dns.RcodeNameError
			}
			return resp, nil
		}
	}

	// Check TTL cache and Stale-While-Revalidate
	cacheKey := domain + ":" + strconv.Itoa(int(qtype))
	now := time.Now()

	r.cacheMu.RLock()
	entry, ok := r.cache[cacheKey]
	r.cacheMu.RUnlock()

	if ok && entry != nil {
		if now.Before(entry.expiresAt) {
			// Fresh cache hit (<1ms)
			resp := copyMsg(entry.msg, req.Id)
			adjustTTL(resp, uint32(entry.expiresAt.Sub(now).Seconds()))
			return resp, nil
		}
		if now.Before(entry.staleUntil) {
			// Optimistic Stale-While-Revalidate hit
			if entry.refreshing.CompareAndSwap(false, true) {
				go func() {
					defer entry.refreshing.Store(false)
					refreshCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
					defer cancel()
					_, _ = r.fetchAndCache(refreshCtx, req, domain, qtype, cacheKey)
				}()
			}
			resp := copyMsg(entry.msg, req.Id)
			adjustTTL(resp, 1)
			return resp, nil
		}
	}

	// Fresh upstream fetch
	return r.fetchAndCache(ctx, req, domain, qtype, cacheKey)
}

func (r *Resolver) fetchAndCache(ctx context.Context, req *dns.Msg, domain string, qtype uint16, cacheKey string) (*dns.Msg, error) {
	var resp *dns.Msg
	var err error

	// Determine upstream: Bootstrap (Stage 3) vs Remote (Stage 4)
	if r.isBootstrapOrDirect(domain) {
		resp, err = r.queryDoH(ctx, r.directHTTPClient, r.opts.BootstrapDoH, req)
	} else {
		resp, err = r.queryDoH(ctx, r.proxyHTTPClient, r.opts.RemoteDoH, req)
	}

	if err != nil {
		return nil, err
	}

	r.recordIPs(resp, domain)
	r.storeCache(cacheKey, resp)

	return resp, nil
}

func (r *Resolver) checkHosts(req *dns.Msg, domain string, qtype uint16) *dns.Msg {
	if len(r.opts.Hosts) == 0 {
		return nil
	}
	ipStr, found := r.opts.Hosts[domain]
	if !found {
		return nil
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}

	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.RecursionAvailable = true

	if ip.To4() != nil && qtype == dns.TypeA {
		rr, _ := dns.NewRR(fmt.Sprintf("%s 300 IN A %s", req.Question[0].Name, ipStr))
		resp.Answer = append(resp.Answer, rr)
		r.recordIPs(resp, domain)
		return resp
	}
	if ip.To4() == nil && qtype == dns.TypeAAAA {
		rr, _ := dns.NewRR(fmt.Sprintf("%s 300 IN AAAA %s", req.Question[0].Name, ipStr))
		resp.Answer = append(resp.Answer, rr)
		r.recordIPs(resp, domain)
		return resp
	}

	return nil
}

func (r *Resolver) isMagicDNS(domain string) bool {
	if r.opts.MagicDNSEndpoint == "" {
		return false
	}
	if strings.HasSuffix(domain, ".ts.net") {
		return true
	}
	// Peer short name without dots
	if !strings.Contains(domain, ".") {
		return true
	}
	return false
}

func (r *Resolver) queryMagicDNS(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	resp, _, err := r.dnsClient.ExchangeContext(ctx, req, r.opts.MagicDNSEndpoint)
	return resp, err
}

func (r *Resolver) isBootstrapOrDirect(domain string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// 1. In BootstrapDomains
	if _, ok := r.bootstrapSet[domain]; ok {
		return true
	}

	// 2. Private or local domain
	if isPrivateDomain(domain) {
		return true
	}

	// 3. Router matches DIRECT
	if r.opts.Router != nil {
		action, _ := r.opts.Router.Match(domain)
		if action.Type == routing.ActionDirect {
			return true
		}
	}

	return false
}

func isPrivateDomain(domain string) bool {
	if domain == "localhost" ||
		strings.HasSuffix(domain, ".local") ||
		strings.HasSuffix(domain, ".lan") ||
		strings.HasSuffix(domain, ".home.arpa") ||
		strings.HasSuffix(domain, ".internal") {
		return true
	}
	return false
}

func (r *Resolver) queryDoH(ctx context.Context, client *http.Client, endpoints []string, req *dns.Msg) (*dns.Msg, error) {
	wire, err := req.Pack()
	if err != nil {
		return nil, err
	}

	var lastErr error
	for _, ep := range endpoints {
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, bytes.NewReader(wire))
		if err != nil {
			lastErr = err
			continue
		}
		httpReq.Header.Set("Content-Type", "application/dns-message")
		httpReq.Header.Set("Accept", "application/dns-message")

		httpResp, err := client.Do(httpReq)
		if err != nil {
			lastErr = err
			continue
		}

		body, err := io.ReadAll(httpResp.Body)
		_ = httpResp.Body.Close()

		if httpResp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("doh status %d", httpResp.StatusCode)
			continue
		}
		if err != nil {
			lastErr = err
			continue
		}

		ans := new(dns.Msg)
		if err := ans.Unpack(body); err != nil {
			lastErr = err
			continue
		}
		ans.Id = req.Id
		return ans, nil
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errors.New("no doh endpoints available")
}

func (r *Resolver) recordIPs(msg *dns.Msg, domain string) {
	if r.opts.IPCache == nil || msg == nil {
		return
	}
	for _, ans := range msg.Answer {
		if a, ok := ans.(*dns.A); ok && a.A != nil {
			r.opts.IPCache.Put(a.A, domain)
		} else if aaaa, ok := ans.(*dns.AAAA); ok && aaaa.AAAA != nil {
			r.opts.IPCache.Put(aaaa.AAAA, domain)
		}
	}
}

func (r *Resolver) storeCache(key string, msg *dns.Msg) {
	if msg == nil || len(msg.Answer) == 0 {
		return
	}

	var minTTL uint32 = 3600
	for i, ans := range msg.Answer {
		ttl := ans.Header().Ttl
		if i == 0 || ttl < minTTL {
			minTTL = ttl
		}
	}
	if minTTL < 1 {
		minTTL = 1
	}

	now := time.Now()
	entry := &cacheEntry{
		msg:        copyMsg(msg, 0),
		cachedAt:   now,
		expiresAt:  now.Add(time.Duration(minTTL) * time.Second),
		staleUntil: now.Add(24 * time.Hour),
		minTTL:     minTTL,
	}

	r.cacheMu.Lock()
	r.cache[key] = entry
	r.cacheMu.Unlock()
}

func copyMsg(orig *dns.Msg, id uint16) *dns.Msg {
	cp := orig.Copy()
	if id != 0 {
		cp.Id = id
	}
	return cp
}

func adjustTTL(msg *dns.Msg, newTTL uint32) {
	if newTTL == 0 {
		newTTL = 1
	}
	for _, ans := range msg.Answer {
		ans.Header().Ttl = newTTL
	}
}
