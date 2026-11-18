package boxengine

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"naive-client/internal/warp"

	"github.com/sagernet/sing-box/adapter"
)

// warpOutboundLifecycle coordinates lazy initialization, shutdown cancellation,
// and in-flight cleanup synchronization for custom WARP outbounds.
//
// Lock ordering: initMu -> mu (never hold mu across network I/O or Engine.mu).
type warpOutboundLifecycle struct {
	closeCtx    context.Context
	closeCancel context.CancelFunc

	initMu    sync.Mutex
	mu        sync.Mutex
	closed    bool
	wg        sync.WaitGroup
	closeOnce sync.Once
}

func newWarpOutboundLifecycle(ctx context.Context) warpOutboundLifecycle {
	if ctx == nil {
		ctx = context.Background()
	}
	closeCtx, closeCancel := context.WithCancel(ctx)
	return warpOutboundLifecycle{
		closeCtx:    closeCtx,
		closeCancel: closeCancel,
	}
}

func (l *warpOutboundLifecycle) start(stage adapter.StartStage, scope *adapter.Scope, closeFn func() error) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	if scope != nil {
		scope.Add(closeFn)
	}
	return nil
}

func (l *warpOutboundLifecycle) isClosedLocked() bool {
	return l.closed || (l.closeCtx != nil && l.closeCtx.Err() != nil)
}

func (l *warpOutboundLifecycle) isClosed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.isClosedLocked()
}

func (l *warpOutboundLifecycle) deriveContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return deriveLifecycleContext(ctx, l.closeCtx, timeout)
}

// close cancels active operations, atomically transitions to closed while detaching any
// active resource under mu, closes the detached resource without holding mu, and waits
// for tracked in-flight initialization/invalidation calls to finish.
func (l *warpOutboundLifecycle) close(detach func() func() error) error {
	var err error
	l.closeOnce.Do(func() {
		if l.closeCancel != nil {
			l.closeCancel()
		}
		var closer func() error
		l.mu.Lock()
		l.closed = true
		if detach != nil {
			closer = detach()
		}
		l.mu.Unlock()
		if closer != nil {
			err = closer()
		}
		l.wg.Wait()
	})
	return err
}

func deriveLifecycleContext(ctx, lifeCtx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	var subCtx context.Context
	var cancel context.CancelFunc
	if timeout > 0 {
		subCtx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		subCtx, cancel = context.WithCancel(ctx)
	}
	if lifeCtx == nil {
		return subCtx, cancel
	}
	stop := context.AfterFunc(lifeCtx, cancel)
	return subCtx, func() {
		stop()
		cancel()
	}
}

func resolveDetourDialer(detour string, outboundMgr adapter.OutboundManager, eng *Engine) (warp.Dialer, error) {
	if detour == "" {
		return nil, nil
	}
	var ob adapter.Outbound
	var ok bool
	if outboundMgr != nil {
		ob, ok = outboundMgr.Outbound(detour)
	}
	if !ok && eng != nil {
		ob, ok = eng.GetOutbound(detour)
	}
	if !ok {
		return nil, fmt.Errorf("detour outbound %q not found", detour)
	}
	return &outboundDialerAdapter{ob: ob}, nil
}

func newWarpProvisionHTTPClient(upstreamDialer warp.Dialer, timeout time.Duration) *http.Client {
	if upstreamDialer == nil {
		return nil
	}
	tr := &http.Transport{
		DialContext: func(c context.Context, network, addr string) (net.Conn, error) {
			return upstreamDialer.DialContext(c, network, addr)
		},
		TLSClientConfig: &tls.Config{
			ServerName: "api.cloudflareclient.com",
		},
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}
}

func closeHTTPTransportIdle(c *http.Client) {
	if c == nil {
		return
	}
	if tr, ok := c.Transport.(*http.Transport); ok {
		tr.CloseIdleConnections()
	}
}

func loadGlobalWarpAccount(eng *Engine) warp.Account {
	if eng == nil {
		return warp.Account{}
	}
	eng.mu.RLock()
	defer eng.mu.RUnlock()
	if eng.cloudflareConfig == nil {
		return warp.Account{}
	}
	return eng.cloudflareConfig.Account
}

func saveGlobalWarpAccount(eng *Engine, enrolled warp.Account) {
	if eng == nil {
		return
	}
	eng.mu.Lock()
	if eng.cloudflareConfig != nil {
		eng.cloudflareConfig.Account = enrolled
	}
	eng.mu.Unlock()
}

func selectEndpointSelector(eng *Engine) *warp.EndpointSelector {
	if eng != nil && eng.endpointSelector != nil {
		return eng.endpointSelector
	}
	return warp.DefaultEndpointSelector()
}

func resolveHostIP(ctx context.Context, host string) (netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr, nil
	}
	rCtx, rCancel := context.WithTimeout(ctx, 1200*time.Millisecond)
	defer rCancel()
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(c context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 800 * time.Millisecond}
			return d.DialContext(c, "udp", "223.5.5.5:53")
		},
	}
	ips, err := r.LookupIP(rCtx, "ip4", host)
	if err == nil && len(ips) > 0 {
		return netip.ParseAddr(ips[0].String())
	}

	dCtx, dCancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer dCancel()
	ips, err = net.DefaultResolver.LookupIP(dCtx, "ip4", host)
	if err == nil && len(ips) > 0 {
		return netip.ParseAddr(ips[0].String())
	}
	return netip.Addr{}, fmt.Errorf("failed to resolve host %q: %w", host, err)
}
