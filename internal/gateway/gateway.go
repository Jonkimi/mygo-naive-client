package gateway

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"naive-client/internal/dns/ipcache"
	"naive-client/internal/dns/sniffer"
	"naive-client/internal/telemetry"
)

type Blocker interface {
	Match(domain string) (blocked bool, rule string)
}

type DialTargetFunc func(ctx context.Context, target string) (net.Conn, string, error)

type Options struct {
	BindAddr   string
	Tracker    *telemetry.Tracker
	DialTarget DialTargetFunc
	IPCache    *ipcache.Cache
	Blocker    Blocker
}

type Gateway struct {
	opts     Options
	listener net.Listener
	closed   atomic.Bool
	wg       sync.WaitGroup
	addr     string
}

func New(opts Options) (*Gateway, error) {
	if opts.BindAddr == "" {
		opts.BindAddr = "127.0.0.1:10809"
	}
	return &Gateway{
		opts: opts,
	}, nil
}

func (g *Gateway) Start() error {
	ln, err := net.Listen("tcp", g.opts.BindAddr)
	if err != nil {
		return err
	}
	g.listener = ln
	g.addr = ln.Addr().String()

	g.wg.Add(1)
	go g.acceptLoop()
	return nil
}

func (g *Gateway) Stop() error {
	if g.closed.Swap(true) {
		return nil
	}
	if g.listener != nil {
		_ = g.listener.Close()
	}
	g.wg.Wait()
	return nil
}

func (g *Gateway) Addr() string {
	if g.addr != "" {
		return g.addr
	}
	return g.opts.BindAddr
}

func (g *Gateway) acceptLoop() {
	defer g.wg.Done()
	for {
		conn, err := g.listener.Accept()
		if err != nil {
			if g.closed.Load() {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}

		g.wg.Add(1)
		go func(c net.Conn) {
			defer g.wg.Done()
			g.handleConn(c)
		}(conn)
	}
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

func (g *Gateway) handleConn(conn net.Conn) {
	defer conn.Close()

	br := bufio.NewReader(conn)
	firstByte, err := br.Peek(1)
	if err != nil {
		return
	}

	bConn := &bufferedConn{
		Conn: conn,
		r:    br,
	}

	if firstByte[0] == 0x05 {
		g.handleSocks5(bConn, br)
	} else {
		g.handleHTTP(bConn, br)
	}
}

func (g *Gateway) resolveHost(host string, br *bufio.Reader) string {
	ip := net.ParseIP(host)
	if ip == nil {
		return host
	}
	if g.opts.IPCache != nil {
		if domain, ok := g.opts.IPCache.Lookup(ip); ok && domain != "" {
			return domain
		}
	}
	if br != nil {
		if sniffed, _, err := sniffer.Sniff(br); err == nil && sniffed != "" {
			return sniffed
		}
	}
	return host
}

func (g *Gateway) handleSocks5(conn net.Conn, br *bufio.Reader) {
	// 1. Negotiation
	header := make([]byte, 2)
	if _, err := io.ReadFull(br, header); err != nil {
		return
	}
	nMethods := int(header[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}

	// Reply: 0x05 (version), 0x00 (NO AUTH)
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// 2. Request
	reqHead := make([]byte, 4)
	if _, err := io.ReadFull(br, reqHead); err != nil {
		return
	}
	cmd := reqHead[1]
	if cmd != 0x01 { // Only CONNECT supported
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	atyp := reqHead[3]
	var host string
	switch atyp {
	case 0x01: // IPv4
		ipv4 := make([]byte, 4)
		if _, err := io.ReadFull(br, ipv4); err != nil {
			return
		}
		host = net.IP(ipv4).String()
	case 0x03: // Domain
		domainLenByte, err := br.ReadByte()
		if err != nil {
			return
		}
		domainBytes := make([]byte, int(domainLenByte))
		if _, err := io.ReadFull(br, domainBytes); err != nil {
			return
		}
		host = string(domainBytes)
	case 0x04: // IPv6
		ipv6 := make([]byte, 16)
		if _, err := io.ReadFull(br, ipv6); err != nil {
			return
		}
		host = net.IP(ipv6).String()
	default:
		_, _ = conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var portBytes [2]byte
	if _, err := io.ReadFull(br, portBytes[:]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBytes[:])
	effectiveHost := g.resolveHost(host, nil)
	target := net.JoinHostPort(effectiveHost, strconv.Itoa(int(port)))

	// Check Blocker
	if g.opts.Blocker != nil {
		if blocked, _ := g.opts.Blocker.Match(effectiveHost); blocked {
			_, _ = conn.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
	}

	// 3. Dial target
	dialStart := time.Now()
	remoteConn, nodeID, dialErr := g.dial(target)
	dialRTT := time.Since(dialStart)

	if g.opts.Tracker != nil && nodeID != "" {
		g.opts.Tracker.RecordDial(nodeID, effectiveHost, dialRTT, dialErr)
	}

	if dialErr != nil {
		_, _ = conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remoteConn.Close()

	// Reply SOCKS5 Success
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	// Sniff first payload if host was raw IP
	if net.ParseIP(host) != nil && g.opts.IPCache != nil {
		if sniffed, _, err := sniffer.Sniff(br); err == nil && sniffed != "" {
			g.opts.IPCache.Put(net.ParseIP(host), sniffed)
		}
	}

	// 4. Relay
	g.relay(conn, remoteConn)
}

func (g *Gateway) handleHTTP(conn net.Conn, br *bufio.Reader) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	if req.Method == http.MethodConnect {
		target := req.URL.Host
		if target == "" {
			target = req.Host
		}
		host, port, err := net.SplitHostPort(target)
		if err != nil {
			host = target
			port = "443"
		}
		effectiveHost := g.resolveHost(host, nil)
		target = net.JoinHostPort(effectiveHost, port)

		if g.opts.Blocker != nil {
			if blocked, _ := g.opts.Blocker.Match(effectiveHost); blocked {
				_, _ = conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
				return
			}
		}

		dialStart := time.Now()
		remoteConn, nodeID, dialErr := g.dial(target)
		dialRTT := time.Since(dialStart)

		if g.opts.Tracker != nil && nodeID != "" {
			g.opts.Tracker.RecordDial(nodeID, effectiveHost, dialRTT, dialErr)
		}

		if dialErr != nil {
			_, _ = conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return
		}
		defer remoteConn.Close()

		if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			return
		}

		g.relay(conn, remoteConn)
		return
	}

	// Standard HTTP Proxy request
	target := req.URL.Host
	if target == "" {
		target = req.Host
	}
	if !hasPort(target) {
		target = net.JoinHostPort(target, "80")
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		port = "80"
	}
	effectiveHost := g.resolveHost(host, nil)
	target = net.JoinHostPort(effectiveHost, port)

	if g.opts.Blocker != nil {
		if blocked, _ := g.opts.Blocker.Match(effectiveHost); blocked {
			_, _ = conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
			return
		}
	}

	dialStart := time.Now()
	remoteConn, nodeID, dialErr := g.dial(target)
	dialRTT := time.Since(dialStart)

	if g.opts.Tracker != nil && nodeID != "" {
		g.opts.Tracker.RecordDial(nodeID, effectiveHost, dialRTT, dialErr)
	}

	if dialErr != nil {
		_, _ = conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer remoteConn.Close()

	// Forward original HTTP request
	if err := req.Write(remoteConn); err != nil {
		return
	}

	g.relay(conn, remoteConn)
}

func (g *Gateway) dial(target string) (net.Conn, string, error) {
	if g.opts.DialTarget != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return g.opts.DialTarget(ctx, target)
	}
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	return conn, "direct", err
}

func (g *Gateway) relay(client, remote net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(remote, client)
		if tc, ok := remote.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		} else {
			_ = remote.Close()
		}
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, remote)
		if tc, ok := client.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		} else {
			_ = client.Close()
		}
	}()

	wg.Wait()
}

func hasPort(s string) bool {
	_, _, err := net.SplitHostPort(s)
	return err == nil
}
