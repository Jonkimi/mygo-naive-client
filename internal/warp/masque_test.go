package warp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/quic-go/quicvarint"
	"golang.org/x/net/http2"
)

func TestConnectMASQUE_InvalidAccount(t *testing.T) {
	ctx := context.Background()
	_, err := ConnectMASQUE(ctx, nil, "127.0.0.1:443", nil, true, true)
	if err == nil {
		t.Errorf("expected error with nil account")
	}
}

func TestConnectMASQUE_InvalidCert(t *testing.T) {
	ctx := context.Background()
	acc := &Account{
		MASQUEPrivateKey: "invalid-key",
		MASQUECertPEM:    "invalid-cert",
	}
	_, err := ConnectMASQUE(ctx, nil, "127.0.0.1:443", acc, true, true)
	if err == nil {
		t.Errorf("expected error with invalid client certificate")
	}
}

// Regression: dialMASQUEH2 previously passed a short-lived dialCtx directly to connectip.DialH2
// and immediately called h2Cancel() after DialH2 returned, killing the active HTTP/2 CONNECT stream.
// Additionally, the 1500-byte read buffer truncated larger HTTP/2 capsule IP packets.
func TestConnectMASQUE_H2_LongLivedStreamAndLargePayload(t *testing.T) {
	serverNS, err := NewNetstack("10.99.0.1/32", "")
	if err != nil {
		t.Fatalf("NewNetstack failed: %v", err)
	}
	defer serverNS.Close()

	// Ensure server netstack accepts TCP connections destined for 10.99.0.1:80
	_ = serverNS.Stack.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4([4]byte{10, 99, 0, 1}), PrefixLen: 32},
	}, stack.AddressProperties{})

	tcpLn, err := gonet.ListenTCP(serverNS.Stack, tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFrom4([4]byte{10, 99, 0, 1}),
		Port: 80,
	}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("gonet.ListenTCP failed: %v", err)
	}
	defer tcpLn.Close()

	largePayload := strings.Repeat("WARP-MASQUE-H2-", 300) // 4500 bytes (> 1500B MTU)
	go func() {
		for {
			c, err := tcpLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				req, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					return
				}
				_ = req.Body.Close()
				resp := &http.Response{
					StatusCode:    http.StatusOK,
					ProtoMajor:    1,
					ProtoMinor:    1,
					Header:        make(http.Header),
					Body:          io.NopCloser(strings.NewReader(largePayload)),
					ContentLength: int64(len(largePayload)),
				}
				_ = resp.Write(conn)
			}(c)
		}
	}()

	srvCert := generateTestServerCert(t)
	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer rawLn.Close()

	tlsLn := tls.NewListener(rawLn, &tls.Config{
		Certificates: []tls.Certificate{srvCert},
		NextProtos:   []string{"h2"},
	})

	var handlerWG sync.WaitGroup
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerWG.Add(1)
		defer handlerWG.Done()
		if r.Method != http.MethodConnect || r.Header.Get("cf-connect-proto") != "cf-connect-ip" {
			http.Error(w, "bad masque connect", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}

		ctx, cancel := context.WithCancel(r.Context())
		outboundDone := make(chan struct{})
		defer func() {
			cancel()
			<-outboundDone
		}()

		// Server outbound (serverNS -> client HTTP/2 capsule response)
		go func() {
			defer close(outboundDone)
			defer cancel()
			for {
				pkt, err := serverNS.ReadPacket(ctx)
				if err != nil {
					return
				}
				var frame []byte
				frame = quicvarint.Append(frame, 0) // DATAGRAM capsule type 0
				frame = quicvarint.Append(frame, uint64(len(pkt)))
				frame = append(frame, pkt...)
				if _, err := w.Write(frame); err != nil {
					return
				}
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
			}
		}()

		// Server inbound (client HTTP/2 capsule request -> serverNS)
		br := bufio.NewReader(r.Body)
		for {
			cType, err := quicvarint.Read(br)
			if err != nil {
				return
			}
			cLen, err := quicvarint.Read(br)
			if err != nil {
				return
			}
			buf := make([]byte, cLen)
			if _, err := io.ReadFull(br, buf); err != nil {
				return
			}
			if cType == 0 && len(buf) > 0 {
				_ = serverNS.InjectPacket(buf)
			}
		}
	})

	srv := &http.Server{
		Handler: handler,
	}
	if err := http2.ConfigureServer(srv, &http2.Server{}); err != nil {
		t.Fatalf("ConfigureServer failed: %v", err)
	}
	go func() {
		_ = srv.Serve(tlsLn)
	}()
	defer func() {
		_ = srv.Close()
		handlerWG.Wait()
	}()

	priv, _, certPEM, err := GenerateMASQUEKeypair()
	if err != nil {
		t.Fatalf("GenerateMASQUEKeypair failed: %v", err)
	}
	acc := &Account{
		MASQUEPrivateKey: priv,
		MASQUECertPEM:    certPEM,
		MASQUEIPv4:       "172.16.0.2",
	}

	// Use a short-lived dial context to prove ConnectMASQUE decouples it from stream lifetime
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 3*time.Second)
	tun, err := ConnectMASQUE(dialCtx, nil, rawLn.Addr().String(), acc, true, false)
	dialCancel()
	if err != nil {
		t.Fatalf("ConnectMASQUE H2 failed: %v", err)
	}
	defer tun.Close()

	if tun.Protocol() != "h2" {
		t.Fatalf("expected protocol h2, got %s", tun.Protocol())
	}

	// Verify tunnel survives after dialCtx was canceled and handles multiple requests + >1500B payloads
	for i := 0; i < 2; i++ {
		reqCtx, reqCancel := context.WithTimeout(context.Background(), 3*time.Second)
		conn, err := tun.DialContextTCP(reqCtx, "10.99.0.1:80")
		if err != nil {
			reqCancel()
			t.Fatalf("attempt %d: DialContextTCP failed: %v", i+1, err)
		}
		_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: 10.99.0.1\r\nConnection: close\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			_ = conn.Close()
			reqCancel()
			t.Fatalf("attempt %d: ReadResponse failed: %v", i+1, err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		_ = conn.Close()
		reqCancel()
		if err != nil {
			t.Fatalf("attempt %d: ReadAll failed: %v", i+1, err)
		}
		if !bytes.Equal(body, []byte(largePayload)) {
			t.Fatalf("attempt %d: body mismatch: got %d bytes, want %d bytes", i+1, len(body), len(largePayload))
		}
	}

	// Regression: dialing after tunnel closure must fail immediately instead of hanging until ctx timeout.
	_ = tun.Close()
	start := time.Now()
	closedCtx, closedCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer closedCancel()
	if _, err := tun.DialContextTCP(closedCtx, "10.99.0.1:80"); err == nil {
		t.Fatalf("expected DialContextTCP on closed tunnel to fail")
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("DialContextTCP on closed tunnel took %v, expected immediate failure", elapsed)
	}
}

type trackingDialer struct {
	networks []string
}

func (d *trackingDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.networks = append(d.networks, network)
	return (&net.Dialer{}).DialContext(ctx, network, addr)
}

func (d *trackingDialer) ListenPacket(ctx context.Context, network, addr string) (net.PacketConn, error) {
	d.networks = append(d.networks, network)
	var lc net.ListenConfig
	return lc.ListenPacket(ctx, "udp", "127.0.0.1:0")
}

func TestConnectMASQUEWithOptions_PreferH2TriesTCPBeforeUDP(t *testing.T) {
	srvCert := generateTestServerCert(t)
	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer rawLn.Close()

	tlsLn := tls.NewListener(rawLn, &tls.Config{
		Certificates: []tls.Certificate{srvCert},
		NextProtos:   []string{"h2"},
	})
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			<-r.Context().Done()
		}),
	}
	_ = http2.ConfigureServer(srv, &http2.Server{})
	go func() { _ = srv.Serve(tlsLn) }()
	defer srv.Close()

	priv, _, certPEM, err := GenerateMASQUEKeypair()
	if err != nil {
		t.Fatalf("GenerateMASQUEKeypair failed: %v", err)
	}
	acc := &Account{
		MASQUEPrivateKey: priv,
		MASQUECertPEM:    certPEM,
		MASQUEIPv4:       "172.16.0.2",
	}

	d := &trackingDialer{}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	tun, err := ConnectMASQUEWithOptions(ctx, d, rawLn.Addr().String(), acc, MASQUEOptions{PreferH2: true})
	if err != nil {
		t.Fatalf("ConnectMASQUEWithOptions(PreferH2) failed: %v", err)
	}
	defer tun.Close()

	if tun.Protocol() != "h2" {
		t.Fatalf("expected protocol h2, got %s", tun.Protocol())
	}
	if len(d.networks) != 1 || d.networks[0] != "tcp" {
		t.Fatalf("expected PreferH2 to dial tcp only when H2 succeeds, got %v", d.networks)
	}
}

func TestConnectMASQUEWithOptions_PreferH2FallsBackToH3WhenTCPFails(t *testing.T) {
	// Closed TCP port ensures TCP dial fails immediately so PreferH2 must fall back to UDP/H3.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	priv, _, certPEM, err := GenerateMASQUEKeypair()
	if err != nil {
		t.Fatalf("GenerateMASQUEKeypair failed: %v", err)
	}
	acc := &Account{
		MASQUEPrivateKey: priv,
		MASQUECertPEM:    certPEM,
		MASQUEIPv4:       "172.16.0.2",
	}

	d := &trackingDialer{}
	ctx, cancel := context.WithTimeout(context.Background(), 3500*time.Millisecond)
	defer cancel()

	_, err = ConnectMASQUEWithOptions(ctx, d, addr, acc, MASQUEOptions{PreferH2: true})
	if err == nil {
		t.Fatalf("expected error against closed endpoint")
	}
	if !strings.Contains(err.Error(), "fallback to HTTP/3 failed") {
		t.Fatalf("expected fallback to HTTP/3 error, got: %v", err)
	}
	if len(d.networks) < 2 || d.networks[0] != "tcp" || d.networks[1] != "udp" {
		t.Fatalf("expected dial sequence [tcp udp], got %v", d.networks)
	}
}

func generateTestServerCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{DefaultMASQUESNI},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load x509 keypair: %v", err)
	}
	return cert
}

// Regression: ResolveDNSOverTunnel must treat valid empty DNS answers as ErrNoDNSRecords
// (skipping redundant TCP fallback after UDP NXDOMAIN/NODATA), and must support AAAA
// on TCP 1.0.0.1:53 when UDP transport fails.
func TestResolveDNSOverTunnel_ErrorClassificationAndTCPFallback(t *testing.T) {
	if _, err := ResolveDNSOverTunnel(context.Background(), nil, "example.com", true, true); err == nil {
		t.Fatalf("expected error for nil dialer")
	}

	serveDNS := func(handle func(req *dns.Msg) *dns.Msg) (net.Conn, error) {
		cConn, sConn := net.Pipe()
		go func() {
			defer sConn.Close()
			dc := &dns.Conn{Conn: sConn}
			req, err := dc.ReadMsg()
			if err != nil {
				return
			}
			resp := handle(req)
			_ = dc.WriteMsg(resp)
		}()
		return cConn, nil
	}

	// 1. UDP returns valid empty answers (NODATA/NXDOMAIN) for A and AAAA -> ErrNoDNSRecords, no TCP attempt.
	var tcpCalls int
	addr, err := ResolveDNSOverTunnel(context.Background(), func(ctx context.Context, network string, server netip.Addr, port uint16) (net.Conn, error) {
		if network == "tcp" {
			tcpCalls++
			return nil, errors.New("unexpected tcp fallback")
		}
		return serveDNS(func(req *dns.Msg) *dns.Msg {
			resp := new(dns.Msg)
			resp.SetReply(req)
			return resp
		})
	}, "missing.example.invalid", true, true)
	if !errors.Is(err, ErrNoDNSRecords) {
		t.Fatalf("expected ErrNoDNSRecords on empty UDP A+AAAA answers, got addr=%v err=%v", addr, err)
	}
	if tcpCalls != 0 {
		t.Fatalf("expected 0 TCP fallback calls after authoritative UDP empty answers, got %d", tcpCalls)
	}

	// 2. UDP transport failure -> TCP 1.0.0.1:53 tries A (empty), then AAAA -> resolves IPv6.
	wantV6 := net.ParseIP("2001:db8::42")
	var udpCalls int
	var tcpTypes []uint16
	addr, err = ResolveDNSOverTunnel(context.Background(), func(ctx context.Context, network string, server netip.Addr, port uint16) (net.Conn, error) {
		if network == "udp" {
			udpCalls++
			return nil, errors.New("udp blocked")
		}
		return serveDNS(func(req *dns.Msg) *dns.Msg {
			tcpTypes = append(tcpTypes, req.Question[0].Qtype)
			resp := new(dns.Msg)
			resp.SetReply(req)
			if req.Question[0].Qtype == dns.TypeAAAA {
				resp.Answer = append(resp.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
					AAAA: wantV6,
				})
			}
			return resp
		})
	}, "v6only.example.invalid", true, true)
	if err != nil {
		t.Fatalf("expected TCP AAAA fallback to succeed, got err=%v", err)
	}
	if addr != netip.MustParseAddr("2001:db8::42") {
		t.Fatalf("expected 2001:db8::42, got %v", addr)
	}
	if udpCalls != 1 {
		t.Fatalf("expected single UDP attempt before TCP fallback on transport error, got %d", udpCalls)
	}
	if len(tcpTypes) != 2 || tcpTypes[0] != dns.TypeA || tcpTypes[1] != dns.TypeAAAA {
		t.Fatalf("expected TCP fallback sequence [A, AAAA], got %v", tcpTypes)
	}

	// 3. Truncated UDP response (TC=1) and SERVFAIL must trigger TCP 1.0.0.1:53 fallback, not ErrNoDNSRecords.
	for _, tc := range []struct {
		name      string
		truncated bool
		rcode     int
	}{
		{name: "truncated", truncated: true, rcode: dns.RcodeSuccess},
		{name: "servfail", truncated: false, rcode: dns.RcodeServerFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var usedTCP bool
			wantV4 := net.ParseIP("198.51.100.99")
			gotAddr, tcErr := ResolveDNSOverTunnel(context.Background(), func(ctx context.Context, network string, server netip.Addr, port uint16) (net.Conn, error) {
				return serveDNS(func(req *dns.Msg) *dns.Msg {
					resp := new(dns.Msg)
					resp.SetReply(req)
					if network == "udp" {
						resp.Truncated = tc.truncated
						resp.Rcode = tc.rcode
						return resp
					}
					usedTCP = true
					resp.Answer = append(resp.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   wantV4,
					})
					return resp
				})
			}, "tc-or-servfail.example.invalid", true, true)
			if tcErr != nil {
				t.Fatalf("expected TCP fallback to succeed for %s, got err=%v", tc.name, tcErr)
			}
			if !usedTCP || gotAddr != netip.MustParseAddr("198.51.100.99") {
				t.Fatalf("expected TCP fallback resolving 198.51.100.99 for %s, got usedTCP=%v addr=%v", tc.name, usedTCP, gotAddr)
			}
		})
	}
}

type failTCPTrackingDialer struct {
	tcpCalls int
	udpCalls int
}

func (d *failTCPTrackingDialer) DialContext(_ context.Context, _ string, _ string) (net.Conn, error) {
	d.tcpCalls++
	return nil, errors.New("tcp failed")
}

func (d *failTCPTrackingDialer) ListenPacket(_ context.Context, _ string, _ string) (net.PacketConn, error) {
	d.udpCalls++
	return nil, errors.New("udp should not be called")
}

// Regression: PreferH2=true on a known H2-only endpoint (e.g. 162.159.199.161:443) must not
// fall back to HTTP/3 QUIC (which always fails with tls handshake failure on non-.1/.2 IPs).
func TestConnectMASQUEWithOptions_H2OnlySkipsH3EvenWhenPreferH2(t *testing.T) {
	priv, _, certPEM, err := GenerateMASQUEKeypair()
	if err != nil {
		t.Fatalf("GenerateMASQUEKeypair: %v", err)
	}
	acc := &Account{
		MASQUEPrivateKey: priv,
		MASQUECertPEM:    certPEM,
		MASQUEIPv4:       "172.16.0.2",
	}
	d := &failTCPTrackingDialer{}
	_, connErr := ConnectMASQUEWithOptions(context.Background(), d, "162.159.199.161:443", acc, MASQUEOptions{PreferH2: true})
	if connErr == nil {
		t.Fatalf("expected error from failing TCP dial")
	}
	if d.tcpCalls != 1 {
		t.Fatalf("expected 1 TCP call, got %d", d.tcpCalls)
	}
	if d.udpCalls != 0 {
		t.Fatalf("expected 0 UDP ListenPacket calls for H2-only endpoint with PreferH2=true, got %d", d.udpCalls)
	}
}

// Regression: when dialCtx expires while connectip.DialH2 is awaiting response headers,
// dialMASQUEH2 must surface context.DeadlineExceeded rather than context.Canceled so
// cooldowns and fallback triggers treat it as a timeout, not caller cancellation.
func TestDialMASQUEH2_TimeoutReturnsDeadlineExceededNotCanceled(t *testing.T) {
	srvCert := generateTestServerCert(t)
	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer rawLn.Close()

	tlsLn := tls.NewListener(rawLn, &tls.Config{
		Certificates: []tls.Certificate{srvCert},
		NextProtos:   []string{"h2"},
	})
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Accept TLS+H2 connection and stall HTTP/2 CONNECT response until client disconnects.
			<-r.Context().Done()
		}),
	}
	_ = http2.ConfigureServer(srv, &http2.Server{})
	go func() { _ = srv.Serve(tlsLn) }()
	defer srv.Close()

	priv, _, certPEM, err := GenerateMASQUEKeypair()
	if err != nil {
		t.Fatalf("GenerateMASQUEKeypair: %v", err)
	}
	acc := &Account{
		MASQUEPrivateKey: priv,
		MASQUECertPEM:    certPEM,
		MASQUEIPv4:       "172.16.0.2",
	}
	cert, err := ParseMASQUETLSCertificate(acc.MASQUECertPEM, acc.MASQUEPrivateKey)
	if err != nil {
		t.Fatalf("ParseMASQUETLSCertificate: %v", err)
	}
	ns, err := NewNetstack(acc.MASQUEIPv4, DefaultIPv6)
	if err != nil {
		t.Fatalf("NewNetstack: %v", err)
	}
	defer ns.Close()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer dialCancel()
	tunnelCtx, tunnelCancel := context.WithCancel(context.Background())
	defer tunnelCancel()

	_, dialErr := dialMASQUEH2(dialCtx, &defaultDialer{}, rawLn.Addr().String(), &tls.Config{
		ServerName:         DefaultMASQUESNI,
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
	}, ns, tunnelCtx, tunnelCancel, MASQUEOptions{})
	if dialErr == nil {
		t.Fatalf("expected timeout error from stalled H2 CONNECT")
	}
	if !errors.Is(dialErr, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got %v", dialErr)
	}
	if errors.Is(dialErr, context.Canceled) {
		t.Fatalf("timeout must not be wrapped as context.Canceled: %v", dialErr)
	}
}

type recordingTCPDialer struct {
	mu       sync.Mutex
	recorded []*writeRecorderConn
}

func (d *recordingTCPDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var nd net.Dialer
	c, err := nd.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	rec := &writeRecorderConn{Conn: c}
	d.mu.Lock()
	d.recorded = append(d.recorded, rec)
	d.mu.Unlock()
	return rec, nil
}

func (d *recordingTCPDialer) ListenPacket(_ context.Context, _ string, _ string) (net.PacketConn, error) {
	return nil, errors.New("unexpected udp ListenPacket")
}

func TestConnectMASQUEWithOptions_H2_TLSFragmentation(t *testing.T) {
	srvCert := generateTestServerCert(t)
	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer rawLn.Close()

	tlsLn := tls.NewListener(rawLn, &tls.Config{
		Certificates: []tls.Certificate{srvCert},
		ClientAuth:   tls.RequireAnyClientCert,
		NextProtos:   []string{"h2"},
	})
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodConnect || r.Header.Get("cf-connect-proto") != "cf-connect-ip" {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			<-r.Context().Done()
		}),
	}
	_ = http2.ConfigureServer(srv, &http2.Server{})
	go func() { _ = srv.Serve(tlsLn) }()
	defer srv.Close()

	priv, _, certPEM, err := GenerateMASQUEKeypair()
	if err != nil {
		t.Fatalf("GenerateMASQUEKeypair: %v", err)
	}
	acc := &Account{
		MASQUEPrivateKey: priv,
		MASQUECertPEM:    certPEM,
		MASQUEIPv4:       "172.16.0.2",
	}

	dialer := &recordingTCPDialer{}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	tun, err := ConnectMASQUEWithOptions(ctx, dialer, rawLn.Addr().String(), acc, MASQUEOptions{
		ForceH2:     true,
		TLSFragment: true,
		UTLS:        true,
	})
	if err != nil {
		t.Fatalf("ConnectMASQUEWithOptions(TLSFragment=true) failed: %v", err)
	}
	defer tun.Close()

	if tun.Protocol() != "h2" {
		t.Fatalf("expected protocol h2, got %q", tun.Protocol())
	}

	dialer.mu.Lock()
	recs := append([]*writeRecorderConn(nil), dialer.recorded...)
	dialer.mu.Unlock()
	if len(recs) == 0 {
		t.Fatalf("expected at least 1 recorded TCP connection")
	}
	writes := recs[0].snapshotWrites()
	if len(writes) < 4 {
		t.Fatalf("expected fragmented ClientHello to produce multiple TCP writes, got %d", len(writes))
	}
	for _, w := range writes {
		if bytes.Contains(w, []byte(DefaultMASQUESNI)) || bytes.Contains(w, []byte("cloudflareclient.com")) {
			t.Fatalf("expected no single wire write to expose full MASQUE SNI, got %q", w)
		}
	}
}

