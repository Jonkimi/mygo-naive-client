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
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

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

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Header.Get("cf-connect-proto") != "cf-connect-ip" {
			http.Error(w, "bad masque connect", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}

		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()

		// Server outbound (serverNS -> client HTTP/2 capsule response)
		go func() {
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
