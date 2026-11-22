package warp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type writeRecorderConn struct {
	net.Conn
	mu     sync.Mutex
	writes [][]byte
}

func (c *writeRecorderConn) Write(p []byte) (int, error) {
	cp := make([]byte, len(p))
	copy(cp, p)
	c.mu.Lock()
	c.writes = append(c.writes, cp)
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func (c *writeRecorderConn) snapshotWrites() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([][]byte, len(c.writes))
	copy(out, c.writes)
	return out
}

func TestTLSFragmentConn_SplitsClientHelloSNIAcrossRecordsAndCompletesMTLS(t *testing.T) {
	srvCert := generateTestServerCert(t)
	priv, _, certPEM, err := GenerateMASQUEKeypair()
	if err != nil {
		t.Fatalf("GenerateMASQUEKeypair: %v", err)
	}
	clientCert, err := ParseMASQUETLSCertificate(certPEM, priv)
	if err != nil {
		t.Fatalf("ParseMASQUETLSCertificate: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	srvErrCh := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			srvErrCh <- err
			return
		}
		defer raw.Close()

		tSrv := tls.Server(raw, &tls.Config{
			Certificates: []tls.Certificate{srvCert},
			ClientAuth:   tls.RequireAnyClientCert,
			NextProtos:   []string{"h2"},
		})
		if err := tSrv.Handshake(); err != nil {
			srvErrCh <- err
			return
		}
		buf := make([]byte, 16)
		n, err := tSrv.Read(buf)
		if err != nil {
			srvErrCh <- err
			return
		}
		if string(buf[:n]) != "ping-masque" {
			srvErrCh <- errors.New("unexpected payload")
			return
		}
		_, err = tSrv.Write([]byte("pong-masque"))
		srvErrCh <- err
	}()

	rawConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rawConn.Close()

	rec := &writeRecorderConn{Conn: rawConn}
	fragConn := newTLSFragmentConnWithConfig(context.Background(), rec, tlsFragmentConfig{
		minChunk: 3,
		maxChunk: 6,
		minDelay: 1 * time.Millisecond,
		maxDelay: 2 * time.Millisecond,
	})

	tlsClient := tls.Client(fragConn, &tls.Config{
		ServerName:         DefaultMASQUESNI,
		Certificates:       []tls.Certificate{clientCert},
		NextProtos:         []string{"h2"},
		InsecureSkipVerify: true,
	})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("fragmented TLS handshake failed: %v", err)
	}
	if _, err := tlsClient.Write([]byte("ping-masque")); err != nil {
		t.Fatalf("write app data: %v", err)
	}
	resp := make([]byte, 16)
	n, err := tlsClient.Read(resp)
	if err != nil {
		t.Fatalf("read app data: %v", err)
	}
	if string(resp[:n]) != "pong-masque" {
		t.Fatalf("unexpected response %q", string(resp[:n]))
	}
	if sErr := <-srvErrCh; sErr != nil {
		t.Fatalf("server error: %v", sErr)
	}

	writes := rec.snapshotWrites()
	if len(writes) < 4 {
		t.Fatalf("expected fragmented ClientHello to produce multiple TCP writes, got %d", len(writes))
	}

	// Verify ClientHello writes (those before Finished/app data) are valid TLS Handshake records
	// and that no single write contains the plaintext SNI domain.
	var reassembledHandshake []byte
	handshakeRecordCount := 0
	for _, w := range writes {
		if bytes.Contains(w, []byte(DefaultMASQUESNI)) || bytes.Contains(w, []byte("cloudflareclient.com")) {
			t.Fatalf("single fragmented write must not contain complete SNI hostname: %q", w)
		}
		if len(w) >= tlsRecordHeaderLen && w[0] == tlsContentHandshake {
			recLen := int(binary.BigEndian.Uint16(w[3:5]))
			if len(w) == tlsRecordHeaderLen+recLen && handshakeRecordCount < 20 {
				// Stop collecting once we hit the subsequent Finished record (after server hello).
				// ClientHello always begins with 0x01 in the first record.
				if handshakeRecordCount == 0 || w[5] != tlsHandshakeClientHel {
					reassembledHandshake = append(reassembledHandshake, w[tlsRecordHeaderLen:]...)
					handshakeRecordCount++
				}
			}
		}
	}
	if !bytes.Contains(reassembledHandshake, []byte(DefaultMASQUESNI)) {
		t.Fatalf("expected reassembled handshake records to preserve SNI %q", DefaultMASQUESNI)
	}
}

func TestTLSFragmentConn_NonClientHelloPassesThrough(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	rec := &writeRecorderConn{Conn: c1}
	frag := newTLSFragmentConn(context.Background(), rec)

	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	done := make(chan []byte, 1)
	go func() {
		buf := make([]byte, len(payload))
		_, _ = io.ReadFull(c2, buf)
		done <- buf
	}()

	n, err := frag.Write(payload)
	if err != nil || n != len(payload) {
		t.Fatalf("Write failed: n=%d err=%v", n, err)
	}
	got := <-done
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %q", got)
	}
	if len(rec.snapshotWrites()) != 1 {
		t.Fatalf("expected non-TLS write to pass through in 1 write, got %d", len(rec.snapshotWrites()))
	}
}

func TestTLSFragmentConn_ContextCanceledDuringDelay(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	go func() {
		_, _ = io.Copy(io.Discard, c2)
	}()

	// Build a minimal valid TLS ClientHello with SNI
	srvCert := generateTestServerCert(t)
	var captured []byte
	p1, p2 := net.Pipe()
	go func() {
		defer p2.Close()
		buf := make([]byte, 4096)
		n, _ := p2.Read(buf)
		captured = buf[:n]
	}()
	tc := tls.Client(p1, &tls.Config{
		ServerName:         DefaultMASQUESNI,
		Certificates:       []tls.Certificate{srvCert},
		InsecureSkipVerify: true,
	})
	_ = tc.Handshake()
	_ = p1.Close()
	if len(captured) == 0 {
		t.Fatalf("failed to capture ClientHello")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	frag := newTLSFragmentConnWithConfig(ctx, c1, tlsFragmentConfig{
		minChunk: 4,
		maxChunk: 6,
		minDelay: 2 * time.Second,
		maxDelay: 2 * time.Second,
	})

	start := time.Now()
	_, err := frag.Write(captured)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("expected canceled fragment write to abort promptly, took %v", elapsed)
	}
}
