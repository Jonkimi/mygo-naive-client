package sniffer_test

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"net"
	"testing"

	"naive-client/internal/dns/sniffer"
)

// Tests that Sniff extracts TLS SNI and HTTP Host using Peek without consuming bytes.
func TestSniff_TLSClientHello(t *testing.T) {
	// Create a real TLS ClientHello by dialing a mock TLS listener.
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		conf := &tls.Config{
			ServerName:         "my.subdomain.example.com",
			InsecureSkipVerify: true,
		}
		tlsClient := tls.Client(clientConn, conf)
		// Handshake will send ClientHello. It may fail later because serverConn isn't completing it,
		// but the ClientHello will be written into the pipe.
		_ = tlsClient.Handshake()
	}()

	br := bufio.NewReader(serverConn)
	domain, proto, err := sniffer.Sniff(br)
	if err != nil {
		t.Fatalf("expected successful sniff, got err: %v", err)
	}
	if proto != "tls" {
		t.Fatalf("expected proto tls, got %q", proto)
	}
	if domain != "my.subdomain.example.com" {
		t.Fatalf("expected domain my.subdomain.example.com, got %q", domain)
	}

	// Verify peek was lossless: buffered reader still has unread bytes
	if br.Buffered() == 0 {
		t.Fatalf("expected reader to retain unread buffered bytes")
	}
}

func TestSniff_HTTPHost(t *testing.T) {
	httpReq := "GET /index.html HTTP/1.1\r\n" +
		"User-Agent: curl/7.68.0\r\n" +
		"Host: api.github.com:443\r\n" +
		"Accept: */*\r\n\r\n"

	br := bufio.NewReader(stringsNewReader(httpReq))
	domain, proto, err := sniffer.Sniff(br)
	if err != nil {
		t.Fatalf("expected successful sniff, got err: %v", err)
	}
	if proto != "http" {
		t.Fatalf("expected proto http, got %q", proto)
	}
	if domain != "api.github.com" {
		t.Fatalf("expected domain api.github.com (port stripped), got %q", domain)
	}

	// Verify reader can still read the original bytes
	line, err := br.ReadString('\n')
	if err != nil || line != "GET /index.html HTTP/1.1\r\n" {
		t.Fatalf("reader was altered, got %q, err=%v", line, err)
	}
}

func TestSniff_NonMatchingOrShortData(t *testing.T) {
	// Random junk bytes
	br := bufio.NewReader(bytes.NewReader([]byte{0x01, 0x02, 0x03, 0x04}))
	domain, proto, err := sniffer.Sniff(br)
	if err == nil && domain != "" {
		t.Fatalf("expected no match, got %v / %v", domain, proto)
	}

	// SSH handshake
	sshBr := bufio.NewReader(bytes.NewReader([]byte("SSH-2.0-OpenSSH_8.2\r\n")))
	domain, proto, err = sniffer.Sniff(sshBr)
	if err == nil && domain != "" {
		t.Fatalf("expected no match on SSH, got %v / %v", domain, proto)
	}
}

func stringsNewReader(s string) *bytes.Reader {
	return bytes.NewReader([]byte(s))
}
