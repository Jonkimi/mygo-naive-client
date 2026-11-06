package dns_test

import (
	"testing"
	"time"

	"github.com/miekg/dns"

	internaldns "naive-client/internal/dns"
)

// Tests that internal/dns Server listens on UDP and TCP, resolves via Resolver,
// and shuts down cleanly.
func TestDNSServer_ServeAndShutdown(t *testing.T) {
	res := internaldns.NewResolver(internaldns.ResolverOptions{
		Hosts: map[string]string{
			"local.test": "127.0.0.99",
		},
	})

	srv, err := internaldns.NewServer(internaldns.ServerOptions{
		BindAddr: "127.0.0.1:0",
		Resolver: res,
	})
	if err != nil {
		t.Fatalf("failed to create dns server: %v", err)
	}

	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start dns server: %v", err)
	}
	defer srv.Stop()

	udpAddr := srv.UDPAddr()
	if udpAddr == "" {
		t.Fatalf("empty udp addr")
	}

	// Test UDP query
	client := new(dns.Client)
	client.Timeout = 2 * time.Second
	req := new(dns.Msg)
	req.SetQuestion("local.test.", dns.TypeA)

	resp, _, err := client.Exchange(req, udpAddr)
	if err != nil {
		t.Fatalf("udp exchange failed: %v", err)
	}
	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "127.0.0.99" {
		t.Fatalf("unexpected udp answer: %v", resp.Answer)
	}

	// Test TCP query
	tcpClient := &dns.Client{Net: "tcp", Timeout: 2 * time.Second}
	tcpAddr := srv.TCPAddr()
	if tcpAddr == "" {
		t.Fatalf("empty tcp addr")
	}

	respTCP, _, err := tcpClient.Exchange(req, tcpAddr)
	if err != nil {
		t.Fatalf("tcp exchange failed: %v", err)
	}
	if len(respTCP.Answer) != 1 || respTCP.Answer[0].(*dns.A).A.String() != "127.0.0.99" {
		t.Fatalf("unexpected tcp answer: %v", respTCP.Answer)
	}
}
