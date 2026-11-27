//go:build darwin

package tailnet

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/sagernet/tailscale/ipn/ipnstate"
)

// Tests parsing port and token from lsof -F n output for App Store Tailscale IPNExtension.
func TestParseDarwinLsofSameUserProof(t *testing.T) {
	out := []byte("p26144\nf12\nn/Users/test/Library/Group Containers/W5364U7YZB.group.io.tailscale.ipn.macos/sameuserproof-65057-a5110d37be20ca5d2a3b\n")
	port, token, err := parseDarwinLsofSameUserProof(out)
	if err != nil {
		t.Fatalf("parseDarwinLsofSameUserProof failed: %v", err)
	}
	if port != 65057 || token != "a5110d37be20ca5d2a3b" {
		t.Fatalf("got (%d, %q), want (65057, a5110d37be20ca5d2a3b)", port, token)
	}

	if _, _, err := parseDarwinLsofSameUserProof([]byte("p1\nn/tmp/other\n")); err == nil {
		t.Error("expected error when sameuserproof path is missing")
	}
	if _, _, err := parseDarwinLsofSameUserProof([]byte("n/Users/x/.tailscale.ipn.macos/sameuserproof-bad-tok\n")); err == nil {
		t.Error("expected error for non-numeric port")
	}
}

// Regression: bare local.Client pooled connections under synthetic local-tailscaled.sock:80 and
// ran uncached lsof twice per request, stalling when IPNExtension restarted on a new port.
func TestDarwinHostClient_CachesAndRetriesOnPortChange(t *testing.T) {
	newStatusServer := func(expectedToken, hostName string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, pass, ok := r.BasicAuth()
			if !ok || pass != expectedToken {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(&ipnstate.Status{
				BackendState: "Running",
				Self: &ipnstate.PeerStatus{
					HostName: hostName,
					Online:   true,
				},
			})
		}))
	}

	srv1 := newStatusServer("tok-one", "mac-one")
	defer srv1.Close()
	_, p1Str, _ := net.SplitHostPort(srv1.Listener.Addr().String())
	port1, _ := strconv.Atoi(p1Str)

	srv2 := newStatusServer("tok-two", "mac-two")
	defer srv2.Close()
	_, p2Str, _ := net.SplitHostPort(srv2.Listener.Addr().String())
	port2, _ := strconv.Atoi(p2Str)

	var activePhase atomic.Int32
	var discoverCalls atomic.Int32
	client := &darwinHostClient{
		dialHost: "127.0.0.1",
		discoverFn: func(ctx context.Context) (int, string, error) {
			discoverCalls.Add(1)
			if activePhase.Load() == 0 {
				return port1, "tok-one", nil
			}
			return port2, "tok-two", nil
		},
	}

	// 1. First two calls reuse cached credentials with a single discovery.
	st1, err := client.Status(context.Background())
	if err != nil || st1.Self == nil || st1.Self.HostName != "mac-one" {
		t.Fatalf("first Status() = %+v, err=%v", st1, err)
	}
	st2, err := client.Status(context.Background())
	if err != nil || st2.Self == nil || st2.Self.HostName != "mac-one" {
		t.Fatalf("second Status() = %+v, err=%v", st2, err)
	}
	if got := discoverCalls.Load(); got != 1 {
		t.Fatalf("discoverCalls after cached hits = %d, want 1", got)
	}

	// 2. Simulate IPNExtension restart on a new port & token: closed srv1 triggers cache invalidation and retry.
	srv1.Close()
	activePhase.Store(1)

	st3, err := client.Status(context.Background())
	if err != nil || st3.Self == nil || st3.Self.HostName != "mac-two" {
		t.Fatalf("Status() after port rotation = %+v, err=%v", st3, err)
	}
	if got := discoverCalls.Load(); got != 2 {
		t.Fatalf("discoverCalls after rotation = %d, want 2", got)
	}
}
