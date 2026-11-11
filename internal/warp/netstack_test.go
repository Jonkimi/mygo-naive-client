package warp

import (
	"context"
	"testing"
	"time"
)

func TestNetstack_CreateAndClose(t *testing.T) {
	ns, err := NewNetstack("172.16.0.2/32", "2606:4700:110:8a36::2/128")
	if err != nil {
		t.Fatalf("NewNetstack failed: %v", err)
	}
	defer ns.Close()

	if !ns.IPv4.IsValid() || !ns.IPv6.IsValid() {
		t.Errorf("invalid IP addresses on netstack")
	}

	// Test read with cancel
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err = ns.ReadPacket(ctx)
	if err == nil {
		t.Errorf("expected timeout reading packet from empty netstack")
	}
}
