package ipcache_test

import (
	"net"
	"strconv"
	"sync"
	"testing"

	"naive-client/internal/dns/ipcache"
)

// Tests that IPDomainCache stores and retrieves IP-to-domain mappings,
// triggers bypass callbacks for bootstrap domains, and evicts LRU items.
func TestIPDomainCache_BasicAndLRU(t *testing.T) {
	cache := ipcache.New(3)

	cache.Put(net.ParseIP("1.1.1.1"), "one.one.one.one")
	cache.Put(net.ParseIP("8.8.8.8"), "dns.google")
	cache.Put(net.ParseIP("9.9.9.9"), "quad9.net")

	if d, ok := cache.Lookup(net.ParseIP("1.1.1.1")); !ok || d != "one.one.one.one" {
		t.Fatalf("expected one.one.one.one, got %q (ok=%v)", d, ok)
	}

	// Access 1.1.1.1 to mark it recent, then add 4.4.4.4. 8.8.8.8 should be evicted.
	_, _ = cache.Lookup(net.ParseIP("1.1.1.1"))
	cache.Put(net.ParseIP("4.4.4.4"), "other.net")

	if _, ok := cache.Lookup(net.ParseIP("8.8.8.8")); ok {
		t.Fatalf("expected 8.8.8.8 to be evicted")
	}
	if _, ok := cache.Lookup(net.ParseIP("1.1.1.1")); !ok {
		t.Fatalf("expected 1.1.1.1 to remain in cache")
	}
}

func TestIPDomainCache_BootstrapBypassCallback(t *testing.T) {
	var bypassed []string
	var mu sync.Mutex

	cache := ipcache.New(100)
	cache.SetBootstrapDomains([]string{"proxy.example.com", "doh.pub"})
	cache.SetOnBypassIP(func(ip net.IP) {
		mu.Lock()
		defer mu.Unlock()
		bypassed = append(bypassed, ip.String())
	})

	// Normal domain -> should not trigger callback
	cache.Put(net.ParseIP("93.184.216.34"), "example.com")
	if len(bypassed) != 0 {
		t.Fatalf("unexpected bypass callback for non-bootstrap domain")
	}

	// Bootstrap domain -> should trigger callback
	cache.Put(net.ParseIP("104.16.1.1"), "proxy.example.com")
	cache.Put(net.ParseIP("1.12.12.12"), "DOH.PUB")

	mu.Lock()
	defer mu.Unlock()
	if len(bypassed) != 2 || bypassed[0] != "104.16.1.1" || bypassed[1] != "1.12.12.12" {
		t.Fatalf("unexpected bypassed IPs: %v", bypassed)
	}
}

func TestIPDomainCache_IPv6AndConcurrency(t *testing.T) {
	cache := ipcache.New(1000)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ip := net.ParseIP("2001:db8::" + strconv.Itoa(idx))
			domain := "host" + strconv.Itoa(idx) + ".example.com"
			cache.Put(ip, domain)
			val, ok := cache.Lookup(ip)
			if !ok || val != domain {
				t.Errorf("lookup failed for %v: got %v, ok=%v", ip, val, ok)
			}
		}(i)
	}
	wg.Wait()
}
