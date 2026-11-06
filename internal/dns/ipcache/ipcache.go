package ipcache

import (
	"container/list"
	"net"
	"strings"
	"sync"
)

type entry struct {
	key    string
	domain string
}

// Cache is a thread-safe LRU cache mapping IP strings to domains.
type Cache struct {
	mu               sync.RWMutex
	capacity         int
	ll               *list.List
	items            map[string]*list.Element
	bootstrapDomains map[string]struct{}
	onBypassIP       func(net.IP)
}

// New creates an IPDomainCache with the given capacity.
func New(capacity int) *Cache {
	if capacity <= 0 {
		capacity = 10000
	}
	return &Cache{
		capacity:         capacity,
		ll:               list.New(),
		items:            make(map[string]*list.Element),
		bootstrapDomains: make(map[string]struct{}),
	}
}

// SetBootstrapDomains updates the bootstrap domain set.
func (c *Cache) SetBootstrapDomains(domains []string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.bootstrapDomains = make(map[string]struct{}, len(domains))
	for _, d := range domains {
		clean := strings.ToLower(strings.TrimSpace(d))
		if clean != "" {
			c.bootstrapDomains[clean] = struct{}{}
		}
	}
}

// SetOnBypassIP registers a callback invoked when a bootstrap domain's IP is inserted.
func (c *Cache) SetOnBypassIP(fn func(net.IP)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onBypassIP = fn
}

func normalizeIP(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.To16().String()
}

// Put records an IP to domain mapping and checks for bootstrap bypass.
func (c *Cache) Put(ip net.IP, domain string) {
	key := normalizeIP(ip)
	if key == "" || domain == "" {
		return
	}

	cleanDomain := strings.ToLower(strings.TrimSpace(domain))

	c.mu.Lock()
	var bypassCallback func(net.IP)
	if _, isBootstrap := c.bootstrapDomains[cleanDomain]; isBootstrap && c.onBypassIP != nil {
		bypassCallback = c.onBypassIP
	}

	if elem, ok := c.items[key]; ok {
		c.ll.MoveToFront(elem)
		elem.Value.(*entry).domain = domain
	} else {
		elem := c.ll.PushFront(&entry{key: key, domain: domain})
		c.items[key] = elem
		if c.ll.Len() > c.capacity {
			oldest := c.ll.Back()
			if oldest != nil {
				c.ll.Remove(oldest)
				delete(c.items, oldest.Value.(*entry).key)
			}
		}
	}
	c.mu.Unlock()

	if bypassCallback != nil {
		bypassCallback(ip)
	}
}

// Lookup queries the domain associated with the given IP.
func (c *Cache) Lookup(ip net.IP) (string, bool) {
	key := normalizeIP(ip)
	if key == "" {
		return "", false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.ll.MoveToFront(elem)
		return elem.Value.(*entry).domain, true
	}
	return "", false
}

// Len returns the current number of cached IP entries.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ll.Len()
}
