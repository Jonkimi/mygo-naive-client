package tailnet

import (
	"net"
	"sort"
	"strings"
)

// Mode represents the Tailnet operational mode.
type Mode string

const (
	ModeAuto     Mode = "auto"     // Auto-detect host daemon, fall back to embedded
	ModeHost     Mode = "host"     // Force host tailscaled daemon cooperation
	ModeEmbedded Mode = "embedded" // Force sing-box native embedded tailscale endpoint
	ModeOff      Mode = "off"      // Disabled
)

// NodeInfo contains identity information of a Tailscale node.
type NodeInfo struct {
	IPs      []string `json:"ips,omitempty"`
	Hostname string   `json:"hostname,omitempty"`
	DNSName  string   `json:"dnsName,omitempty"`
	OS       string   `json:"os,omitempty"`
	Online   bool     `json:"online"`
}

// PeerInfo describes a peer device discovered in the Tailnet.
type PeerInfo struct {
	ID             string   `json:"id"`
	Hostname       string   `json:"hostname"`
	DNSName        string   `json:"dnsName,omitempty"`
	IPs            []string `json:"ips,omitempty"`
	AllowedIPs     []string `json:"allowedIps,omitempty"`
	OS             string   `json:"os,omitempty"`
	Online         bool     `json:"online"`
	ExitNode       bool     `json:"exitNode"`       // true if currently active exit node
	ExitNodeOption bool     `json:"exitNodeOption"` // true if capable of serving as exit node
	Active         bool     `json:"active"`
}

// Status represents the unified status of the Tailnet integration.
type Status struct {
	Enabled         bool       `json:"enabled"`
	ActiveMode      Mode       `json:"activeMode"`   // "host", "embedded", or "off"
	BackendState    string     `json:"backendState"` // "Running", "NeedsLogin", "Stopped", "Starting", "Offline"
	AuthURL         string     `json:"authUrl,omitempty"`
	MagicDNSSuffix  string     `json:"magicDnsSuffix,omitempty"`
	Self            NodeInfo   `json:"self"`
	Peers           []PeerInfo `json:"peers,omitempty"`
	CurrentExitNode string     `json:"currentExitNode,omitempty"`
	SubnetRoutes    []string   `json:"subnetRoutes,omitempty"`
	Error           string     `json:"error,omitempty"`
}

// Config specifies the persisted user configuration for Tailnet.
type Config struct {
	Enabled            bool     `json:"enabled"`
	Mode               Mode     `json:"mode"`
	ControlURL         string   `json:"controlUrl,omitempty"`
	AuthKey            string   `json:"authKey,omitempty"`
	Hostname           string   `json:"hostname,omitempty"`
	AcceptRoutes       bool     `json:"acceptRoutes"`
	ExitNode           string   `json:"exitNode,omitempty"`
	ExposeMixedPort    bool     `json:"exposeMixedPort"`
	AdvertiseExitNode  bool     `json:"advertiseExitNode"`
	AdvertiseRoutes    []string `json:"advertiseRoutes,omitempty"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() Config {
	return Config{
		Enabled:         false,
		Mode:            ModeAuto,
		AcceptRoutes:    true,
		ExposeMixedPort: false,
	}
}

// ExtractNodeName resolves the display node name for a Tailscale node.
// It prefers the configured Tailnet name in dnsName (stripping magicDNSSuffix
// or falling back to the first DNS label) and falls back to fallbackHostname
// when dnsName is empty.
func ExtractNodeName(dnsName, magicDNSSuffix, fallbackHostname string) string {
	cleanDNS := strings.Trim(strings.TrimSpace(dnsName), ".")
	if cleanDNS != "" {
		suffix := strings.Trim(strings.TrimSpace(magicDNSSuffix), ".")
		if suffix != "" {
			dotSuffix := "." + suffix
			if len(cleanDNS) > len(dotSuffix) && strings.EqualFold(cleanDNS[len(cleanDNS)-len(dotSuffix):], dotSuffix) {
				if name := cleanDNS[:len(cleanDNS)-len(dotSuffix)]; name != "" {
					return name
				}
			}
		}
		if first, _, _ := strings.Cut(cleanDNS, "."); first != "" {
			return first
		}
	}
	return strings.TrimSpace(fallbackHostname)
}

// SortPeers sorts a slice of PeerInfo deterministically:
// 1. Online peers first, offline peers last
// 2. Case-insensitive hostname in ascending order
// 3. ID in ascending order (tie-breaker)
func SortPeers(peers []PeerInfo) {
	sort.Slice(peers, func(i, j int) bool {
		if peers[i].Online != peers[j].Online {
			return peers[i].Online // true comes before false
		}
		hostI := strings.ToLower(peers[i].Hostname)
		hostJ := strings.ToLower(peers[j].Hostname)
		if hostI != hostJ {
			return hostI < hostJ
		}
		return peers[i].ID < peers[j].ID
	})
}

// NormalizeHost trims whitespace, IPv6 brackets, trailing dots, and lowercases a host string.
func NormalizeHost(host string) string {
	h := strings.TrimSpace(host)
	h = strings.TrimPrefix(h, "[")
	h = strings.TrimSuffix(h, "]")
	h = strings.Trim(h, ".")
	return strings.ToLower(h)
}

// IsTailnetIP reports whether ip falls within Tailscale's CGNAT (100.64.0.0/10) or ULA (fd7a:115c:a1e0::/48) ranges.
func IsTailnetIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127
	}
	return len(ip) == net.IPv6len &&
		ip[0] == 0xfd && ip[1] == 0x7a && ip[2] == 0x11 &&
		ip[3] == 0x5c && ip[4] == 0xa1 && ip[5] == 0xe0
}

// IsTailnetIPString reports whether raw parses as a Tailnet IP address or host/subnet CIDR within Tailnet ranges.
func IsTailnetIPString(raw string) bool {
	norm := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(raw), "["), "]")
	if norm == "" {
		return false
	}
	if ip := net.ParseIP(norm); ip != nil {
		return IsTailnetIP(ip)
	}
	if ip, ipNet, err := net.ParseCIDR(norm); err == nil && ipNet != nil {
		ones, _ := ipNet.Mask.Size()
		if ip.To4() != nil {
			return ones >= 10 && IsTailnetIP(ip)
		}
		return ones >= 48 && IsTailnetIP(ip)
	}
	return false
}

// IsTailnetHostname reports whether host is a Tailscale MagicDNS domain or single-label peer hostname
// when Tailnet host or embedded mode is active. Returns false for IPs, localhost/.local, or inactive modes.
func IsTailnetHostname(mode Mode, host, magicDNSSuffix string) bool {
	if mode != ModeHost && mode != ModeEmbedded {
		return false
	}
	norm := NormalizeHost(host)
	if norm == "" || net.ParseIP(norm) != nil {
		return false
	}
	if norm == "localhost" || strings.HasSuffix(norm, ".local") || strings.HasSuffix(norm, ".localhost") {
		return false
	}
	if norm == "ts.net" || strings.HasSuffix(norm, ".ts.net") {
		return true
	}
	if suffix := NormalizeHost(magicDNSSuffix); suffix != "" && (norm == suffix || strings.HasSuffix(norm, "."+suffix)) {
		return true
	}
	return !strings.Contains(norm, ".")
}

// IsTailnetTarget reports whether host (IP or hostname) targets a Tailnet destination in active modes.
// When hostRecords is non-empty, ambiguous single-label hostnames only match if present in hostRecords.
func IsTailnetTarget(mode Mode, host, magicDNSSuffix string, hostRecords map[string][]string) bool {
	if mode != ModeHost && mode != ModeEmbedded {
		return false
	}
	norm := NormalizeHost(host)
	if norm == "" {
		return false
	}
	if ip := net.ParseIP(norm); ip != nil {
		return IsTailnetIP(ip)
	}
	if norm == "localhost" || strings.HasSuffix(norm, ".local") || strings.HasSuffix(norm, ".localhost") {
		return false
	}
	if norm == "ts.net" || strings.HasSuffix(norm, ".ts.net") {
		return true
	}
	if suffix := NormalizeHost(magicDNSSuffix); suffix != "" && (norm == suffix || strings.HasSuffix(norm, "."+suffix)) {
		return true
	}
	if len(hostRecords) > 0 {
		_, ok := hostRecords[norm]
		return ok
	}
	return !strings.Contains(norm, ".")
}

// ExcludeAddressesFromStatus builds deduplicated Tailnet CGNAT, ULA, and subnet route CIDRs from st.
func ExcludeAddressesFromStatus(st *Status) []string {
	excludes := append([]string{}, DefaultTailnetSubnets...)
	seen := make(map[string]bool, len(excludes))
	for _, sub := range excludes {
		seen[sub] = true
	}
	if st == nil {
		return excludes
	}
	for _, sub := range st.SubnetRoutes {
		sub = strings.TrimSpace(sub)
		if sub == "" || sub == "0.0.0.0/0" || sub == "::/0" {
			continue
		}
		if !seen[sub] {
			seen[sub] = true
			excludes = append(excludes, sub)
		}
	}
	return excludes
}

// HostRecordsFromStatus extracts a normalized hostname -> Tailscale IP list index from Self and Peers.
func HostRecordsFromStatus(st *Status) map[string][]string {
	if st == nil {
		return nil
	}
	suffix := NormalizeHost(st.MagicDNSSuffix)
	records := make(map[string][]string)
	addNode := func(hostname, dnsName string, ips []string) {
		var validIPs []string
		for _, rawIP := range ips {
			ip := net.ParseIP(strings.TrimSpace(rawIP))
			if ip != nil {
				validIPs = append(validIPs, ip.String())
			}
		}
		if len(validIPs) == 0 {
			return
		}
		var keys []string
		addKey := func(k string) {
			k = NormalizeHost(k)
			if k == "" || k == "localhost" || net.ParseIP(k) != nil {
				return
			}
			keys = append(keys, k)
		}
		addKey(hostname)
		addKey(dnsName)
		if dnsNorm := NormalizeHost(dnsName); dnsNorm != "" {
			if first, _, ok := strings.Cut(dnsNorm, "."); ok {
				addKey(first)
			}
		}
		if suffix != "" {
			if hNorm := NormalizeHost(hostname); hNorm != "" && !strings.Contains(hNorm, ".") {
				addKey(hNorm + "." + suffix)
			}
		}
		for _, k := range keys {
			existing := records[k]
			for _, ip := range validIPs {
				seen := false
				for _, e := range existing {
					if e == ip {
						seen = true
						break
					}
				}
				if !seen {
					existing = append(existing, ip)
				}
			}
			records[k] = existing
		}
	}
	addNode(st.Self.Hostname, st.Self.DNSName, st.Self.IPs)
	for _, p := range st.Peers {
		addNode(p.Hostname, p.DNSName, p.IPs)
	}
	if len(records) == 0 {
		return nil
	}
	return records
}

