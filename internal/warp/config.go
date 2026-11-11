package warp

import (
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Mode represents the WARP transport protocol mode.
type Mode string

const (
	ModeAuto      Mode = "auto"      // MASQUE H3 -> H2 fallback -> WireGuard
	ModeMASQUE    Mode = "masque"    // MASQUE (H3 with H2 fallback)
	ModeWireGuard Mode = "wireguard" // WireGuard (UDP 2408 + 3-byte reserved)
)

const (
	DefaultMASQUEEndpoint    = "162.159.198.2:443"
	DefaultMASQUESNI         = "consumer-masque.cloudflareclient.com"
	DefaultWireGuardEndpoint = "162.159.192.1:2408"
	DefaultWireGuardPubKey   = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
	DefaultIPv4              = "172.16.0.2"
	DefaultIPv6              = "2606:4700:110:8a36:df92:1074:9602:57a2"
	DefaultMTU               = 1280
	DefaultWarpProbeURL      = "http://connect.rom.miui.com/generate_204"
)

// Account holds Cloudflare device registration and credentials.
type Account struct {
	DeviceID        string  `json:"deviceId,omitempty"`
	AccessToken     string  `json:"accessToken,omitempty"`
	AccountID       string  `json:"accountId,omitempty"`
	AccountType     string  `json:"accountType,omitempty"` // "free", "unlimited" (WARP+)
	LicenseKey      string  `json:"licenseKey,omitempty"`
	WGPrivateKey    string  `json:"wgPrivateKey,omitempty"`
	WGPublicKey     string  `json:"wgPublicKey,omitempty"`
	WGPeerPublicKey string  `json:"wgPeerPublicKey,omitempty"`
	ClientID        string  `json:"clientId,omitempty"`
	Reserved        []uint8 `json:"reserved,omitempty"`
	IPv4            string  `json:"ipv4,omitempty"`
	IPv6            string  `json:"ipv6,omitempty"`

	// Dedicated MASQUE registration slot
	MASQUEDeviceID   string `json:"masqueDeviceId,omitempty"`
	MASQUEToken      string `json:"masqueToken,omitempty"`
	MASQUEPrivateKey string `json:"masquePrivateKey,omitempty"`
	MASQUEPublicKey  string `json:"masquePublicKey,omitempty"`
	MASQUECertPEM    string `json:"masqueCertPem,omitempty"`
	MASQUEIPv4       string `json:"masqueIpv4,omitempty"`
	MASQUEIPv6       string `json:"masqueIpv6,omitempty"`
}

// IsRegistered returns true if an account has been registered for either WireGuard or MASQUE.
func (a Account) IsRegistered() bool {
	return a.DeviceID != "" || a.MASQUEDeviceID != "" || a.WGPrivateKey != "" || a.MASQUEPrivateKey != ""
}

// TunnelConfig holds Cloudflare Zero Trust Tunnel (cloudflared inbound) settings.
type TunnelConfig struct {
	Enabled       bool   `json:"enabled"`
	Token         string `json:"token,omitempty"`
	Protocol      string `json:"protocol,omitempty"` // "auto", "quic", "http2"
	PostQuantum   bool   `json:"postQuantum,omitempty"`
	HAConnections int    `json:"haConnections,omitempty"` // default 4
}

// Config represents the complete Cloudflare settings persisted in app state.
type Config struct {
	WarpEnabled       bool         `json:"warpEnabled"`
	DirectWarpEnabled bool         `json:"directWarpEnabled,omitempty"` // true if direct traffic routes through built-in WARP
	Account           Account      `json:"account"`
	DefaultMode       Mode         `json:"defaultMode,omitempty"` // "auto", "masque", "wireguard"
	CleanIP           string       `json:"cleanIp,omitempty"`     // clean Anycast IP override
	CleanPort         int          `json:"cleanPort,omitempty"`   // clean Anycast Port override
	ProbeURL          string       `json:"probeUrl,omitempty"`    // latency probe endpoint for WARP (default http://connect.rom.miui.com/generate_204)
	Tunnel            TunnelConfig `json:"tunnel"`
}

// ResolveEndpoint returns host and port for WARP connections based on mode and clean IP overrides.
func (c Config) ResolveEndpoint(mode Mode) (string, int) {
	host := strings.TrimSpace(c.CleanIP)
	port := c.CleanPort

	defaultEndpoint := DefaultMASQUEEndpoint
	if mode == ModeWireGuard {
		defaultEndpoint = DefaultWireGuardEndpoint
	}

	defHost, defPortStr, _ := net.SplitHostPort(defaultEndpoint)
	defPort, _ := strconv.Atoi(defPortStr)

	if host == "" {
		host = defHost
	}
	if port <= 0 {
		port = defPort
	}
	return host, port
}

// ParseClientIDReserved parses Base64 or comma-separated client ID into 3 bytes.
func ParseClientIDReserved(raw string) ([]uint8, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	// Try Base64 first
	if data, err := base64.StdEncoding.DecodeString(raw); err == nil && len(data) == 3 {
		return []uint8{data[0], data[1], data[2]}, nil
	}
	// Try comma separated e.g. "12,34,56"
	parts := strings.Split(raw, ",")
	if len(parts) == 3 {
		var res []uint8
		for _, p := range parts {
			val, err := strconv.ParseUint(strings.TrimSpace(p), 10, 8)
			if err != nil {
				return nil, fmt.Errorf("invalid reserved byte %q: %w", p, err)
			}
			res = append(res, uint8(val))
		}
		return res, nil
	}
	return nil, fmt.Errorf("invalid client ID / reserved format %q (expected 3 bytes)", raw)
}
