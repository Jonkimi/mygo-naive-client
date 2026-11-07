package tailnet

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
