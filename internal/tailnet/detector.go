package tailnet

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/sagernet/tailscale/client/local"
	"github.com/sagernet/tailscale/ipn"
	"github.com/sagernet/tailscale/ipn/ipnstate"
	"github.com/sagernet/tailscale/tailcfg"
)

// HostClient abstracts the communication with the host tailscaled LocalAPI.
type HostClient interface {
	Status(ctx context.Context) (*ipnstate.Status, error)
	SetExitNode(ctx context.Context, id string) error
	SetUseExitNode(ctx context.Context, on bool) error
}

type realHostClient struct {
	client *local.Client
}

func newRealHostClient() *realHostClient {
	return &realHostClient{
		client: &local.Client{},
	}
}

func (r *realHostClient) Status(ctx context.Context) (*ipnstate.Status, error) {
	return r.client.Status(ctx)
}

func (r *realHostClient) SetExitNode(ctx context.Context, id string) error {
	mp := &ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			ExitNodeID: tailcfg.StableNodeID(id),
		},
		ExitNodeIDSet: true,
	}
	_, err := r.client.EditPrefs(ctx, mp)
	return err
}

func (r *realHostClient) SetUseExitNode(ctx context.Context, on bool) error {
	return r.client.SetUseExitNode(ctx, on)
}

// Detector probes and collects status from the host Tailscale daemon.
type Detector struct {
	client HostClient
}

// NewDetector creates a default Detector connecting to the host's LocalAPI.
func NewDetector() *Detector {
	return &Detector{
		client: newRealHostClient(),
	}
}

// NewDetectorWithClient creates a Detector with a custom HostClient (used for testing).
func NewDetectorWithClient(client HostClient) *Detector {
	return &Detector{
		client: client,
	}
}

// DetectHost checks if a local tailscaled is running and queries its status.
func (d *Detector) DetectHost(ctx context.Context) (*Status, error) {
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
	}

	st, err := d.client.Status(ctx)
	if err != nil {
		return nil, fmt.Errorf("host tailscaled not detected: %w", err)
	}

	status := ConvertIPNStatus(st)
	status.ActiveMode = ModeHost
	status.Enabled = true
	return status, nil
}

// ConvertIPNStatus transforms tailscale ipnstate.Status into our unified Status.
func ConvertIPNStatus(st *ipnstate.Status) *Status {
	if st == nil {
		return &Status{
			BackendState: "Offline",
		}
	}

	magicDNS := st.MagicDNSSuffix
	if magicDNS == "" && st.CurrentTailnet != nil {
		magicDNS = st.CurrentTailnet.MagicDNSSuffix
	}
	magicDNS = NormalizeHost(magicDNS)

	var self NodeInfo
	if st.Self != nil {
		self.Hostname = ExtractNodeName(st.Self.DNSName, magicDNS, st.Self.HostName)
		self.DNSName = strings.TrimSuffix(st.Self.DNSName, ".")
		self.OS = st.Self.OS
		self.Online = st.Self.Online
		for _, ip := range st.Self.TailscaleIPs {
			self.IPs = append(self.IPs, ip.String())
		}
	}

	var peers []PeerInfo
	var subnetRoutes []string
	var currentExitNode string

	for _, ps := range st.Peer {
		if ps == nil {
			continue
		}
		var ips []string
		for _, ip := range ps.TailscaleIPs {
			ips = append(ips, ip.String())
		}

		var allowedIPs []string
		if ps.AllowedIPs != nil {
			for i := 0; i < ps.AllowedIPs.Len(); i++ {
				pfx := ps.AllowedIPs.At(i)
				pfxStr := pfx.String()
				allowedIPs = append(allowedIPs, pfxStr)
				// Subnet routes (non-single host CIDRs, excluding default quad-zero routes)
				if !pfx.IsSingleIP() && pfx.Bits() > 0 {
					subnetRoutes = append(subnetRoutes, pfxStr)
				}
			}
		}

		if ps.ExitNode {
			currentExitNode = string(ps.ID)
		}

		peers = append(peers, PeerInfo{
			ID:             string(ps.ID),
			Hostname:       ExtractNodeName(ps.DNSName, magicDNS, ps.HostName),
			DNSName:        strings.TrimSuffix(ps.DNSName, "."),
			IPs:            ips,
			AllowedIPs:     allowedIPs,
			OS:             ps.OS,
			Online:         ps.Online,
			ExitNode:       ps.ExitNode,
			ExitNodeOption: ps.ExitNodeOption,
			Active:         ps.Active,
		})
	}

	SortPeers(peers)

	return &Status{
		BackendState:    st.BackendState,
		AuthURL:         st.AuthURL,
		MagicDNSSuffix:  magicDNS,
		Self:            self,
		Peers:           peers,
		CurrentExitNode: currentExitNode,
		SubnetRoutes:    subnetRoutes,
	}
}

// DetectHostInterface returns the network interface name used by Tailscale (e.g. "utun6", "tailscale0")
// by inspecting system interfaces for a Tailscale CGNAT IP (100.64.0.0/10) or ULA (fd7a:115c:a1e0::/48).
func DetectHostInterface() string {
	return DetectHostInterfaceForIPs()
}

// DetectHostInterfaceForIPs returns the host Tailscale network interface name, preferring an
// interface that owns one of preferredIPs before falling back to Darwin route lookup and CGNAT/ULA scan.
func DetectHostInterfaceForIPs(preferredIPs ...string) string {
	preferred := make(map[string]bool, len(preferredIPs))
	for _, raw := range preferredIPs {
		if ip := net.ParseIP(strings.TrimSpace(raw)); ip != nil {
			preferred[ip.String()] = true
		}
	}

	ifaces, err := net.Interfaces()
	if err == nil {
		// Pass 1: exact Self IP match if known from LocalAPI.
		if len(preferred) > 0 {
			for _, iface := range ifaces {
				if iface.Flags&net.FlagUp == 0 {
					continue
				}
				for _, ip := range interfaceIPs(iface) {
					if preferred[ip.String()] {
						return iface.Name
					}
				}
			}
		}
		// Pass 2: explicit Tailscale-named interface carrying a Tailnet IP.
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 {
				continue
			}
			lower := strings.ToLower(iface.Name)
			if !strings.Contains(lower, "tailscale") {
				continue
			}
			for _, ip := range interfaceIPs(iface) {
				if IsTailnetIP(ip) {
					return iface.Name
				}
			}
		}
	}

	// Pass 3: on macOS, route lookup for MagicDNS VIP disambiguates multiple utun interfaces
	// and avoids matching ISP CGNAT on physical NICs (e.g., en0).
	if runtime.GOOS == "darwin" {
		if out, err := exec.Command("route", "-n", "get", "100.100.100.100").Output(); err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				fields := strings.Fields(line)
				if len(fields) >= 2 && fields[0] == "interface:" {
					iface := fields[1]
					if strings.HasPrefix(iface, "utun") {
						return iface
					}
				}
			}
		}
	}

	// Pass 4: scan remaining UP interfaces for Tailscale ULA or CGNAT.
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 {
				continue
			}
			for _, ip := range interfaceIPs(iface) {
				if IsTailnetIP(ip) {
					return iface.Name
				}
			}
		}
	}
	return ""
}

func interfaceIPs(iface net.Interface) []net.IP {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}
	var ips []net.IP
	for _, addr := range addrs {
		switch v := addr.(type) {
		case *net.IPNet:
			if v.IP != nil {
				ips = append(ips, v.IP)
			}
		case *net.IPAddr:
			if v.IP != nil {
				ips = append(ips, v.IP)
			}
		}
	}
	return ips
}

