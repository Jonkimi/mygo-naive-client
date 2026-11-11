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

	var self NodeInfo
	if st.Self != nil {
		self.Hostname = st.Self.HostName
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
			Hostname:       ps.HostName,
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

	magicDNS := st.MagicDNSSuffix
	if magicDNS == "" && st.CurrentTailnet != nil {
		magicDNS = st.CurrentTailnet.MagicDNSSuffix
	}

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
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
					return iface.Name
				}
			}
			if len(ip) == 16 && ip[0] == 0xfd && ip[1] == 0x7a && ip[2] == 0x11 && ip[3] == 0x5c && ip[4] == 0xa1 && ip[5] == 0xe0 {
				return iface.Name
			}
		}
	}
	// Fallback on macOS via route lookup for Tailscale MagicDNS IP
	if runtime.GOOS == "darwin" {
		out, err := exec.Command("route", "-n", "get", "100.100.100.100").Output()
		if err == nil {
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
	return ""
}

