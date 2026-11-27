//go:build !darwin

package tailnet

import (
	"context"
	"net"
	"net/http"

	"github.com/sagernet/tailscale/client/local"
	"github.com/sagernet/tailscale/ipn"
	"github.com/sagernet/tailscale/ipn/ipnstate"
	"github.com/sagernet/tailscale/paths"
	"github.com/sagernet/tailscale/safesocket"
	"github.com/sagernet/tailscale/tailcfg"
)

type realHostClient struct {
	client *local.Client
}

func newRealHostClient() HostClient {
	return &realHostClient{
		client: &local.Client{
			Transport: &http.Transport{
				DisableKeepAlives: true,
				Proxy:             nil,
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return safesocket.ConnectContext(ctx, paths.DefaultTailscaledSocket())
				},
			},
		},
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
