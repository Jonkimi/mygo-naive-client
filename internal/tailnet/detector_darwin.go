//go:build darwin

package tailnet

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/tailscale/client/local"
	"github.com/sagernet/tailscale/ipn"
	"github.com/sagernet/tailscale/ipn/ipnstate"
	"github.com/sagernet/tailscale/paths"
	"github.com/sagernet/tailscale/safesocket"
	"github.com/sagernet/tailscale/tailcfg"
)

const darwinCredDiscoverTimeout = 2 * time.Second

type darwinAuthRoundTripper struct {
	token string
	base  http.RoundTripper
}

func (rt *darwinAuthRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	cloned := req.Clone(req.Context())
	cloned.SetBasicAuth("", rt.token)
	return rt.base.RoundTrip(cloned)
}

type darwinHostClient struct {
	mu                 sync.Mutex
	port               int
	token              string
	hasCreds           bool
	discoverMu         sync.Mutex
	discoverFn         func(ctx context.Context) (int, string, error)
	dialHost           string
	unixSocketFallback func() *local.Client
}

func newRealHostClient() HostClient {
	return &darwinHostClient{
		discoverFn: discoverDarwinTailscaleCreds,
		dialHost:   "127.0.0.1",
		unixSocketFallback: func() *local.Client {
			return &local.Client{
				UseSocketOnly: true,
				Transport: &http.Transport{
					DisableKeepAlives: true,
					Proxy:             nil,
					DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
						return safesocket.ConnectContext(ctx, paths.DefaultTailscaledSocket())
					},
				},
			}
		},
	}
}

func (c *darwinHostClient) newTCPClient(port int, token string) *local.Client {
	host := c.dialHost
	if host == "" {
		host = "127.0.0.1"
	}
	targetAddr := net.JoinHostPort(host, strconv.Itoa(port))
	tr := &http.Transport{
		DisableKeepAlives: true,
		Proxy:             nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", targetAddr)
		},
	}
	return &local.Client{
		OmitAuth: true,
		Transport: &darwinAuthRoundTripper{
			token: token,
			base:  tr,
		},
	}
}

func (c *darwinHostClient) resolveClient(ctx context.Context) (client *local.Client, port int, token string, fromCache bool) {
	c.mu.Lock()
	if c.hasCreds && c.port > 0 && c.token != "" {
		port, token = c.port, c.token
		c.mu.Unlock()
		return c.newTCPClient(port, token), port, token, true
	}
	c.mu.Unlock()

	c.discoverMu.Lock()
	defer c.discoverMu.Unlock()

	c.mu.Lock()
	if c.hasCreds && c.port > 0 && c.token != "" {
		port, token = c.port, c.token
		c.mu.Unlock()
		return c.newTCPClient(port, token), port, token, true
	}
	c.mu.Unlock()

	discover := c.discoverFn
	if discover == nil {
		discover = discoverDarwinTailscaleCreds
	}
	if p, tok, err := discover(ctx); err == nil && p > 0 && tok != "" {
		c.mu.Lock()
		c.port = p
		c.token = tok
		c.hasCreds = true
		c.mu.Unlock()
		return c.newTCPClient(p, tok), p, tok, false
	}

	if c.unixSocketFallback != nil {
		return c.unixSocketFallback(), 0, "", false
	}
	return &local.Client{
		UseSocketOnly: true,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			Proxy:             nil,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return safesocket.ConnectContext(ctx, paths.DefaultTailscaledSocket())
			},
		},
	}, 0, "", false
}

func (c *darwinHostClient) invalidateIfMatches(port int, token string) {
	c.mu.Lock()
	if c.hasCreds && c.port == port && c.token == token {
		c.port = 0
		c.token = ""
		c.hasCreds = false
	}
	c.mu.Unlock()
}

func (c *darwinHostClient) doWithRetry(ctx context.Context, fn func(*local.Client) error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	client, port, token, fromCache := c.resolveClient(ctx)
	err := fn(client)
	if err == nil || !fromCache || ctx.Err() != nil {
		return err
	}
	c.invalidateIfMatches(port, token)
	client, _, _, _ = c.resolveClient(ctx)
	return fn(client)
}

func (c *darwinHostClient) Status(ctx context.Context) (*ipnstate.Status, error) {
	var st *ipnstate.Status
	err := c.doWithRetry(ctx, func(lc *local.Client) error {
		var callErr error
		st, callErr = lc.Status(ctx)
		return callErr
	})
	return st, err
}

func (c *darwinHostClient) SetExitNode(ctx context.Context, id string) error {
	return c.doWithRetry(ctx, func(lc *local.Client) error {
		mp := &ipn.MaskedPrefs{
			Prefs: ipn.Prefs{
				ExitNodeID: tailcfg.StableNodeID(id),
			},
			ExitNodeIDSet: true,
		}
		_, err := lc.EditPrefs(ctx, mp)
		return err
	})
}

func (c *darwinHostClient) SetUseExitNode(ctx context.Context, on bool) error {
	return c.doWithRetry(ctx, func(lc *local.Client) error {
		return lc.SetUseExitNode(ctx, on)
	})
}

func discoverDarwinTailscaleCreds(ctx context.Context) (int, string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	discoverCtx := ctx
	if dl, ok := ctx.Deadline(); !ok || time.Until(dl) > darwinCredDiscoverTimeout {
		var cancel context.CancelFunc
		discoverCtx, cancel = context.WithTimeout(ctx, darwinCredDiscoverTimeout)
		defer cancel()
	}

	if port, token, err := readDarwinAppStoreSameUserProof(discoverCtx); err == nil {
		return port, token, nil
	}
	if port, token, err := readDarwinMacsysSameUserProof(discoverCtx, "/Library/Tailscale"); err == nil {
		return port, token, nil
	}
	return 0, "", safesocket.ErrTokenNotFound
}

func readDarwinAppStoreSameUserProof(ctx context.Context) (int, string, error) {
	lsofBin := "/usr/sbin/lsof"
	if _, err := os.Stat(lsofBin); err != nil {
		lsofBin = "lsof"
	}
	cmd := exec.CommandContext(ctx, lsofBin,
		"-n",
		"-P",
		"-a",
		fmt.Sprintf("-u%d", os.Getuid()),
		"-c", "IPNExtension",
		"-F", "n",
	)
	out, err := cmd.Output()
	if err != nil {
		return 0, "", err
	}
	return parseDarwinLsofSameUserProof(out)
}

func parseDarwinLsofSameUserProof(out []byte) (int, string, error) {
	bs := bufio.NewScanner(bytes.NewReader(out))
	subStr := []byte(".tailscale.ipn.macos/sameuserproof-")
	for bs.Scan() {
		line := bs.Bytes()
		_, after, ok := bytes.Cut(line, subStr)
		if !ok {
			continue
		}
		f := strings.SplitN(strings.TrimSpace(string(after)), "-", 2)
		if len(f) != 2 {
			continue
		}
		portStr, token := f[0], f[1]
		if token == "" {
			continue
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 {
			continue
		}
		return port, token, nil
	}
	return 0, "", safesocket.ErrTokenNotFound
}

func readDarwinMacsysSameUserProof(ctx context.Context, sharedDir string) (int, string, error) {
	portStr, err := os.Readlink(filepath.Join(sharedDir, "ipnport"))
	if err != nil {
		return 0, "", err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 {
		return 0, "", errors.New("invalid ipnport symlink")
	}
	authb, err := os.ReadFile(filepath.Join(sharedDir, "sameuserproof-"+portStr))
	if err != nil {
		return 0, "", err
	}
	auth := strings.TrimSpace(string(authb))
	if auth == "" {
		return 0, "", errors.New("empty auth token in sameuserproof file")
	}
	dialCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "tcp", net.JoinHostPort("127.0.0.1", portStr))
	if err != nil {
		return 0, "", err
	}
	_ = conn.Close()
	return port, auth, nil
}
