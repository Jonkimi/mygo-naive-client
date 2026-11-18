package boxengine

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"naive-client/internal/warp"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// warpOutboundLifecycle coordinates lazy initialization, shutdown cancellation,
// and in-flight cleanup synchronization for custom WARP outbounds.
//
// Lock ordering: mu never held across network I/O, Engine.mu, or init wait.
type warpOutboundLifecycle struct {
	closeCtx    context.Context
	closeCancel context.CancelFunc

	mu        sync.Mutex
	initBusy  bool
	initCh    chan struct{}
	closed    bool
	wg        sync.WaitGroup
	closeOnce sync.Once
}

func newWarpOutboundLifecycle(ctx context.Context) warpOutboundLifecycle {
	if ctx == nil {
		ctx = context.Background()
	}
	closeCtx, closeCancel := context.WithCancel(ctx)
	return warpOutboundLifecycle{
		closeCtx:    closeCtx,
		closeCancel: closeCancel,
	}
}

func (l *warpOutboundLifecycle) start(stage adapter.StartStage, scope *adapter.Scope, closeFn func() error) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	if scope != nil {
		scope.Add(closeFn)
	}
	return nil
}

func (l *warpOutboundLifecycle) isClosedLocked() bool {
	return l.closed || (l.closeCtx != nil && l.closeCtx.Err() != nil)
}

func (l *warpOutboundLifecycle) isClosed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.isClosedLocked()
}

func (l *warpOutboundLifecycle) doneChan() <-chan struct{} {
	if l.closeCtx == nil {
		return nil
	}
	return l.closeCtx.Done()
}

func (l *warpOutboundLifecycle) acquireInit(ctx context.Context, tryFast func() (bool, error)) (func(), bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		l.mu.Lock()
		if l.isClosedLocked() {
			l.mu.Unlock()
			return nil, false, errors.New("outbound closed")
		}
		if tryFast != nil {
			ready, err := tryFast()
			if err != nil || ready {
				l.mu.Unlock()
				return nil, ready, err
			}
		}
		if !l.initBusy {
			l.initBusy = true
			ch := make(chan struct{})
			l.initCh = ch
			l.wg.Add(1)
			l.mu.Unlock()
			return func() {
				l.mu.Lock()
				l.initBusy = false
				l.initCh = nil
				close(ch)
				l.mu.Unlock()
				l.wg.Done()
			}, false, nil
		}
		waitCh := l.initCh
		l.mu.Unlock()

		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		select {
		case <-waitCh:
		case <-ctx.Done():
			return nil, false, ctx.Err()
		case <-l.doneChan():
			return nil, false, errors.New("outbound closed")
		}
	}
}

func (l *warpOutboundLifecycle) deriveContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return deriveLifecycleContext(ctx, l.closeCtx, timeout)
}

func resolveDomainViaDialerDNS(ctx context.Context, d N.Dialer, host string, allowV4, allowV6 bool) (netip.Addr, error) {
	if d == nil {
		return netip.Addr{}, errors.New("nil dialer")
	}
	return warp.ResolveDNSOverTunnel(ctx, func(dCtx context.Context, network string, server netip.Addr, port uint16) (net.Conn, error) {
		return d.DialContext(dCtx, network, M.SocksaddrFrom(server, port))
	}, host, allowV4, allowV6)
}

// close cancels active operations, atomically transitions to closed while detaching any
// active resource under mu, closes the detached resource without holding mu, and waits
// for tracked in-flight initialization/invalidation calls to finish.
func (l *warpOutboundLifecycle) close(detach func() func() error) error {
	var err error
	l.closeOnce.Do(func() {
		if l.closeCancel != nil {
			l.closeCancel()
		}
		var closer func() error
		l.mu.Lock()
		l.closed = true
		if detach != nil {
			closer = detach()
		}
		l.mu.Unlock()
		if closer != nil {
			err = closer()
		}
		l.wg.Wait()
	})
	return err
}

func deriveLifecycleContext(ctx, lifeCtx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	var subCtx context.Context
	var cancel context.CancelFunc
	if timeout > 0 {
		subCtx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		subCtx, cancel = context.WithCancel(ctx)
	}
	if lifeCtx == nil {
		return subCtx, cancel
	}
	if lifeCtx.Err() != nil {
		cancel()
		return subCtx, cancel
	}
	stop := context.AfterFunc(lifeCtx, cancel)
	return subCtx, func() {
		stop()
		cancel()
	}
}

func resolveDetourDialer(detour string, outboundMgr adapter.OutboundManager, eng *Engine) (warp.Dialer, error) {
	if detour == "" {
		return nil, nil
	}
	var ob adapter.Outbound
	var ok bool
	if outboundMgr != nil {
		ob, ok = outboundMgr.Outbound(detour)
	}
	if !ok && eng != nil {
		ob, ok = eng.GetOutbound(detour)
	}
	if !ok {
		return nil, fmt.Errorf("detour outbound %q not found", detour)
	}
	return &outboundDialerAdapter{ob: ob}, nil
}

func newWarpProvisionHTTPClient(upstreamDialer warp.Dialer, timeout time.Duration) *http.Client {
	if upstreamDialer == nil {
		return nil
	}
	tr := &http.Transport{
		DialContext: func(c context.Context, network, addr string) (net.Conn, error) {
			return upstreamDialer.DialContext(c, network, addr)
		},
		TLSClientConfig: &tls.Config{
			ServerName: "api.cloudflareclient.com",
		},
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}
}

func closeHTTPTransportIdle(c *http.Client) {
	if c == nil {
		return
	}
	if tr, ok := c.Transport.(*http.Transport); ok {
		tr.CloseIdleConnections()
	}
}

func cloneWarpAccount(acc warp.Account) warp.Account {
	return acc.Clone()
}

func loadGlobalWarpAccount(eng *Engine) warp.Account {
	if eng == nil {
		return warp.Account{}
	}
	eng.mu.RLock()
	defer eng.mu.RUnlock()
	if eng.cloudflareConfig == nil {
		return warp.Account{}
	}
	return cloneWarpAccount(eng.cloudflareConfig.Account)
}

func saveGlobalWarpAccount(eng *Engine, enrolled warp.Account) {
	if eng == nil {
		return
	}
	accCopy := cloneWarpAccount(enrolled)
	var onUpdate func(warp.Account)
	eng.mu.Lock()
	if eng.cloudflareConfig != nil {
		eng.cloudflareConfig.Account = accCopy
	}
	onUpdate = eng.onCloudflareAccountUpdate
	eng.mu.Unlock()
	if onUpdate != nil {
		onUpdate(cloneWarpAccount(accCopy))
	}
}

func selectEndpointSelector(eng *Engine) *warp.EndpointSelector {
	if eng != nil && eng.endpointSelector != nil {
		return eng.endpointSelector
	}
	return warp.DefaultEndpointSelector()
}
