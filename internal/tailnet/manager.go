package tailnet

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

// Default Tailnet CGNAT & ULA IP prefixes according to Tailscale spec and ADR 0007.
var DefaultTailnetSubnets = []string{
	"100.64.0.0/10",
	"fd7a:115c:a1e0::/48",
}

// Manager orchestrates Tailnet dual-mode runtime (Host daemon vs Embedded sing-box endpoint).
type Manager struct {
	mu           sync.RWMutex
	cfg          Config
	detector     *Detector
	status       Status
	subscribers  map[int]func(Status)
	nextSubID    int
	embeddedEp   adapter.TailscaleEndpoint
	cancelCtx    context.Context
	cancelFunc   context.CancelFunc
	epCancel     context.CancelFunc
	pollTicker   *time.Ticker
}

// NewManager creates and initializes a Tailnet Manager.
func NewManager(cfg Config, detector *Detector) *Manager {
	if detector == nil {
		detector = NewDetector()
	}
	ctx, cancel := context.WithCancel(context.Background())
	mgr := &Manager{
		cfg:         cfg,
		detector:    detector,
		subscribers: make(map[int]func(Status)),
		cancelCtx:   ctx,
		cancelFunc:  cancel,
	}

	mgr.initStatus()
	mgr.startPoller()
	return mgr
}

func (m *Manager) initStatus() {
	m.status = Status{
		Enabled:    m.cfg.Enabled,
		ActiveMode: m.cfg.Mode,
	}
	if !m.cfg.Enabled || m.cfg.Mode == ModeOff {
		m.status.ActiveMode = ModeOff
		m.status.BackendState = "Offline"
	}
}

// UpdateConfig updates the manager's configuration and triggers a state refresh.
func (m *Manager) UpdateConfig(cfg Config) {
	m.mu.Lock()
	m.cfg = cfg
	if cfg.Mode != ModeEmbedded {
		if m.epCancel != nil {
			m.epCancel()
			m.epCancel = nil
		}
		m.embeddedEp = nil
	}
	m.initStatus()
	m.mu.Unlock()

	m.Refresh(context.Background())
}

// GetConfig returns a copy of current config.
func (m *Manager) GetConfig() Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg
}

// Status returns a copy of the current unified Status.
func (m *Manager) Status() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status
}

// SetError updates the error message in status and marks state as Offline if appropriate.
func (m *Manager) SetError(errStr string) {
	m.updateStatus(func(s *Status) {
		s.Error = errStr
		if errStr != "" && s.BackendState != "NeedsLogin" {
			s.BackendState = "Offline"
		}
	})
}

// ShouldUseHostMode returns true if Tailnet is currently operating via host tailscaled daemon.
func (m *Manager) ShouldUseHostMode() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg.Enabled && m.status.ActiveMode == ModeHost
}

// ShouldUseEmbeddedMode returns true if Tailnet should run in sing-box native embedded mode.
func (m *Manager) ShouldUseEmbeddedMode() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg.Enabled && m.status.ActiveMode == ModeEmbedded
}

// GetHostExcludeAddresses returns CGNAT, ULA, and discovered subnet routes for TUN exclusion.
func (m *Manager) GetHostExcludeAddresses() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	excludes := append([]string{}, DefaultTailnetSubnets...)
	seen := make(map[string]bool)
	for _, sub := range excludes {
		seen[sub] = true
	}

	for _, sub := range m.status.SubnetRoutes {
		if !seen[sub] {
			seen[sub] = true
			excludes = append(excludes, sub)
		}
	}
	return excludes
}

// GetMagicDNSSuffix returns the active MagicDNS suffix.
func (m *Manager) GetMagicDNSSuffix() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status.MagicDNSSuffix
}

// Refresh checks the active mode and updates status accordingly.
func (m *Manager) Refresh(ctx context.Context) {
	m.mu.RLock()
	enabled := m.cfg.Enabled
	mode := m.cfg.Mode
	m.mu.RUnlock()

	if !enabled || mode == ModeOff {
		m.updateStatus(func(s *Status) {
			s.Enabled = false
			s.ActiveMode = ModeOff
			s.BackendState = "Offline"
			s.Error = ""
		})
		return
	}

	if mode == ModeHost || mode == ModeAuto {
		st, err := m.detector.DetectHost(ctx)
		if err == nil && st.BackendState == "Running" {
			m.updateStatus(func(s *Status) {
				*s = *st
				s.Enabled = true
				s.ActiveMode = ModeHost
				s.Error = ""
			})
			return
		}

		if mode == ModeHost {
			// Host mode explicitly requested but failed
			m.updateStatus(func(s *Status) {
				s.Enabled = true
				s.ActiveMode = ModeHost
				s.BackendState = "Offline"
				if err != nil {
					s.Error = err.Error()
				}
			})
			return
		}
	}

	// Fall back to or explicitly use embedded mode
	m.updateStatus(func(s *Status) {
		s.Enabled = true
		s.ActiveMode = ModeEmbedded
		if s.BackendState == "" || s.BackendState == "Offline" {
			s.BackendState = "Starting"
		}
		s.Error = ""
	})
}

// BindEmbeddedEndpoint attaches sing-box's adapter.TailscaleEndpoint to receive live status.
func (m *Manager) BindEmbeddedEndpoint(ep adapter.TailscaleEndpoint) {
	m.mu.Lock()
	if m.epCancel != nil {
		m.epCancel()
		m.epCancel = nil
	}
	m.embeddedEp = ep
	if ep == nil {
		m.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(m.cancelCtx)
	m.epCancel = cancel
	m.mu.Unlock()

	go func() {
		_ = ep.SubscribeTailscaleStatus(ctx, func(status *adapter.TailscaleEndpointStatus) {
			if status == nil || ctx.Err() != nil {
				return
			}
			m.updateFromEmbedded(status)
		})
	}()
}

func (m *Manager) updateFromEmbedded(st *adapter.TailscaleEndpointStatus) {
	m.mu.RLock()
	mode := m.cfg.Mode
	enabled := m.cfg.Enabled
	ep := m.embeddedEp
	active := m.status.ActiveMode
	m.mu.RUnlock()

	if !enabled || ep == nil {
		return
	}
	if mode == ModeHost || mode == ModeOff || (mode == ModeAuto && active == ModeHost) {
		return
	}
	var self NodeInfo
	if st.Self != nil {
		self.Hostname = st.Self.HostName
		self.DNSName = st.Self.DNSName
		self.OS = st.Self.OS
		self.Online = st.Self.Online
		self.IPs = st.Self.TailscaleIPs
	}

	var peers []PeerInfo
	var currentExitNode string
	for _, group := range st.UserGroups {
		for _, p := range group.Peers {
			if p == nil {
				continue
			}
			if p.ExitNode {
				currentExitNode = p.StableID
			}
			peers = append(peers, PeerInfo{
				ID:             p.StableID,
				Hostname:       p.HostName,
				DNSName:        p.DNSName,
				IPs:            p.TailscaleIPs,
				OS:             p.OS,
				Online:         p.Online,
				ExitNode:       p.ExitNode,
				ExitNodeOption: p.ExitNodeOption,
				Active:         p.Active,
			})
		}
	}

	m.updateStatus(func(s *Status) {
		s.ActiveMode = ModeEmbedded
		s.BackendState = st.BackendState
		s.AuthURL = st.AuthURL
		s.MagicDNSSuffix = st.MagicDNSSuffix
		s.Self = self
		s.Peers = peers
		s.CurrentExitNode = currentExitNode
		s.Error = ""
	})
}

// SetExitNode configures the active exit node in either host daemon or embedded core.
func (m *Manager) SetExitNode(ctx context.Context, peerID string) error {
	m.mu.RLock()
	mode := m.status.ActiveMode
	ep := m.embeddedEp
	m.mu.RUnlock()

	if mode == ModeHost {
		if peerID == "" {
			return m.detector.client.SetUseExitNode(ctx, false)
		}
		return m.detector.client.SetExitNode(ctx, peerID)
	}

	if mode == ModeEmbedded {
		if ep == nil {
			return errors.New("embedded sing-box tailscale endpoint is not active")
		}
		return ep.SetTailscaleExitNode(ctx, peerID)
	}

	return fmt.Errorf("cannot set exit node in mode %s", mode)
}

func (m *Manager) updateStatus(fn func(*Status)) {
	m.mu.Lock()
	fn(&m.status)
	stCopy := m.status
	var subs []func(Status)
	for _, fnSub := range m.subscribers {
		subs = append(subs, fnSub)
	}
	m.mu.Unlock()

	for _, sub := range subs {
		sub(stCopy)
	}
}

// Subscribe registers a listener for status changes and returns an unsubscribe function.
func (m *Manager) Subscribe(fn func(Status)) func() {
	m.mu.Lock()
	id := m.nextSubID
	m.nextSubID++
	m.subscribers[id] = fn
	initial := m.status
	m.mu.Unlock()

	// Initial notification
	fn(initial)

	return func() {
		m.mu.Lock()
		delete(m.subscribers, id)
		m.mu.Unlock()
	}
}

func (m *Manager) startPoller() {
	m.pollTicker = time.NewTicker(5 * time.Second)
	go func() {
		for {
			select {
			case <-m.cancelCtx.Done():
				return
			case <-m.pollTicker.C:
				m.mu.RLock()
				activeMode := m.status.ActiveMode
				m.mu.RUnlock()
				if activeMode == ModeHost || activeMode == ModeAuto {
					m.Refresh(context.Background())
				}
			}
		}
	}()
}

// Close gracefully stops polling and cleans up resources.
func (m *Manager) Close() {
	m.cancelFunc()
	m.mu.Lock()
	if m.epCancel != nil {
		m.epCancel()
		m.epCancel = nil
	}
	m.embeddedEp = nil
	m.mu.Unlock()
	if m.pollTicker != nil {
		m.pollTicker.Stop()
	}
}
