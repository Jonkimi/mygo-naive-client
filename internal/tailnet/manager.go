package tailnet

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

// Default Tailnet CGNAT & ULA IP prefixes according to Tailscale spec and ADR 0007.
var DefaultTailnetSubnets = []string{
	"100.64.0.0/10",
	"fd7a:115c:a1e0::/48",
}

const hostDetectTTL = 15 * time.Second

// Manager orchestrates Tailnet dual-mode runtime (Host daemon vs Embedded sing-box endpoint).
type Manager struct {
	mu               sync.RWMutex
	cfg              Config
	detector         *Detector
	status           Status
	subscribers      map[int]func(Status)
	nextSubID        int
	embeddedEp       adapter.TailscaleEndpoint
	cancelCtx        context.Context
	cancelFunc       context.CancelFunc
	epCancel         context.CancelFunc
	pollTicker       *time.Ticker
	refreshMu        sync.Mutex
	hostFailStreak   int
	hostDetectMu     sync.Mutex
	hostDetected     bool
	hostDetectResult *Status
	hostDetectAt     time.Time
	hostDetectWait   chan struct{}
	now              func() time.Time
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
	m.hostFailStreak = 0
	m.status = Status{
		Enabled:    m.cfg.Enabled,
		ActiveMode: m.cfg.Mode,
	}
	if !m.cfg.Enabled || m.cfg.Mode == ModeOff {
		m.status.ActiveMode = ModeOff
		m.status.BackendState = "Offline"
	}
}

func configsEqual(a, b Config) bool {
	return a.Enabled == b.Enabled &&
		a.Mode == b.Mode &&
		a.ControlURL == b.ControlURL &&
		a.AuthKey == b.AuthKey &&
		a.Hostname == b.Hostname &&
		a.AcceptRoutes == b.AcceptRoutes &&
		a.ExitNode == b.ExitNode &&
		a.ExposeMixedPort == b.ExposeMixedPort &&
		a.AdvertiseExitNode == b.AdvertiseExitNode &&
		slices.Equal(a.AdvertiseRoutes, b.AdvertiseRoutes)
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

// UpdateConfigAsync updates configuration when changed and triggers a background refresh
// without blocking the caller; unchanged configs are a no-op.
func (m *Manager) UpdateConfigAsync(cfg Config) {
	m.mu.Lock()
	if configsEqual(m.cfg, cfg) {
		m.mu.Unlock()
		return
	}
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

	m.RefreshAsync()
}

// RefreshAsync triggers a non-blocking background Tailnet status refresh.
func (m *Manager) RefreshAsync() {
	go m.Refresh(m.cancelCtx)
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

func (m *Manager) nowTime() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}

func cloneStatusPtr(st *Status) *Status {
	if st == nil {
		return nil
	}
	c := *st
	return &c
}

func (m *Manager) startHostDetectLocked(detector *Detector) chan struct{} {
	ch := make(chan struct{})
	m.hostDetectWait = ch
	go m.runHostDetect(detector, ch)
	return ch
}

func (m *Manager) runHostDetect(detector *Detector, ch chan struct{}) {
	ctx, cancel := context.WithTimeout(m.cancelCtx, defaultHostDetectTimeout)
	defer cancel()

	st, err := detector.DetectHost(ctx)
	var res *Status
	if err == nil && st != nil {
		res = cloneStatusPtr(st)
	}

	if res != nil && res.BackendState == "Running" {
		m.mu.RLock()
		shouldSync := m.cfg.Enabled && (m.cfg.Mode == ModeHost || m.cfg.Mode == ModeAuto)
		m.mu.RUnlock()
		if shouldSync {
			m.updateStatus(func(s *Status) {
				*s = *res
				s.Enabled = true
				s.ActiveMode = ModeHost
				s.Error = ""
				m.hostFailStreak = 0
			})
		}
	}

	m.hostDetectMu.Lock()
	m.hostDetectResult = res
	m.hostDetectAt = m.nowTime()
	m.hostDetected = true
	if m.hostDetectWait == ch {
		m.hostDetectWait = nil
	}
	m.hostDetectMu.Unlock()
	close(ch)
}

// WarmHostDetection starts a non-blocking background host Tailscale probe if no result is cached yet.
func (m *Manager) WarmHostDetection() {
	m.mu.RLock()
	detector := m.detector
	m.mu.RUnlock()
	if detector == nil {
		return
	}
	m.hostDetectMu.Lock()
	if !m.hostDetected && m.hostDetectWait == nil {
		m.startHostDetectLocked(detector)
	}
	m.hostDetectMu.Unlock()
}

// DetectHostStatus queries the host Tailscale daemon directly regardless of current config,
// returning cached results immediately and refreshing stale entries in the background.
func (m *Manager) DetectHostStatus() *Status {
	m.mu.RLock()
	if m.status.BackendState == "Running" && (m.status.ActiveMode == ModeHost || m.status.ActiveMode == ModeAuto) {
		st := m.status
		m.mu.RUnlock()
		return &st
	}
	detector := m.detector
	m.mu.RUnlock()
	if detector == nil {
		return nil
	}

	m.hostDetectMu.Lock()
	if m.hostDetected {
		res := cloneStatusPtr(m.hostDetectResult)
		if m.nowTime().Sub(m.hostDetectAt) >= hostDetectTTL && m.hostDetectWait == nil {
			m.startHostDetectLocked(detector)
		}
		m.hostDetectMu.Unlock()
		return res
	}
	waitCh := m.hostDetectWait
	if waitCh == nil {
		waitCh = m.startHostDetectLocked(detector)
	}
	m.hostDetectMu.Unlock()

	<-waitCh

	m.hostDetectMu.Lock()
	res := cloneStatusPtr(m.hostDetectResult)
	m.hostDetectMu.Unlock()
	return res
}

// GetHostExcludeAddresses returns CGNAT, ULA, and discovered subnet routes for TUN exclusion.
func (m *Manager) GetHostExcludeAddresses() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return ExcludeAddressesFromStatus(&m.status)
}

// GetHostRecords returns normalized Tailnet hostname -> IP mappings from current Self and Peers status.
func (m *Manager) GetHostRecords() map[string][]string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return HostRecordsFromStatus(&m.status)
}

// GetHostInterface returns the host Tailscale network interface name using known Self IPs when available.
func (m *Manager) GetHostInterface() string {
	m.mu.RLock()
	ips := append([]string{}, m.status.Self.IPs...)
	m.mu.RUnlock()
	return DetectHostInterfaceForIPs(ips...)
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
		handled := m.refreshHostMode(ctx, mode)
		if handled {
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

func (m *Manager) refreshHostMode(ctx context.Context, mode Mode) bool {
	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()

	st, err := m.detector.DetectHost(ctx)
	if err == nil && st.BackendState == "Running" {
		m.hostDetectMu.Lock()
		m.hostDetectResult = cloneStatusPtr(st)
		m.hostDetectAt = m.nowTime()
		m.hostDetected = true
		m.hostDetectMu.Unlock()

		m.updateStatus(func(s *Status) {
			*s = *st
			s.Enabled = true
			s.ActiveMode = ModeHost
			s.Error = ""
			m.hostFailStreak = 0
		})
		return true
	}

	m.mu.Lock()
	wasRunningHost := m.status.ActiveMode == ModeHost && m.status.BackendState == "Running"
	isTransientTimeout := err != nil && errors.Is(err, context.DeadlineExceeded)
	if wasRunningHost && isTransientTimeout && m.hostFailStreak == 0 {
		m.hostFailStreak = 1
		m.mu.Unlock()
		return true
	}
	m.hostFailStreak++
	m.mu.Unlock()

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
		return true
	}
	return false
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
		self.Hostname = ExtractNodeName(st.Self.DNSName, st.MagicDNSSuffix, st.Self.HostName)
		self.DNSName = strings.TrimSuffix(st.Self.DNSName, ".")
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
				Hostname:       ExtractNodeName(p.DNSName, st.MagicDNSSuffix, p.HostName),
				DNSName:        strings.TrimSuffix(p.DNSName, "."),
				IPs:            p.TailscaleIPs,
				OS:             p.OS,
				Online:         p.Online,
				ExitNode:       p.ExitNode,
				ExitNodeOption: p.ExitNodeOption,
				Active:         p.Active,
			})
		}
	}

	SortPeers(peers)

	m.updateStatus(func(s *Status) {
		s.ActiveMode = ModeEmbedded
		s.BackendState = st.BackendState
		s.AuthURL = st.AuthURL
		s.MagicDNSSuffix = NormalizeHost(st.MagicDNSSuffix)
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
					m.Refresh(m.cancelCtx)
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
