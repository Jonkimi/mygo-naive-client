package app

import (
	"testing"
	"time"

	"github.com/egoist/mygo/ui"

	"naive-client/internal/config"
	"naive-client/internal/runner"
	"naive-client/locales"
)

func TestNaiveH2_SlowDownloadDoesNotTriggerUnhealthy(t *testing.T) {
	h2Svc := config.Service{
		ID:       "svc-naive-h2",
		Name:     "HK-Naive-H2",
		Protocol: config.ProtoNaive,
		Engine:   config.EngineSidecar,
		Listens:  []string{"socks://127.0.0.1:0"},
		Proxies:  []string{"https://user:pass@hk.example.com:443"},
	}
	quicSvc := config.Service{
		ID:       "svc-naive-quic",
		Name:     "JP-Naive-QUIC",
		Protocol: config.ProtoNaive,
		Engine:   config.EngineSidecar,
		Listens:  []string{"socks://127.0.0.1:0"},
		Proxies:  []string{"quic://user:pass@jp.example.com:443"},
	}
	h2WarpSvc := config.Service{
		ID:         "svc-naive-h2-warp",
		Name:       "HK-Naive-H2-WARP",
		Protocol:   config.ProtoNaive,
		Engine:     config.EngineSidecar,
		Listens:    []string{"socks://127.0.0.1:0"},
		Proxies:    []string{"https://user:pass@hk.example.com:443"},
		EnableWARP: true,
	}

	a, tt, _ := newTestApp(t, []config.Service{h2Svc, quicSvc, h2WarpSvc})
	slowNormalStatus := runner.Status{
		State:         runner.StateRunning,
		Latency:       138 * time.Millisecond,
		DownloadSpeed: 52 * 1024,
	}

	for _, svc := range []config.Service{h2Svc, quicSvc, h2WarpSvc} {
		a.mgr.SetStatusForTest(svc.ID, slowNormalStatus)
		if a.isNodeUnhealthy(svc, slowNormalStatus) {
			t.Errorf("expected %s not to be marked unhealthy from slow download speed alone", svc.ID)
		}
	}

	tt.Frame()
	cat := a.catalog()
	if _, ok := tt.Find(cat.StatusUnhealthy()); ok {
		t.Fatalf("did not expect %q badge on card for slow download speed alone", cat.StatusUnhealthy())
	}
}

func TestNaiveH2_CardOverflowMenuRestartAndQuicExclusion(t *testing.T) {
	h2Svc := config.Service{
		ID:       "svc-h2-menu",
		Name:     "HK-Naive-H2",
		Protocol: config.ProtoNaive,
		Engine:   config.EngineSidecar,
		Listens:  []string{"socks://127.0.0.1:0"},
		Proxies:  []string{"https://user:pass@hk.example.com:443"},
	}
	quicSvc := config.Service{
		ID:       "svc-quic-menu",
		Name:     "JP-Naive-QUIC",
		Protocol: config.ProtoNaive,
		Engine:   config.EngineSidecar,
		Listens:  []string{"socks://127.0.0.1:0"},
		Proxies:  []string{"quic://user:pass@jp.example.com:443"},
	}
	quicChainSvc := config.Service{
		ID:       "svc-quic-chain-menu",
		Name:     "SG-Naive-QUIC-Chain",
		Protocol: config.ProtoNaive,
		Engine:   config.EngineSidecar,
		Listens:  []string{"socks://127.0.0.1:0"},
		Proxies:  []string{"quic://edge.example.com:443, https://hop2.example.com:443"},
	}

	a, tt, _ := newTestApp(t, []config.Service{h2Svc, quicSvc, quicChainSvc})
	for _, svc := range []config.Service{h2Svc, quicSvc, quicChainSvc} {
		a.mgr.SetStatusForTest(svc.ID, runner.Status{
			State:         runner.StateRunning,
			Latency:       80 * time.Millisecond,
			DownloadSpeed: 52 * 1024,
		})
	}
	tt.Frame()
	cat := a.catalog()

	// 1. QUIC Naive nodes (direct and chained) must not expose the HTTP/2 restart action in overflow menu.
	for _, svc := range []config.Service{quicSvc, quicChainSvc} {
		if err := tt.Click(cat.MoreActionsForNode(svc.Name)); err != nil {
			t.Fatalf("open overflow menu for %s: %v", svc.Name, err)
		}
		tt.Frame()
		if tt.HasText(cat.ActionRestartNode()) {
			t.Fatalf("did not expect %q in overflow menu for QUIC node %s", cat.ActionRestartNode(), svc.Name)
		}
		tt.Key(0, ui.KeyEscape)
		tt.Frame()
	}

	// 2. HTTP/2 Naive sidecar exposes Restart Node in overflow menu and clicking it restarts the service.
	if err := tt.Click(cat.MoreActionsForNode(h2Svc.Name)); err != nil {
		t.Fatalf("open overflow menu for %s: %v", h2Svc.Name, err)
	}
	tt.Frame()
	if !tt.HasText(cat.ActionRestartNode()) {
		t.Fatalf("expected %q in overflow menu for HTTP/2 Naive node", cat.ActionRestartNode())
	}
	if err := tt.Click(cat.ActionRestartNode()); err != nil {
		t.Fatalf("click %q in overflow menu: %v", cat.ActionRestartNode(), err)
	}
	tt.Frame()

	rtAfter := a.mgr.StatusOf(h2Svc.ID)
	if rtAfter.State != runner.StateStarting && rtAfter.State != runner.StateRunning {
		t.Fatalf("expected restarted node to be Starting or Running, got %v (err=%q)", rtAfter.State, rtAfter.LastError)
	}
	if rtAfter.DownloadSpeed != 0 {
		t.Fatalf("expected restart to clear prior DownloadSpeed, got %v", rtAfter.DownloadSpeed)
	}
	if !tt.HasText(cat.ToastServiceRestarted(h2Svc.Name)) {
		t.Fatalf("expected restart toast %q, got texts: %v", cat.ToastServiceRestarted(h2Svc.Name), tt.Texts())
	}
}

func TestNaiveH2_DrawerHintAndRestartAndQuicExclusion(t *testing.T) {
	h2Svc := config.Service{
		ID:       "svc-h2-drawer",
		Name:     "HK-Naive-H2",
		Protocol: config.ProtoNaive,
		Engine:   config.EngineSidecar,
		Listens:  []string{"socks://127.0.0.1:0"},
		Proxies:  []string{"https://user:pass@hk.example.com:443"},
	}
	quicSvc := config.Service{
		ID:       "svc-quic-drawer",
		Name:     "JP-Naive-QUIC",
		Protocol: config.ProtoNaive,
		Engine:   config.EngineSidecar,
		Listens:  []string{"socks://127.0.0.1:0"},
		Proxies:  []string{"quic://user:pass@jp.example.com:443"},
	}

	a, tt, _ := newTestApp(t, []config.Service{h2Svc, quicSvc})
	cat := a.catalog()

	// 1. QUIC node drawer must not show HTTP/2 hint or H2 restart action even when speed is low.
	a.mgr.SetStatusForTest(quicSvc.ID, runner.Status{
		State:         runner.StateRunning,
		Latency:       138 * time.Millisecond,
		DownloadSpeed: 52 * 1024,
	})
	a.activeNodeDrawerID = quicSvc.ID
	tt.Frame()
	tt.Advance(300 * time.Millisecond)
	if tt.HasText(cat.NaiveH2TelemetryHint()) {
		t.Fatalf("did not expect HTTP/2 telemetry hint in QUIC node drawer")
	}
	if tt.HasText(cat.ActionRestartNode()) {
		t.Fatalf("did not expect %q in QUIC node drawer", cat.ActionRestartNode())
	}

	// 2. Stopped HTTP/2 Naive sidecar shows subtle HTTP/2 hint, but restart button is disabled.
	a.activeNodeDrawerID = h2Svc.ID
	tt.Frame()
	if !tt.HasText(cat.NaiveH2TelemetryHint()) {
		t.Fatalf("expected HTTP/2 telemetry hint in HTTP/2 Naive node drawer")
	}
	_ = tt.Click("btn-drawer-restart-" + h2Svc.ID)
	tt.Frame()
	if a.mgr.StatusOf(h2Svc.ID).State != runner.StateStopped {
		t.Fatalf("expected stopped node restart button to be disabled")
	}

	// 3. Running HTTP/2 Naive sidecar (even with slow download speed) stays non-unhealthy and allows one-click restart.
	a.mgr.SetStatusForTest(h2Svc.ID, runner.Status{
		State:         runner.StateRunning,
		Latency:       138 * time.Millisecond,
		DownloadSpeed: 52 * 1024,
	})
	a.state.Language = locales.LangEn
	a.applyLanguagePolicy()
	tt.Frame()
	enCat := a.catalog()

	if _, ok := tt.Find(enCat.StatusUnhealthy()); ok {
		t.Fatalf("did not expect %q status in drawer for slow speed alone", enCat.StatusUnhealthy())
	}
	if !tt.HasText(enCat.NaiveH2TelemetryHint()) {
		t.Fatalf("expected English HTTP/2 telemetry hint, got texts: %v", tt.Texts())
	}

	if err := tt.Click("btn-drawer-restart-" + h2Svc.ID); err != nil {
		t.Fatalf("click drawer restart button: %v", err)
	}
	tt.Frame()
	if !tt.HasText(enCat.ToastServiceRestarted(h2Svc.Name)) {
		t.Fatalf("expected English restart toast %q, got texts: %v", enCat.ToastServiceRestarted(h2Svc.Name), tt.Texts())
	}
}
