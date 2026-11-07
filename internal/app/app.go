package app

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"naive-client/internal/blocker"
	"naive-client/internal/boxengine"
	"naive-client/internal/config"
	"naive-client/internal/geodata"
	"naive-client/internal/routing"
	"naive-client/internal/runner"
	"naive-client/internal/sysproxy"
	"naive-client/internal/tailnet"
	"naive-client/internal/telemetry"
	"naive-client/internal/tunhelper"
	"naive-client/internal/updater"
	"naive-client/locales"

	"github.com/sagernet/sing-tun"
)

// TabID identifies a page in the sidebar navigation.
type TabID int

const (
	TabNodes TabID = iota
	TabRouting
	TabInsights
	TabTailnet
	TabSettings
)

type importDialogState struct {
	open     bool
	rawInput string
	errText  string
}

type deleteDialogState struct {
	open    bool
	svcID   string
	svcName string
}

type ruleEditorForm struct {
	open          bool
	isNew         bool
	isFinal       bool
	ruleID        string
	name          string
	desc          string
	actionIndex   int // 0: PROXY_TAG, 1: PROXY_POOL, 2: DIRECT, 3: BLOCK
	tag           string
	tags          []string
	tagQuery      string
	domainsInput  string
	cidrsInput    string
	keywordsInput string
	geosites      []string
	geoips        []string
	geositeQuery  string
	geoipQuery    string
	tab           int // 0: Domains/IPs, 1: GeoData
	errText       string
}

type app struct {
	win      *mygo.Window
	tray     *mygo.Tray
	headless bool
	quitting bool
	dataDir  string

	state PersistedState
	mgr   *runner.Manager

	tracker        *telemetry.Tracker
	failureMonitor *telemetry.FailureMonitor
	gateway        *boxengine.Engine
	lastGatewaySig string
	sysproxy       *sysproxy.Sysproxy
	router         *routing.Router
	blocker        *blocker.Engine
	tailnetMgr     *tailnet.Manager
	tunDevice      *tunhelper.ReceivedDevice
	mockTunDevice  func() (*tunhelper.ReceivedDevice, error)
	mockTunCreator func(options tun.Options) (tun.Tun, error)

	localVersion    string
	latestRelease   *updater.Release
	hasUpdate       bool
	checkingUpdate  bool
	updatingCore    bool

	localXrayVersion   string
	latestXrayRelease  *updater.Release
	hasXrayUpdate      bool
	checkingXrayUpdate bool
	updatingXrayCore   bool
	updateXrayError    string

	localGeodataVersion   string
	latestGeodataRelease  *updater.Release
	hasGeodataUpdate      bool
	checkingGeodataUpdate bool
	updatingGeoData       bool
	geoSiteTags     []string
	geoIPTags       []string
	cachedIPDB      *geodata.GeoIPDB
	cachedSiteDB    *geodata.GeoSiteDB
	cachedIPTags    []string
	cachedSiteTags  []string
	cachedAdsRules  *blocker.ParsedRules
	updateStageText string
	updatePercent   float64
	updateError     string

	stateLoaded      bool
	openAtLogin      bool
	geoDataReady     bool
	gatewayPortInput       string
	autoProbeIntervalInput string
	expandedLogs           map[string]bool
	telemetryUIMu          sync.Mutex
	lastTelemetryUI        time.Time
	telemetryPending       bool

	activeTab          TabID
	activeLogDrawerID  string
	activeRuleDrawerID string
	activeNodeDrawerID string
	activeTagFilter    string
	searchQuery        string

	showRoutingDnsDetail  bool
	showRoutingPoolDetail bool

	insightsFilter           string
	insightsSearch           string
	insightsShowManageRules  bool
	blockerAllowlistInput    string
	blockerDenylistInput     string
	blockerSubscriptionInput string

	batchTesting bool
	batchStage   string
	batchCancel  context.CancelFunc

	editor     editorForm
	importDlg  importDialogState
	deleteDlg  deleteDialogState
	ruleEditor ruleEditorForm

	pendingToast string
	clipboardMem string // fallback clipboard used in headless tests
	quitCh       chan struct{}
}

func (a *app) catalog() locales.Messages {
	return locales.In(locales.ResolveLocale(a.state.Language))
}

func (a *app) localizedRuleName(rule routing.Rule) string {
	cat := a.catalog()
	switch rule.ID {
	case "preset-block-ads":
		return cat.PresetRuleBlockAds()
	case "preset-ai-services":
		return cat.PresetRuleAIServices()
	case "preset-streaming":
		return cat.PresetRuleStreaming()
	case "preset-gfw":
		return cat.PresetRuleGFW()
	case "preset-lan-direct":
		return cat.PresetRuleBypassLan()
	default:
		return rule.Name
	}
}

func (a *app) localizedRuleDescription(rule routing.Rule) string {
	cat := a.catalog()
	switch rule.ID {
	case "preset-block-ads":
		return cat.PresetRuleBlockAdsDesc()
	case "preset-ai-services":
		return cat.PresetRuleAIServicesDesc()
	case "preset-streaming":
		return cat.PresetRuleStreamingDesc()
	case "preset-gfw":
		return cat.PresetRuleGFWDesc()
	case "preset-lan-direct":
		return cat.PresetRuleBypassLanDesc()
	default:
		return rule.Description
	}
}

func (a *app) toggleSidebar() {
	a.state.SidebarCollapsed = !a.state.SidebarCollapsed
	a.saveState()
	if a.win != nil {
		a.win.Invalidate()
	}
}

func (a *app) applyLanguagePolicy() {
	if a.headless {
		return
	}
	tag := ""
	if a.state.Language != locales.LangSystem && a.state.Language != "" {
		tag = a.state.Language
	}
	mygo.App.SetLocale(tag)
	a.rebuildTrayMenu()
	a.installAppMenu()
	if a.win != nil {
		a.win.Invalidate()
	}
}

func (a *app) findService(id string) (config.Service, bool) {
	for _, s := range a.state.Services {
		if s.ID == id {
			return s, true
		}
	}
	return config.Service{}, false
}

// Run launches the NaiveClient desktop application.
func Run() error {
	a := newApp("")
	a.initClientUpdater()
	if !mygo.App.RequestSingleInstanceLock() {
		mygo.App.Quit()
		return nil
	}

	mygo.App.OnSecondInstance(func(args []string, workingDir string) {
		a.showMainWindow()
	})
	mygo.App.OnActivate(func(hasVisibleWindows bool) {
		a.showMainWindow()
	})
	mygo.App.OnWindowAllClosed(func() {
		// Keep running in system tray
	})
	mygo.App.OnBeforeQuit(func(e *mygo.QuitEvent) {
		a.quitting = true
	})
	mygo.App.OnWillQuit(func(e *mygo.QuitEvent) {
		select {
		case <-a.quitCh:
		default:
			close(a.quitCh)
		}
		if a.batchCancel != nil {
			a.batchCancel()
		}
		if a.tailnetMgr != nil {
			a.tailnetMgr.Close()
		}
		a.stopGateway()
		if a.mgr != nil {
			_ = a.mgr.StopAll()
		}
		a.destroyTray()
	})

	mygo.App.WhenReady(func() {
		a.loadState()
		a.initSubsystems()

		a.win = mygo.NewWindow(mygo.WindowOptions{
			Title:           "NaiveClient",
			Width:           900,
			Height:          660,
			MinWidth:        720,
			MinHeight:       500,
			StateKey:        "main",
			BackgroundColor: "#0f1117",
			Content:         ui.View(a.view),
		})
		a.win.OnClose(func(e *mygo.CloseEvent) {
			if a.quitting || a.state.AppIcon == appIconDock {
				return
			}
			e.PreventDefault()
			a.win.Hide()
		})

		a.applyLanguagePolicy()
		a.installAppMenu()
		a.applyAppIconPolicy()
		a.boot()
	})

	return mygo.App.Run()
}

func newApp(dataDir string) *app {
	recPath := filepath.Join(dataDir, "network-recovery.json")
	st := defaultPersistedState()
	blk := blocker.NewEngine(blocker.Options{
		Allowlist: st.BlockerAllowlist,
		Denylist:  st.BlockerDenylist,
		Disabled:  !st.BlockerEnabled,
	})
	tnCfg := st.tailnetConfig()
	tnMgr := tailnet.NewManager(tnCfg, nil)
	a := &app{
		dataDir:        dataDir,
		state:          st,
		stateLoaded:    dataDir != "",
		expandedLogs:   make(map[string]bool),
		tracker:        telemetry.NewTracker(),
		failureMonitor: telemetry.NewFailureMonitor(500),
		sysproxy:       sysproxy.New(recPath),
		router:         routing.NewRouter(st.RoutingRules, st.RoutingFinal),
		blocker:        blk,
		tailnetMgr:     tnMgr,
		quitCh:         make(chan struct{}),
	}
	a.refreshGeoDataStatus()
	return a
}

func (a *app) initSubsystems() {
	binPath := a.resolveBinaryPath()
	cfgDir := filepath.Join(a.userDataDir(), "configs")
	a.mgr = runner.NewManager(binPath, cfgDir, func() {
		if a.gateway != nil {
			a.gateway.UpdateNodes(a.state.Services, a.mgr.AllocatedPorts(), a.mgr.RunningServiceIDs())
		}
		a.dispatchUI(func() {
			a.rebuildTrayMenu()
		})
	})
	a.mgr.OnLog = func(id string) {
		if a.win != nil {
			a.win.Update(func() {
				if a.activeLogDrawerID == id || a.expandedLogs[id] {
					a.win.Invalidate()
				}
			})
		}
	}
	a.mgr.OnProbeSuccess = func(id string, rtt time.Duration) {
		if a.tracker != nil {
			a.tracker.RecordProbe(id, rtt)
		}
	}
	a.mgr.OnProbeFailure = func(id string, err error) {
		if a.tracker != nil {
			a.tracker.RecordProbeFailure(id)
		}
	}
	a.mgr.OnServiceStarted = func(svc config.Service) {
		if a.tracker != nil {
			a.tracker.ResetNode(svc.ID)
		}
		if a.headless || !a.state.AutoProbeOnStart {
			return
		}
		// Cold Start (Path A): Asynchronously probe the newly running service
		// so its real end-to-end HTTPS RTT breaks initial tie in QualityTracker immediately.
		go func() {
			time.Sleep(200 * time.Millisecond)
			if a.mgr != nil && a.mgr.StatusOf(svc.ID).State == runner.StateRunning {
				a.mgr.ProbeService(svc, a.state.ProbeURL)
			}
		}()
	}
	a.syncBinaryPathAndVersion()
	a.syncXrayBinaryPathAndVersion()
}

func (a *app) syncBinaryPathAndVersion() {
	binPath := a.resolveBinaryPath()
	if a.mgr != nil {
		a.mgr.SetBinaryPath(binPath)
	}
	detected := updater.DetectLocalVersion(binPath)
	if a.state.InstalledNaiveTag != "" && strings.TrimSpace(a.state.CustomNaiveBinaryPath) == "" {
		a.localVersion = a.state.InstalledNaiveTag
	} else {
		a.localVersion = detected
	}
	if a.latestRelease != nil {
		a.hasUpdate = updater.NeedsUpdateWithTag(a.state.InstalledNaiveTag, detected, a.latestRelease.TagName)
	}
}

func (a *app) syncXrayBinaryPathAndVersion() {
	binPath := a.resolveXrayBinaryPath()
	if a.mgr != nil {
		a.mgr.SetXrayBinaryPath(binPath)
	}
	detected := updater.DetectLocalXrayVersion(binPath)
	if a.state.InstalledXrayTag != "" && strings.TrimSpace(a.state.CustomXrayBinaryPath) == "" {
		a.localXrayVersion = a.state.InstalledXrayTag
	} else {
		a.localXrayVersion = detected
	}
	if a.latestXrayRelease != nil {
		a.hasXrayUpdate = updater.NeedsUpdateWithTag(a.state.InstalledXrayTag, detected, a.latestXrayRelease.TagName)
	}
}

func (a *app) boot() {
	if !a.headless {
		a.openAtLogin = mygo.App.OpenAtLogin()
	}
	if a.sysproxy != nil {
		_ = a.sysproxy.RecoverIfDirty()
	}
	if a.state.GatewayEnabled {
		if err := a.startGateway(); err != nil && a.tailnetMgr != nil {
			a.tailnetMgr.SetError(err.Error())
		}
	}

	if a.localVersion != "" {
		for _, svc := range a.state.Services {
			if svc.AutoStart {
				_ = a.mgr.Start(svc)
			}
		}
	}

	if a.state.AutoCheckUpdate {
		a.triggerCheckUpdate(false)
	}
	if a.state.AutoCheckXray {
		a.triggerCheckXrayUpdate(false)
	}
	a.triggerCheckGeodataUpdate(false)

	go a.startPeriodicUpdateCheck()
	go a.startPeriodicProbe()
}

func (a *app) startPeriodicUpdateCheck() {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-a.quitCh:
			return
		case <-ticker.C:
			a.dispatchUI(func() {
				if a.state.AutoCheckUpdate {
					a.triggerCheckUpdate(false)
				}
				if a.state.AutoCheckXray {
					a.triggerCheckXrayUpdate(false)
				}
				a.triggerCheckGeodataUpdate(false)
			})
		}
	}
}

func (a *app) startPeriodicProbe() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	var lastProbe time.Time
	for {
		select {
		case <-a.quitCh:
			return
		case <-ticker.C:
			if a.headless || !a.state.AutoProbePeriodic {
				continue
			}
			intervalMin := a.state.AutoProbeInterval
			if intervalMin <= 0 {
				intervalMin = 5
			}
			interval := time.Duration(intervalMin) * time.Minute
			if !lastProbe.IsZero() && time.Since(lastProbe) < interval {
				continue
			}
			lastProbe = time.Now()
			a.probeAllRunningServicesSilent()
		}
	}
}

// probeAllRunningServicesSilent performs a quiet, parallel latency probe on all running services
// to refresh QualityTracker metrics without interrupting the UI or showing toasts.
func (a *app) probeAllRunningServicesSilent() {
	if a.mgr == nil {
		return
	}
	var running []config.Service
	for _, svc := range a.state.Services {
		if a.mgr.StatusOf(svc.ID).State == runner.StateRunning {
			running = append(running, svc)
		}
	}
	if len(running) == 0 {
		return
	}

	probeURL := a.state.ProbeURL
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		var wg sync.WaitGroup
		for _, svc := range running {
			wg.Add(1)
			go func(s config.Service) {
				defer wg.Done()
				// ProbeServiceCtx updates inst.status.Latency and fires OnProbeSuccess,
				// which automatically records probe RTT into QualityTracker via a.tracker.RecordProbe.
				_, _ = a.mgr.ProbeServiceCtx(ctx, s, probeURL)
			}(svc)
		}
		wg.Wait()
	}()
}

// notifyTelemetryUI triggers a rate-limited UI re-render when business traffic records real RTT samples.
func (a *app) notifyTelemetryUI() {
	a.telemetryUIMu.Lock()
	now := time.Now()
	elapsed := now.Sub(a.lastTelemetryUI)
	if elapsed >= 800*time.Millisecond {
		a.lastTelemetryUI = now
		a.telemetryPending = false
		a.telemetryUIMu.Unlock()
		a.dispatchUI(nil)
		return
	}
	if !a.telemetryPending {
		a.telemetryPending = true
		remaining := 800*time.Millisecond - elapsed
		time.AfterFunc(remaining, func() {
			a.telemetryUIMu.Lock()
			a.lastTelemetryUI = time.Now()
			a.telemetryPending = false
			a.telemetryUIMu.Unlock()
			a.dispatchUI(nil)
		})
	}
	a.telemetryUIMu.Unlock()
}

func (a *app) dispatchUI(fn func()) {
	if a.win != nil {
		a.win.Update(func() {
			if fn != nil {
				fn()
			}
			a.win.Invalidate()
		})
		return
	}
	if fn != nil {
		fn()
	}
}

func (a *app) toast(msg string) {
	a.pendingToast = msg
}

// Service Actions
func (a *app) isServiceActive(id string) bool {
	st := a.mgr.StatusOf(id).State
	return st == runner.StateRunning || st == runner.StateStarting
}

func (a *app) toggleService(svc config.Service) {
	if a.isServiceActive(svc.ID) {
		_ = a.mgr.Stop(svc.ID)
		a.toast("已停止服务: " + svc.Name)
		a.rebuildTrayMenu()
		return
	}
	if err := a.mgr.Start(svc); err != nil {
		a.toast("启动失败: " + err.Error())
	} else {
		a.toast("已启动服务: " + svc.Name)
	}
	a.rebuildTrayMenu()
}

func (a *app) startAllServices() {
	cat := a.catalog()
	started := 0
	var lastErr error
	for _, svc := range a.state.Services {
		if !a.isServiceActive(svc.ID) {
			if err := a.mgr.Start(svc); err != nil {
				lastErr = err
			} else {
				started++
			}
		}
	}
	if lastErr != nil && started == 0 {
		a.toast("启动失败: " + lastErr.Error())
	} else if started > 0 {
		a.toast(fmt.Sprintf("已启动 %d 个服务", started))
	} else if len(a.state.Services) > 0 {
		a.toast(cat.AllRunningTip())
	}
	a.rebuildTrayMenu()
}

func (a *app) stopAllServices() {
	cat := a.catalog()
	stopped := a.mgr.StopAll()
	if len(stopped) > 0 {
		a.toast(fmt.Sprintf("已停止 %d 个服务", len(stopped)))
	} else if len(a.state.Services) > 0 {
		a.toast(cat.AllStoppedTip())
	}
	a.rebuildTrayMenu()
}

func (a *app) triggerServiceProbe(svc config.Service) {
	if a.mgr.StatusOf(svc.ID).State != runner.StateRunning {
		a.toast(a.catalog().TestRequiresRunning())
		return
	}
	a.mgr.ProbeService(svc, a.state.ProbeURL)
}

func (a *app) triggerServiceDownloadTest(svc config.Service) {
	if a.mgr.StatusOf(svc.ID).State != runner.StateRunning {
		a.toast(a.catalog().TestRequiresRunning())
		return
	}
	a.mgr.DownloadTestService(svc, a.state.DownloadTestURL)
}

func (a *app) triggerBatchTest() {
	if a.batchTesting {
		if a.batchCancel != nil {
			a.batchCancel()
			a.batchCancel = nil
		}
		a.batchTesting = false
		a.batchStage = ""
		a.toast("已取消测速")
		return
	}

	var targets []config.Service
	for _, svc := range a.state.Services {
		if a.mgr.StatusOf(svc.ID).State == runner.StateRunning {
			targets = append(targets, svc)
		}
	}
	if len(targets) == 0 {
		a.toast(a.catalog().TestRequiresRunning())
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	a.batchCancel = cancel
	a.batchTesting = true
	a.batchStage = "测延迟中..."

	probeURL := a.state.ProbeURL
	downloadURL := a.state.DownloadTestURL

	go func() {
		defer func() {
			a.dispatchUI(func() {
				a.batchTesting = false
				a.batchStage = ""
				a.batchCancel = nil
			})
		}()

		// Phase 1: Parallel latency probes
		var wg sync.WaitGroup
		for _, svc := range targets {
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			go func(s config.Service) {
				defer wg.Done()
				_, _ = a.mgr.ProbeServiceCtx(ctx, s, probeURL)
			}(svc)
		}
		wg.Wait()

		if ctx.Err() != nil {
			return
		}

		// Phase 2: Serial download speed tests
		total := len(targets)
		for i, svc := range targets {
			if ctx.Err() != nil {
				return
			}
			idx := i + 1
			a.dispatchUI(func() {
				a.batchStage = fmt.Sprintf("测速中 (%d/%d)...", idx, total)
			})
			_, _ = a.mgr.DownloadTestServiceCtx(ctx, svc, downloadURL)
		}

		if ctx.Err() != nil {
			return
		}

		var successes, failures int
		for _, svc := range targets {
			st := a.mgr.StatusOf(svc.ID)
			if st.ProbeError != "" || st.SpeedError != "" {
				failures++
			} else {
				successes++
			}
		}

		a.dispatchUI(func() {
			if failures == 0 {
				a.toast(fmt.Sprintf("一键测速完成：全部 %d 个服务测速成功", successes))
			} else {
				a.toast(fmt.Sprintf("一键测速完成：%d 个成功，%d 个失败", successes, failures))
			}
		})
	}()
}

// Update Tracking & Seamless Hot-Swap
func (a *app) buildUpdaterHTTPOptions(timeout time.Duration) updater.HTTPClientOptions {
	opts := updater.HTTPClientOptions{
		ProxyURL: strings.TrimSpace(a.state.UpdateProxy),
		Timeout:  timeout,
	}
	if opts.ProxyURL == "" && a.state.UseRunningServiceForUpd {
		if a.gateway != nil && a.state.GatewayEnabled && a.gateway.Port() > 0 {
			ep := config.ListenEndpoint{
				Proto: "http",
				Addr:  "127.0.0.1",
				Port:  a.gateway.Port(),
			}
			opts.LocalEndpoint = &ep
		} else if a.mgr != nil {
			if ep, ok := a.mgr.FirstRunningEndpoint(); ok {
				opts.LocalEndpoint = &ep
			}
		}
	}
	return opts
}

func (a *app) triggerCheckUpdate(manual bool) {
	if a.checkingUpdate || a.updatingCore {
		return
	}
	if manual {
		a.triggerCheckXrayUpdate(false)
		a.triggerCheckGeodataUpdate(false)
	}
	a.checkingUpdate = true
	a.updateError = ""
	a.syncBinaryPathAndVersion()
	opts := a.buildUpdaterHTTPOptions(20 * time.Second)

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		rel, err := updater.CheckLatest(ctx, opts)
		a.dispatchUI(func() {
			a.checkingUpdate = false
			binPath := a.resolveBinaryPath()
			detected := updater.DetectLocalVersion(binPath)
			if a.state.InstalledNaiveTag != "" && strings.TrimSpace(a.state.CustomNaiveBinaryPath) == "" {
				a.localVersion = a.state.InstalledNaiveTag
			} else {
				a.localVersion = detected
			}
			if err != nil {
				a.updateError = err.Error()
				if manual {
					a.toast("检查更新失败: " + err.Error())
				}
				return
			}
			a.latestRelease = rel
			a.hasUpdate = updater.NeedsUpdateWithTag(a.state.InstalledNaiveTag, detected, rel.TagName)
			if rel != nil && a.state.LastKnownRemoteTag != rel.TagName {
				a.state.LastKnownRemoteTag = rel.TagName
				a.saveState()
			}
			a.rebuildTrayMenu()

			if a.hasUpdate && rel != nil {
				if !manual && a.state.AutoUpdateCore && !a.updatingCore {
					a.triggerSeamlessUpdate(true)
					return
				}
				if manual {
					a.toast("发现新版本: " + rel.TagName)
				}
			} else if manual {
				a.toast("当前已是最新版本")
			}
		})
	}()
}

func (a *app) triggerSeamlessUpdate(auto ...bool) {
	isAuto := len(auto) > 0 && auto[0]
	if a.updatingCore {
		return
	}
	a.updatingCore = true
	a.updateError = ""
	a.updateStageText = "正在获取版本信息..."
	a.updatePercent = 2

	binPath := a.resolveBinaryPath()
	mirror := a.state.GitHubMirror
	opts := a.buildUpdaterHTTPOptions(15 * time.Minute)
	rel := a.latestRelease

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		defer cancel()

		if rel == nil {
			fetched, err := updater.CheckLatest(ctx, opts)
			if err != nil {
				a.dispatchUI(func() {
					a.updatingCore = false
					a.updateStageText = ""
					a.updateError = err.Error()
					if isAuto {
						a.toast("自动更新内核失败: " + err.Error())
					} else {
						a.toast("获取最新版本失败: " + err.Error())
					}
				})
				return
			}
			rel = fetched
		}

		err := updater.SeamlessUpdate(
			ctx,
			rel,
			binPath,
			a.mgr,
			opts,
			mirror,
			func(progress float64, stage string) {
				a.dispatchUI(func() {
					a.updateStageText = stage
					a.updatePercent = progress * 100
				})
			},
		)

		a.dispatchUI(func() {
			a.updatingCore = false
			a.latestRelease = rel
			if err != nil {
				a.syncBinaryPathAndVersion()
				a.rebuildTrayMenu()
				a.updateStageText = ""
				a.updateError = err.Error()
				if isAuto {
					a.toast("自动无感更新内核失败: " + err.Error())
				} else {
					a.toast("无感更新失败: " + err.Error())
				}
				return
			}

			// Persist installed exact tag and SHA256 checksum
			if strings.TrimSpace(a.state.CustomNaiveBinaryPath) == "" {
				a.state.InstalledNaiveTag = rel.TagName
				if sum, sumErr := updater.FileSHA256(binPath); sumErr == nil {
					a.state.InstalledNaiveSHA256 = sum
				}
				a.saveState()
			}

			a.syncBinaryPathAndVersion()
			a.rebuildTrayMenu()
			a.hasUpdate = false
			a.updateStageText = ""
			a.updatePercent = 0
			if isAuto {
				a.toast(fmt.Sprintf("已自动无感更新 NaiveProxy 内核至 %s", rel.TagName))
			} else {
				a.toast(fmt.Sprintf("已无感更新至 %s", rel.TagName))
			}
		})
	}()
}

func (a *app) triggerCheckXrayUpdate(manual bool) {
	if a.checkingXrayUpdate {
		return
	}
	a.checkingXrayUpdate = true
	a.updateXrayError = ""
	a.syncXrayBinaryPathAndVersion()
	opts := a.buildUpdaterHTTPOptions(20 * time.Second)

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		rel, err := updater.CheckLatestXray(ctx, opts)
		a.dispatchUI(func() {
			a.checkingXrayUpdate = false
			binPath := a.resolveXrayBinaryPath()
			detected := updater.DetectLocalXrayVersion(binPath)
			if a.state.InstalledXrayTag != "" && strings.TrimSpace(a.state.CustomXrayBinaryPath) == "" {
				a.localXrayVersion = a.state.InstalledXrayTag
			} else {
				a.localXrayVersion = detected
			}
			if err != nil {
				a.updateXrayError = err.Error()
				if manual {
					a.toast("检查 Xray 更新失败: " + err.Error())
				}
				return
			}
			a.latestXrayRelease = rel
			a.hasXrayUpdate = updater.NeedsUpdateWithTag(a.state.InstalledXrayTag, detected, rel.TagName)
			if rel != nil && a.state.LastKnownRemoteXrayTag != rel.TagName {
				a.state.LastKnownRemoteXrayTag = rel.TagName
				a.saveState()
			}
			if a.hasXrayUpdate && rel != nil {
				if !manual && a.state.AutoUpdateXray && !a.updatingXrayCore {
					a.triggerSeamlessXrayUpdate(true)
					return
				}
				if manual {
					a.toast("发现 Xray 新版本: " + rel.TagName)
				}
			} else if manual {
				a.toast("Xray 当前已是最新版本")
			}
		})
	}()
}

func (a *app) triggerSeamlessXrayUpdate(auto ...bool) {
	isAuto := len(auto) > 0 && auto[0]
	if a.updatingXrayCore {
		return
	}
	a.updatingXrayCore = true
	a.updateXrayError = ""

	binPath := a.resolveXrayBinaryPath()
	mirror := a.state.GitHubMirror
	opts := a.buildUpdaterHTTPOptions(15 * time.Minute)
	rel := a.latestXrayRelease

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		defer cancel()

		if rel == nil {
			fetched, err := updater.CheckLatestXray(ctx, opts)
			if err != nil {
				a.dispatchUI(func() {
					a.updatingXrayCore = false
					a.updateXrayError = err.Error()
					if isAuto {
						a.toast("自动更新 Xray 失败: " + err.Error())
					} else {
						a.toast("获取 Xray 最新版本失败: " + err.Error())
					}
				})
				return
			}
			rel = fetched
		}

		err := updater.SeamlessUpdateXray(
			ctx,
			rel,
			binPath,
			a.mgr,
			opts,
			mirror,
			func(progress float64, stage string) {},
		)

		a.dispatchUI(func() {
			a.updatingXrayCore = false
			a.latestXrayRelease = rel
			if err != nil {
				a.syncXrayBinaryPathAndVersion()
				a.updateXrayError = err.Error()
				if isAuto {
					a.toast("自动更新 Xray 核心失败: " + err.Error())
				} else {
					a.toast("更新 Xray 核心失败: " + err.Error())
				}
				return
			}

			if strings.TrimSpace(a.state.CustomXrayBinaryPath) == "" {
				a.state.InstalledXrayTag = rel.TagName
				if sum, sumErr := updater.FileSHA256(binPath); sumErr == nil {
					a.state.InstalledXraySHA256 = sum
				}
				a.saveState()
			}

			a.syncXrayBinaryPathAndVersion()
			a.hasXrayUpdate = false
			if isAuto {
				a.toast(fmt.Sprintf("已自动更新 Xray-core 内核至 %s", rel.TagName))
			} else {
				a.toast(fmt.Sprintf("已成功安装/更新 Xray-core 至 %s", rel.TagName))
			}
		})
	}()
}

// Clipboard & Export Helpers
func (a *app) copyV2rayNLink(svc config.Service) {
	uri := svc.V2rayNSocksURI()
	a.writeClipboard(uri, "已复制本地链接: "+uri)
}

func (a *app) copyShareLink(svc config.Service) {
	uri := svc.ShareURI()
	if uri == "" {
		a.toast("该服务未配置可导出的远端节点")
		return
	}
	a.writeClipboard(uri, a.catalog().CopiedNaiveShareLink())
}

func (a *app) copyNaiveShareLink(svc config.Service) {
	a.copyShareLink(svc)
}

func (a *app) writeClipboard(text, toastMsg string) {
	a.clipboardMem = text
	if !a.headless {
		mygo.Clipboard.WriteText(text)
	}
	if toastMsg != "" {
		a.toast(toastMsg)
	}
}

func (a *app) readClipboard() string {
	if !a.headless {
		if text := mygo.Clipboard.ReadText(); text != "" {
			return text
		}
	}
	if a.clipboardMem != "" {
		return a.clipboardMem
	}
	return os.Getenv("NAIVE_CLIENT_TEST_CLIPBOARD")
}

func (a *app) startDormantServiceForTag(tag string) {
	tag = strings.TrimSpace(strings.TrimPrefix(tag, "PROXY_TAG:"))
	var wantTags []string
	for _, part := range strings.Split(tag, ",") {
		if p := strings.TrimSpace(part); p != "" {
			wantTags = append(wantTags, p)
		}
	}
	for _, svc := range a.state.Services {
		matches := false
		if tag == "" || tag == "PROXY_POOL" || len(wantTags) == 0 {
			matches = true
		} else {
			for _, t := range svc.Tags {
				for _, wt := range wantTags {
					if strings.EqualFold(t, wt) {
						matches = true
						break
					}
				}
				if matches {
					break
				}
			}
		}
		if matches && !a.isServiceActive(svc.ID) {
			_ = a.mgr.Start(svc)
			for i := 0; i < 20; i++ {
				st := a.mgr.StatusOf(svc.ID)
				if st.State == runner.StateRunning {
					if a.gateway != nil {
						a.gateway.UpdateNodes(a.state.Services, a.mgr.AllocatedPorts(), a.mgr.RunningServiceIDs())
					}
					return
				}
				time.Sleep(20 * time.Millisecond)
			}
			return
		}
	}
}

func (a *app) requestTunDevice() (*tunhelper.ReceivedDevice, error) {
	if a.mockTunDevice != nil {
		return a.mockTunDevice()
	}
	binPath := a.resolveBinaryPath()
	if binPath == "" {
		if exe, err := os.Executable(); err == nil {
			binPath = exe
		}
	}
	client := tunhelper.NewClient()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return client.RequestDevice(ctx, binPath)
}

func (a *app) startGateway() error {
	if a.gateway != nil {
		_ = a.gateway.Stop()
		a.gateway = nil
		a.lastGatewaySig = ""
	}
	if a.tailnetMgr != nil && a.state.TailnetMode != string(tailnet.ModeEmbedded) {
		a.tailnetMgr.BindEmbeddedEndpoint(nil)
	}
	if !a.state.GatewayEnabled {
		return nil
	}
	port := a.state.GatewayPort
	if port <= 0 {
		port = 10809
	}

	var allocPorts map[string]int
	var activeIDs map[string]bool
	if a.mgr != nil {
		allocPorts = a.mgr.AllocatedPorts()
		activeIDs = a.mgr.RunningServiceIDs()
	}

	var tunFD int
	var tunName string
	if a.state.TrafficMode == "tun" {
		if a.tunDevice == nil {
			dev, err := a.requestTunDevice()
			if err != nil {
				return fmt.Errorf("request TUN device: %w", err)
			}
			a.tunDevice = dev
		}
		if a.tunDevice != nil {
			tunFD = a.tunDevice.FD
			tunName = a.tunDevice.Name
		}
	} else {
		if a.tunDevice != nil {
			_ = a.tunDevice.Close()
			a.tunDevice = nil
		}
	}

	var tunAddrs []string
	if a.mockTunDevice != nil {
		tunAddrs = []string{"127.0.0.1/24"}
	}

	var tnCfg tailnet.Config
	var tnMode tailnet.Mode = tailnet.ModeOff
	var tnExcludes []string
	var tnSuffix string
	if a.tailnetMgr != nil {
		tnCfg = a.tailnetMgr.GetConfig()
		if a.tailnetMgr.ShouldUseHostMode() {
			tnMode = tailnet.ModeHost
			tnExcludes = a.tailnetMgr.GetHostExcludeAddresses()
			tnSuffix = a.tailnetMgr.GetMagicDNSSuffix()
		} else if a.tailnetMgr.ShouldUseEmbeddedMode() {
			tnMode = tailnet.ModeEmbedded
			tnSuffix = a.tailnetMgr.GetMagicDNSSuffix()
		}
	}

	eng, err := boxengine.New(boxengine.EngineOptions{
		ListenAddr:            fmt.Sprintf("127.0.0.1:%d", port),
		TrafficMode:           a.state.TrafficMode,
		TunFD:                 tunFD,
		TunInterface:          tunName,
		TunAddresses:          tunAddrs,
		TunCreator:            a.mockTunCreator,
		Services:              a.state.Services,
		AllocatedPorts:        allocPorts,
		ActiveIDs:             activeIDs,
		Rules:                 a.state.RoutingRules,
		FinalAction:           string(a.state.RoutingFinal.Type),
		FinalRoute:            a.state.RoutingFinal,
		GeoSiteDB:             a.cachedSiteDB,
		GeoIPDB:               a.cachedIPDB,
		Tracker:               a.tracker,
		FailureMonitor:        a.failureMonitor,
		Blocker:               a.blocker,
		BootstrapDNS:          parseDNSList(a.state.BootstrapDNS, boxengine.DefaultBootstrapDNS),
		DomesticDoH:           parseDNSList(a.effectiveDomesticDNS(), boxengine.DefaultDomesticDoH),
		RemoteDoH:             parseDNSList(a.effectiveRemoteDNS(), boxengine.DefaultRemoteDoH),
		PreferIPv4:            a.state.PreferIPv4,
		TailnetConfig:         &tnCfg,
		TailnetMode:           tnMode,
		TailnetHostExcludes:   tnExcludes,
		TailnetMagicDNSSuffix: tnSuffix,
		StateDir:              a.userDataDir(),
		OnDemandStart: func(tag string) {
			a.startDormantServiceForTag(tag)
		},
		OnTelemetryUpdate: func() {
			a.notifyTelemetryUI()
		},
	})
	if err != nil {
		return err
	}
	if err := eng.Start(); err != nil {
		return err
	}
	a.gateway = eng
	a.lastGatewaySig = a.gatewayConfigSignature()

	if a.tailnetMgr != nil {
		if tnMode == tailnet.ModeEmbedded {
			a.tailnetMgr.BindEmbeddedEndpoint(eng.TailscaleEndpoint())
		} else {
			a.tailnetMgr.BindEmbeddedEndpoint(nil)
		}
	}

	if a.state.TrafficMode == "sysproxy" && a.sysproxy != nil {
		_ = a.sysproxy.Set(eng.Addr(), a.state.SystemProxyBypass)
	} else if a.state.TrafficMode == "tun" && a.sysproxy != nil {
		_ = a.sysproxy.MarkDirtyTun(tunName)
	}
	a.releaseUnusedMemory()
	return nil
}

func (a *app) effectiveDomesticDNS() string {
	if a.state.DomesticDNS != "" {
		return a.state.DomesticDNS
	}
	return a.state.BootstrapDoH
}

func (a *app) effectiveRemoteDNS() string {
	if a.state.RemoteDNS != "" {
		return a.state.RemoteDNS
	}
	return a.state.RemoteDoH
}

func parseDNSList(s string, defaults []string) []string {
	var list []string
	for _, part := range strings.Split(s, ",") {
		clean := strings.TrimSpace(part)
		if clean != "" {
			list = append(list, clean)
		}
	}
	if len(list) == 0 {
		return defaults
	}
	return list
}

func (a *app) collectBootstrapDomains() []string {
	var domains []string
	seen := make(map[string]bool)
	add := func(host string) {
		host = strings.TrimSpace(host)
		if host == "" {
			return
		}
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.ToLower(host)
		if net.ParseIP(host) == nil && !seen[host] {
			seen[host] = true
			domains = append(domains, host)
		}
	}

	for _, svc := range a.state.Services {
		for _, p := range svc.Proxies {
			if u, err := url.Parse(p); err == nil && u.Hostname() != "" {
				add(u.Hostname())
			}
		}
		if svc.ExternalURI != "" {
			if u, err := url.Parse(svc.ExternalURI); err == nil && u.Hostname() != "" {
				add(u.Hostname())
			}
		}
	}

	// Collect domestic DoH domains to ensure they can be resolved via Bootstrap DNS without deadlocking.
	for _, ep := range parseDNSList(a.effectiveDomesticDNS(), boxengine.DefaultDomesticDoH) {
		if u, err := url.Parse(ep); err == nil && u.Hostname() != "" {
			add(u.Hostname())
		}
	}

	return domains
}

func (a *app) initDNS() {
	if a.gateway != nil {
		_ = a.startGateway()
	}
}

func (a *app) stopGateway() {
	if a.sysproxy != nil {
		_ = a.sysproxy.Unset()
	}
	if a.gateway != nil {
		_ = a.gateway.Stop()
		a.gateway = nil
		a.lastGatewaySig = ""
	}
	if a.tailnetMgr != nil && a.state.TailnetMode != string(tailnet.ModeEmbedded) {
		a.tailnetMgr.BindEmbeddedEndpoint(nil)
	}
	if a.tunDevice != nil {
		_ = a.tunDevice.Close()
		a.tunDevice = nil
	}
}

func (a *app) setTrafficMode(mode string) error {
	switch mode {
	case "port":
		a.state.TrafficMode = "port"
		if a.sysproxy != nil {
			_ = a.sysproxy.Unset()
		}
		if a.tunDevice != nil {
			_ = a.tunDevice.Close()
			a.tunDevice = nil
			if a.gateway != nil {
				_ = a.startGateway()
			}
		}
		a.saveState()
		if a.win != nil {
			a.win.Invalidate()
		}
		return nil
	case "sysproxy":
		a.state.TrafficMode = "sysproxy"
		if a.tunDevice != nil {
			_ = a.tunDevice.Close()
			a.tunDevice = nil
			if err := a.startGateway(); err != nil {
				return err
			}
		} else if a.gateway == nil {
			if err := a.startGateway(); err != nil {
				return err
			}
		}
		if a.sysproxy != nil && a.gateway != nil {
			if err := a.sysproxy.Set(a.gateway.Addr(), a.state.SystemProxyBypass); err != nil {
				return err
			}
		}
		a.saveState()
		if a.win != nil {
			a.win.Invalidate()
		}
		return nil
	case "tun":
		a.state.TrafficMode = "tun"
		if a.sysproxy != nil {
			_ = a.sysproxy.Unset()
		}
		if err := a.startGateway(); err != nil {
			a.state.TrafficMode = "port"
			_ = a.startGateway()
			a.toast("TUN Mode error: " + err.Error())
			a.saveState()
			if a.win != nil {
				a.win.Invalidate()
			}
			return err
		}
		a.saveState()
		if a.win != nil {
			a.win.Invalidate()
		}
		return nil
	default:
		return fmt.Errorf("unsupported traffic mode: %s", mode)
	}
}

func (a *app) geodataDir() string {
	return filepath.Join(a.userDataDir(), "geodata")
}

func sameTagSet(a, b []string) bool {
	ma := make(map[string]bool, len(a))
	for _, t := range a {
		clean := strings.ToUpper(strings.TrimSpace(t))
		if clean != "" {
			ma[clean] = true
		}
	}
	mb := make(map[string]bool, len(b))
	for _, t := range b {
		clean := strings.ToUpper(strings.TrimSpace(t))
		if clean != "" {
			mb[clean] = true
		}
	}
	if len(ma) != len(mb) {
		return false
	}
	for k := range ma {
		if !mb[k] {
			return false
		}
	}
	return true
}

func (a *app) loadGeoTagsIfPresent() {
	dir := a.geodataDir()
	if len(a.geoSiteTags) == 0 {
		if f, err := os.Open(filepath.Join(dir, "geosite.dat")); err == nil {
			defer f.Close()
			if tags, err := geodata.ListGeoTags(f); err == nil && len(tags) > 0 {
				a.geoSiteTags = tags
			}
		}
	}
	if len(a.geoIPTags) == 0 {
		if f, err := os.Open(filepath.Join(dir, "geoip.dat")); err == nil {
			defer f.Close()
			if tags, err := geodata.ListGeoTags(f); err == nil && len(tags) > 0 {
				a.geoIPTags = tags
			}
		}
	}
}

func (a *app) availableGeoSiteTags() []string {
	if len(a.geoSiteTags) == 0 {
		a.loadGeoTagsIfPresent()
	}
	return a.geoSiteTags
}

func (a *app) availableGeoIPTags() []string {
	if len(a.geoIPTags) == 0 {
		a.loadGeoTagsIfPresent()
	}
	return a.geoIPTags
}

func isCategoryAdsBlockRule(r routing.Rule) bool {
	if r.ID == "preset-block-ads" {
		return true
	}
	if r.Action.Type != routing.ActionBlock {
		return false
	}
	for _, tag := range r.GeoSite {
		if strings.EqualFold(strings.TrimSpace(tag), "category-ads-all") {
			return true
		}
	}
	return false
}

func (a *app) releaseUnusedMemory() {
	if a.headless {
		return
	}
	debug.FreeOSMemory()
}

func (a *app) loadGeoDataIfPresent() {
	a.refreshGeoDataStatus()
	if a.router == nil {
		return
	}
	dir := a.geodataDir()
	ipPath := filepath.Join(dir, "geoip.dat")
	sitePath := filepath.Join(dir, "geosite.dat")

	var reqIPTags []string
	var reqSiteTags []string
	hasAdsRuleInRouting := false
	for _, r := range a.state.RoutingRules {
		if isCategoryAdsBlockRule(r) {
			hasAdsRuleInRouting = true
		}
		if !r.Enabled {
			continue
		}
		reqIPTags = append(reqIPTags, r.GeoIP...)
		reqSiteTags = append(reqSiteTags, r.GeoSite...)
	}
	if !hasAdsRuleInRouting && a.state.BlockerEnabled && a.state.BlockerBlockAds {
		reqSiteTags = append(reqSiteTags, "category-ads-all")
	}

	prevIPDB := a.cachedIPDB
	prevSiteDB := a.cachedSiteDB

	var ipDB *geodata.GeoIPDB
	if len(reqIPTags) > 0 {
		ipDB = a.cachedIPDB
		if ipDB == nil || !sameTagSet(reqIPTags, a.cachedIPTags) {
			missingIP := ipDB.MissingTags(reqIPTags)
			if len(missingIP) == 0 && ipDB != nil {
				ipDB = ipDB.WithTags(reqIPTags, nil)
				a.cachedIPDB = ipDB
				a.cachedIPTags = append([]string(nil), reqIPTags...)
			} else if f, err := os.Open(ipPath); err == nil {
				if loaded, err := geodata.LoadGeoIP(f, missingIP); err == nil {
					ipDB = ipDB.WithTags(reqIPTags, loaded)
					a.cachedIPDB = ipDB
					a.cachedIPTags = append([]string(nil), reqIPTags...)
				}
				_ = f.Close()
			}
		}
	} else {
		a.cachedIPDB = nil
		a.cachedIPTags = nil
	}

	var siteDB *geodata.GeoSiteDB
	if len(reqSiteTags) > 0 {
		siteDB = a.cachedSiteDB
		if siteDB == nil || !sameTagSet(reqSiteTags, a.cachedSiteTags) {
			missingSite := siteDB.MissingTags(reqSiteTags)
			if len(missingSite) == 0 && siteDB != nil {
				siteDB = siteDB.WithTags(reqSiteTags, nil)
				a.cachedSiteDB = siteDB
				a.cachedSiteTags = append([]string(nil), reqSiteTags...)
			} else if f, err := os.Open(sitePath); err == nil {
				if loaded, err := geodata.LoadGeoSite(f, missingSite); err == nil {
					siteDB = siteDB.WithTags(reqSiteTags, loaded)
					a.cachedSiteDB = siteDB
					a.cachedSiteTags = append([]string(nil), reqSiteTags...)
				}
				_ = f.Close()
			}
		}
	} else {
		a.cachedSiteDB = nil
		a.cachedSiteTags = nil
	}

	a.router.SetGeoData(ipDB, siteDB)
	a.syncBlockerRules()
	if prevIPDB != a.cachedIPDB || prevSiteDB != a.cachedSiteDB {
		a.releaseUnusedMemory()
	}
}

func (a *app) refreshGeoDataStatus() {
	dir := a.geodataDir()
	ipPath := filepath.Join(dir, "geoip.dat")
	sitePath := filepath.Join(dir, "geosite.dat")
	st1, err1 := os.Stat(ipPath)
	st2, err2 := os.Stat(sitePath)
	a.geoDataReady = err1 == nil && err2 == nil && st1.Size() > 0 && st2.Size() > 0
	if a.geoDataReady {
		if a.state.InstalledGeodataTag != "" {
			a.localGeodataVersion = a.state.InstalledGeodataTag
		} else if v := geodata.DetectLocalVersion(dir); v != "" {
			a.localGeodataVersion = v
			a.state.InstalledGeodataTag = v
			if a.stateLoaded {
				a.saveState()
			}
		} else {
			a.localGeodataVersion = st1.ModTime().Format("20060102")
		}
	} else {
		a.localGeodataVersion = ""
	}
	if a.latestGeodataRelease != nil {
		a.hasGeodataUpdate = a.geoDataReady && updater.NeedsUpdateWithTag(a.state.InstalledGeodataTag, a.localGeodataVersion, a.latestGeodataRelease.TagName)
	}
}

func (a *app) hasGeoData() bool {
	return a.geoDataReady
}

func (a *app) triggerCheckGeodataUpdate(manual bool) {
	if a.checkingGeodataUpdate {
		return
	}
	a.checkingGeodataUpdate = true
	opts := a.buildUpdaterHTTPOptions(20 * time.Second)

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		rel, err := updater.CheckLatestGeodata(ctx, opts)
		a.dispatchUI(func() {
			a.checkingGeodataUpdate = false
			a.refreshGeoDataStatus()
			if err != nil {
				if manual {
					a.toast("检查规则库更新失败: " + err.Error())
				}
				return
			}
			a.latestGeodataRelease = rel
			if a.geoDataReady {
				a.hasGeodataUpdate = updater.NeedsUpdateWithTag(a.state.InstalledGeodataTag, a.localGeodataVersion, rel.TagName)
			}
			if rel != nil && a.state.LastKnownRemoteGeodataTag != rel.TagName {
				a.state.LastKnownRemoteGeodataTag = rel.TagName
				a.saveState()
			}
			if a.hasGeodataUpdate && rel != nil {
				if manual {
					a.toast("发现规则库新版本: " + rel.TagName)
				}
			} else if manual {
				a.toast("规则库当前已是最新版本")
			}
		})
	}()
}

func (a *app) triggerUpdateGeoData() {
	if a.updatingGeoData {
		return
	}
	a.updatingGeoData = true
	if a.win != nil {
		a.win.Invalidate()
	}
	a.toast("正在下载与校验最新规则库 (Loyalsoldier)...")
	rel := a.latestGeodataRelease
	targetTag := ""
	if rel != nil {
		targetTag = rel.TagName
	}
	go func() {
		httpOpts := a.buildUpdaterHTTPOptions(60 * time.Second)
		opts := geodata.UpdateOptions{
			DestDir:      a.geodataDir(),
			GitHubMirror: a.state.GitHubMirror,
			ProxyURL:     httpOpts.ProxyURL,
			ProxyEP:      httpOpts.LocalEndpoint,
			Tag:          targetTag,
		}
		ver, err := geodata.Update(context.Background(), opts, nil)
		a.dispatchUI(func() {
			a.updatingGeoData = false
			if err != nil {
				a.toast("规则库更新失败: " + err.Error())
			} else {
				if ver != "" {
					a.state.InstalledGeodataTag = ver
					a.localGeodataVersion = ver
					a.hasGeodataUpdate = false
					a.saveState()
				}
				a.cachedIPDB = nil
				a.cachedSiteDB = nil
				a.cachedIPTags = nil
				a.cachedSiteTags = nil
				a.cachedAdsRules = nil
				a.geoSiteTags = nil
				a.geoIPTags = nil
				a.refreshGeoDataStatus()
				a.syncRouter()
				a.syncBlockerRules()
				if ver != "" {
					a.toast(fmt.Sprintf("规则库已更新至 %s 并重新加载", ver))
				} else {
					a.toast("规则库已更新并重新加载")
				}
			}
			if a.win != nil {
				a.win.Invalidate()
			}
		})
	}()
}

func (a *app) gatewayConfigSignature() string {
	type svcSig struct {
		ID          string
		Engine      config.ExecutionEngine
		Kind        config.NodeKind
		Protocol    config.Protocol
		Server      string
		Proxies     []string
		ExternalURI string
		Tags        []string
	}
	svcs := make([]svcSig, len(a.state.Services))
	for i, s := range a.state.Services {
		svcs[i] = svcSig{
			ID:          s.ID,
			Engine:      s.Engine,
			Kind:        s.Kind,
			Protocol:    s.Protocol,
			Server:      s.Server,
			Proxies:     s.Proxies,
			ExternalURI: s.ExternalURI,
			Tags:        s.Tags,
		}
	}
	sigObj := struct {
		Port        int
		TrafficMode string
		Svcs        []svcSig
		Rules       []routing.Rule
		Final       routing.RouteAction
		HasSiteDB   bool
		HasIPDB     bool
		GeoTag      string
		Bootstrap   string
		Domestic    string
		Remote      string
		PreferIPv4  bool
	}{
		Port:        a.state.GatewayPort,
		TrafficMode: a.state.TrafficMode,
		Svcs:        svcs,
		Rules:       a.state.RoutingRules,
		Final:       a.state.RoutingFinal,
		HasSiteDB:   a.cachedSiteDB != nil,
		HasIPDB:     a.cachedIPDB != nil,
		GeoTag:      a.localGeodataVersion,
		Bootstrap:   a.state.BootstrapDNS,
		Domestic:    a.effectiveDomesticDNS(),
		Remote:      a.effectiveRemoteDNS(),
		PreferIPv4:  a.state.PreferIPv4,
	}
	return fmt.Sprintf("%#v", sigObj)
}

func (a *app) syncRouter() {
	a.router = routing.NewRouter(a.state.RoutingRules, a.state.RoutingFinal)
	a.loadGeoDataIfPresent()
	if a.gateway != nil {
		var allocPorts map[string]int
		var activeIDs map[string]bool
		if a.mgr != nil {
			allocPorts = a.mgr.AllocatedPorts()
			activeIDs = a.mgr.RunningServiceIDs()
		}
		a.gateway.UpdateNodes(a.state.Services, allocPorts, activeIDs)
		if !a.state.GatewayEnabled || a.gatewayConfigSignature() != a.lastGatewaySig {
			_ = a.startGateway()
		}
	}
}

func (a *app) dialThroughPool(ctx context.Context, target string) (net.Conn, string, error) {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}

	// 1. Evaluate routing rules
	var action routing.RouteAction
	if a.router != nil {
		act, _ := a.router.Match(target)
		action = act
	} else {
		action = routing.RouteAction{Type: routing.ActionProxyPool}
	}

	// 2. Dispatch according to RouteAction
	switch action.Type {
	case routing.ActionBlock:
		return nil, "", fmt.Errorf("connection to %s blocked by routing rules", target)

	case routing.ActionDirect:
		var d net.Dialer
		network := "tcp"
		if a.state.PreferIPv4 {
			h, _, err := net.SplitHostPort(target)
			if err != nil {
				h = target
			}
			ip := net.ParseIP(h)
			if ip == nil || ip.To4() != nil {
				network = "tcp4"
			}
		}
		conn, err := d.DialContext(ctx, network, target)
		return conn, "direct", err

	case routing.ActionProxyService:
		if a.mgr != nil && action.ServiceID != "" {
			for _, svc := range a.state.Services {
				if svc.ID == action.ServiceID {
					if a.mgr.StatusOf(svc.ID).State == runner.StateRunning {
						ep, err := svc.OutboundEndpoint()
						if err != nil {
							return nil, svc.ID, err
						}
						conn, err := runner.DialEndpoint(ctx, ep, target)
						return conn, svc.ID, err
					}
					return nil, "", fmt.Errorf("proxy service %s is not running for %s", action.ServiceID, target)
				}
			}
			return nil, "", fmt.Errorf("proxy service %s not found for %s", action.ServiceID, target)
		}
		return nil, "", fmt.Errorf("no proxy service specified for %s", target)

	case routing.ActionProxyTag:
		tags := action.GetTags()
		if a.mgr != nil && len(tags) > 0 {
			var tagSvcs []config.Service
			var tagIDs []string
			var stoppedTagSvcs []config.Service

			for _, svc := range a.state.Services {
				hasTag := false
				for _, t := range svc.Tags {
					for _, targetTag := range tags {
						if strings.EqualFold(strings.TrimSpace(t), strings.TrimSpace(targetTag)) {
							hasTag = true
							break
						}
					}
					if hasTag {
						break
					}
				}
				if hasTag {
					if a.mgr.StatusOf(svc.ID).State == runner.StateRunning {
						tagSvcs = append(tagSvcs, svc)
						tagIDs = append(tagIDs, svc.ID)
					} else {
						stoppedTagSvcs = append(stoppedTagSvcs, svc)
					}
				}
			}

			// Decision 5 in ADR-0002: If no node under this tag is running, automatically launch on-demand
			if len(tagSvcs) == 0 && len(stoppedTagSvcs) > 0 {
				launchSvc := stoppedTagSvcs[0]
				if err := a.mgr.Start(launchSvc); err == nil {
					for retry := 0; retry < 20; retry++ {
						if a.mgr.StatusOf(launchSvc.ID).State == runner.StateRunning {
							tagSvcs = append(tagSvcs, launchSvc)
							tagIDs = append(tagIDs, launchSvc.ID)
							break
						}
						time.Sleep(50 * time.Millisecond)
					}
				}
			}

			if len(tagSvcs) > 0 {
				bestID := tagIDs[0]
				if a.tracker != nil {
					if sel, ok := a.tracker.SelectBest(tagIDs, host); ok {
						bestID = sel
					}
				}
				for _, svc := range tagSvcs {
					if svc.ID == bestID {
						ep, err := svc.OutboundEndpoint()
						if err != nil {
							return nil, svc.ID, err
						}
						conn, err := runner.DialEndpoint(ctx, ep, target)
						return conn, svc.ID, err
					}
				}
			}
			return nil, "", fmt.Errorf("no active proxy available for tag(s) %s for %s", strings.Join(tags, ","), target)
		}
		return nil, "", fmt.Errorf("no tag specified for proxy tag route for %s", target)
	}

	// 3. Fallback: Global active ProxyPool
	var runningSvcs []config.Service
	var runningIDs []string
	if a.mgr != nil {
		for _, svc := range a.state.Services {
			st := a.mgr.StatusOf(svc.ID)
			if st.State == runner.StateRunning {
				runningSvcs = append(runningSvcs, svc)
				runningIDs = append(runningIDs, svc.ID)
			}
		}
	}

	if len(runningSvcs) == 0 {
		return nil, "", fmt.Errorf("no active proxy available in pool for %s", target)
	}

	bestID := runningIDs[0]
	if a.tracker != nil {
		if sel, ok := a.tracker.SelectBest(runningIDs, host); ok {
			bestID = sel
		}
	}

	var bestSvc *config.Service
	for i := range runningSvcs {
		if runningSvcs[i].ID == bestID {
			bestSvc = &runningSvcs[i]
			break
		}
	}
	if bestSvc == nil {
		bestSvc = &runningSvcs[0]
	}

	ep, err := bestSvc.OutboundEndpoint()
	if err != nil {
		return nil, bestSvc.ID, err
	}

	conn, err := runner.DialEndpoint(ctx, ep, target)
	return conn, bestSvc.ID, err
}

func (a *app) blockerAsDNS() blocker.Blocker {
	if a.blocker != nil {
		return a.blocker.AsDNS()
	}
	return nil
}

func (a *app) blockerAsGateway() blocker.Blocker {
	if a.blocker != nil {
		return a.blocker.AsGateway()
	}
	return nil
}

func (a *app) blockerMatchesAllowlist(domain string) bool {
	domain = strings.Trim(strings.ToLower(strings.TrimSpace(domain)), ".")
	for _, d := range a.state.BlockerAllowlist {
		if strings.Trim(strings.ToLower(strings.TrimSpace(d)), ".") == domain {
			return true
		}
	}
	return false
}

func (a *app) blockerMatchesDenylist(domain string) bool {
	domain = strings.Trim(strings.ToLower(strings.TrimSpace(domain)), ".")
	for _, d := range a.state.BlockerDenylist {
		if strings.Trim(strings.ToLower(strings.TrimSpace(d)), ".") == domain {
			return true
		}
	}
	return false
}

func (a *app) syncBlocker() {
	if a.blocker == nil {
		a.blocker = blocker.NewEngine(blocker.Options{
			Allowlist: a.state.BlockerAllowlist,
			Denylist:  a.state.BlockerDenylist,
			Disabled:  !a.state.BlockerEnabled,
		})
	} else {
		a.blocker.SetEnabled(a.state.BlockerEnabled)
	}
	a.syncBlockerRules()
}

func (a *app) syncBlockerRules() {
	if a.blocker == nil {
		return
	}

	prevAds := a.cachedAdsRules
	if !a.state.BlockerEnabled {
		a.cachedAdsRules = nil
		a.blocker.SwapRuleset(blocker.NewParsedRules())
		if prevAds != nil {
			a.releaseUnusedMemory()
		}
		return
	}

	// 1. Built-in geosite category-ads-all (always share cachedSiteDB when available so only one copy exists)
	if a.state.BlockerBlockAds {
		var adsDB *geodata.GeoSiteDB
		if a.cachedSiteDB != nil && a.cachedSiteDB.HasTag("category-ads-all") {
			adsDB = a.cachedSiteDB
		} else if a.cachedAdsRules != nil && a.cachedAdsRules.GeoAds != nil {
			if prev, ok := a.cachedAdsRules.GeoAds.(*geodata.GeoSiteDB); ok && prev.HasTag("category-ads-all") {
				adsDB = prev
			}
		}
		if adsDB == nil {
			sitePath := filepath.Join(a.geodataDir(), "geosite.dat")
			if f, err := os.Open(sitePath); err == nil {
				adsDB, _ = geodata.LoadGeoSite(f, []string{"category-ads-all"})
				_ = f.Close()
			}
		}
		if adsDB != nil && adsDB.HasTag("category-ads-all") {
			cached := blocker.NewParsedRules()
			cached.GeoAds = adsDB
			a.cachedAdsRules = cached
		} else {
			a.cachedAdsRules = nil
		}
	} else {
		a.cachedAdsRules = nil
	}

	// 2. External Subscriptions cached on disk
	var extRules []*blocker.ParsedRules
	if len(a.state.BlockerSubscriptions) > 0 {
		subDir := filepath.Join(a.userDataDir(), "blocker_cache")
		_ = os.MkdirAll(subDir, 0o755)
		for _, subURL := range a.state.BlockerSubscriptions {
			subURL = strings.TrimSpace(subURL)
			if subURL == "" {
				continue
			}
			hash := fmt.Sprintf("%x", sha256.Sum256([]byte(subURL)))
			cachePath := filepath.Join(subDir, hash+".txt")
			if f, err := os.Open(cachePath); err == nil {
				if parsed, err := blocker.ParseRuleStream(f, subURL); err == nil {
					extRules = append(extRules, parsed)
				}
				_ = f.Close()
			}
		}
	}

	// Fast path: if no external subscription rules exist, share cachedAdsRules directly without cloning maps
	if len(extRules) == 0 {
		if a.state.BlockerBlockAds && a.cachedAdsRules != nil {
			a.blocker.SwapRuleset(a.cachedAdsRules)
		} else {
			a.blocker.SwapRuleset(blocker.NewParsedRules())
		}
		if prevAds != nil && a.cachedAdsRules == nil {
			a.releaseUnusedMemory()
		}
		return
	}

	merged := blocker.NewParsedRules()
	if a.state.BlockerBlockAds && a.cachedAdsRules != nil {
		merged.Merge(a.cachedAdsRules)
	}
	for _, parsed := range extRules {
		merged.Merge(parsed)
	}
	a.blocker.SwapRuleset(merged)
	a.clearDNSCache()
	if prevAds != nil && a.cachedAdsRules == nil {
		a.releaseUnusedMemory()
	}
}

func (a *app) clearDNSCache() {
	if a.gateway != nil {
		a.gateway.ClearDNSCache()
	}
}

func (a *app) addBlockerAllowlist(domain string) {
	d := strings.Trim(strings.ToLower(strings.TrimSpace(domain)), ".")
	if d == "" {
		return
	}
	if a.blocker != nil {
		a.blocker.AddAllowlist(d)
		a.blocker.RemoveDenylist(d)
	}
	found := false
	for _, x := range a.state.BlockerAllowlist {
		if x == d {
			found = true
			break
		}
	}
	if !found {
		a.state.BlockerAllowlist = append(a.state.BlockerAllowlist, d)
	}
	var newDeny []string
	for _, x := range a.state.BlockerDenylist {
		if x != d {
			newDeny = append(newDeny, x)
		}
	}
	a.state.BlockerDenylist = newDeny
	a.saveState()
	a.clearDNSCache()
	a.toast(a.catalog().ToastAddedAllowlist())
}

func (a *app) removeBlockerAllowlist(domain string) {
	d := strings.Trim(strings.ToLower(strings.TrimSpace(domain)), ".")
	if d == "" {
		return
	}
	if a.blocker != nil {
		a.blocker.RemoveAllowlist(d)
	}
	var newAllow []string
	for _, x := range a.state.BlockerAllowlist {
		if x != d {
			newAllow = append(newAllow, x)
		}
	}
	a.state.BlockerAllowlist = newAllow
	a.saveState()
	a.clearDNSCache()
	a.toast(a.catalog().ToastRemovedAllowlist())
}

func (a *app) addBlockerDenylist(domain string) {
	d := strings.Trim(strings.ToLower(strings.TrimSpace(domain)), ".")
	if d == "" {
		return
	}
	if a.blocker != nil {
		a.blocker.AddDenylist(d)
		a.blocker.RemoveAllowlist(d)
	}
	found := false
	for _, x := range a.state.BlockerDenylist {
		if x == d {
			found = true
			break
		}
	}
	if !found {
		a.state.BlockerDenylist = append(a.state.BlockerDenylist, d)
	}
	var newAllow []string
	for _, x := range a.state.BlockerAllowlist {
		if x != d {
			newAllow = append(newAllow, x)
		}
	}
	a.state.BlockerAllowlist = newAllow
	a.saveState()
	a.clearDNSCache()
	a.toast(a.catalog().ToastAddedDenylist())
}

func (a *app) removeBlockerDenylist(domain string) {
	d := strings.Trim(strings.ToLower(strings.TrimSpace(domain)), ".")
	if d == "" {
		return
	}
	if a.blocker != nil {
		a.blocker.RemoveDenylist(d)
	}
	var newDeny []string
	for _, x := range a.state.BlockerDenylist {
		if x != d {
			newDeny = append(newDeny, x)
		}
	}
	a.state.BlockerDenylist = newDeny
	a.saveState()
	a.clearDNSCache()
	a.toast(a.catalog().ToastRemovedDenylist())
}

func (a *app) toggleBlockerEnabled() {
	a.state.BlockerEnabled = !a.state.BlockerEnabled
	if a.blocker != nil {
		a.blocker.SetEnabled(a.state.BlockerEnabled)
	}
	a.saveState()
	a.clearDNSCache()
	if a.state.BlockerEnabled {
		a.toast(a.catalog().ToastProtectionEnabled())
	} else {
		a.toast(a.catalog().ToastProtectionPaused())
	}
}

func (a *app) toggleBlockerBlockAds() {
	a.setBlockerBlockAds(!a.state.BlockerBlockAds)
	if a.state.BlockerBlockAds {
		a.toast(a.catalog().ToastAdsBlockEnabled())
	} else {
		a.toast(a.catalog().ToastAdsBlockDisabled())
	}
}

func (a *app) setBlockerBlockAds(enabled bool) {
	a.state.BlockerBlockAds = enabled
	for i := range a.state.RoutingRules {
		if isCategoryAdsBlockRule(a.state.RoutingRules[i]) {
			a.state.RoutingRules[i].Enabled = enabled
			break
		}
	}
	a.saveState()
	if a.win != nil {
		a.win.Invalidate()
	}
}

func (a *app) addBlockerSubscription(rawURL string) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return
	}
	for _, s := range a.state.BlockerSubscriptions {
		if s == rawURL {
			return
		}
	}
	a.state.BlockerSubscriptions = append(a.state.BlockerSubscriptions, rawURL)
	a.saveState()
	a.toast(a.catalog().ToastAddedSubscription())
}

func (a *app) removeBlockerSubscription(rawURL string) {
	rawURL = strings.TrimSpace(rawURL)
	var newSubs []string
	for _, s := range a.state.BlockerSubscriptions {
		if s != rawURL {
			newSubs = append(newSubs, s)
		}
	}
	a.state.BlockerSubscriptions = newSubs
	a.syncBlockerRules()
	a.saveState()
	a.toast(a.catalog().ToastRemovedSubscription())
}
