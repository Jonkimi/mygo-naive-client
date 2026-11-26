package app

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
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
	"naive-client/internal/warp"
	"naive-client/locales"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
)

// TabID identifies a page in the sidebar navigation.
type TabID int

const (
	TabNodes TabID = iota
	TabRouting
	TabInsights
	TabTailnet
	TabCloudflare
	TabLogs
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
	open             bool
	isNew            bool
	isFinal          bool
	returnToDrawer   bool
	ruleID           string
	name             string
	desc             string
	actionIndex      int // 0: Proxy, 1: Direct, 2: Block
	directWarp       bool
	targets          []routing.TargetRef
	targetQuery      string
	dispatchPolicy   string // "smart" or "order"
	strictIsolation  bool   // true = fail-closed (FallbackToPool=false)
	domainsInput     string
	fullDomainsInput string
	cidrsInput       string
	keywordsInput    string
	geosites         []string
	geoips           []string
	geositeQuery     string
	geoipQuery       string
	tab              int // 0: GeoData, 1: Domains/IPs
	scroll           ui.ScrollState
	errText          string
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
	gateway         *boxengine.Engine
	startingGateway *boxengine.Engine
	gatewayStarting bool
	lastGatewayErr  error
	lastGatewaySig  string
	gwSnap          gatewayConfigSnapshot
	stateRev        uint64
	persistedRev    uint64
	sysproxyMu     sync.Mutex    // serializes access to sysproxyOps and worker lifecycle
	sysproxyOps    []func()      // FIFO queue so slow networksetup calls stay ordered off the UI thread
	sysproxySignal chan struct{} // buffered(1) wakeup signal for the sysproxy worker
	sysproxyClosed bool
	sysproxy       *sysproxy.Sysproxy
	router          *routing.Router
	blocker         *blocker.Engine
	tailnetMgr      *tailnet.Manager
	tailnetUnsub    func()
	tailnetSyncMu   sync.Mutex
	tailnetSyncTimer *time.Timer
	tunDevice       *tunhelper.ReceivedDevice
	tunForceIPv6    bool
	mockTunDevice    func() (*tunhelper.ReceivedDevice, error)
	mockTunCreator   func(options tun.Options) (tun.Tun, error)
	mockNodeResolver func(host string) []net.IP
	resolvedNodeIPs  map[string][]net.IP
	resolvedNodeMu   sync.RWMutex
	dormantStartMu     sync.Mutex
	gatewayLifecycleMu sync.Mutex
	gatewayMu          sync.Mutex
	persistMu          sync.Mutex
	toastMu            sync.Mutex
	uiQueueMu          sync.Mutex
	uiQueue            []func()
	uiQueueEnabled     bool
	uiServices         ui.Services
	hasUIServices      bool

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
	probeURLHandle         ui.Handle
	warpProbeURLHandle     ui.Handle
	expandedLogs           map[string]bool
	telemetryUIMu          sync.Mutex
	lastTelemetryUI        time.Time
	telemetryPending       bool
	recoveryProbeMu        sync.Mutex
	lastRecoveryProbeAt    map[string]time.Time
	halfOpenProbing        map[string]bool
	cooldownTimers         map[string]*time.Timer

	activeTab              TabID
	activeLogDrawerID      string
	logDrawerLastID        string
	logDrawerSearch        string
	logDrawerLevel         string
	logDrawerPaused        bool
	logDrawerFrozenEntries []runner.LogEntry
	logDrawerScroll        ui.ScrollState
	logDrawerFollow        bool
	logDrawerLastMaxSeq    uint64
	activeRuleDrawerID     string
	activeNodeDrawerID string
	nodeDrawerLastID   string
	nodeDrawerHelpOpen bool
	nodeDrawerJSONOpen bool
	activeTagFilter    string
	searchQuery        string
	onlyRunningFilter  bool
	openNodeMenuID     string
	openBatchMenu      bool

	routingSearch           string
	openRoutingMoreMenu     bool
	showRoutingStrategyHelp bool

	insightsFilter           string
	insightsSearch           string
	insightsShowManageRules  bool
	insightsRulesScroll      ui.ScrollState
	blockerAllowlistInput    string
	blockerDenylistInput     string
	blockerSubscriptionInput string

	gatewayLogs        *runner.LogBuffer
	logsSubTab         int
	logsEngineLevel    string
	logsLevelFilter    string
	logsSourceFilter   string
	logsSearchQuery    string
	logsSelectedNodeID string
	logsPaused         bool
	logsFrozenLines    []string

	settingsSubTab         int
	settingsExpandNaiveAdv bool
	settingsExpandXrayAdv  bool
	dnsStrategyHelpOpen    bool
	dnsOptimisticHelpOpen  bool

	batchTesting bool
	batchStage   string
	batchCancel  context.CancelFunc
	batchRunID   uint64

	editor     editorForm
	importDlg  importDialogState
	deleteDlg  deleteDialogState
	ruleEditor ruleEditorForm

	// Cloudflare workbench state
	cloudflareSubTab       int
	cloudflareScroll       ui.ScrollState
	warpRegistering        bool
	warpBindingLicense     bool
	warpScanning           bool
	warpShowLicenseForm    bool
	warpShowAdvanced       bool
	warpScanResults        []warp.EndpointCandidateResult
	warpEndpointScanner    func(context.Context, warp.ScanOptions) ([]warp.EndpointCandidateResult, error)
	warpLicenseInput       string
	warpCleanEndpointInput string
	tunnelTokenInput       string
	tunnelTokenVisible     bool

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
	case "preset-cn-direct":
		return cat.PresetRuleCnDirect()
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
	case "preset-cn-direct":
		return cat.PresetRuleCnDirectDesc()
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
		if a.tray == nil && runtime.GOOS != "darwin" {
			mygo.App.Quit()
		}
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
		a.cancelAllCooldownWakeups()
		a.tailnetSyncMu.Lock()
		if a.tailnetSyncTimer != nil {
			a.tailnetSyncTimer.Stop()
			a.tailnetSyncTimer = nil
		}
		a.tailnetSyncMu.Unlock()
		if a.tailnetUnsub != nil {
			a.tailnetUnsub()
			a.tailnetUnsub = nil
		}
		if a.tailnetMgr != nil {
			a.tailnetMgr.Close()
		}
		var wg sync.WaitGroup
		if a.mgr != nil {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = a.mgr.StopAll()
			}()
		}
		a.stopGateway()
		wg.Wait()
		a.closeSysproxyWorker()
		a.destroyTray()
	})

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		select {
		case <-sigCh:
			a.quitting = true
			if a.batchCancel != nil {
				a.batchCancel()
			}
			var wg sync.WaitGroup
			if a.mgr != nil {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_ = a.mgr.StopAll()
				}()
			}
			a.stopGateway()
			wg.Wait()
			a.closeSysproxyWorker()
			mygo.App.Quit()
		case <-a.quitCh:
			return
		}
	}()

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
			if a.quitting {
				return
			}
			e.PreventDefault()
			if a.state.AppIcon == appIconDock && runtime.GOOS != "darwin" {
				mygo.App.Quit()
				return
			}
			a.win.Hide()
		})

		a.applyLanguagePolicy()
		a.installAppMenu()
		a.applyAppIconPolicy()
		go a.boot()
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
	a.gatewayLogs = runner.NewLogBuffer(1000, func() {
		if a.win != nil {
			a.win.Update(func() {
				if a.activeTab == TabLogs && a.logsSubTab == 0 && !a.logsPaused {
					a.win.Invalidate()
				}
			})
		}
	})
	if st.AutoProbeInterval > 0 {
		a.tracker.SetProbeInterval(time.Duration(st.AutoProbeInterval) * time.Minute)
	}
	a.refreshGeoDataStatus()
	a.refreshGatewaySnapshot()
	return a
}

func (a *app) initSubsystems() {
	if a.tracker != nil {
		if a.state.AutoProbeInterval > 0 {
			a.tracker.SetProbeInterval(time.Duration(a.state.AutoProbeInterval) * time.Minute)
		}
		a.tracker.SetActiveRecoveryProbe(!a.headless && a.state.AutoProbePeriodic)
		a.tracker.SetOnHealthChange(func(nodeID string, recovered bool) {
			if recovered {
				a.cancelCooldownWakeup(nodeID)
				if a.mgr != nil {
					var clearSpeedIf func(string) bool
					for _, svc := range a.snapshotServices() {
						if svc.ID == nodeID && (svc.EffectiveProtocol() == config.ProtoWARP || svc.EnableWARP) {
							clearSpeedIf = isWarpTunnelError
							break
						}
					}
					a.mgr.ClearRecoveredErrors(nodeID, clearSpeedIf)
				}
			} else {
				sc := a.tracker.GetScore(nodeID)
				if sc.CircuitState == telemetry.CircuitOpen && sc.CircuitCooldownRemaining > 0 {
					a.scheduleCooldownWakeup(nodeID, sc.CircuitCooldownRemaining)
				}
			}
			a.notifyTelemetryUI()
		})
	}
	binPath := a.resolveBinaryPath()
	cfgDir := filepath.Join(a.userDataDir(), "configs")
	a.mgr = runner.NewManager(binPath, cfgDir, func() {
		if gw := a.getGateway(); gw != nil {
			gw.UpdateNodes(a.snapshotServices(), a.mgr.AllocatedPorts(), a.mgr.RunningServiceIDs())
		}
		a.dispatchUI(func() {
			a.rebuildTrayMenu()
		})
	})
	a.mgr.SetLogLevel(a.state.LogLevel)
	a.mgr.SetDNSStrategy(a.effectiveProxyDNSStrategy())
	a.appendSystemLog("INFO", "Client initialized (gateway port :%d, traffic mode: %s, log level: %s)", a.state.GatewayPort, a.state.TrafficMode, normalizeLogLevel(a.state.LogLevel))
	a.mgr.PreStartChecker = func(svc config.Service) error {
		if svc.EffectiveEngine() == config.EngineSingBox {
			if a.getGateway() == nil {
				if a.isGatewayEnabled() {
					if err := a.startGatewayWithFallback(); err != nil {
						return fmt.Errorf("网关内核启动失败: %w", err)
					}
				} else {
					return errors.New("网关功能未开启，请先在设置中启用网关")
				}
			}
		} else if svc.EnableWARP && !a.isGatewayEnabled() {
			return errors.New("网关功能未开启，开启 WARP 链式代理需先在设置中启用网关")
		}
		return nil
	}
	a.mgr.ServiceDialer = func(ctx context.Context, svc config.Service, network, addr string) (net.Conn, error) {
		if err := a.ensureGatewaySynced(); err != nil {
			return nil, err
		}
		gw := a.getGateway()
		if gw == nil {
			return nil, errors.New("gateway engine is not running")
		}
		return gw.DialNode(ctx, svc.ID, network, addr)
	}
	if a.blocker != nil && a.blocker.Logger() != nil {
		// Durations/errors are annotated after the entry is created; redraw Insights so they show up.
		a.blocker.Logger().SetOnUpdate(func() {
			if a.win != nil {
				a.win.Update(func() {
					if a.activeTab == TabInsights {
						a.win.Invalidate()
					}
				})
			}
		})
	}
	a.mgr.OnLog = func(id string) {
		if a.win != nil {
			a.win.Update(func() {
				if (a.activeLogDrawerID == id && !a.logDrawerPaused) || a.expandedLogs[id] || (a.activeTab == TabLogs && a.logsSubTab == 1 && !a.logsPaused && (a.logsSelectedNodeID == id || a.logsSelectedNodeID == "")) {
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
	a.mgr.OnAutoProbeSuccess = func(id string, rtt time.Duration) {
		if a.tracker != nil {
			a.tracker.RecordAutoProbe(id, rtt)
		}
	}
	a.mgr.OnProbeFailure = func(id string, err error) {
		if a.tracker != nil {
			reason := ""
			if err != nil {
				reason = err.Error()
			}
			a.tracker.RecordProbeFailureReason(id, reason)
		}
	}
	a.mgr.OnServiceStarted = func(svc config.Service) {
		a.cancelCooldownWakeup(svc.ID)
		if a.tracker != nil {
			a.tracker.ResetNode(svc.ID)
		}
		if svc.EffectiveEngine() != config.EngineSingBox && a.isGatewayEnabled() && a.isGatewayActiveOrStarting() {
			go func() {
				_ = a.ensureGatewaySynced()
			}()
		}
		if a.headless || !a.state.AutoProbeOnStart {
			return
		}
		// Cold Start (Path A): Asynchronously probe the newly running service
		// so its real end-to-end HTTPS RTT breaks initial tie in QualityTracker immediately.
		go func() {
			if svc.EffectiveEngine() != config.EngineSingBox {
				st := a.mgr.StatusOf(svc.ID)
				if st.AllocatedPort > 0 {
					a.waitLocalPortReady(svc.ID, st.AllocatedPort, 2*time.Second)
				}
			} else {
				time.Sleep(200 * time.Millisecond)
			}
			if a.mgr != nil && a.mgr.StatusOf(svc.ID).State == runner.StateRunning {
				if svc.EnableWARP && a.isGatewayEnabled() {
					_ = a.ensureGatewaySynced()
				}
				probeCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				_, _ = a.mgr.ProbeServiceAutoCtx(probeCtx, svc, a.probeURLForService(svc))
				cancel()
			}
		}()
	}
	a.syncBinaryPathAndVersion()
	a.syncXrayBinaryPathAndVersion()
	if a.tailnetMgr != nil {
		a.tailnetSyncMu.Lock()
		if a.tailnetSyncTimer != nil {
			a.tailnetSyncTimer.Stop()
			a.tailnetSyncTimer = nil
		}
		a.tailnetSyncMu.Unlock()
		if a.tailnetUnsub != nil {
			a.tailnetUnsub()
		}
		var sigMu sync.Mutex
		firstEvent := true
		prevSig := ""
		a.tailnetUnsub = a.tailnetMgr.Subscribe(func(st tailnet.Status) {
			sig := tailnetHostStateSig(st)
			sigMu.Lock()
			if firstEvent {
				prevSig = sig
				firstEvent = false
				sigMu.Unlock()
				return
			}
			if sig == prevSig {
				sigMu.Unlock()
				return
			}
			prevSig = sig
			sigMu.Unlock()

			// Only auto-sync gateway when cooperating with host tailscaled (never on embedded
			// status notifications, which originate inside the running sing-box engine).
			if st.ActiveMode != tailnet.ModeHost || st.BackendState != "Running" {
				return
			}
			if a.state.TailnetMode == string(tailnet.ModeOff) || a.state.TailnetMode == string(tailnet.ModeEmbedded) {
				return
			}
			a.scheduleTailnetGatewaySync()
		})
	}
}

func (a *app) syncBinaryPathAndVersion() {
	binPath := a.resolveBinaryPath()
	if a.mgr != nil {
		a.mgr.SetBinaryPath(binPath)
	}
	var detected string
	if a.state.InstalledNaiveTag != "" && strings.TrimSpace(a.state.CustomNaiveBinaryPath) == "" {
		a.localVersion = a.state.InstalledNaiveTag
	} else {
		detected = updater.DetectLocalVersion(binPath)
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
	var detected string
	if a.state.InstalledXrayTag != "" && strings.TrimSpace(a.state.CustomXrayBinaryPath) == "" {
		a.localXrayVersion = a.state.InstalledXrayTag
	} else {
		detected = updater.DetectLocalXrayVersion(binPath)
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
	if sp := a.sysproxy; sp != nil {
		a.runSysproxyOpSync(func() { _ = sp.RecoverIfDirty() })
	}
	if a.localVersion != "" {
		for _, svc := range a.state.Services {
			if svc.AutoStart && svc.EffectiveEngine() != config.EngineSingBox {
				_ = a.mgr.Start(svc)
			}
		}
	}
	if a.state.GatewayEnabled {
		if err := a.startGatewayWithFallback(); err != nil && a.tailnetMgr != nil {
			a.tailnetMgr.SetError(err.Error())
		}
	}
	for _, svc := range a.state.Services {
		if svc.AutoStart && !a.isServiceActive(svc.ID) {
			if svc.EffectiveEngine() == config.EngineSingBox || a.localVersion != "" {
				_ = a.mgr.Start(svc)
			}
		}
	}

	a.dispatchUI(nil)

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
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	var lastProbe time.Time
	for {
		select {
		case <-a.quitCh:
			return
		case <-ticker.C:
			if a.tracker != nil {
				a.tracker.SetActiveRecoveryProbe(!a.headless && a.state.AutoProbePeriodic)
			}
			if a.headless || !a.state.AutoProbePeriodic {
				continue
			}
			intervalMin := a.state.AutoProbeInterval
			if intervalMin <= 0 {
				intervalMin = 5
			}
			interval := time.Duration(intervalMin) * time.Minute
			if a.tracker != nil {
				a.tracker.SetProbeInterval(interval)
			}
			if lastProbe.IsZero() || time.Since(lastProbe) >= interval {
				lastProbe = time.Now()
				a.probeAllRunningServicesSilent()
				continue
			}
			a.probeDegradedServicesSilent()
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
	for _, svc := range a.snapshotServices() {
		if a.mgr.StatusOf(svc.ID).State == runner.StateRunning {
			running = append(running, svc)
		}
	}
	if len(running) == 0 {
		return
	}

	a.probeServicesListSilent(running)
}

var halfOpenProbeGap = 300 * time.Millisecond

const halfOpenProbeAttempts = 3

// probeDegradedServicesSilent runs expedited silent verification probes for nodes in Half-Open
// recovery, nodes with nascent probe/dial failures, or WARP nodes with tunnel errors.
func (a *app) probeDegradedServicesSilent() {
	if a.mgr == nil || a.tracker == nil {
		return
	}
	now := time.Now()
	var targets []config.Service
	var halfOpenTargets []config.Service

	a.recoveryProbeMu.Lock()
	if a.lastRecoveryProbeAt == nil {
		a.lastRecoveryProbeAt = make(map[string]time.Time)
	}
	if a.halfOpenProbing == nil {
		a.halfOpenProbing = make(map[string]bool)
	}
	for _, svc := range a.snapshotServices() {
		rt := a.mgr.StatusOf(svc.ID)
		if rt.State != runner.StateRunning || rt.Probing {
			continue
		}
		sc := a.tracker.GetScore(svc.ID)
		if sc.CircuitState == telemetry.CircuitHalfOpen {
			if !a.halfOpenProbing[svc.ID] {
				a.halfOpenProbing[svc.ID] = true
				a.lastRecoveryProbeAt[svc.ID] = now
				halfOpenTargets = append(halfOpenTargets, svc)
			}
			continue
		}
		if lastAt, ok := a.lastRecoveryProbeAt[svc.ID]; ok && now.Sub(lastAt) < 20*time.Second {
			continue
		}
		isWarpNode := svc.EffectiveProtocol() == config.ProtoWARP || svc.EnableWARP
		shouldProbe := false
		switch {
		case sc.CircuitState == telemetry.CircuitClosed && sc.ConsecutiveFailures > 0 && !sc.LastFailure.IsZero() && now.Sub(sc.LastFailure) >= 25*time.Second:
			shouldProbe = true
		case isWarpNode && isWarpTunnelError(rt.ProbeError):
			if lastAt, ok := a.lastRecoveryProbeAt[svc.ID]; !ok || now.Sub(lastAt) >= 60*time.Second {
				shouldProbe = true
			}
		}
		if shouldProbe {
			a.lastRecoveryProbeAt[svc.ID] = now
			targets = append(targets, svc)
		}
	}
	a.recoveryProbeMu.Unlock()

	if len(targets) > 0 {
		a.probeServicesListSilent(targets)
	}
	for _, svc := range halfOpenTargets {
		a.probeHalfOpenService(svc)
	}
}

func (a *app) probeHalfOpenService(svc config.Service) {
	go func() {
		defer func() {
			a.recoveryProbeMu.Lock()
			delete(a.halfOpenProbing, svc.ID)
			a.recoveryProbeMu.Unlock()
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		defer cancel()

		for i := 0; i < halfOpenProbeAttempts; i++ {
			select {
			case <-a.quitCh:
				return
			default:
			}
			if a.mgr == nil || a.tracker == nil {
				return
			}
			if a.mgr.StatusOf(svc.ID).State != runner.StateRunning {
				return
			}
			if a.tracker.GetScore(svc.ID).CircuitState != telemetry.CircuitHalfOpen {
				return
			}
			if _, err := a.mgr.ProbeServiceAutoCtx(ctx, svc, a.probeURLForService(svc)); err != nil {
				return
			}
			if a.tracker.GetScore(svc.ID).CircuitState != telemetry.CircuitHalfOpen {
				return
			}
			if i+1 < halfOpenProbeAttempts && halfOpenProbeGap > 0 {
				timer := time.NewTimer(halfOpenProbeGap)
				select {
				case <-a.quitCh:
					timer.Stop()
					return
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
			}
		}
	}()
}

func (a *app) probeServicesListSilent(targets []config.Service) {
	go func() {
		// Parent safety deadline exceeds ProbeServiceAutoCtx's internal 10s timeout so timeouts
		// are always reported as probe failures rather than parent context cancellations.
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		var wg sync.WaitGroup
		for _, svc := range targets {
			wg.Add(1)
			go func(s config.Service) {
				defer wg.Done()
				_, _ = a.mgr.ProbeServiceAutoCtx(ctx, s, a.probeURLForService(s))
			}(svc)
		}
		wg.Wait()
	}()
}

func (a *app) cancelCooldownWakeup(nodeID string) {
	a.recoveryProbeMu.Lock()
	if t, ok := a.cooldownTimers[nodeID]; ok && t != nil {
		t.Stop()
		delete(a.cooldownTimers, nodeID)
	}
	a.recoveryProbeMu.Unlock()
}

func (a *app) cancelAllCooldownWakeups() {
	a.recoveryProbeMu.Lock()
	for id, t := range a.cooldownTimers {
		if t != nil {
			t.Stop()
		}
		delete(a.cooldownTimers, id)
	}
	a.recoveryProbeMu.Unlock()
}

func (a *app) scheduleCooldownWakeup(nodeID string, delay time.Duration) {
	if delay <= 0 {
		return
	}
	a.recoveryProbeMu.Lock()
	if a.cooldownTimers == nil {
		a.cooldownTimers = make(map[string]*time.Timer)
	}
	if old, ok := a.cooldownTimers[nodeID]; ok && old != nil {
		old.Stop()
	}
	var timer *time.Timer
	timer = time.AfterFunc(delay+25*time.Millisecond, func() {
		a.recoveryProbeMu.Lock()
		if a.cooldownTimers[nodeID] == timer {
			delete(a.cooldownTimers, nodeID)
		}
		a.recoveryProbeMu.Unlock()

		select {
		case <-a.quitCh:
			return
		default:
		}
		if a.tracker != nil && a.tracker.ActiveRecoveryProbe() {
			a.probeDegradedServicesSilent()
		}
		a.notifyTelemetryUI()
	})
	a.cooldownTimers[nodeID] = timer
	a.recoveryProbeMu.Unlock()
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

func (a *app) setUIQueueEnabled(enabled bool) {
	a.uiQueueMu.Lock()
	a.uiQueueEnabled = enabled
	a.uiQueueMu.Unlock()
}

func (a *app) setUIServices(svc ui.Services) {
	a.uiQueueMu.Lock()
	if a.uiQueueEnabled {
		a.uiServices = svc
		a.hasUIServices = true
	}
	a.uiQueueMu.Unlock()
}

// drainUI executes queued headless UI callbacks on the caller's UI/test
// goroutine, preserving MyGo's single-threaded UI confinement in Tester mode.
func (a *app) drainUI() {
	for {
		a.uiQueueMu.Lock()
		if !a.uiQueueEnabled || len(a.uiQueue) == 0 {
			a.uiQueueMu.Unlock()
			return
		}
		pending := a.uiQueue
		a.uiQueue = nil
		a.uiQueueMu.Unlock()

		for _, fn := range pending {
			if fn != nil {
				fn()
			}
		}
	}
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
	a.uiQueueMu.Lock()
	queued := a.uiQueueEnabled
	var svc ui.Services
	hasSvc := false
	if queued {
		if fn != nil {
			a.uiQueue = append(a.uiQueue, fn)
		}
		if a.hasUIServices {
			svc = a.uiServices
			hasSvc = true
		}
	}
	a.uiQueueMu.Unlock()
	if queued {
		if hasSvc {
			svc.Invalidate()
		}
		return
	}
	if fn != nil {
		fn()
	}
}

func (a *app) toast(msg string) {
	a.toastMu.Lock()
	a.pendingToast = msg
	a.toastMu.Unlock()
}

func (a *app) consumePendingToast() string {
	a.toastMu.Lock()
	msg := a.pendingToast
	a.pendingToast = ""
	a.toastMu.Unlock()
	return msg
}

// Service Actions
func (a *app) isServiceActive(id string) bool {
	st := a.mgr.StatusOf(id).State
	return st == runner.StateRunning || st == runner.StateStarting
}

func (a *app) toggleService(svc config.Service) {
	if a.isServiceActive(svc.ID) {
		_ = a.mgr.Stop(svc.ID)
		if svc.IsBuiltinWarp() {
			// Rules other than the Direct ➔ WARP preset may still depend on the node.
			// Then only stop it and leave the user's rules alone; otherwise turn the
			// feature off, which makes saveState drop the node.
			if n := a.otherWarpRuleCount(); n > 0 {
				a.toast(a.catalog().CloudflareDirectWarpStoppedStillUsedToast(n))
			} else {
				a.setCnDirectWarpEnabled(false)
				a.toast(a.catalog().CloudflareDirectWarpDisabledToast())
			}
			a.rebuildTrayMenu()
			return
		}
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

func (a *app) restartService(svc config.Service) {
	cat := a.catalog()
	if err := a.mgr.Start(svc); err != nil {
		a.toast(cat.ToastServiceRestartFailed(svc.Name, err.Error()))
		return
	}
	a.toast(cat.ToastServiceRestarted(svc.Name))
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

func (a *app) probeURLForService(svc config.Service) string {
	if svc.EffectiveProtocol() == config.ProtoWARP {
		if strings.TrimSpace(a.state.Cloudflare.ProbeURL) != "" {
			return strings.TrimSpace(a.state.Cloudflare.ProbeURL)
		}
		return defaultWarpProbeURL
	}
	if strings.TrimSpace(a.state.ProbeURL) != "" {
		return a.state.ProbeURL
	}
	return defaultProbeURL
}

func isWarpTunnelError(errText string) bool {
	if errText == "" {
		return false
	}
	lower := strings.ToLower(errText)
	return strings.Contains(lower, "warp server") ||
		strings.Contains(lower, "not registered") ||
		strings.Contains(lower, "凭证未注册") ||
		strings.Contains(lower, "detour outbound") ||
		strings.Contains(lower, "masque") ||
		strings.Contains(lower, "wireguard")
}

func (a *app) nodeLatencyMs(serviceID string, rt runner.Status) (ms, ewmaMs, probeMs int) {
	if a.tracker != nil && rt.State == runner.StateRunning {
		if sc := a.tracker.GetScore(serviceID); sc.EWMA > 0 {
			ewmaMs = int(max(1, sc.EWMA.Milliseconds()))
		}
	}
	if rt.Latency > 0 {
		probeMs = int(max(1, rt.Latency.Milliseconds()))
	}
	ms = ewmaMs
	if ms <= 0 {
		ms = probeMs
	}
	return ms, ewmaMs, probeMs
}

func (a *app) isNodeUnhealthy(svc config.Service, rt runner.Status) bool {
	if rt.State != runner.StateRunning {
		return false
	}
	if rt.LastError != "" {
		return true
	}
	isWarpNode := svc.EffectiveProtocol() == config.ProtoWARP || svc.EnableWARP
	if isWarpNode && (isWarpTunnelError(rt.ProbeError) || isWarpTunnelError(rt.SpeedError)) {
		return true
	}
	if a.tracker != nil {
		sc := a.tracker.GetScore(svc.ID)
		if sc.IsBroken || sc.CircuitState != telemetry.CircuitClosed {
			return true
		}
	}
	return false
}

func (a *app) diagnoseNodeUnhealthy(svc config.Service, rt runner.Status) (hint string, isWarp bool, isUnregistered bool) {
	cat := a.catalog()
	isWarpNode := svc.EffectiveProtocol() == config.ProtoWARP || svc.EnableWARP

	if isWarpNode {
		combinedErr := strings.ToLower(rt.ProbeError + rt.SpeedError)
		if !a.getCloudflareAccount().IsRegistered() ||
			strings.Contains(combinedErr, "not registered") ||
			strings.Contains(combinedErr, "凭证未注册") {
			return cat.WarpUnhealthyUnregisteredHint(), true, true
		}

		endpoint := "auto"
		if gw := a.getGateway(); gw != nil {
			if ob, ok := gw.GetOutbound(svc.ID); ok {
				type activeEndpointProvider interface {
					ActiveEndpoint() string
				}
				if p, ok := common.Cast[activeEndpointProvider](ob); ok {
					if ep := strings.TrimSpace(p.ActiveEndpoint()); ep != "" {
						endpoint = ep
					}
				}
			}
		}
		if endpoint == "auto" {
			if ep := extractWarpServerEndpoint(rt.ProbeError + " " + rt.SpeedError); ep != "" {
				endpoint = ep
			}
		}
		if endpoint == "auto" {
			if svc.WARPConfig != nil && strings.TrimSpace(svc.WARPConfig.Endpoint) != "" {
				endpoint = strings.TrimSpace(svc.WARPConfig.Endpoint)
			} else if svc.EffectiveProtocol() == config.ProtoWARP && a.state.Cloudflare.CleanIP != "" {
				host, port := a.state.Cloudflare.ResolveEndpoint(warp.ModeAuto)
				endpoint = net.JoinHostPort(host, strconv.Itoa(port))
			}
		}

		if svc.EffectiveProtocol() == config.ProtoWARP {
			return cat.WarpUnhealthyDirectHint(endpoint), true, false
		}
		return cat.WarpUnhealthyDetourHint(endpoint), true, false
	}

	if rt.ProbeError != "" {
		return rt.ProbeError, false, false
	}
	if a.tracker != nil {
		sc := a.tracker.GetScore(svc.ID)
		label := circuitLabelForScore(cat, sc)
		if sc.LastFailureReason != "" {
			return label + " · " + sc.LastFailureReason, false, false
		}
		return label, false, false
	}
	return cat.NodeDrawerCircuitTripped(), false, false
}

func circuitLabelForScore(cat locales.Messages, sc telemetry.QualityScore) string {
	if sc.CircuitState == telemetry.CircuitHalfOpen {
		return cat.NodeDrawerCircuitHalfOpen()
	}
	if sc.CircuitCooldownRemaining > 0 {
		secs := max(1, int(math.Ceil(sc.CircuitCooldownRemaining.Seconds())))
		return cat.NodeDrawerCircuitTrippedCooldown(secs)
	}
	return cat.NodeDrawerCircuitTripped()
}

func extractWarpServerEndpoint(errText string) string {
	const prefix = "warp server ("
	idx := strings.Index(strings.ToLower(errText), prefix)
	if idx < 0 {
		return ""
	}
	rest := errText[idx+len(prefix):]
	end := strings.IndexByte(rest, ')')
	if end <= 0 {
		return ""
	}
	ep := strings.TrimSpace(rest[:end])
	if ep == "" || ep == "auto" {
		return ""
	}
	return ep
}

func (a *app) triggerServiceProbe(svc config.Service) {
	if a.mgr.StatusOf(svc.ID).State != runner.StateRunning {
		a.toast(a.catalog().TestRequiresRunning())
		return
	}
	a.mgr.ProbeService(svc, a.probeURLForService(svc))
}

func (a *app) triggerServiceDownloadTest(svc config.Service) {
	if a.mgr.StatusOf(svc.ID).State != runner.StateRunning {
		a.toast(a.catalog().TestRequiresRunning())
		return
	}
	a.mgr.DownloadTestService(svc, a.state.DownloadTestURL)
}

func (a *app) cancelServiceDownloadTest(svc config.Service) {
	a.mgr.CancelDownloadTest(svc.ID)
}

func (a *app) triggerBatchTest() {
	if a.batchTesting {
		a.batchRunID++
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

	a.batchRunID++
	runID := a.batchRunID
	ctx, cancel := context.WithCancel(context.Background())
	a.batchCancel = cancel
	a.batchTesting = true
	a.batchStage = "测延迟中..."

	downloadURL := a.state.DownloadTestURL
	probeURLs := make(map[string]string, len(targets))
	for _, svc := range targets {
		probeURLs[svc.ID] = a.probeURLForService(svc)
	}

	go func() {
		defer func() {
			a.dispatchUI(func() {
				if a.batchRunID != runID {
					return
				}
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
			probeURL := probeURLs[svc.ID]
			go func(s config.Service, url string) {
				defer wg.Done()
				_, _ = a.mgr.ProbeServiceCtx(ctx, s, url)
			}(svc, probeURL)
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
				if a.batchRunID != runID {
					return
				}
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
			if a.batchRunID != runID {
				return
			}
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
		if gw := a.getGateway(); gw != nil && a.state.GatewayEnabled && gw.Port() > 0 {
			ep := config.ListenEndpoint{
				Proto: "http",
				Addr:  "127.0.0.1",
				Port:  gw.Port(),
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
			var detected string
			if a.state.InstalledNaiveTag != "" && strings.TrimSpace(a.state.CustomNaiveBinaryPath) == "" {
				a.localVersion = a.state.InstalledNaiveTag
			} else {
				detected = updater.DetectLocalVersion(binPath)
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
			var detected string
			if a.state.InstalledXrayTag != "" && strings.TrimSpace(a.state.CustomXrayBinaryPath) == "" {
				a.localXrayVersion = a.state.InstalledXrayTag
			} else {
				detected = updater.DetectLocalXrayVersion(binPath)
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

func mergeRegisteredWarpAccount(cur, base, enrolled warp.Account) warp.Account {
	out := cur.Clone()
	if enrolled.DeviceID != "" {
		out.DeviceID = enrolled.DeviceID
		out.AccessToken = enrolled.AccessToken
		out.AccountID = enrolled.AccountID
		out.AccountType = enrolled.AccountType
		out.LicenseKey = enrolled.LicenseKey
		out.WGPrivateKey = enrolled.WGPrivateKey
		out.WGPublicKey = enrolled.WGPublicKey
		out.WGPeerPublicKey = enrolled.WGPeerPublicKey
		out.ClientID = enrolled.ClientID
		out.Reserved = append([]uint8(nil), enrolled.Reserved...)
		out.IPv4 = enrolled.IPv4
		out.IPv6 = enrolled.IPv6
	}
	if enrolled.MASQUEDeviceID != "" || enrolled.MASQUEPrivateKey != "" {
		if cur.MASQUEPrivateKey == "" || cur.MASQUEPrivateKey == base.MASQUEPrivateKey {
			out.MASQUEDeviceID = enrolled.MASQUEDeviceID
			out.MASQUEToken = enrolled.MASQUEToken
			out.MASQUEPrivateKey = enrolled.MASQUEPrivateKey
			out.MASQUEPublicKey = enrolled.MASQUEPublicKey
			out.MASQUECertPEM = enrolled.MASQUECertPEM
			out.MASQUEIPv4 = enrolled.MASQUEIPv4
			out.MASQUEIPv6 = enrolled.MASQUEIPv6
			out.MASQUEEnrolled = enrolled.MASQUEEnrolled
		}
	}
	return out
}

// Cloudflare WARP registration and license actions
func (a *app) triggerWarpRegister() {
	if a.warpRegistering {
		return
	}
	a.warpRegistering = true
	if a.win != nil {
		a.win.Invalidate()
	}
	accSnap := a.getCloudflareAccount()
	licenseSnap := a.warpLicenseInput
	go func() {
		defer func() {
			a.dispatchUI(func() {
				a.warpRegistering = false
				if a.win != nil {
					a.win.Invalidate()
				}
			})
		}()
		cli := warp.NewClient(nil)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		acc, err := cli.ProvisionAll(ctx, accSnap, licenseSnap)
		a.dispatchUI(func() {
			cat := a.catalog()
			if err != nil {
				a.toast(cat.CloudflareWarpToastRegFailed(err.Error()))
				return
			}
			a.gatewayMu.Lock()
			merged := mergeRegisteredWarpAccount(a.state.Cloudflare.Account, accSnap, acc)
			a.state.Cloudflare.Account = merged
			a.gwSnap.Cloudflare.Account = merged.Clone()
			a.gatewayMu.Unlock()
			a.saveState()
			a.toast(cat.CloudflareWarpToastRegSuccess(merged.IPv4))
			for _, svc := range a.snapshotServices() {
				if (svc.EffectiveProtocol() == config.ProtoWARP || svc.EnableWARP) && a.mgr != nil && a.mgr.StatusOf(svc.ID).State == runner.StateRunning {
					a.mgr.ProbeService(svc, a.probeURLForService(svc))
				}
			}
		})
	}()
}

func (a *app) triggerWarpBindLicense() {
	key := strings.TrimSpace(a.warpLicenseInput)
	if key == "" {
		a.toast(a.catalog().CloudflareWarpToastLicenseEmpty())
		return
	}
	if a.warpBindingLicense {
		return
	}
	a.warpBindingLicense = true
	if a.win != nil {
		a.win.Invalidate()
	}
	accSnap := a.getCloudflareAccount()
	go func() {
		defer func() {
			a.dispatchUI(func() {
				a.warpBindingLicense = false
				if a.win != nil {
					a.win.Invalidate()
				}
			})
		}()
		cli := warp.NewClient(nil)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		err := cli.BindLicense(ctx, &accSnap, key)
		a.dispatchUI(func() {
			cat := a.catalog()
			if err != nil {
				a.toast(cat.CloudflareWarpToastLicenseFailed(err.Error()))
				return
			}
			a.gatewayMu.Lock()
			merged := a.state.Cloudflare.Account.Clone()
			merged.LicenseKey = key
			if accSnap.AccountType != "" {
				merged.AccountType = accSnap.AccountType
			}
			if accSnap.AccountID != "" {
				merged.AccountID = accSnap.AccountID
			}
			a.state.Cloudflare.Account = merged
			a.gwSnap.Cloudflare.Account = merged.Clone()
			a.gatewayMu.Unlock()
			a.warpShowLicenseForm = false
			a.saveState()
			a.toast(cat.CloudflareWarpToastLicenseSuccess(merged.AccountType))
		})
	}()
}

func (a *app) resetWarpNodesHealth(reprobe bool) {
	for _, svc := range a.snapshotServices() {
		if svc.EffectiveProtocol() != config.ProtoWARP && !svc.EnableWARP {
			continue
		}
		a.cancelCooldownWakeup(svc.ID)
		if a.tracker != nil {
			a.tracker.ResetNode(svc.ID)
		}
		if a.mgr != nil {
			a.mgr.ClearErrors(svc.ID)
			if reprobe && !a.headless && a.mgr.StatusOf(svc.ID).State == runner.StateRunning {
				a.mgr.ProbeService(svc, a.probeURLForService(svc))
			}
		}
	}
}

func (a *app) applyWarpCleanEndpoint(raw string) {
	raw = strings.TrimSpace(raw)
	a.warpCleanEndpointInput = raw
	if raw == "" {
		a.state.Cloudflare.CleanIP = ""
		a.state.Cloudflare.CleanPort = 0
	} else if h, pStr, err := net.SplitHostPort(raw); err == nil {
		a.state.Cloudflare.CleanIP = strings.Trim(h, "[]")
		if p, err := strconv.Atoi(pStr); err == nil && p > 0 {
			a.state.Cloudflare.CleanPort = p
		} else {
			a.state.Cloudflare.CleanPort = 0
		}
	} else {
		a.state.Cloudflare.CleanIP = strings.Trim(raw, "[]")
		a.state.Cloudflare.CleanPort = 0
	}
	a.saveState()
	a.resetWarpNodesHealth(false)
	if a.win != nil {
		a.win.Invalidate()
	}
}

func (a *app) triggerWarpEndpointScan() {
	if a.warpScanning {
		return
	}
	a.warpScanning = true
	if a.win != nil {
		a.win.Invalidate()
	}
	mode := a.state.Cloudflare.EffectiveDirectMode()
	preferH2 := a.state.Cloudflare.MasquePreferH2
	acc := a.getCloudflareAccount()
	scanner := a.warpEndpointScanner
	if scanner == nil {
		scanner = warp.ScanBestEndpoints
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		results, err := scanner(ctx, warp.ScanOptions{
			Mode:           mode,
			PreferH2:       preferH2,
			TLSFragment:    true,
			UTLS:           true,
			Account:        &acc,
			Dialer:         warp.NewBypassTUNDialer(),
			TopN:           8,
			SampleCount:    64,
			Concurrency:    24,
			ProbeRounds:    3,
			PerProbeTimout: 2500 * time.Millisecond,
		})
		a.dispatchUI(func() {
			a.warpScanning = false
			cat := a.catalog()
			if err != nil {
				a.toast(cat.CloudflareWarpScanFailed(err.Error()))
				if a.win != nil {
					a.win.Invalidate()
				}
				return
			}
			a.warpScanResults = results
			if len(results) == 0 {
				a.toast(cat.CloudflareWarpScanEmpty())
				if a.win != nil {
					a.win.Invalidate()
				}
				return
			}
			best := results[0]
			a.applyWarpCleanEndpoint(best.Endpoint)
			lossPct := int(best.LossRate*100 + 0.5)
			a.toast(cat.CloudflareWarpScanSuccess(best.Endpoint, int(best.RTT.Milliseconds()), lossPct))
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

func cloneService(s config.Service) config.Service {
	cp := s
	cp.Tags = append([]string(nil), s.Tags...)
	cp.ALPN = append([]string(nil), s.ALPN...)
	cp.Listens = append([]string(nil), s.Listens...)
	cp.Proxies = append([]string(nil), s.Proxies...)
	if s.WARPConfig != nil {
		wc := *s.WARPConfig
		wc.Reserved = append([]uint8(nil), s.WARPConfig.Reserved...)
		if s.WARPConfig.MasquePreferH2 != nil {
			b := *s.WARPConfig.MasquePreferH2
			wc.MasquePreferH2 = &b
		}
		cp.WARPConfig = &wc
	}
	return cp
}

func (a *app) cloneServiceNode(svc config.Service) {
	cat := a.catalog()
	cp := cloneService(svc)
	cp.ID = a.generateServiceID()

	existingNames := make(map[string]bool, len(a.state.Services))
	usedPorts := make(map[int]bool)
	for _, s := range a.state.Services {
		existingNames[s.Name] = true
		for _, l := range s.Listens {
			if ep, err := config.ParseListenURI(l); err == nil && ep.Port > 0 {
				usedPorts[ep.Port] = true
			}
		}
	}

	baseName := cat.ClonedNodeName(svc.Name)
	name := baseName
	for n := 2; existingNames[name]; n++ {
		name = fmt.Sprintf("%s %d", baseName, n)
	}
	cp.Name = name

	if cp.EffectiveEngine() == config.EngineSidecar {
		for i, l := range cp.Listens {
			ep, err := config.ParseListenURI(l)
			if err != nil || ep.Port <= 0 {
				continue
			}
			newPort := 1080
			for port := 1080; port < 20000; port++ {
				if !usedPorts[port] {
					newPort = port
					usedPorts[port] = true
					break
				}
			}
			host := ep.Addr
			if host == "" {
				host = "127.0.0.1"
			}
			auth := ""
			if ep.User != "" {
				if ep.Pass != "" {
					auth = ep.User + ":" + ep.Pass + "@"
				} else {
					auth = ep.User + "@"
				}
			}
			cp.Listens[i] = fmt.Sprintf("%s://%s%s", ep.Proto, auth, net.JoinHostPort(host, strconv.Itoa(newPort)))
		}
	}

	a.state.Services = append(a.state.Services, cp)
	a.saveState()
	a.rebuildTrayMenu()
	a.toast(cat.ToastNodeCloned(cp.Name))
}

func cloneServices(svcs []config.Service) []config.Service {
	if svcs == nil {
		return nil
	}
	out := make([]config.Service, len(svcs))
	for i, s := range svcs {
		out[i] = cloneService(s)
	}
	return out
}

func cloneRouteAction(act routing.RouteAction) routing.RouteAction {
	cp := act
	cp.Tags = append([]string(nil), act.Tags...)
	cp.Targets = append([]routing.TargetRef(nil), act.Targets...)
	return cp
}

func cloneRoutingRules(rules []routing.Rule) []routing.Rule {
	if rules == nil {
		return nil
	}
	out := make([]routing.Rule, len(rules))
	for i, r := range rules {
		out[i] = r
		out[i].DomainSuffix = append([]string(nil), r.DomainSuffix...)
		out[i].DomainKeyword = append([]string(nil), r.DomainKeyword...)
		out[i].DomainFull = append([]string(nil), r.DomainFull...)
		out[i].IPCidr = append([]string(nil), r.IPCidr...)
		out[i].GeoSite = append([]string(nil), r.GeoSite...)
		out[i].GeoIP = append([]string(nil), r.GeoIP...)
		out[i].Action = cloneRouteAction(r.Action)
	}
	return out
}

type gatewayConfigSnapshot struct {
	Initialized       bool
	GatewayEnabled    bool
	GatewayPort       int
	TrafficMode       string
	Services          []config.Service
	Rules             []routing.Rule
	Final             routing.RouteAction
	GeoSiteDB         *geodata.GeoSiteDB
	GeoIPDB           *geodata.GeoIPDB
	GeoTag            string
	BootstrapDomains  []string
	BootstrapDNS      string
	DomesticDNS        string
	RemoteDNS          string
	PreferIPv4         bool
	DNSStrategy        string
	DirectDNSStrategy  string
	ProxyDNSStrategy   string
	DNSOptimisticCache bool
	LogLevel           string
	TailnetEnabled    bool
	TailnetMode       string
	TailnetStateSig   string
	Cloudflare        warp.Config
	SystemProxyBypass []string
}

func cloneGatewayConfigSnapshot(snap gatewayConfigSnapshot) gatewayConfigSnapshot {
	cp := snap
	cp.Services = cloneServices(snap.Services)
	cp.Rules = cloneRoutingRules(snap.Rules)
	cp.Final = cloneRouteAction(snap.Final)
	cp.BootstrapDomains = append([]string(nil), snap.BootstrapDomains...)
	cp.Cloudflare.Account = snap.Cloudflare.Account.Clone()
	cp.SystemProxyBypass = append([]string(nil), snap.SystemProxyBypass...)
	return cp
}

func (a *app) buildGatewaySnapshotFromUI() gatewayConfigSnapshot {
	a.gatewayMu.Lock()
	cf := a.state.Cloudflare
	cf.Account = a.state.Cloudflare.Account.Clone()
	a.gatewayMu.Unlock()
	return gatewayConfigSnapshot{
		Initialized:       true,
		GatewayEnabled:    a.state.GatewayEnabled,
		GatewayPort:       a.state.GatewayPort,
		TrafficMode:       a.state.TrafficMode,
		Services:          cloneServices(a.state.Services),
		Rules:             cloneRoutingRules(a.state.RoutingRules),
		Final:             cloneRouteAction(a.state.RoutingFinal),
		GeoSiteDB:         a.cachedSiteDB,
		GeoIPDB:           a.cachedIPDB,
		GeoTag:            a.localGeodataVersion,
		BootstrapDomains:  a.collectBootstrapDomains(),
		BootstrapDNS:      a.state.BootstrapDNS,
		DomesticDNS:        a.effectiveDomesticDNS(),
		RemoteDNS:          a.effectiveRemoteDNS(),
		PreferIPv4:         a.state.PreferIPv4,
		DNSStrategy:        normalizeDNSStrategy(a.state.DNSStrategy, a.state.PreferIPv4),
		DirectDNSStrategy:  normalizeOptionalDNSStrategy(a.state.DirectDNSStrategy),
		ProxyDNSStrategy:   normalizeOptionalDNSStrategy(a.state.ProxyDNSStrategy),
		DNSOptimisticCache: a.state.DNSOptimisticCache,
		LogLevel:           a.state.LogLevel,
		TailnetEnabled:    a.state.TailnetEnabled,
		TailnetMode:       a.state.TailnetMode,
		TailnetStateSig:   a.currentTailnetStateSig(),
		Cloudflare:        cf,
		SystemProxyBypass: append([]string(nil), a.state.SystemProxyBypass...),
	}
}

func (a *app) refreshGatewaySnapshot() {
	snap := a.buildGatewaySnapshotFromUI()
	a.gatewayMu.Lock()
	a.gwSnap = snap
	a.gatewayMu.Unlock()
}

func (a *app) refreshServicesSnapshot() {
	services := cloneServices(a.state.Services)
	a.gatewayMu.Lock()
	if !a.gwSnap.Initialized {
		a.gatewayMu.Unlock()
		a.refreshGatewaySnapshot()
		return
	}
	a.gwSnap.Services = services
	a.gatewayMu.Unlock()
}

func (a *app) snapshotServices() []config.Service {
	a.gatewayMu.Lock()
	svcs := cloneServices(a.gwSnap.Services)
	initialized := a.gwSnap.Initialized
	a.gatewayMu.Unlock()
	if !initialized {
		return cloneServices(a.state.Services)
	}
	return svcs
}

func (a *app) getGatewaySnapshot() gatewayConfigSnapshot {
	a.gatewayMu.Lock()
	defer a.gatewayMu.Unlock()
	return cloneGatewayConfigSnapshot(a.gwSnap)
}

func (a *app) isGatewayEnabled() bool {
	a.gatewayMu.Lock()
	if a.gwSnap.Initialized {
		enabled := a.gwSnap.GatewayEnabled
		a.gatewayMu.Unlock()
		return enabled
	}
	a.gatewayMu.Unlock()
	return a.state.GatewayEnabled
}

func (a *app) getCloudflareAccount() warp.Account {
	a.gatewayMu.Lock()
	acc := a.state.Cloudflare.Account.Clone()
	a.gatewayMu.Unlock()
	return acc
}

func (a *app) startDormantServiceForTag(eng *boxengine.Engine, tag string) {
	a.dormantStartMu.Lock()
	defer a.dormantStartMu.Unlock()

	tag = strings.TrimSpace(strings.TrimPrefix(tag, "PROXY_TAG:"))
	var wantTags []string
	for _, part := range strings.Split(tag, ",") {
		if p := strings.TrimSpace(part); p != "" {
			wantTags = append(wantTags, p)
		}
	}

	matchesService := func(svc config.Service) bool {
		if strings.HasPrefix(tag, "node:") {
			targetID := strings.TrimSpace(strings.TrimPrefix(tag, "node:"))
			return targetID != "" && svc.ID == targetID
		}
		if tag == "" || tag == "PROXY_POOL" || len(wantTags) == 0 {
			return !svc.IsBuiltinWarp()
		}
		for _, t := range svc.Tags {
			for _, wt := range wantTags {
				if strings.EqualFold(t, wt) {
					return true
				}
			}
		}
		return false
	}

	services := a.snapshotServices()

	// If a matching service is already running or starting, wait briefly for it to reach StateRunning
	// rather than spawning another service or restarting the same service.
	for _, svc := range services {
		if matchesService(svc) && a.isServiceActive(svc.ID) {
			for i := 0; i < 20; i++ {
				st := a.mgr.StatusOf(svc.ID)
				if st.State == runner.StateRunning {
					if eng != nil {
						eng.UpdateNodes(services, a.mgr.AllocatedPorts(), a.mgr.RunningServiceIDs())
					}
					return
				}
				time.Sleep(20 * time.Millisecond)
			}
			return
		}
	}

	for _, svc := range services {
		if matchesService(svc) && !a.isServiceActive(svc.ID) {
			_ = a.mgr.Start(svc)
			for i := 0; i < 20; i++ {
				st := a.mgr.StatusOf(svc.ID)
				if st.State == runner.StateRunning {
					if eng != nil {
						eng.UpdateNodes(services, a.mgr.AllocatedPorts(), a.mgr.RunningServiceIDs())
					}
					return
				}
				time.Sleep(20 * time.Millisecond)
			}
			return
		}
	}
}

func (a *app) requestTunDevice(forceIPv6Route bool) (*tunhelper.ReceivedDevice, error) {
	if a.mockTunDevice != nil {
		return a.mockTunDevice()
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve current executable: %w", err)
	}
	if realPath, err := filepath.EvalSymlinks(exe); err == nil {
		exe = realPath
	}
	client := tunhelper.NewClient()
	client.ForceIPv6Route = forceIPv6Route
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	excludeIPs := a.collectNodeServerIPs()
	return client.RequestDevice(ctx, exe, excludeIPs...)
}

func (a *app) collectNodeServerIPs() []string {
	var ips []string
	seen := make(map[string]bool)
	var mu sync.Mutex

	var pendingDomains []string
	seenDomains := make(map[string]bool)

	addHost := func(host string) {
		host = strings.TrimSpace(host)
		host = strings.TrimPrefix(host, "[")
		host = strings.TrimSuffix(host, "]")
		if host == "" {
			return
		}
		if ip := net.ParseIP(host); ip != nil {
			s := ip.String()
			mu.Lock()
			if !seen[s] {
				seen[s] = true
				ips = append(ips, s)
			}
			mu.Unlock()
			return
		}
		lower := strings.ToLower(host)
		if !seenDomains[lower] {
			seenDomains[lower] = true
			pendingDomains = append(pendingDomains, host)
		}
	}

	for _, svc := range a.state.Services {
		if svc.Server != "" {
			addHost(svc.Server)
		}
		for _, proxyURI := range svc.Proxies {
			if u, err := url.Parse(proxyURI); err == nil && u.Hostname() != "" {
				addHost(u.Hostname())
			}
		}
		if svc.ExternalURI != "" {
			if u, err := url.Parse(svc.ExternalURI); err == nil && u.Hostname() != "" {
				addHost(u.Hostname())
			}
		}
	}
	// Exclude bootstrap DNS & domestic DoH IPs from TUN routing to prevent routing deadlocks
	for _, b := range parseDNSList(a.state.BootstrapDNS, effectiveDefaultDNSList(boxengine.DefaultBootstrapDNS, boxengine.DefaultBootstrapDNSV6)) {
		if host, _, err := net.SplitHostPort(b); err == nil {
			b = host
		}
		addHost(b)
	}
	for _, d := range parseDNSList(a.effectiveDomesticDNS(), effectiveDefaultDNSList(boxengine.DefaultDomesticDoH, boxengine.DefaultDomesticDoHV6)) {
		if u, err := url.Parse(d); err == nil && u.Hostname() != "" {
			addHost(u.Hostname())
		} else {
			if host, _, err := net.SplitHostPort(d); err == nil {
				d = host
			}
			addHost(d)
		}
	}
	// Exclude Cloudflare WARP Anycast subnets from TUN routing to prevent routing loops for local WARP and scans
	for _, warpCIDR := range warp.AnycastBypassCIDRs() {
		if !seen[warpCIDR] {
			seen[warpCIDR] = true
			ips = append(ips, warpCIDR)
		}
	}
	if a.state.Cloudflare.CleanIP != "" {
		addHost(a.state.Cloudflare.CleanIP)
	}
	for _, svc := range a.state.Services {
		if svc.WARPConfig != nil && svc.WARPConfig.Endpoint != "" {
			addHost(svc.WARPConfig.Endpoint)
		}
	}

	if len(pendingDomains) > 0 {
		resolvedMap := make(map[string][]net.IP, len(pendingDomains))
		var wg sync.WaitGroup
		sem := make(chan struct{}, 8) // Limit concurrent lookups
		for _, host := range pendingDomains {
			wg.Add(1)
			go func(targetHost string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				resolved := a.resolveNodeHostIPs(targetHost)

				mu.Lock()
				resolvedMap[strings.ToLower(strings.TrimSpace(targetHost))] = resolved
				for _, ip := range resolved {
					if tailnet.IsTailnetIP(ip) {
						continue
					}
					s := ip.String()
					if !seen[s] {
						seen[s] = true
						ips = append(ips, s)
					}
				}
				mu.Unlock()
			}(host)
		}
		wg.Wait()
		if a != nil {
			a.resolvedNodeMu.Lock()
			if a.resolvedNodeIPs == nil {
				a.resolvedNodeIPs = make(map[string][]net.IP)
			}
			for k, v := range resolvedMap {
				if len(v) > 0 {
					a.resolvedNodeIPs[k] = v
				}
			}
			a.resolvedNodeMu.Unlock()
		}
	}

	return ips
}

func (a *app) resolveNodeHostIPs(host string) []net.IP {
	if a != nil && a.mockNodeResolver != nil {
		return a.mockNodeResolver(host)
	}
	if a != nil && a.tailnetMgr != nil {
		st := a.tailnetMgr.Status()
		records := a.tailnetMgr.GetHostRecords()
		norm := tailnet.NormalizeHost(host)
		if ips := lookupHostRecordNetIPs(records, norm, st.MagicDNSSuffix); len(ips) > 0 {
			return ips
		}
		// Never leak Tailscale hostnames to public DNS (223.5.5.5); resolve via MagicDNS 100.100.100.100.
		if a.state.TailnetMode != string(tailnet.ModeOff) && tailnet.IsTailnetHostname(tailnet.ModeHost, norm, st.MagicDNSSuffix) {
			if a.state.TailnetMode == string(tailnet.ModeEmbedded) {
				return nil
			}
			lookupTarget := norm
			if sfx := tailnet.NormalizeHost(st.MagicDNSSuffix); sfx != "" && !strings.Contains(norm, ".") {
				lookupTarget = norm + "." + sfx
			}
			if ips := lookupDNSServer(lookupTarget, "100.100.100.100:53", 800*time.Millisecond); len(ips) > 0 {
				return ips
			}
			ctx, cancel := context.WithTimeout(context.Background(), 1000*time.Millisecond)
			ips, _ := net.DefaultResolver.LookupIP(ctx, "ip", host)
			cancel()
			return ips
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	ips, _ := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if len(ips) == 0 {
		if !warp.IsIPv6OnlyHost() {
			ips = lookupDNSServer(host, "223.5.5.5:53", 1000*time.Millisecond)
		}
		if len(ips) == 0 {
			ips = lookupDNSServer(host, "[2400:3200::1]:53", 1000*time.Millisecond)
		}
	}
	return ips
}

func lookupHostRecordNetIPs(records map[string][]string, normHost, suffix string) []net.IP {
	if len(records) == 0 || normHost == "" {
		return nil
	}
	rawIPs := records[normHost]
	if len(rawIPs) == 0 && !strings.Contains(normHost, ".") {
		if sfx := tailnet.NormalizeHost(suffix); sfx != "" {
			rawIPs = records[normHost+"."+sfx]
		}
	}
	var out []net.IP
	for _, rawIP := range rawIPs {
		if ip := net.ParseIP(strings.TrimSpace(rawIP)); ip != nil {
			out = append(out, ip)
		}
	}
	return out
}

func lookupDNSServer(host, serverAddr string, timeout time.Duration) []net.IP {
	if strings.TrimSpace(host) == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "udp", serverAddr)
		},
	}
	ips, _ := r.LookupIP(ctx, "ip", host)
	return ips
}

func (a *app) nodeIPResolver() func(host string) []net.IP {
	if a.mockNodeResolver != nil {
		return a.mockNodeResolver
	}
	return func(host string) []net.IP {
		key := strings.ToLower(strings.TrimSpace(host))
		a.resolvedNodeMu.RLock()
		if ips, ok := a.resolvedNodeIPs[key]; ok && len(ips) > 0 {
			a.resolvedNodeMu.RUnlock()
			return ips
		}
		a.resolvedNodeMu.RUnlock()

		ips := a.resolveNodeHostIPs(host)
		if len(ips) > 0 {
			a.resolvedNodeMu.Lock()
			if a.resolvedNodeIPs == nil {
				a.resolvedNodeIPs = make(map[string][]net.IP)
			}
			a.resolvedNodeIPs[key] = ips
			a.resolvedNodeMu.Unlock()
		}
		return ips
	}
}


func (a *app) getGateway() *boxengine.Engine {
	a.gatewayMu.Lock()
	gw := a.gateway
	a.gatewayMu.Unlock()
	return gw
}

func (a *app) isGatewayActiveOrStarting() bool {
	a.gatewayMu.Lock()
	active := a.gateway != nil || a.startingGateway != nil || a.gatewayStarting
	a.gatewayMu.Unlock()
	return active
}

func (a *app) waitLocalPortReady(svcID string, port int, maxWait time.Duration) {
	if port <= 0 {
		return
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(maxWait)
	for time.Now().Before(deadline) {
		if a.mgr == nil || a.mgr.StatusOf(svcID).State != runner.StateRunning {
			return
		}
		conn, err := net.DialTimeout("tcp", addr, 150*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (a *app) getTunDevice() *tunhelper.ReceivedDevice {
	a.gatewayMu.Lock()
	dev := a.tunDevice
	a.gatewayMu.Unlock()
	return dev
}

func (a *app) getLastGatewayErr() error {
	a.gatewayMu.Lock()
	err := a.lastGatewayErr
	a.gatewayMu.Unlock()
	return err
}

func (a *app) setLastGatewayErr(err error) {
	a.gatewayMu.Lock()
	a.lastGatewayErr = err
	a.gatewayMu.Unlock()
}

func (a *app) getTrafficMode() string {
	a.gatewayMu.Lock()
	var m string
	if a.gwSnap.Initialized {
		m = a.gwSnap.TrafficMode
	} else {
		m = a.state.TrafficMode
	}
	a.gatewayMu.Unlock()
	return m
}

func (a *app) setTrafficModeState(mode string) {
	a.gatewayMu.Lock()
	a.state.TrafficMode = mode
	if a.gwSnap.Initialized {
		a.gwSnap.TrafficMode = mode
	}
	a.gatewayMu.Unlock()
}

func (a *app) setSnapshotTrafficModeLocked(mode string) {
	a.gatewayMu.Lock()
	if a.gwSnap.Initialized {
		a.gwSnap.TrafficMode = mode
	}
	a.gatewayMu.Unlock()
}

func (a *app) handleGatewayCloudflareAccountUpdate(eng *boxengine.Engine, acc warp.Account) {
	if eng == nil {
		return
	}
	var allocPorts map[string]int
	if a.mgr != nil {
		allocPorts = a.mgr.AllocatedPorts()
	}
	accCopy := acc.Clone()
	a.gatewayMu.Lock()
	if a.gateway != eng && a.startingGateway != eng {
		a.gatewayMu.Unlock()
		return
	}
	if !a.gwSnap.Initialized {
		a.state.Cloudflare.Account = accCopy
		snap, rev := a.snapshotPersistedStateLocked()
		a.gatewayMu.Unlock()
		a.persistStateFiles(snap, rev)
		if a.win != nil {
			a.win.Invalidate()
		}
		return
	}
	prevSig := a.gatewayConfigSignatureForSnapshot(a.gwSnap, allocPorts)
	a.state.Cloudflare.Account = accCopy
	a.gwSnap.Cloudflare.Account = accCopy.Clone()
	if prevSig == a.lastGatewaySig {
		a.lastGatewaySig = a.gatewayConfigSignatureForSnapshot(a.gwSnap, allocPorts)
	}
	snap, rev := a.snapshotPersistedStateLocked()
	a.gatewayMu.Unlock()

	a.persistStateFiles(snap, rev)
	if a.win != nil {
		a.win.Invalidate()
	}
}

func (a *app) ensureGatewaySynced() error {
	a.gatewayLifecycleMu.Lock()
	var allocPorts map[string]int
	if a.mgr != nil {
		allocPorts = a.mgr.AllocatedPorts()
	}
	a.gatewayMu.Lock()
	snap := cloneGatewayConfigSnapshot(a.gwSnap)
	gw := a.gateway
	lastSig := a.lastGatewaySig
	a.gatewayMu.Unlock()
	if !snap.Initialized {
		a.refreshGatewaySnapshot()
		snap = a.getGatewaySnapshot()
	}
	if !snap.GatewayEnabled {
		a.gatewayLifecycleMu.Unlock()
		return errors.New("gateway engine is not running")
	}
	if gw != nil && a.gatewayConfigSignatureForSnapshot(snap, allocPorts) == lastSig {
		a.gatewayLifecycleMu.Unlock()
		return nil
	}
	needSave, toastMsg, err := a.startGatewayWithFallbackLocked()
	a.gatewayLifecycleMu.Unlock()
	if needSave || toastMsg != "" {
		a.dispatchUI(func() {
			if toastMsg != "" {
				a.toast(toastMsg)
			}
			if needSave {
				a.setTrafficModeState("port")
				a.saveState()
			}
		})
	}
	if err != nil && a.getGateway() == nil {
		return fmt.Errorf("网关内核启动失败: %w", err)
	}
	return err
}

func (a *app) startGateway() error {
	a.gatewayLifecycleMu.Lock()
	defer a.gatewayLifecycleMu.Unlock()
	a.refreshGatewaySnapshot()
	return a.startGatewayLocked()
}

func (a *app) detachGatewayLocked(closeTun bool) (*boxengine.Engine, *tunhelper.ReceivedDevice) {
	a.gatewayMu.Lock()
	oldGw := a.gateway
	a.gateway = nil
	a.startingGateway = nil
	a.lastGatewayErr = nil
	a.lastGatewaySig = ""
	var oldTun *tunhelper.ReceivedDevice
	if closeTun {
		oldTun = a.tunDevice
		a.tunDevice = nil
	}
	a.gatewayMu.Unlock()
	return oldGw, oldTun
}

func (a *app) startGatewayLocked() error {
	a.gatewayMu.Lock()
	a.gatewayStarting = true
	a.gatewayMu.Unlock()
	defer func() {
		a.gatewayMu.Lock()
		a.gatewayStarting = false
		a.gatewayMu.Unlock()
	}()
	if oldGw, _ := a.detachGatewayLocked(false); oldGw != nil {
		// Release gatewayMu before calling Stop() so in-flight engine callbacks
		// (e.g. OnCloudflareAccountUpdate) cannot ABBA-deadlock during shutdown.
		_ = oldGw.Stop()
	}
	snap := a.getGatewaySnapshot()
	if !snap.Initialized {
		a.refreshGatewaySnapshot()
		snap = a.getGatewaySnapshot()
	}
	if a.tailnetMgr != nil && snap.TailnetMode != string(tailnet.ModeEmbedded) {
		a.tailnetMgr.BindEmbeddedEndpoint(nil)
	}
	if !snap.GatewayEnabled {
		return nil
	}
	port := snap.GatewayPort
	if port <= 0 {
		port = 10809
	}

	var allocPorts map[string]int
	var activeIDs map[string]bool
	if a.mgr != nil {
		allocPorts = a.mgr.AllocatedPorts()
		activeIDs = a.mgr.RunningServiceIDs()
	}

	trafficMode := snap.TrafficMode
	wantForceIPv6 := effectiveSnapSubStrategy(snap.ProxyDNSStrategy, snap.DNSStrategy) != "ipv4_only" ||
		effectiveSnapSubStrategy(snap.DirectDNSStrategy, snap.DNSStrategy) != "ipv4_only"
	var tunFD int
	var tunName string
	if trafficMode == "tun" {
		if runtime.GOOS == "windows" {
			if a.mockTunDevice != nil {
				curTun := a.getTunDevice()
				if curTun == nil {
					dev, err := a.mockTunDevice()
					if err != nil {
						err = fmt.Errorf("request TUN device: %w", err)
						a.setLastGatewayErr(err)
						return err
					}
					a.gatewayMu.Lock()
					a.tunDevice = dev
					a.tunForceIPv6 = wantForceIPv6
					a.gatewayMu.Unlock()
					curTun = dev
				}
				if curTun != nil {
					tunFD = curTun.FD
					tunName = curTun.Name
				}
			} else {
				// On Windows, Wintun runs in-process via wintun.dll with TunFD == 0.
				// It requires the client process to be running with Administrator privileges.
				if !tunhelper.IsElevated() {
					err := errors.New("TUN 模式在 Windows 上需要以管理员身份运行客户端")
					a.setLastGatewayErr(err)
					return err
				}
			}
		} else {
			curTun := a.getTunDevice()
			a.gatewayMu.Lock()
			prevForceIPv6 := a.tunForceIPv6
			a.gatewayMu.Unlock()
			if curTun != nil && a.mockTunDevice == nil && prevForceIPv6 != wantForceIPv6 {
				a.gatewayMu.Lock()
				if a.tunDevice == curTun {
					a.tunDevice = nil
				}
				a.gatewayMu.Unlock()
				_ = curTun.Close()
				curTun = nil
			}
			if curTun == nil {
				dev, err := a.requestTunDevice(wantForceIPv6)
				if err != nil {
					err = fmt.Errorf("request TUN device: %w", err)
					a.setLastGatewayErr(err)
					return err
				}
				a.gatewayMu.Lock()
				a.tunDevice = dev
				a.tunForceIPv6 = wantForceIPv6
				a.gatewayMu.Unlock()
				curTun = dev
			}
			if curTun != nil {
				// sing-tun wraps the fd in an os.File and closes it with the engine, so
				// give it a private duplicate; ReceivedDevice keeps closing its own copy.
				// Sharing one fd number made the second close hit an unrelated, reused fd.
				tunFD = curTun.FD
				if a.mockTunDevice == nil {
					fd, err := tunhelper.DupFD(curTun.FD)
					if err != nil {
						err = fmt.Errorf("duplicate TUN fd: %w", err)
						a.setLastGatewayErr(err)
						return err
					}
					tunFD = fd
				}
				tunName = curTun.Name
			}
		}
	} else {
		a.gatewayMu.Lock()
		oldTun := a.tunDevice
		a.tunDevice = nil
		a.gatewayMu.Unlock()
		if oldTun != nil {
			_ = oldTun.Close()
		}
	}

	var tunAddrs []string
	if a.mockTunDevice != nil {
		tunAddrs = []string{"127.0.0.1/24"}
	}

	tnInfo := a.resolveTailnetRuntimeInfo(snap)
	tnCfg := tnInfo.Config
	tnMode := tnInfo.Mode

	cfCfg := snap.Cloudflare
	cfCfg.Account = cfCfg.Account.Clone()
	var eng *boxengine.Engine
	var err error
	eng, err = boxengine.New(boxengine.EngineOptions{
		ListenAddr:            fmt.Sprintf("127.0.0.1:%d", port),
		TrafficMode:           trafficMode,
		TunFD:                 tunFD,
		TunInterface:          tunName,
		TunAddresses:          tunAddrs,
		TunCreator:            a.mockTunCreator,
		NodeIPResolver:        a.nodeIPResolver(),
		Services:              cloneServices(snap.Services),
		AllocatedPorts:        allocPorts,
		ActiveIDs:             activeIDs,
		Rules:                 cloneRoutingRules(snap.Rules),
		FinalAction:           string(snap.Final.Type),
		FinalRoute:            cloneRouteAction(snap.Final),
		GeoSiteDB:             snap.GeoSiteDB,
		GeoIPDB:               snap.GeoIPDB,
		Tracker:               a.tracker,
		FailureMonitor:        a.failureMonitor,
		Blocker:               a.blocker,
		BootstrapDomains:      append([]string(nil), snap.BootstrapDomains...),
		BootstrapDNS:          parseOptionalDNSList(snap.BootstrapDNS),
		DomesticDoH:           parseOptionalDNSList(snap.DomesticDNS),
		RemoteDoH:             parseOptionalDNSList(snap.RemoteDNS),
		PreferIPv4:            snap.PreferIPv4,
		DNSStrategy:           snap.DNSStrategy,
		DirectDNSStrategy:     snap.DirectDNSStrategy,
		ProxyDNSStrategy:      snap.ProxyDNSStrategy,
		DNSOptimisticCache:    snap.DNSOptimisticCache,
		DualStackLoopback:     canBindIPv6Loopback(port),
		TailnetConfig:         &tnCfg,
		TailnetMode:           tnMode,
		TailnetHostExcludes:   tnInfo.Excludes,
		TailnetMagicDNSSuffix: tnInfo.MagicDNSSuffix,
		TailnetHostRecords:    tnInfo.HostRecords,
		TailnetHostInterface:  tnInfo.HostInterface,
		CloudflareConfig:      &cfCfg,
		OnCloudflareAccountUpdate: func(acc warp.Account) {
			a.dispatchUI(func() {
				a.handleGatewayCloudflareAccountUpdate(eng, acc)
			})
		},
		StateDir:              a.userDataDir(),
		LogLevel:              normalizeLogLevel(snap.LogLevel),
		OnLog:                 a.appendGatewayLog,
		OnDemandStart: func(tag string) {
			a.startDormantServiceForTag(eng, tag)
		},
		OnTelemetryUpdate: func() {
			a.notifyTelemetryUI()
		},
	})
	if err != nil {
		if trafficMode == "tun" {
			if _, oldTun := a.detachGatewayLocked(true); oldTun != nil {
				_ = oldTun.Close()
			}
		}
		a.setLastGatewayErr(err)
		a.appendSystemLog("ERROR", "Gateway build failed: %v", err)
		return err
	}
	a.gatewayMu.Lock()
	a.startingGateway = eng
	a.gatewayMu.Unlock()
	if err := eng.Start(); err != nil {
		a.gatewayMu.Lock()
		if a.startingGateway == eng {
			a.startingGateway = nil
		}
		a.gatewayMu.Unlock()
		_ = eng.Close()
		if trafficMode == "tun" {
			if _, oldTun := a.detachGatewayLocked(true); oldTun != nil {
				_ = oldTun.Close()
			}
		}
		a.setLastGatewayErr(err)
		a.appendSystemLog("ERROR", "Gateway start failed: %v", err)
		return err
	}
	a.gatewayMu.Lock()
	if a.startingGateway == eng {
		a.startingGateway = nil
	}
	a.gateway = eng
	a.gatewayStarting = false
	a.lastGatewayErr = nil
	if a.gwSnap.Initialized {
		snap.Cloudflare.Account = a.gwSnap.Cloudflare.Account.Clone()
	}
	snap.TailnetStateSig = a.currentTailnetStateSig()
	a.lastGatewaySig = a.gatewayConfigSignatureForSnapshot(snap, allocPorts)
	a.gatewayMu.Unlock()
	a.appendSystemLog("INFO", "Gateway started on %s (mode: %s)", eng.Addr(), trafficMode)

	if a.tailnetMgr != nil {
		if tnMode == tailnet.ModeEmbedded {
			a.tailnetMgr.BindEmbeddedEndpoint(eng.TailscaleEndpoint())
		} else {
			a.tailnetMgr.BindEmbeddedEndpoint(nil)
		}
	}

	if trafficMode == "sysproxy" && a.sysproxy != nil {
		sp, addr, bypass := a.sysproxy, eng.Addr(), snap.SystemProxyBypass
		a.runSysproxyOp(func() { _ = sp.Set(addr, bypass) })
	} else if trafficMode == "tun" && a.sysproxy != nil {
		sp := a.sysproxy
		a.runSysproxyOp(func() { _ = sp.MarkDirtyTun(tunName) })
	}
	a.releaseUnusedMemory()
	return nil
}

func (a *app) effectiveDomesticDNS() string {
	dns := a.state.DomesticDNS
	if dns == "" {
		dns = a.state.BootstrapDoH
	}
	// If 100.100.100.100 was set in domestic DNS to work around Tailscale,
	// fall back to default public domestic DoH so domestic domains don't flood MagicDNS.
	if strings.Contains(dns, "100.100.100.100") {
		return ""
	}
	return dns
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

func parseOptionalDNSList(s string) []string {
	return parseDNSList(s, nil)
}

func effectiveDefaultDNSList(v4, v6 []string) []string {
	if warp.IsIPv6OnlyHost() {
		return v6
	}
	return v4
}

func effectiveSnapSubStrategy(override, global string) string {
	if s := normalizeOptionalDNSStrategy(override); s != "" {
		return s
	}
	return global
}

func (a *app) effectiveProxyDNSStrategy() string {
	global := normalizeDNSStrategy(a.state.DNSStrategy, a.state.PreferIPv4)
	return effectiveSnapSubStrategy(a.state.ProxyDNSStrategy, global)
}

func canBindIPv6Loopback(port int) bool {
	if port <= 0 {
		return false
	}
	ln, err := net.Listen("tcp6", fmt.Sprintf("[::1]:%d", port))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

func (a *app) collectBootstrapDomains() []string {
	var tnStatus tailnet.Status
	if a.tailnetMgr != nil {
		tnStatus = a.tailnetMgr.Status()
	}
	effectiveMode := tnStatus.ActiveMode
	if effectiveMode == "" || effectiveMode == tailnet.ModeOff {
		// In ModeAuto with TailnetEnabled false, cooperative host detection may still enable
		// ModeHost at gateway startup; never hijack *.ts.net to public bootstrap-dns (223.5.5.5).
		if a.state.TailnetMode != string(tailnet.ModeOff) {
			effectiveMode = tailnet.ModeHost
		}
	}

	var domains []string
	seen := make(map[string]bool)
	add := func(host string, excludeTailnet bool) {
		host = strings.TrimSpace(host)
		if host == "" {
			return
		}
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = tailnet.NormalizeHost(host)
		if host == "" || net.ParseIP(host) != nil {
			return
		}
		if excludeTailnet && tailnet.IsTailnetHostname(effectiveMode, host, tnStatus.MagicDNSSuffix) {
			return
		}
		if !seen[host] {
			seen[host] = true
			domains = append(domains, host)
		}
	}

	for _, svc := range a.state.Services {
		if svc.Server != "" {
			add(svc.Server, true)
		}
		for _, p := range svc.Proxies {
			if u, err := url.Parse(p); err == nil && u.Hostname() != "" {
				add(u.Hostname(), true)
			}
		}
		if svc.ExternalURI != "" {
			if u, err := url.Parse(svc.ExternalURI); err == nil && u.Hostname() != "" {
				add(u.Hostname(), true)
			}
		}
	}

	// Collect domestic DoH domains to ensure they can be resolved via Bootstrap DNS without deadlocking.
	for _, ep := range parseDNSList(a.effectiveDomesticDNS(), effectiveDefaultDNSList(boxengine.DefaultDomesticDoH, boxengine.DefaultDomesticDoHV6)) {
		if u, err := url.Parse(ep); err == nil && u.Hostname() != "" {
			add(u.Hostname(), false)
		}
	}

	return domains
}

func (a *app) initDNS() {
	if a.getGateway() != nil {
		_ = a.startGateway()
	}
}

func (a *app) stopGateway() {
	if sp := a.sysproxy; sp != nil {
		a.runSysproxyOpSync(func() { _ = sp.Unset() })
	}
	a.gatewayLifecycleMu.Lock()
	oldGw, oldTun := a.detachGatewayLocked(true)
	if oldGw != nil {
		_ = oldGw.Stop()
	}
	if oldTun != nil {
		_ = oldTun.Close()
	}
	a.gatewayLifecycleMu.Unlock()
	if a.tailnetMgr != nil && a.state.TailnetMode != string(tailnet.ModeEmbedded) {
		a.tailnetMgr.BindEmbeddedEndpoint(nil)
	}
}

type tailnetRuntimeInfo struct {
	Config         tailnet.Config
	Mode           tailnet.Mode
	Excludes       []string
	MagicDNSSuffix string
	HostRecords    map[string][]string
	HostInterface  string
}

func (a *app) resolveTailnetRuntimeInfo(snap gatewayConfigSnapshot) tailnetRuntimeInfo {
	info := tailnetRuntimeInfo{Mode: tailnet.ModeOff}
	if a.tailnetMgr != nil {
		info.Config = a.tailnetMgr.GetConfig()
	}
	if snap.TailnetMode == string(tailnet.ModeOff) {
		return info
	}

	if a.tailnetMgr != nil {
		if a.tailnetMgr.ShouldUseHostMode() {
			st := a.tailnetMgr.Status()
			if st.BackendState != "Running" {
				if detected := a.tailnetMgr.DetectHostStatus(); detected != nil && detected.BackendState == "Running" {
					st = *detected
				}
			}
			info.Mode = tailnet.ModeHost
			info.Excludes = tailnet.ExcludeAddressesFromStatus(&st)
			info.MagicDNSSuffix = st.MagicDNSSuffix
			info.HostRecords = tailnet.HostRecordsFromStatus(&st)
			info.HostInterface = tailnet.DetectHostInterfaceForIPs(st.Self.IPs...)
		} else if a.tailnetMgr.ShouldUseEmbeddedMode() {
			info.Mode = tailnet.ModeEmbedded
			info.MagicDNSSuffix = a.tailnetMgr.GetMagicDNSSuffix()
		} else if hostSt := a.tailnetMgr.DetectHostStatus(); hostSt != nil && hostSt.BackendState == "Running" {
			info.Mode = tailnet.ModeHost
			info.Excludes = tailnet.ExcludeAddressesFromStatus(hostSt)
			info.MagicDNSSuffix = hostSt.MagicDNSSuffix
			info.HostRecords = tailnet.HostRecordsFromStatus(hostSt)
			info.HostInterface = tailnet.DetectHostInterfaceForIPs(hostSt.Self.IPs...)
		}
	}

	if runtime.GOOS == "darwin" && (info.Mode == tailnet.ModeOff || (info.Mode == tailnet.ModeHost && info.MagicDNSSuffix == "")) {
		if sfx := detectDarwinTailscaleMagicDNS("/etc/resolv.conf", "/etc/resolver"); sfx != "" {
			if info.Mode == tailnet.ModeOff {
				info.Mode = tailnet.ModeHost
				info.Excludes = append([]string(nil), tailnet.DefaultTailnetSubnets...)
			}
			if info.MagicDNSSuffix == "" {
				info.MagicDNSSuffix = sfx
			}
		}
	}

	if info.Mode == tailnet.ModeHost && info.HostInterface == "" {
		info.HostInterface = tailnet.DetectHostInterface()
	}
	return info
}

func detectDarwinTailscaleMagicDNS(resolvConfPath, resolverDir string) string {
	if resolvConfPath != "" {
		if data, err := os.ReadFile(resolvConfPath); err == nil {
			s := string(data)
			if strings.Contains(s, "100.100.100.100") {
				for _, l := range strings.Split(s, "\n") {
					f := strings.Fields(l)
					if len(f) >= 2 && (f[0] == "search" || f[0] == "domain") {
						for _, tok := range f[1:] {
							clean := tailnet.NormalizeHost(tok)
							if clean == "ts.net" || strings.HasSuffix(clean, ".ts.net") {
								return clean
							}
						}
					}
				}
			}
		}
	}

	if resolverDir != "" {
		if entries, err := os.ReadDir(resolverDir); err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				cleanName := tailnet.NormalizeHost(entry.Name())
				if cleanName != "ts.net" && !strings.HasSuffix(cleanName, ".ts.net") {
					continue
				}
				data, err := os.ReadFile(filepath.Join(resolverDir, entry.Name()))
				if err != nil {
					continue
				}
				content := string(data)
				if strings.Contains(content, "100.100.100.100") || strings.Contains(content, "tailscaled") {
					return cleanName
				}
			}
		}
	}

	return ""
}

func tailnetHostStateSig(st tailnet.Status) string {
	var b strings.Builder
	b.WriteString(string(st.ActiveMode))
	b.WriteByte('|')
	b.WriteString(st.BackendState)
	b.WriteByte('|')
	b.WriteString(tailnet.NormalizeHost(st.MagicDNSSuffix))
	b.WriteByte('|')
	routes := append([]string(nil), st.SubnetRoutes...)
	sort.Strings(routes)
	b.WriteString(strings.Join(routes, ","))
	b.WriteByte('|')
	records := tailnet.HostRecordsFromStatus(&st)
	if len(records) > 0 {
		keys := make([]string, 0, len(records))
		for k := range records {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			b.WriteString(k)
			b.WriteByte('=')
			b.WriteString(strings.Join(records[k], ","))
			b.WriteByte(';')
		}
	}
	return b.String()
}

func (a *app) currentTailnetStateSig() string {
	if a.tailnetMgr == nil {
		return ""
	}
	return tailnetHostStateSig(a.tailnetMgr.Status())
}

func (a *app) scheduleTailnetGatewaySync() {
	select {
	case <-a.quitCh:
		return
	default:
	}
	a.tailnetSyncMu.Lock()
	if a.tailnetSyncTimer != nil {
		a.tailnetSyncTimer.Stop()
	}
	a.tailnetSyncTimer = time.AfterFunc(80*time.Millisecond, func() {
		select {
		case <-a.quitCh:
			return
		default:
		}
		if a.tailnetMgr != nil {
			cfg := a.tailnetMgr.GetConfig()
			if cfg.Enabled && (cfg.Mode == tailnet.ModeOff || cfg.Mode == tailnet.ModeEmbedded) {
				return
			}
		}
		if snap := a.getGatewaySnapshot(); snap.Initialized && (snap.TailnetMode == string(tailnet.ModeOff) || snap.TailnetMode == string(tailnet.ModeEmbedded)) {
			return
		}
		if !a.isGatewayEnabled() || !a.isGatewayActiveOrStarting() {
			return
		}
		a.refreshGatewaySnapshot()
		_ = a.ensureGatewaySynced()
	})
	a.tailnetSyncMu.Unlock()
}

func (a *app) enqueueSysproxyOp(op func()) bool {
	a.sysproxyMu.Lock()
	if a.sysproxyClosed {
		a.sysproxyMu.Unlock()
		return false
	}
	if a.sysproxySignal == nil {
		a.sysproxySignal = make(chan struct{}, 1)
		sig := a.sysproxySignal
		go a.runSysproxyWorker(sig)
	}
	a.sysproxyOps = append(a.sysproxyOps, op)
	sig := a.sysproxySignal
	a.sysproxyMu.Unlock()
	select {
	case sig <- struct{}{}:
	default:
	}
	return true
}

func (a *app) runSysproxyWorker(sig chan struct{}) {
	for {
		a.sysproxyMu.Lock()
		if len(a.sysproxyOps) == 0 {
			if a.sysproxyClosed {
				a.sysproxyMu.Unlock()
				return
			}
			a.sysproxyMu.Unlock()
			<-sig
			continue
		}
		op := a.sysproxyOps[0]
		a.sysproxyOps[0] = nil
		a.sysproxyOps = a.sysproxyOps[1:]
		if len(a.sysproxyOps) == 0 {
			a.sysproxyOps = nil
		}
		a.sysproxyMu.Unlock()
		op()
	}
}

func (a *app) hasSysproxyWorker() bool {
	a.sysproxyMu.Lock()
	started := a.sysproxySignal != nil
	a.sysproxyMu.Unlock()
	return started
}

func (a *app) closeSysproxyWorker() {
	a.sysproxyMu.Lock()
	if a.sysproxyClosed {
		a.sysproxyMu.Unlock()
		return
	}
	a.sysproxyClosed = true
	sig := a.sysproxySignal
	a.sysproxyMu.Unlock()
	if sig != nil {
		select {
		case sig <- struct{}{}:
		default:
		}
	}
}

// runSysproxyOp queues a system-proxy change on a single worker. Each
// networksetup call takes tens to hundreds of ms and a switch makes many of
// them, so doing it inline froze the UI for 2-3s; the queue keeps rapid clicks ordered.
func (a *app) runSysproxyOp(op func()) {
	if op == nil {
		return
	}
	a.enqueueSysproxyOp(op)
}

// runSysproxyOpSync queues op on the sysproxy worker and waits for it (and all
// earlier queued ops) to finish.
func (a *app) runSysproxyOpSync(op func()) {
	done := make(chan struct{})
	enqueued := a.enqueueSysproxyOp(func() {
		defer close(done)
		if op != nil {
			op()
		}
	})
	if !enqueued {
		if op != nil {
			op()
		}
		return
	}
	<-done
}

// releaseTunDevice stops the running gateway before closing the TUN device.
// Regression: closing the fd while the engine still owned it made sing-tun
// fail with "UTUN_OPT_MAX_PENDING_PACKETS: invalid argument" when leaving TUN mode.
func (a *app) releaseTunDevice() {
	a.gatewayLifecycleMu.Lock()
	oldGw, oldTun := a.detachGatewayLocked(true)
	if oldGw != nil {
		_ = oldGw.Stop()
	}
	if oldTun != nil {
		_ = oldTun.Close()
	}
	a.gatewayLifecycleMu.Unlock()
}

// startGatewayWithFallback starts the gateway and, if TUN mode fails (e.g. TUN helper
// timeout or permission denial), cleans up the TUN device, falls back to "port" mode,
// saves state, and restarts the gateway in port mode.
func (a *app) startGatewayWithFallback() error {
	a.gatewayLifecycleMu.Lock()
	a.refreshGatewaySnapshot()
	needSave, toastMsg, err := a.startGatewayWithFallbackLocked()
	a.gatewayLifecycleMu.Unlock()
	if toastMsg != "" {
		a.toast(toastMsg)
	}
	if needSave {
		a.setTrafficModeState("port")
		a.saveState()
	}
	return err
}

func (a *app) startGatewayWithFallbackLocked() (bool, string, error) {
	err := a.startGatewayLocked()
	if err == nil {
		if a.win != nil {
			a.win.Invalidate()
		}
		return false, "", nil
	}
	if a.getTrafficMode() == "tun" {
		_ = os.WriteFile(filepath.Join(a.userDataDir(), "last_tun_error.txt"), []byte(err.Error()), 0644)
		a.appendSystemLog("WARN", "TUN mode failed (%v); falling back to port mode", err)
		if _, oldTun := a.detachGatewayLocked(true); oldTun != nil {
			_ = oldTun.Close()
		}
		a.setSnapshotTrafficModeLocked("port")
		fallbackErr := a.startGatewayLocked()
		toastMsg := "TUN Mode error: " + err.Error()
		if a.win != nil {
			a.win.Invalidate()
		}
		if fallbackErr != nil {
			return true, toastMsg, fmt.Errorf("tun start error: %w (port fallback error: %v)", err, fallbackErr)
		}
		return true, toastMsg, err
	}
	if a.win != nil {
		a.win.Invalidate()
	}
	return false, "", err
}

func (a *app) appendGatewayLog(level, msg string) {
	if a.gatewayLogs == nil {
		return
	}
	ts := time.Now().Format("15:04:05")
	a.gatewayLogs.AppendLine(fmt.Sprintf("[%s] [%s] [sing-box] %s", ts, strings.ToUpper(strings.TrimSpace(level)), msg))
}

func (a *app) appendSystemLog(level, format string, args ...any) {
	if a.gatewayLogs == nil {
		return
	}
	ts := time.Now().Format("15:04:05")
	msg := fmt.Sprintf(format, args...)
	a.gatewayLogs.AppendLine(fmt.Sprintf("[%s] [%s] [system] %s", ts, strings.ToUpper(strings.TrimSpace(level)), msg))
}

func (a *app) setLogLevel(level string) {
	norm := normalizeLogLevel(level)
	a.logsEngineLevel = norm
	if a.state.LogLevel == norm {
		return
	}
	a.state.LogLevel = norm
	if gw := a.getGateway(); gw != nil {
		gw.SetLogLevel(norm)
	}
	if a.mgr != nil {
		a.mgr.SetLogLevel(norm)
	}
	a.saveState()
	a.appendSystemLog("INFO", "Engine log level changed to %s", strings.ToUpper(norm))
}

func (a *app) setTrafficMode(mode string) error {
	a.appendSystemLog("INFO", "Switching traffic takeover mode to %s", mode)
	switch mode {
	case "port":
		a.setTrafficModeState("port")
		if sp := a.sysproxy; sp != nil {
			a.runSysproxyOp(func() { _ = sp.Unset() })
		}
		if a.getTunDevice() != nil {
			restart := a.getGateway() != nil
			a.releaseTunDevice()
			if restart || a.state.GatewayEnabled {
				_ = a.startGateway()
			}
		} else if a.getGateway() == nil && a.state.GatewayEnabled {
			_ = a.startGateway()
		}
		a.saveState()
		if a.win != nil {
			a.win.Invalidate()
		}
		return nil
	case "sysproxy":
		a.setTrafficModeState("sysproxy")
		if a.getTunDevice() != nil {
			a.releaseTunDevice()
			if err := a.startGateway(); err != nil {
				if a.win != nil {
					a.win.Invalidate()
				}
				return err
			}
		} else if a.getGateway() == nil {
			if err := a.startGateway(); err != nil {
				if a.win != nil {
					a.win.Invalidate()
				}
				return err
			}
		}
		if sp := a.sysproxy; sp != nil {
			if gw := a.getGateway(); gw != nil {
				addr, bypass := gw.Addr(), a.state.SystemProxyBypass
				a.runSysproxyOp(func() { _ = sp.Set(addr, bypass) })
			}
		}
		a.saveState()
		if a.win != nil {
			a.win.Invalidate()
		}
		return nil
	case "tun":
		a.setTrafficModeState("tun")
		if sp := a.sysproxy; sp != nil {
			a.runSysproxyOp(func() { _ = sp.Unset() })
		}
		if err := a.startGatewayWithFallback(); err != nil {
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
	a.refreshGatewaySnapshot()
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

// engineTrafficMode collapses "port" and "sysproxy": the sing-box config is
// identical for both (only TUN adds an inbound), so switching between them must
// not restart the engine. Regression: saveState -> syncRouter saw a changed
// signature and rebuilt the gateway, so port -> sysproxy took 2s+.
func engineTrafficMode(mode string) string {
	if mode == "tun" {
		return "tun"
	}
	return "port"
}

func (a *app) gatewayConfigSignature() string {
	var allocPorts map[string]int
	if a.mgr != nil {
		allocPorts = a.mgr.AllocatedPorts()
	}
	return a.gatewayConfigSignatureForSnapshot(a.buildGatewaySnapshotFromUI(), allocPorts)
}

func (a *app) gatewayConfigSignatureForSnapshot(snap gatewayConfigSnapshot, allocPorts map[string]int) string {
	type warpConfigSig struct {
		HasConfig      bool
		Transport      config.WarpTransport
		MasquePreferH2 string
		Endpoint       string
		PrivateKey     string
		AddressIPv4    string
		AddressIPv6    string
		Reserved       []uint8
		PeerPubKey     string
		MTU            int
	}
	type svcSig struct {
		ID                   string
		Engine               config.ExecutionEngine
		Kind                 config.NodeKind
		Protocol             config.Protocol
		Server               string
		ServerPort           int
		UUID                 string
		Password             string
		Security             string
		SNI                  string
		ALPN                 []string
		Fingerprint          string
		PublicKey            string
		ShortID              string
		SpiderX              string
		Flow                 string
		Network              string
		Path                 string
		Host                 string
		ServiceName          string
		Method               string
		Plugin               string
		PluginOpts           string
		CongestionController string
		UpMbps               int
		DownMbps             int
		UDPRelayMode         string
		ZeroRTTHandshake     bool
		ExtraJSON            string
		Proxies              []string
		ExternalURI          string
		Tags                 []string
		Listens              []string
		EnableWARP           bool
		WARPConfig           warpConfigSig
	}
	svcs := make([]svcSig, len(snap.Services))
	for i, s := range snap.Services {
		var wcSig warpConfigSig
		if s.WARPConfig != nil {
			preferH2 := "inherit"
			if s.WARPConfig.MasquePreferH2 != nil {
				preferH2 = strconv.FormatBool(*s.WARPConfig.MasquePreferH2)
			}
			wcSig = warpConfigSig{
				HasConfig:      true,
				Transport:      s.WARPConfig.Transport,
				MasquePreferH2: preferH2,
				Endpoint:       s.WARPConfig.Endpoint,
				PrivateKey:     s.WARPConfig.PrivateKey,
				AddressIPv4:    s.WARPConfig.AddressIPv4,
				AddressIPv6:    s.WARPConfig.AddressIPv6,
				Reserved:       s.WARPConfig.Reserved,
				PeerPubKey:     s.WARPConfig.PeerPubKey,
				MTU:            s.WARPConfig.MTU,
			}
		}
		svcs[i] = svcSig{
			ID:                   s.ID,
			Engine:               s.Engine,
			Kind:                 s.Kind,
			Protocol:             s.Protocol,
			Server:               s.Server,
			ServerPort:           s.ServerPort,
			UUID:                 s.UUID,
			Password:             s.Password,
			Security:             s.Security,
			SNI:                  s.SNI,
			ALPN:                 s.ALPN,
			Fingerprint:          s.Fingerprint,
			PublicKey:            s.PublicKey,
			ShortID:              s.ShortID,
			SpiderX:              s.SpiderX,
			Flow:                 s.Flow,
			Network:              s.Network,
			Path:                 s.Path,
			Host:                 s.Host,
			ServiceName:          s.ServiceName,
			Method:               s.Method,
			Plugin:               s.Plugin,
			PluginOpts:           s.PluginOpts,
			CongestionController: s.CongestionController,
			UpMbps:               s.UpMbps,
			DownMbps:             s.DownMbps,
			UDPRelayMode:         s.UDPRelayMode,
			ZeroRTTHandshake:     s.ZeroRTTHandshake,
			ExtraJSON:            s.ExtraJSON,
			Proxies:              s.Proxies,
			ExternalURI:          s.ExternalURI,
			Tags:                 s.Tags,
			Listens:              s.Listens,
			EnableWARP:           s.EnableWARP,
			WARPConfig:           wcSig,
		}
	}
	sigObj := struct {
		Port             int
		TrafficMode      string
		Svcs             []svcSig
		AllocatedPorts   map[string]int
		Rules            []routing.Rule
		Final            routing.RouteAction
		HasSiteDB        bool
		HasIPDB          bool
		GeoTag           string
		BootstrapDomains []string
		Bootstrap        string
		Domestic         string
		Remote             string
		PreferIPv4         bool
		DNSStrategy        string
		DirectDNSStrategy  string
		ProxyDNSStrategy   string
		DNSOptimisticCache bool
		TailnetEnabled     bool
		TailnetMode        string
		TailnetStateSig  string
		Cloudflare       warp.Config
	}{
		Port:             snap.GatewayPort,
		TrafficMode:      engineTrafficMode(snap.TrafficMode),
		Svcs:             svcs,
		AllocatedPorts:   allocPorts,
		Rules:            snap.Rules,
		Final:            snap.Final,
		HasSiteDB:        snap.GeoSiteDB != nil,
		HasIPDB:          snap.GeoIPDB != nil,
		GeoTag:           snap.GeoTag,
		BootstrapDomains: snap.BootstrapDomains,
		Bootstrap:        snap.BootstrapDNS,
		Domestic:         snap.DomesticDNS,
		Remote:             snap.RemoteDNS,
		PreferIPv4:         snap.PreferIPv4,
		DNSStrategy:        snap.DNSStrategy,
		DirectDNSStrategy:  snap.DirectDNSStrategy,
		ProxyDNSStrategy:   snap.ProxyDNSStrategy,
		DNSOptimisticCache: snap.DNSOptimisticCache,
		TailnetEnabled:     snap.TailnetEnabled,
		TailnetMode:      snap.TailnetMode,
		TailnetStateSig:  snap.TailnetStateSig,
		Cloudflare:       snap.Cloudflare,
	}
	return fmt.Sprintf("%#v", sigObj)
}

func (a *app) syncRouter() {
	a.router = routing.NewRouter(a.state.RoutingRules, a.state.RoutingFinal)
	a.loadGeoDataIfPresent()
	a.refreshGatewaySnapshot()
	a.gatewayLifecycleMu.Lock()
	var allocPorts map[string]int
	var activeIDs map[string]bool
	if a.mgr != nil {
		allocPorts = a.mgr.AllocatedPorts()
		activeIDs = a.mgr.RunningServiceIDs()
	}
	gw := a.getGateway()
	if gw != nil {
		a.gatewayMu.Lock()
		snap := cloneGatewayConfigSnapshot(a.gwSnap)
		lastSig := a.lastGatewaySig
		a.gatewayMu.Unlock()
		gw.UpdateNodes(cloneServices(snap.Services), allocPorts, activeIDs)
		needsRestart := !snap.GatewayEnabled || a.gatewayConfigSignatureForSnapshot(snap, allocPorts) != lastSig
		if needsRestart {
			_ = a.startGatewayLocked()
		}
	}
	a.gatewayLifecycleMu.Unlock()
}

// otherWarpRuleCount counts the routing rules (including the final fallback)
// that target the built-in WARP node, excluding the Direct ➔ WARP preset.
func (a *app) otherWarpRuleCount() int {
	n := 0
	if a.state.RoutingFinal.TargetsNode(config.BuiltinWarpServiceID) {
		n++
	}
	for _, r := range a.state.RoutingRules {
		if r.ID != "preset-cn-direct" && r.Enabled && r.Action.TargetsNode(config.BuiltinWarpServiceID) {
			n++
		}
	}
	return n
}

func (a *app) isBuiltinWarpNeeded() bool {
	if a.state.RoutingFinal.TargetsNode(config.BuiltinWarpServiceID) {
		return true
	}
	for _, r := range a.state.RoutingRules {
		if r.Enabled && r.Action.TargetsNode(config.BuiltinWarpServiceID) {
			return true
		}
	}
	return false
}

func (a *app) syncBuiltinWarpService() {
	needed := a.isBuiltinWarpNeeded()
	foundIdx := -1
	for i, s := range a.state.Services {
		if s.IsBuiltinWarp() {
			foundIdx = i
			break
		}
	}

	if needed {
		cat := a.catalog()
		nodeName := cat.BuiltinWarpNodeName()
		if nodeName == "" {
			nodeName = "Cloudflare WARP"
		}

		cleanIP := a.state.Cloudflare.CleanIP
		if a.state.Cloudflare.CleanPort > 0 && cleanIP != "" {
			cleanIP = net.JoinHostPort(cleanIP, strconv.Itoa(a.state.Cloudflare.CleanPort))
		}

		warpTransport := config.WarpTransportMasque
		if a.state.Cloudflare.EffectiveDirectMode() == warp.ModeWireGuard {
			warpTransport = config.WarpTransportWireGuard
		}

		preferH2 := a.state.Cloudflare.MasquePreferH2
		warpSvc := config.Service{
			ID:        config.BuiltinWarpServiceID,
			Name:      nodeName,
			Protocol:  config.ProtoWARP,
			Engine:    config.EngineSingBox,
			AutoStart: true,
			WARPConfig: &config.WarpNodeConfig{
				Transport:      warpTransport,
				MasquePreferH2: &preferH2,
				Endpoint:       cleanIP,
			},
		}

		if foundIdx < 0 {
			a.state.Services = append(a.state.Services, warpSvc)
		} else {
			a.state.Services[foundIdx].Name = nodeName
			a.state.Services[foundIdx].AutoStart = true
			if a.state.Services[foundIdx].WARPConfig == nil {
				a.state.Services[foundIdx].WARPConfig = warpSvc.WARPConfig
			} else {
				a.state.Services[foundIdx].WARPConfig.Transport = warpTransport
				a.state.Services[foundIdx].WARPConfig.MasquePreferH2 = &preferH2
				a.state.Services[foundIdx].WARPConfig.Endpoint = cleanIP
			}
			warpSvc = a.state.Services[foundIdx]
		}

		a.refreshServicesSnapshot()
		if a.mgr != nil && a.mgr.StatusOf(config.BuiltinWarpServiceID).State != runner.StateRunning {
			if a.getGateway() != nil || a.state.GatewayEnabled {
				_ = a.mgr.Start(warpSvc)
			}
		}

		registered := a.getCloudflareAccount().IsRegistered()
		if !registered && !a.warpRegistering {
			a.triggerWarpRegister()
		}
	} else {
		if foundIdx >= 0 {
			if a.mgr != nil {
				_ = a.mgr.Stop(config.BuiltinWarpServiceID)
			}
			a.state.Services = append(a.state.Services[:foundIdx], a.state.Services[foundIdx+1:]...)
			a.refreshServicesSnapshot()
		}
	}
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
	domain = blocker.NormalizeUserDomain(domain)
	if domain == "" {
		return false
	}
	for _, d := range a.state.BlockerAllowlist {
		if blocker.NormalizeUserDomain(d) == domain {
			return true
		}
	}
	return false
}

func (a *app) blockerMatchesDenylist(domain string) bool {
	domain = blocker.NormalizeUserDomain(domain)
	if domain == "" {
		return false
	}
	for _, d := range a.state.BlockerDenylist {
		if blocker.NormalizeUserDomain(d) == domain {
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
		a.blocker.SetAllowlist(a.state.BlockerAllowlist)
		a.blocker.SetDenylist(a.state.BlockerDenylist)
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
	if gw := a.getGateway(); gw != nil {
		gw.ClearDNSCache()
	}
}

func (a *app) addBlockerAllowlist(domain string) {
	d := blocker.NormalizeUserDomain(domain)
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
	d := blocker.NormalizeUserDomain(domain)
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
	d := blocker.NormalizeUserDomain(domain)
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
	d := blocker.NormalizeUserDomain(domain)
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
