package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"naive-client/internal/config"
	"naive-client/internal/runner"
	"naive-client/internal/updater"
	"naive-client/locales"
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

type app struct {
	win      *mygo.Window
	tray     *mygo.Tray
	headless bool
	quitting bool
	dataDir  string

	state PersistedState
	mgr   *runner.Manager

	localVersion    string
	latestRelease   *updater.Release
	hasUpdate       bool
	checkingUpdate  bool
	updatingCore    bool
	updateStageText string
	updatePercent   float64
	updateError     string

	mainScroll         ui.ScrollState
	settingsPageScroll ui.ScrollState
	expandedLogs       map[string]bool

	activeTab         TabID
	activeLogDrawerID string
	searchQuery       string

	batchTesting bool
	batchStage   string
	batchCancel  context.CancelFunc

	editor    editorForm
	importDlg importDialogState
	deleteDlg deleteDialogState

	pendingToast string
	clipboardMem string // fallback clipboard used in headless tests
	quitCh       chan struct{}
}

func (a *app) catalog() locales.Messages {
	return locales.In(locales.ResolveLocale(a.state.Language))
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
	return &app{
		dataDir:      dataDir,
		state:        defaultPersistedState(),
		expandedLogs: make(map[string]bool),
		quitCh:       make(chan struct{}),
	}
}

func (a *app) initSubsystems() {
	binPath := a.resolveBinaryPath()
	cfgDir := filepath.Join(a.userDataDir(), "configs")
	a.mgr = runner.NewManager(binPath, cfgDir, func() {
		a.dispatchUI(func() {
			a.rebuildTrayMenu()
		})
	})
	a.mgr.OnLog = func(id string) {
		if a.win != nil {
			a.win.Update(func() {
				if a.expandedLogs[id] {
					a.win.Invalidate()
				}
			})
		}
	}
	a.syncBinaryPathAndVersion()
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

func (a *app) boot() {
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

	go a.startPeriodicUpdateCheck()
}

func (a *app) startPeriodicUpdateCheck() {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-a.quitCh:
			return
		case <-ticker.C:
			if a.state.AutoCheckUpdate {
				a.dispatchUI(func() {
					a.triggerCheckUpdate(false)
				})
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
	}
	a.rebuildTrayMenu()
}

func (a *app) stopAllServices() {
	stopped := a.mgr.StopAll()
	if len(stopped) > 0 {
		a.toast(fmt.Sprintf("已停止 %d 个服务", len(stopped)))
	}
	a.rebuildTrayMenu()
}

func (a *app) triggerServiceProbe(svc config.Service) {
	if a.mgr.StatusOf(svc.ID).State != runner.StateRunning {
		a.toast("请先启动服务后再进行延迟测速")
		return
	}
	a.mgr.ProbeService(svc, a.state.ProbeURL)
}

func (a *app) triggerServiceDownloadTest(svc config.Service) {
	if a.mgr.StatusOf(svc.ID).State != runner.StateRunning {
		a.toast("请先启动服务后再进行下载测速")
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
		a.toast("当前没有运行中的服务")
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
	if opts.ProxyURL == "" && a.state.UseRunningServiceForUpd && a.mgr != nil {
		if ep, ok := a.mgr.FirstRunningEndpoint(); ok {
			opts.LocalEndpoint = &ep
		}
	}
	return opts
}

func (a *app) triggerCheckUpdate(manual bool) {
	if a.checkingUpdate || a.updatingCore {
		return
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

// Clipboard & Export Helpers
func (a *app) copyV2rayNLink(svc config.Service) {
	uri := svc.V2rayNSocksURI()
	a.writeClipboard(uri, "已复制本地链接: "+uri)
}

func (a *app) copyNaiveShareLink(svc config.Service) {
	uri := svc.NaiveShareURI()
	if uri == "" {
		a.toast("该服务未配置可导出的远端节点")
		return
	}
	a.writeClipboard(uri, "已复制 Naive 分享链接")
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
