package app

import (
	"runtime"
	"strings"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
)

type settingsForm struct {
	open             bool
	scroll           ui.ScrollState
	appearance       int
	appIcon          int
	openAtLogin      bool
	clientAutoChecks bool
	clientAutoDl     bool
	autoCheckUpd     bool
	autoUpdateCore   bool
	useRunning       bool
	mirror           string
	updateProxy      string
	probeURL         string
	downloadURL      string
	customBin        string
}

var (
	appearanceCodes  = []string{appearanceSystem, appearanceLight, appearanceDark}
	appearanceLabels = []string{"跟随系统", "浅色", "深色"}

	appIconCodes  = []string{appIconBoth, appIconDock, appIconMenubar}
	appIconLabels = []string{"程序坞与菜单栏", "仅程序坞", "仅菜单栏"}
)

func indexOfCode(codes []string, v string) int {
	for i, c := range codes {
		if c == v {
			return i
		}
	}
	return 0
}

func (a *app) openSettingsDialog() {
	openAtLogin := false
	clientAutoChecks := true
	clientAutoDl := false
	if !a.headless {
		openAtLogin = mygo.App.OpenAtLogin()
		clientAutoChecks = clientUpdateChecks()
		clientAutoDl = clientUpdateDownloads()
	}
	a.settingsDlg = settingsForm{
		open:             true,
		appearance:       indexOfCode(appearanceCodes, a.state.Appearance),
		appIcon:          indexOfCode(appIconCodes, a.state.AppIcon),
		openAtLogin:      openAtLogin,
		clientAutoChecks: clientAutoChecks,
		clientAutoDl:     clientAutoDl,
		autoCheckUpd:     a.state.AutoCheckUpdate,
		autoUpdateCore:   a.state.AutoUpdateCore,
		useRunning:       a.state.UseRunningServiceForUpd,
		mirror:           a.state.GitHubMirror,
		updateProxy:      a.state.UpdateProxy,
		probeURL:         a.state.ProbeURL,
		downloadURL:      a.state.DownloadTestURL,
		customBin:        a.state.CustomNaiveBinaryPath,
	}
}

func (a *app) renderSettingsDialog(c *ui.Context, p palette) {
	ui.DialogBase(c.Key("settings-dialog"), &a.settingsDlg.open, func(backdrop, panel ui.Element) {
		backdrop.Background(ui.RGBA(0, 0, 0, 0.5))
		panel.Column().
			Width(560).Height(560).
			Padding(20).Gap(14).
			Radius(14).Background(p.card).Border(1, p.border).
			Shadow(0, 12, 36, 0, ui.RGBA(0, 0, 0, 0.3)).
			Children(func() {
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
					ui.Text(c, "全局偏好设置").FontSize(16).FontWeight(700).TextColor(p.text)
				})

				ui.Scroll(c.Key("settings-scroll")).
					TrackScroll(&a.settingsDlg.scroll).
					Grow(1).
					Padding(0, 4, 0, 0).
					Gap(14).
					Children(func() {
						// Section 1: Appearance & System Integration
						ui.Column(c).Gap(12).Padding(14).Radius(10).Background(p.surface).Border(1, p.borderSubtle).Children(func() {
							ui.Text(c, "外观与系统集成").FontSize(13).FontWeight(600).TextColor(p.text)

							ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Children(func() {
								ui.Text(c, "界面主题").FontSize(12).TextColor(p.text)
								if segmentedControl(c.Key("set-appearance"), p, &a.settingsDlg.appearance, appearanceLabels) {
									a.state.Appearance = appearanceCodes[a.settingsDlg.appearance]
									a.saveState()
								}
							})

							if runtime.GOOS == "darwin" {
								ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Children(func() {
									ui.Text(c, "图标显示位置").FontSize(12).TextColor(p.text)
									if segmentedControl(c.Key("set-app-icon"), p, &a.settingsDlg.appIcon, appIconLabels) {
										a.state.AppIcon = appIconCodes[a.settingsDlg.appIcon]
										a.saveState()
										a.applyAppIconPolicy()
									}
								})
							}

							if switchRow(c, p, "set-open-login", "开机时自动启动 NaiveClient", &a.settingsDlg.openAtLogin) && !a.headless {
								_ = mygo.App.SetOpenAtLogin(a.settingsDlg.openAtLogin)
							}
						})

						// Section 2: NaiveClient Desktop App Updates
						ui.Column(c).Gap(12).Padding(14).Radius(10).Background(p.surface).Border(1, p.borderSubtle).Children(func() {
							ui.Text(c, "NaiveClient 客户端更新").FontSize(13).FontWeight(600).TextColor(p.text)

							switchRow(c, p, "set-client-auto-check", "自动检查客户端新版本", &a.settingsDlg.clientAutoChecks)
							switchRow(c, p, "set-client-auto-dl", "后台自动下载新版本 (下次打开时生效)", &a.settingsDlg.clientAutoDl)

							ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Children(func() {
								clientVer := mygo.App.Version()
								if clientVer == "" {
									clientVer = "0.1.0"
								}
								ui.Text(c, "当前客户端版本: v"+clientVer).FontSize(12).TextColor(p.textMuted)
								if actionChip(c.Key("btn-client-check-update"), p, iconRefresh, "检查客户端更新", false).Clicked() {
									checkForClientUpdates()
								}
							})
						})

						// Section 3: Naive Core & Release Update Tracking
						ui.Column(c).Gap(12).Padding(14).Radius(10).Background(p.surface).Border(1, p.borderSubtle).Children(func() {
							ui.Text(c, "NaiveProxy 核心与无感更新").FontSize(13).FontWeight(600).TextColor(p.text)

							switchRow(c, p, "set-auto-check", "启动与后台每日自动检查 klzgrad/naiveproxy 最新版本", &a.settingsDlg.autoCheckUpd)
							switchRow(c, p, "set-auto-update-core", "自动更新 NaiveProxy 内核 (检测到新版本在后台自动无感热替换)", &a.settingsDlg.autoUpdateCore)
							switchRow(c, p, "set-use-running", "检查与下载更新时优先通过已运行的本地服务代理", &a.settingsDlg.useRunning)

							labeledInput(c, p, "set-gh-mirror", "GitHub 下载加速镜像前缀 (可选)", &a.settingsDlg.mirror, "例如: https://ghfast.top/")
							labeledInput(c, p, "set-upd-proxy", "指定更新专用代理地址 (可选)", &a.settingsDlg.updateProxy, "例如: socks://127.0.0.1:1080 或 http://127.0.0.1:7890")
							labeledInput(c, p, "set-custom-bin", "自定义本地 naive 可执行文件路径 (留空使用默认管理路径)", &a.settingsDlg.customBin, a.defaultBinaryPath())
						})

						// Section 4: Connectivity & Speed Probe
						ui.Column(c).Gap(12).Padding(14).Radius(10).Background(p.surface).Border(1, p.borderSubtle).Children(func() {
							ui.Text(c, "连通性与速度测试").FontSize(13).FontWeight(600).TextColor(p.text)
							labeledInput(c, p, "set-probe-url", "HTTP 204 延迟测速目标地址", &a.settingsDlg.probeURL, defaultProbeURL)
							labeledInput(c, p, "set-download-url", "下载测速目标地址", &a.settingsDlg.downloadURL, defaultDownloadURL)
						})
					})

				// Footer
				ui.Row(c).AlignItems(ui.Center).Justify(ui.End).Gap(8).
					Padding(10, 0, 0, 0).BorderWidth(1, 0, 0, 0).BorderColor(p.borderSubtle).
					Children(func() {
						if ui.Button(c.Key("settings-cancel"), "取消").Clicked() {
							a.settingsDlg.open = false
						}
						if ui.PrimaryButton(c.Key("settings-save"), "保存设置").Clicked() {
							a.saveSettingsDialog()
						}
					})
			})
	})
}

func (a *app) saveSettingsDialog() {
	a.state.Appearance = appearanceCodes[a.settingsDlg.appearance]
	if runtime.GOOS == "darwin" {
		a.state.AppIcon = appIconCodes[a.settingsDlg.appIcon]
	}
	if !a.headless {
		setClientUpdateChecks(a.settingsDlg.clientAutoChecks)
		setClientUpdateDownloads(a.settingsDlg.clientAutoDl)
	}
	a.state.AutoCheckUpdate = a.settingsDlg.autoCheckUpd
	a.state.AutoUpdateCore = a.settingsDlg.autoUpdateCore
	a.state.UseRunningServiceForUpd = a.settingsDlg.useRunning
	a.state.GitHubMirror = strings.TrimSpace(a.settingsDlg.mirror)
	a.state.UpdateProxy = strings.TrimSpace(a.settingsDlg.updateProxy)
	probe := strings.TrimSpace(a.settingsDlg.probeURL)
	if probe == "" {
		probe = defaultProbeURL
	}
	a.state.ProbeURL = probe
	dl := strings.TrimSpace(a.settingsDlg.downloadURL)
	if dl == "" {
		dl = defaultDownloadURL
	}
	a.state.DownloadTestURL = dl
	a.state.CustomNaiveBinaryPath = strings.TrimSpace(a.settingsDlg.customBin)

	a.saveState()
	a.syncBinaryPathAndVersion()
	a.applyAppIconPolicy()
	a.settingsDlg.open = false
	a.toast("已保存全局设置")
}
