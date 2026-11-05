package app

import (
	"runtime"
	"strings"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"naive-client/internal/i18n"
)

type settingsForm struct {
	open             bool
	scroll           ui.ScrollState
	language         int
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
	langCodes  = []i18n.Lang{i18n.LangSystem, i18n.LangZhHans, i18n.LangEn}
	langLabels = []string{"跟随系统", "简体中文", "English"}

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
	langIdx := 0
	for i, lc := range langCodes {
		if lc == a.state.Language {
			langIdx = i
			break
		}
	}

	a.settingsDlg = settingsForm{
		open:             true,
		language:         langIdx,
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

func (a *app) langLabels() []string {
	cat := a.catalog()
	return []string{cat.LanguageSystem, cat.LanguageZhHans, cat.LanguageEn}
}

func (a *app) appearanceLabels() []string {
	cat := a.catalog()
	return []string{cat.AppearanceSystem, cat.AppearanceLight, cat.AppearanceDark}
}

func (a *app) appIconLabels() []string {
	cat := a.catalog()
	return []string{cat.AppIconBoth, cat.AppIconDock, cat.AppIconMenubar}
}

func (a *app) renderSettingsDialog(c *ui.Context, p palette) {
	cat := a.catalog()
	ui.DialogBase(c.Key("settings-dialog"), &a.settingsDlg.open, func(backdrop, panel ui.Element) {
		backdrop.Background(ui.RGBA(0, 0, 0, 0.5))
		panel.Column().
			Width(560).Height(560).
			Padding(20).Gap(14).
			Radius(14).Background(p.card).Border(1, p.border).
			Shadow(0, 12, 36, 0, ui.RGBA(0, 0, 0, 0.3)).
			Children(func() {
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
					ui.Text(c, cat.SettingsTitle).FontSize(16).FontWeight(700).TextColor(p.text)
				})

				ui.Scroll(c.Key("settings-scroll")).
					TrackScroll(&a.settingsDlg.scroll).
					Grow(1).
					Padding(0, 4, 0, 0).
					Gap(14).
					Children(func() {
						// Section 1: Appearance & System Integration
						ui.Column(c).Gap(12).Padding(14).Radius(10).Background(p.surface).Border(1, p.borderSubtle).Children(func() {
							ui.Text(c, cat.AppearanceLabel).FontSize(13).FontWeight(600).TextColor(p.text)

							ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Children(func() {
								ui.Text(c, cat.LanguageLabel).FontSize(12).TextColor(p.text)
								if segmentedControl(c.Key("set-language"), p, &a.settingsDlg.language, a.langLabels()) {
									a.state.Language = langCodes[a.settingsDlg.language]
									a.saveState()
								}
							})

							ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Children(func() {
								ui.Text(c, cat.ThemeLabel).FontSize(12).TextColor(p.text)
								if segmentedControl(c.Key("set-appearance"), p, &a.settingsDlg.appearance, a.appearanceLabels()) {
									a.state.Appearance = appearanceCodes[a.settingsDlg.appearance]
									a.saveState()
								}
							})

							if runtime.GOOS == "darwin" {
								ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Children(func() {
									ui.Text(c, cat.AppIconLabel).FontSize(12).TextColor(p.text)
									if segmentedControl(c.Key("set-app-icon"), p, &a.settingsDlg.appIcon, a.appIconLabels()) {
										a.state.AppIcon = appIconCodes[a.settingsDlg.appIcon]
										a.saveState()
										a.applyAppIconPolicy()
									}
								})
							}

							if switchRow(c, p, "set-open-login", cat.AutoStartLabel, &a.settingsDlg.openAtLogin) && !a.headless {
								_ = mygo.App.SetOpenAtLogin(a.settingsDlg.openAtLogin)
							}
						})

						// Section 2: NaiveClient Desktop App Updates
						ui.Column(c).Gap(12).Padding(14).Radius(10).Background(p.surface).Border(1, p.borderSubtle).Children(func() {
							ui.Text(c, cat.ClientSectionTitle).FontSize(13).FontWeight(600).TextColor(p.text)

							switchRow(c, p, "set-client-auto-check", cat.ClientAutoCheckLabel, &a.settingsDlg.clientAutoChecks)
							switchRow(c, p, "set-client-auto-dl", cat.ClientAutoDlLabel, &a.settingsDlg.clientAutoDl)

							ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Children(func() {
								clientVer := mygo.App.Version()
								if clientVer == "" {
									clientVer = "0.1.0"
								}
								ui.Text(c, cat.ClientVersionLabel+": v"+clientVer).FontSize(12).TextColor(p.textMuted)
								if actionChip(c.Key("btn-client-check-update"), p, iconRefresh, cat.CheckClientUpdates, false).Clicked() {
									checkForClientUpdates()
								}
							})
						})

						// Section 3: Naive Core & Release Update Tracking
						ui.Column(c).Gap(12).Padding(14).Radius(10).Background(p.surface).Border(1, p.borderSubtle).Children(func() {
							ui.Text(c, cat.CoreSectionTitle).FontSize(13).FontWeight(600).TextColor(p.text)

							switchRow(c, p, "set-auto-check", cat.CoreAutoCheckLabel, &a.settingsDlg.autoCheckUpd)
							switchRow(c, p, "set-auto-update-core", cat.CoreAutoUpdateLabel, &a.settingsDlg.autoUpdateCore)
							switchRow(c, p, "set-use-running", cat.CoreUseRunningProxy, &a.settingsDlg.useRunning)

							labeledInput(c, p, "set-gh-mirror", cat.GitHubMirrorLabel, &a.settingsDlg.mirror, cat.GitHubMirrorHint)
							labeledInput(c, p, "set-upd-proxy", cat.UpdateProxyLabel, &a.settingsDlg.updateProxy, "socks://127.0.0.1:1080")
							labeledInput(c, p, "set-custom-bin", cat.CustomCorePathLabel, &a.settingsDlg.customBin, a.defaultBinaryPath())
						})

						// Section 4: Connectivity & Speed Probe
						ui.Column(c).Gap(12).Padding(14).Radius(10).Background(p.surface).Border(1, p.borderSubtle).Children(func() {
							ui.Text(c, cat.TelemetrySectionTitle).FontSize(13).FontWeight(600).TextColor(p.text)
							labeledInput(c, p, "set-probe-url", cat.ProbeURLLabel, &a.settingsDlg.probeURL, defaultProbeURL)
							labeledInput(c, p, "set-download-url", cat.DownloadURLLabel, &a.settingsDlg.downloadURL, defaultDownloadURL)
						})
					})

				// Footer
				ui.Row(c).AlignItems(ui.Center).Justify(ui.End).Gap(8).
					Padding(10, 0, 0, 0).BorderWidth(1, 0, 0, 0).BorderColor(p.borderSubtle).
					Children(func() {
						if ui.Button(c.Key("settings-cancel"), cat.Cancel).Clicked() {
							a.settingsDlg.open = false
						}
						if ui.PrimaryButton(c.Key("settings-save"), cat.SaveSettings).Clicked() {
							a.saveSettingsDialog()
						}
					})
			})
	})
}

func (a *app) saveSettingsDialog() {
	cat := a.catalog()
	if a.settingsDlg.language >= 0 && a.settingsDlg.language < len(langCodes) {
		a.state.Language = langCodes[a.settingsDlg.language]
	}
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
	a.toast(cat.SaveSettings)
}

func (a *app) renderSettingsPage(c *ui.Context, p palette) {
	cat := a.catalog()

	curLangIdx := 0
	for i, lc := range langCodes {
		if lc == a.state.Language {
			curLangIdx = i
			break
		}
	}
	curAppIdx := indexOfCode(appearanceCodes, a.state.Appearance)
	curIconIdx := indexOfCode(appIconCodes, a.state.AppIcon)

	ui.Scroll(c.Key("settings-page-scroll")).
		TrackScroll(&a.settingsPageScroll).
		Grow(1).Fill().
		Padding(20, 24, 30, 24).Gap(14).
		Children(func() {
			ui.Text(c, cat.SettingsTitle).FontSize(18).FontWeight(700).TextColor(p.text)

			// Section 1: Appearance & Integration
			ui.Column(c).Gap(12).Padding(16).Radius(10).Background(p.card).Border(1, p.borderSubtle).Children(func() {
				ui.Text(c, cat.AppearanceLabel).FontSize(14).FontWeight(600).TextColor(p.text)

				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Children(func() {
					ui.Column(c).Gap(2).Children(func() {
						ui.Text(c, cat.LanguageLabel).FontSize(13).FontWeight(500).TextColor(p.text)
						ui.Text(c, cat.LanguageDesc).FontSize(11).TextColor(p.textMuted)
					})
					if segmentedControl(c.Key("page-set-language"), p, &curLangIdx, a.langLabels()) {
						a.state.Language = langCodes[curLangIdx]
						a.saveState()
					}
				})

				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Children(func() {
					ui.Column(c).Gap(2).Children(func() {
						ui.Text(c, cat.ThemeLabel).FontSize(13).FontWeight(500).TextColor(p.text)
						ui.Text(c, cat.AppearanceDesc).FontSize(11).TextColor(p.textMuted)
					})
					if segmentedControl(c.Key("page-set-appearance"), p, &curAppIdx, a.appearanceLabels()) {
						a.state.Appearance = appearanceCodes[curAppIdx]
						a.saveState()
					}
				})

				if runtime.GOOS == "darwin" {
					ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Children(func() {
						ui.Text(c, cat.AppIconLabel).FontSize(13).FontWeight(500).TextColor(p.text)
						if segmentedControl(c.Key("page-set-app-icon"), p, &curIconIdx, a.appIconLabels()) {
							a.state.AppIcon = appIconCodes[curIconIdx]
							a.saveState()
							a.applyAppIconPolicy()
						}
					})
				}

				openAtLogin := false
				if !a.headless {
					openAtLogin = mygo.App.OpenAtLogin()
				}
				if switchRow(c, p, "page-set-open-login", cat.AutoStartLabel, &openAtLogin) && !a.headless {
					_ = mygo.App.SetOpenAtLogin(openAtLogin)
				}
			})

			// Section 2: NaiveProxy Core & Updates
			ui.Column(c).Gap(12).Padding(16).Radius(10).Background(p.card).Border(1, p.borderSubtle).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
					ui.Text(c, cat.CoreSectionTitle).FontSize(14).FontWeight(600).TextColor(p.text)
					if actionChip(c.Key("page-btn-check-core"), p, iconRefresh, cat.CheckUpdates, a.checkingUpdate || a.updatingCore).Clicked() {
						a.triggerCheckUpdate(true)
					}
				})

				if switchRow(c, p, "page-set-auto-check", cat.CoreAutoCheckLabel, &a.state.AutoCheckUpdate) {
					a.saveState()
				}
				if switchRow(c, p, "page-set-auto-update-core", cat.CoreAutoUpdateLabel, &a.state.AutoUpdateCore) {
					a.saveState()
				}
				if switchRow(c, p, "page-set-use-running", cat.CoreUseRunningProxy, &a.state.UseRunningServiceForUpd) {
					a.saveState()
				}

				if labeledInput(c, p, "page-set-gh-mirror", cat.GitHubMirrorLabel, &a.state.GitHubMirror, cat.GitHubMirrorHint).Changed() {
					a.saveState()
				}
				if labeledInput(c, p, "page-set-upd-proxy", cat.UpdateProxyLabel, &a.state.UpdateProxy, "socks://127.0.0.1:1080").Changed() {
					a.saveState()
				}
				if labeledInput(c, p, "page-set-custom-bin", cat.CustomCorePathLabel, &a.state.CustomNaiveBinaryPath, cat.CustomCorePathHint).Changed() {
					a.saveState()
					a.syncBinaryPathAndVersion()
				}
			})

			// Section 3: Telemetry & Network Testing
			ui.Column(c).Gap(12).Padding(16).Radius(10).Background(p.card).Border(1, p.borderSubtle).Children(func() {
				ui.Text(c, cat.TelemetrySectionTitle).FontSize(14).FontWeight(600).TextColor(p.text)
				if labeledInput(c, p, "page-set-probe-url", cat.ProbeURLLabel, &a.state.ProbeURL, defaultProbeURL).Changed() {
					a.saveState()
				}
				if labeledInput(c, p, "page-set-download-url", cat.DownloadURLLabel, &a.state.DownloadTestURL, defaultDownloadURL).Changed() {
					a.saveState()
				}
			})
		})
}
