package app

import (
	"fmt"
	"runtime"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"naive-client/locales"
)

var (
	langCodes = []string{locales.LangSystem, locales.LangZhHans, locales.LangEn}

	appearanceCodes = []string{appearanceSystem, appearanceLight, appearanceDark}

	appIconCodes = []string{appIconBoth, appIconDock, appIconMenubar}
)

func indexOfCode(codes []string, v string) int {
	for i, c := range codes {
		if c == v {
			return i
		}
	}
	return 0
}

func (a *app) langLabels() []string {
	cat := a.catalog()
	return []string{cat.LanguageSystem(), cat.LanguageZhHans(), cat.LanguageEn()}
}

func (a *app) appearanceLabels() []string {
	cat := a.catalog()
	return []string{cat.AppearanceSystem(), cat.AppearanceLight(), cat.AppearanceDark()}
}

func (a *app) appIconLabels() []string {
	cat := a.catalog()
	return []string{cat.AppIconBoth(), cat.AppIconDock(), cat.AppIconMenubar()}
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
			ui.Text(c, cat.SettingsTitle()).FontSize(18).FontWeight(700).TextColor(p.text)

			// Section 1: Appearance & Integration
			ui.Column(c).Gap(12).Padding(16).Radius(10).Background(p.card).Border(1, p.borderSubtle).Children(func() {
				ui.Text(c, cat.AppearanceLabel()).FontSize(14).FontWeight(600).TextColor(p.text)

				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Children(func() {
					ui.Column(c).Gap(2).Children(func() {
						ui.Text(c, cat.LanguageLabel()).FontSize(13).FontWeight(500).TextColor(p.text)
						ui.Text(c, cat.LanguageDesc()).FontSize(11).TextColor(p.textMuted)
					})
					if segmentedControl(c.Key("page-set-language"), p, &curLangIdx, a.langLabels()) {
						a.state.Language = langCodes[curLangIdx]
						a.saveState()
						a.applyLanguagePolicy()
					}
				})

				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Children(func() {
					ui.Column(c).Gap(2).Children(func() {
						ui.Text(c, cat.ThemeLabel()).FontSize(13).FontWeight(500).TextColor(p.text)
						ui.Text(c, cat.AppearanceDesc()).FontSize(11).TextColor(p.textMuted)
					})
					if segmentedControl(c.Key("page-set-appearance"), p, &curAppIdx, a.appearanceLabels()) {
						a.state.Appearance = appearanceCodes[curAppIdx]
						a.saveState()
					}
				})

				if runtime.GOOS == "darwin" {
					ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Children(func() {
						ui.Text(c, cat.AppIconLabel()).FontSize(13).FontWeight(500).TextColor(p.text)
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
				if switchRow(c, p, "page-set-open-login", cat.AutoStartLabel(), &openAtLogin) && !a.headless {
					_ = mygo.App.SetOpenAtLogin(openAtLogin)
				}
			})

			// Section 2: NaiveProxy Core & Updates
			ui.Column(c).Gap(12).Padding(16).Radius(10).Background(p.card).Border(1, p.borderSubtle).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
					ui.Text(c, cat.CoreSectionTitle()).FontSize(14).FontWeight(600).TextColor(p.text)
					if actionChip(c.Key("page-btn-check-core"), p, iconRefresh, cat.CheckUpdates(), a.checkingUpdate || a.updatingCore).Clicked() {
						a.triggerCheckUpdate(true)
					}
				})

				// Core version and seamless update status banner
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Padding(10).Radius(8).
					Background(p.surface).Border(1, p.borderSubtle).Children(func() {
					ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
						if a.localVersion == "" {
							statusBadge(c, cat.CoreNotInstalled(), p.amber, p.amberBg)
						} else {
							statusBadge(c, cat.CoreLocal()+a.localVersion, p.green, p.greenBg)
						}
						if a.hasUpdate && a.latestRelease != nil {
							tagPill(c, "新版本 "+a.latestRelease.TagName, p.amber, p.amberBg)
						}
					})

					if a.localVersion == "" || a.hasUpdate || a.updatingCore {
						updLabel := cat.InstallCore()
						if a.updatingCore {
							updLabel = cat.Updating()
						} else if a.latestRelease != nil && a.hasUpdate {
							updLabel = fmt.Sprintf("无感更新至 %s", a.latestRelease.TagName)
						}
						if primaryPillButton(c.Key("btn-seamless-update"), p, iconDownload, updLabel, p.accent, a.updatingCore).Clicked() {
							a.triggerSeamlessUpdate()
						}
					}
				})

				if switchRow(c, p, "page-set-auto-check", cat.CoreAutoCheckLabel(), &a.state.AutoCheckUpdate) {
					a.saveState()
				}
				if switchRow(c, p, "page-set-auto-update-core", cat.CoreAutoUpdateLabel(), &a.state.AutoUpdateCore) {
					a.saveState()
				}
				if switchRow(c, p, "page-set-use-running", cat.CoreUseRunningProxy(), &a.state.UseRunningServiceForUpd) {
					a.saveState()
				}

				if labeledInput(c, p, "page-set-gh-mirror", cat.GitHubMirrorLabel(), &a.state.GitHubMirror, cat.GitHubMirrorHint()).Changed() {
					a.saveState()
				}
				if labeledInput(c, p, "page-set-upd-proxy", cat.UpdateProxyLabel(), &a.state.UpdateProxy, "socks://127.0.0.1:1080").Changed() {
					a.saveState()
				}
				if labeledInput(c, p, "page-set-custom-bin", cat.CustomCorePathLabel(), &a.state.CustomNaiveBinaryPath, cat.CustomCorePathHint()).Changed() {
					a.saveState()
					a.syncBinaryPathAndVersion()
				}
			})

			// Section 3: Telemetry & Network Testing
			ui.Column(c).Gap(12).Padding(16).Radius(10).Background(p.card).Border(1, p.borderSubtle).Children(func() {
				ui.Text(c, cat.TelemetrySectionTitle()).FontSize(14).FontWeight(600).TextColor(p.text)
				if labeledInput(c, p, "page-set-probe-url", cat.ProbeURLLabel(), &a.state.ProbeURL, defaultProbeURL).Changed() {
					a.saveState()
				}
				if labeledInput(c, p, "page-set-download-url", cat.DownloadURLLabel(), &a.state.DownloadTestURL, defaultDownloadURL).Changed() {
					a.saveState()
				}
			})
		})
}
