package app

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/sagernet/sing-box/constant"

	"naive-client/internal/boxengine"
	"naive-client/locales"
)

var (
	langCodes = []string{locales.LangSystem, locales.LangZhHans, locales.LangEn}

	appearanceCodes = []string{appearanceSystem, appearanceLight, appearanceDark}

	appIconCodes = []string{appIconBoth, appIconDock, appIconMenubar}

	domesticDNSPresets = []string{
		"https://223.5.5.5/dns-query",
		"https://dns.alidns.com/dns-query",
		"https://1.12.12.12/dns-query",
		"https://doh.pub/dns-query",
	}

	remoteDNSPresets = []string{
		"https://1.1.1.1/dns-query",
		"https://cloudflare-dns.com/dns-query",
		"https://8.8.8.8/dns-query",
		"https://dns.google/dns-query",
		"https://dns.quad9.net/dns-query",
		"https://doh.opendns.com/dns-query",
	}

	bootstrapDNSPresets = []string{
		"223.5.5.5",
		"119.29.29.29",
		"114.114.114.114",
		"180.76.76.76",
		"1.12.12.12",
	}
)

func ensureSelectOption(opts []string, cur string) []string {
	if cur == "" {
		return opts
	}
	for _, o := range opts {
		if o == cur {
			return opts
		}
	}
	res := make([]string, 0, len(opts)+1)
	res = append(res, cur)
	res = append(res, opts...)
	return res
}

func dnsSelectRow(c *ui.Context, p palette, key, label string, value *string, defaultValue string, presets []string, hint string) bool {
	cur := *value
	if cur == "" {
		cur = defaultValue
	}
	options := ensureSelectOption(presets, cur)
	changed := false

	ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Wrap().Children(func() {
		ui.Column(c).Gap(2).Grow(1).Shrink(1).MinWidth(140).Children(func() {
			ui.Text(c, label).FontSize(13).FontWeight(500).TextColor(p.text)
			if hint != "" {
				ui.Text(c, hint).FontSize(11).TextColor(p.textDim)
			}
		})
		if ui.Select(c.Key(key), &cur, options).Label(label).Width(250).MaxWidthPercent(100).Shrink(0).Changed() {
			*value = cur
			changed = true
		}
	})
	return changed
}

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

	if a.settingsSubTab < 0 || a.settingsSubTab > 3 {
		a.settingsSubTab = 0
	}

	ui.Column(c.Key("settings-page")).Grow(1).Fill().MinHeight(0).Children(func() {
		// 1. Fixed Top Header with 4-Tab Segmented Navigation
		ui.Row(c.Key("settings-header")).
			Padding(12, 20, 12, 20).
			AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Wrap().
			Background(p.surface).
			BorderWidth(0, 0, 1, 0).BorderColor(p.borderSubtle).
			Children(func() {
				ui.Text(c, cat.SettingsTitle()).FontSize(17).FontWeight(700).TextColor(p.text).NoWrap()

				tabLabels := []string{
					cat.SettingsTabGeneral(),
					cat.SettingsTabGateway(),
					cat.SettingsTabCore(),
					cat.SettingsTabTelemetry(),
				}
				ui.Row(c).Shrink(0).MaxWidthPercent(100).Children(func() {
					segmentedControl(c.Key("settings-subtab-ctrl"), p, &a.settingsSubTab, tabLabels)
				})
			})

		// 2. Scrollable Centered Content Column (MaxWidth 700)
		ui.Scroll(c.Key("settings-page-scroll")).
			Grow(1).Fill().MinHeight(0).
			Padding(18, 20, 28, 20).
			Children(func() {
				ui.Column(c.Key("settings-content-col")).
					FillWidth().MaxWidth(700).AlignSelf(ui.Center).
					Gap(14).
					Children(func() {
						switch a.settingsSubTab {
						case 0:
							a.renderSettingsGeneralTab(c, p)
						case 1:
							a.renderSettingsGatewayTab(c, p)
						case 2:
							a.renderSettingsCoreTab(c, p)
						case 3:
							a.renderSettingsTelemetryTab(c, p)
						}
					})
			})
	})
}

func (a *app) renderSettingsGeneralTab(c *ui.Context, p palette) {
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

	ui.Column(c).Gap(12).Padding(16).Radius(10).Background(p.card).Border(1, p.borderSubtle).Children(func() {
		ui.Text(c, cat.AppearanceLabel()).FontSize(14).FontWeight(600).TextColor(p.text)

		ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Wrap().Children(func() {
			ui.Column(c).Gap(2).Grow(1).Shrink(1).MinWidth(140).Children(func() {
				ui.Text(c, cat.LanguageLabel()).FontSize(13).FontWeight(500).TextColor(p.text)
				ui.Text(c, cat.LanguageDesc()).FontSize(11).TextColor(p.textMuted)
			})
			if segmentedControl(c.Key("page-set-language"), p, &curLangIdx, a.langLabels()) {
				a.state.Language = langCodes[curLangIdx]
				a.saveState()
				a.applyLanguagePolicy()
			}
		})

		ui.Box(c).FillWidth().Height(1).Background(p.borderSubtle)

		ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Wrap().Children(func() {
			ui.Column(c).Gap(2).Grow(1).Shrink(1).MinWidth(140).Children(func() {
				ui.Text(c, cat.ThemeLabel()).FontSize(13).FontWeight(500).TextColor(p.text)
				ui.Text(c, cat.AppearanceDesc()).FontSize(11).TextColor(p.textMuted)
			})
			if segmentedControl(c.Key("page-set-appearance"), p, &curAppIdx, a.appearanceLabels()) {
				a.state.Appearance = appearanceCodes[curAppIdx]
				a.saveState()
			}
		})

		if runtime.GOOS == "darwin" {
			ui.Box(c).FillWidth().Height(1).Background(p.borderSubtle)

			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Wrap().Children(func() {
				ui.Text(c, cat.AppIconLabel()).FontSize(13).FontWeight(500).TextColor(p.text)
				if segmentedControl(c.Key("page-set-app-icon"), p, &curIconIdx, a.appIconLabels()) {
					a.state.AppIcon = appIconCodes[curIconIdx]
					a.saveState()
					a.applyAppIconPolicy()
				}
			})
		}

		ui.Box(c).FillWidth().Height(1).Background(p.borderSubtle)

		if switchRow(c, p, "page-set-open-login", cat.AutoStartLabel(), &a.openAtLogin) && !a.headless {
			_ = mygo.App.SetOpenAtLogin(a.openAtLogin)
		}
	})
}

func (a *app) renderSettingsGatewayTab(c *ui.Context, p palette) {
	cat := a.catalog()

	// Gateway Card
	ui.Column(c).Gap(12).Padding(16).Radius(10).Background(p.card).Border(1, p.borderSubtle).Children(func() {
		gw := a.getGateway()
		gwErr := a.getLastGatewayErr()
		ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(8).Children(func() {
			ui.Text(c, cat.GatewaySectionTitle()).FontSize(14).FontWeight(600).TextColor(p.text)
			ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
				if gw != nil && a.state.GatewayEnabled {
					statusDot(c, p.green)
					ui.Text(c, "Running :"+fmt.Sprint(a.state.GatewayPort)).
						FontSize(12).FontWeight(500).FontFeatures("tnum").TextColor(p.green).NoWrap()
				} else if a.state.GatewayEnabled && gwErr != nil {
					statusDot(c, p.red)
					ui.Text(c, cat.StatusError()).FontSize(12).FontWeight(500).TextColor(p.red).NoWrap()
				} else {
					hollowStatusDot(c, p.textDim.Alpha(0.5))
					ui.Text(c, cat.StatusStopped()).FontSize(12).TextColor(p.textDim).NoWrap()
				}
			})
		})

		if switchRow(c, p, "page-set-gateway-enable", cat.GatewayAutoStart(), &a.state.GatewayEnabled) {
			a.saveState()
			if a.state.GatewayEnabled {
				if err := a.startGatewayWithFallback(); err != nil {
					a.toast("网关启动失败: " + err.Error())
				}
			} else {
				a.stopGateway()
			}
		}

		if a.state.GatewayEnabled && gw == nil && gwErr != nil {
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(8).Wrap().
				Padding(8, 10, 8, 10).Radius(6).
				Background(p.redBg).Border(1, p.red.Alpha(0.25)).Children(func() {
				ui.Text(c, cat.ErrorPrefix()+gwErr.Error()).FontSize(11).TextColor(p.red).Grow(1).Shrink(1).MinWidth(0)
				btnRetry := quietToolbarButton(c.Key("page-btn-retry-gw"), p, iconRefresh, cat.ActionRetry(), false).
					Label(cat.ActionRetry()).Height(28)
				if btnRetry.Clicked() {
					if err := a.startGatewayWithFallback(); err != nil {
						a.toast(cat.ActionRetry() + ": " + err.Error())
					}
				}
			})
		}

		ui.Box(c).FillWidth().Height(1).Background(p.borderSubtle)

		if a.gatewayPortInput == "" && a.state.GatewayPort > 0 {
			a.gatewayPortInput = strconv.Itoa(a.state.GatewayPort)
		}
		if labeledInput(c, p, "page-set-gateway-port", cat.GatewayPortLabel(), &a.gatewayPortInput, cat.GatewayPortHint()).Changed() {
			if parsed, err := strconv.Atoi(a.gatewayPortInput); err == nil && parsed > 0 && parsed <= 65535 {
				a.state.GatewayPort = parsed
				a.saveState()
				if a.state.GatewayEnabled {
					_ = a.startGatewayWithFallback()
				}
			}
		}
	})

	// Split-DoH & DNS Resolution Card
	ui.Column(c).Gap(12).Padding(16).Radius(10).Background(p.card).Border(1, p.borderSubtle).Children(func() {
		ui.Column(c).Gap(2).Children(func() {
			ui.Text(c, cat.DohSectionTitle()).FontSize(14).FontWeight(600).TextColor(p.text)
			ui.Text(c, cat.DohSectionDesc()).FontSize(11).TextColor(p.textDim)
		})

		if switchRow(c, p, "page-set-dns-prefer-ipv4", cat.DnsPreferIPv4Label(), &a.state.PreferIPv4) {
			a.saveState()
			a.initDNS()
		}

		ui.Box(c).FillWidth().Height(1).Background(p.borderSubtle)

		if dnsSelectRow(c, p, "page-set-dns-domestic", cat.DnsDomesticLabel(), &a.state.DomesticDNS, boxengine.DefaultDomesticDoH[0], domesticDNSPresets, cat.DnsDomesticHint()) {
			a.saveState()
			a.initDNS()
		}

		ui.Box(c).FillWidth().Height(1).Background(p.borderSubtle)

		if dnsSelectRow(c, p, "page-set-dns-remote", cat.DnsRemoteLabel(), &a.state.RemoteDNS, boxengine.DefaultRemoteDoH[0], remoteDNSPresets, cat.DnsRemoteHint()) {
			a.saveState()
			a.initDNS()
		}

		ui.Box(c).FillWidth().Height(1).Background(p.borderSubtle)

		if dnsSelectRow(c, p, "page-set-dns-bootstrap", cat.DnsBootstrapLabel(), &a.state.BootstrapDNS, bootstrapDNSPresets[0], bootstrapDNSPresets, cat.DnsBootstrapHint()) {
			a.saveState()
			a.initDNS()
		}
	})
}

func (a *app) renderSettingsCoreTab(c *ui.Context, p palette) {
	cat := a.catalog()

	sbVer := "v1.14.4"
	if constant.Version != "" && constant.Version != "unknown" {
		sbVer = constant.Version
	}

	busy := a.checkingUpdate || a.checkingXrayUpdate || a.checkingGeodataUpdate ||
		a.updatingCore || a.updatingXrayCore || a.updatingGeoData

	ui.Column(c).Gap(0).Padding(16).Radius(10).Background(p.card).Border(1, p.borderSubtle).Children(func() {
		// Unified Matrix Header
		ui.Row(c).Padding(0, 0, 12, 0).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(8).Children(func() {
			ui.Text(c, cat.TriCoreSectionTitle()).FontSize(14).FontWeight(600).TextColor(p.text)
			btnCheck := quietToolbarButton(c.Key("page-btn-check-core"), p, iconRefresh, cat.CheckUpdates(), busy).
				Label(cat.CheckUpdates()).Height(28).Disabled(busy)
			if !busy && btnCheck.Clicked() {
				a.triggerCheckUpdate(true)
			}
		})

		ui.Box(c).FillWidth().Height(1).Background(p.borderSubtle)

		// 1. In-process sing-box core
		ui.Row(c).Padding(12, 0, 12, 0).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(10).Wrap().Children(func() {
			ui.Row(c).AlignItems(ui.Center).Gap(10).Grow(1).Shrink(1).MinWidth(0).Children(func() {
				statusDot(c, p.green)
				ui.Column(c).Gap(2).Grow(1).Shrink(1).MinWidth(0).Children(func() {
					ui.Row(c).AlignItems(ui.Center).Gap(8).Wrap().Children(func() {
						ui.Text(c, "sing-box "+sbVer).Font("monospace").FontSize(13).FontWeight(600).FontFeatures("tnum").TextColor(p.text)
						ui.Text(c, cat.CoreSingBoxStatus()).FontSize(11).FontWeight(500).TextColor(p.green).NoWrap()
					})
					ui.Text(c, cat.CoreSingBoxDesc()).FontSize(11).TextColor(p.textDim)
				})
			})
			ui.Text(c, cat.SettingsCoreBuiltInLabel()).FontSize(11).TextColor(p.textDim).NoWrap()
		})

		ui.Box(c).FillWidth().Height(1).Background(p.borderSubtle)

		// 2. Official NaiveProxy Sidecar
		ui.Column(c).Padding(12, 0, 12, 0).Gap(10).Children(func() {
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(10).Wrap().Children(func() {
				ui.Row(c).AlignItems(ui.Center).Gap(10).Grow(1).Shrink(1).MinWidth(0).Children(func() {
					if a.localVersion == "" {
						statusDot(c, p.amber)
					} else {
						statusDot(c, p.green)
					}
					ui.Column(c).Gap(2).Grow(1).Shrink(1).MinWidth(0).Children(func() {
						ui.Row(c).AlignItems(ui.Center).Gap(8).Wrap().Children(func() {
							ui.Text(c, cat.CoreNaiveTitle()).FontSize(13).FontWeight(600).TextColor(p.text)
							if a.localVersion == "" {
								ui.Text(c, cat.CoreNotInstalled()).FontSize(11).FontWeight(500).TextColor(p.amber).NoWrap()
							} else {
								ui.Text(c, cat.CoreLocal()+a.localVersion).Font("monospace").FontSize(11).FontWeight(500).FontFeatures("tnum").TextColor(p.green).NoWrap()
							}
							if a.hasUpdate && a.latestRelease != nil {
								ui.Text(c, cat.CoreNewVersion(a.latestRelease.TagName)).FontSize(11).FontWeight(600).FontFeatures("tnum").TextColor(p.amber).NoWrap()
							}
						})
						ui.Text(c, cat.CoreNaiveDesc()).FontSize(11).TextColor(p.textDim)
					})
				})

				ui.Row(c).AlignItems(ui.Center).Gap(6).Shrink(0).Children(func() {
					if a.localVersion == "" || a.hasUpdate || a.updatingCore {
						updLabel := cat.InstallCore()
						if a.updatingCore {
							updLabel = cat.Updating()
						} else if a.latestRelease != nil && a.hasUpdate {
							updLabel = cat.CoreSeamlessUpdateTo(a.latestRelease.TagName)
						}
						if primaryPillButton(c.Key("btn-seamless-update"), p, iconDownload, updLabel, p.accent, a.updatingCore).Height(28).Clicked() {
							a.triggerSeamlessUpdate()
						}
					} else {
						ui.Text(c, cat.SettingsCoreUpToDate()).FontSize(11).TextColor(p.textDim).NoWrap()
					}

					advIcon := iconChevronDown
					if a.settingsExpandNaiveAdv {
						advIcon = iconChevronUp
					}
					btnAdv := quietToolbarButton(c.Key("btn-toggle-naive-adv"), p, advIcon, cat.SettingsCoreAdvancedToggle(), false).
						Label("btn-toggle-naive-adv").Height(28)
					if btnAdv.Clicked() {
						a.settingsExpandNaiveAdv = !a.settingsExpandNaiveAdv
					}
				})
			})

			if a.settingsExpandNaiveAdv {
				ui.Column(c.Key("settings-naive-adv-panel")).
					Padding(12).Radius(8).Background(p.surface).Border(1, p.borderSubtle).Gap(10).
					Children(func() {
						if labeledInput(c, p, "page-set-custom-bin", cat.CustomCorePathLabel(), &a.state.CustomNaiveBinaryPath, cat.CustomCorePathHint()).Changed() {
							a.saveState()
							a.syncBinaryPathAndVersion()
						}
						if switchRow(c, p, "page-set-auto-check", cat.CoreAutoCheckLabel(), &a.state.AutoCheckUpdate) {
							a.saveState()
						}
						if switchRow(c, p, "page-set-auto-update-core", cat.CoreAutoUpdateLabel(), &a.state.AutoUpdateCore) {
							a.saveState()
						}
					})
			}
		})

		ui.Box(c).FillWidth().Height(1).Background(p.borderSubtle)

		// 3. Official Xray-core Sidecar
		ui.Column(c).Padding(12, 0, 12, 0).Gap(10).Children(func() {
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(10).Wrap().Children(func() {
				ui.Row(c).AlignItems(ui.Center).Gap(10).Grow(1).Shrink(1).MinWidth(0).Children(func() {
					if a.localXrayVersion == "" {
						statusDot(c, p.amber)
					} else {
						statusDot(c, p.green)
					}
					ui.Column(c).Gap(2).Grow(1).Shrink(1).MinWidth(0).Children(func() {
						ui.Row(c).AlignItems(ui.Center).Gap(8).Wrap().Children(func() {
							ui.Text(c, cat.CoreXrayTitle()).FontSize(13).FontWeight(600).TextColor(p.text)
							if a.localXrayVersion == "" {
								ui.Text(c, cat.XrayNotInstalled()).FontSize(11).FontWeight(500).TextColor(p.amber).NoWrap()
							} else {
								ui.Text(c, cat.XrayLocal()+a.localXrayVersion).Font("monospace").FontSize(11).FontWeight(500).FontFeatures("tnum").TextColor(p.green).NoWrap()
							}
							if a.hasXrayUpdate && a.latestXrayRelease != nil {
								ui.Text(c, cat.CoreNewVersion(a.latestXrayRelease.TagName)).FontSize(11).FontWeight(600).FontFeatures("tnum").TextColor(p.amber).NoWrap()
							}
						})
						ui.Text(c, cat.CoreXrayDesc()).FontSize(11).TextColor(p.textDim)
					})
				})

				ui.Row(c).AlignItems(ui.Center).Gap(6).Shrink(0).Children(func() {
					if a.localXrayVersion == "" || a.hasXrayUpdate || a.updatingXrayCore {
						updLabel := cat.InstallXray()
						if a.updatingXrayCore {
							updLabel = cat.Updating()
						} else if a.latestXrayRelease != nil && a.hasXrayUpdate {
							updLabel = cat.CoreUpdateTo(a.latestXrayRelease.TagName)
						}
						if primaryPillButton(c.Key("btn-update-xray"), p, iconDownload, updLabel, p.accent, a.updatingXrayCore).Height(28).Clicked() {
							a.triggerSeamlessXrayUpdate()
						}
					} else {
						ui.Text(c, cat.SettingsCoreUpToDate()).FontSize(11).TextColor(p.textDim).NoWrap()
					}

					advIcon := iconChevronDown
					if a.settingsExpandXrayAdv {
						advIcon = iconChevronUp
					}
					btnAdv := quietToolbarButton(c.Key("btn-toggle-xray-adv"), p, advIcon, cat.SettingsCoreAdvancedToggle(), false).
						Label("btn-toggle-xray-adv").Height(28)
					if btnAdv.Clicked() {
						a.settingsExpandXrayAdv = !a.settingsExpandXrayAdv
					}
				})
			})

			if a.settingsExpandXrayAdv {
				ui.Column(c.Key("settings-xray-adv-panel")).
					Padding(12).Radius(8).Background(p.surface).Border(1, p.borderSubtle).Gap(10).
					Children(func() {
						if labeledInput(c, p, "page-set-custom-xray-bin", cat.CustomXrayPathLabel(), &a.state.CustomXrayBinaryPath, cat.CustomCorePathHint()).Changed() {
							a.saveState()
							a.syncXrayBinaryPathAndVersion()
						}
						if switchRow(c, p, "page-set-auto-check-xray", cat.XrayAutoCheckLabel(), &a.state.AutoCheckXray) {
							a.saveState()
						}
						if switchRow(c, p, "page-set-auto-update-xray", cat.XrayAutoUpdateLabel(), &a.state.AutoUpdateXray) {
							a.saveState()
						}
					})
			}
		})

		ui.Box(c).FillWidth().Height(1).Background(p.borderSubtle)

		// 4. Routing GeoData Database (Loyalsoldier)
		ui.Row(c).Padding(12, 0, 0, 0).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(10).Wrap().Children(func() {
			ui.Row(c).AlignItems(ui.Center).Gap(10).Grow(1).Shrink(1).MinWidth(0).Children(func() {
				if !a.hasGeoData() {
					statusDot(c, p.amber)
				} else {
					statusDot(c, p.green)
				}
				ui.Column(c).Gap(2).Grow(1).Shrink(1).MinWidth(0).Children(func() {
					ui.Row(c).AlignItems(ui.Center).Gap(8).Wrap().Children(func() {
						ui.Text(c, cat.GeodataSectionTitle()).FontSize(13).FontWeight(600).TextColor(p.text)
						if !a.hasGeoData() {
							ui.Text(c, cat.GeodataStatusMissing()).FontSize(11).FontWeight(500).TextColor(p.amber).NoWrap()
						} else if a.localGeodataVersion != "" {
							ui.Text(c, cat.GeodataLocal()+a.localGeodataVersion).Font("monospace").FontSize(11).FontWeight(500).FontFeatures("tnum").TextColor(p.green).NoWrap()
						} else {
							ui.Text(c, cat.GeodataStatusReady()).FontSize(11).FontWeight(500).TextColor(p.green).NoWrap()
						}
						if a.hasGeodataUpdate && a.latestGeodataRelease != nil {
							ui.Text(c, cat.CoreNewVersion(a.latestGeodataRelease.TagName)).FontSize(11).FontWeight(600).FontFeatures("tnum").TextColor(p.amber).NoWrap()
						}
					})
					ui.Text(c, cat.GeodataDesc()).FontSize(11).TextColor(p.textDim)
				})
			})

			updLabel := cat.UpdateGeoData()
			if a.updatingGeoData {
				updLabel = cat.Updating()
			} else if a.latestGeodataRelease != nil && a.hasGeodataUpdate {
				updLabel = cat.CoreUpdateTo(a.latestGeodataRelease.TagName)
			}
			if primaryPillButton(c.Key("page-btn-update-geodata"), p, iconDownload, updLabel, p.accent, a.updatingGeoData).Height(28).Shrink(0).Clicked() {
				a.triggerUpdateGeoData()
			}
		})
	})
}

func (a *app) renderSettingsTelemetryTab(c *ui.Context, p palette) {
	cat := a.catalog()

	// Download & Update Channels Card
	ui.Column(c).Gap(12).Padding(16).Radius(10).Background(p.card).Border(1, p.borderSubtle).Children(func() {
		ui.Column(c).Gap(2).Children(func() {
			ui.Text(c, cat.DownloadChannelTitle()).FontSize(14).FontWeight(600).TextColor(p.text)
			ui.Text(c, cat.DownloadChannelDesc()).FontSize(11).TextColor(p.textDim)
		})

		if switchRow(c, p, "page-set-use-running", cat.CoreUseRunningProxy(), &a.state.UseRunningServiceForUpd) {
			a.saveState()
		}

		ui.Box(c).FillWidth().Height(1).Background(p.borderSubtle)

		if labeledInput(c, p, "page-set-gh-mirror", cat.GitHubMirrorLabel(), &a.state.GitHubMirror, cat.GitHubMirrorHint()).Changed() {
			a.saveState()
		}
		if labeledInput(c, p, "page-set-upd-proxy", cat.UpdateProxyLabel(), &a.state.UpdateProxy, "socks://127.0.0.1:1080").Changed() {
			a.saveState()
		}
	})

	// Telemetry & Network Testing Card
	ui.Column(c).Gap(12).Padding(16).Radius(10).Background(p.card).Border(1, p.borderSubtle).Children(func() {
		ui.Text(c, cat.TelemetrySectionTitle()).FontSize(14).FontWeight(600).TextColor(p.text)
		if switchRow(c, p, "page-set-auto-probe", cat.AutoProbeOnStart(), &a.state.AutoProbeOnStart) {
			a.saveState()
		}

		ui.Box(c).FillWidth().Height(1).Background(p.borderSubtle)

		if switchRow(c, p, "page-set-auto-probe-periodic", cat.AutoProbePeriodic(), &a.state.AutoProbePeriodic) {
			a.saveState()
		}
		if a.state.AutoProbePeriodic {
			if a.autoProbeIntervalInput == "" && a.state.AutoProbeInterval > 0 {
				a.autoProbeIntervalInput = strconv.Itoa(a.state.AutoProbeInterval)
			}
			if labeledInput(c, p, "page-set-probe-interval", cat.AutoProbeIntervalLabel(), &a.autoProbeIntervalInput, "5").Changed() {
				if parsed, err := strconv.Atoi(strings.TrimSpace(a.autoProbeIntervalInput)); err == nil && parsed >= 1 && parsed <= 1440 {
					a.state.AutoProbeInterval = parsed
					if a.tracker != nil {
						a.tracker.SetProbeInterval(time.Duration(parsed) * time.Minute)
					}
					a.saveState()
				}
			}
		}

		ui.Box(c).FillWidth().Height(1).Background(p.borderSubtle)

		if labeledInput(c, p, "page-set-probe-url", cat.ProbeURLLabel(), &a.state.ProbeURL, defaultProbeURL).Changed() {
			a.saveState()
		}
		if labeledInput(c, p, "page-set-download-url", cat.DownloadURLLabel(), &a.state.DownloadTestURL, defaultDownloadURL).Changed() {
			a.saveState()
		}
	})
}
