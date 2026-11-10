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

	ui.Row(c).AlignItems(ui.Center).Gap(14).Children(func() {
		ui.Text(c, label).FontSize(13).FontWeight(500).TextColor(p.text).Width(120).Shrink(0)
		if ui.Select(c.Key(key), &cur, options).Label(label).Width(270).Shrink(0).Changed() {
			*value = cur
			changed = true
		}
		ui.Text(c, hint).FontSize(11).TextColor(p.textDim).Grow(1)
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

				if switchRow(c, p, "page-set-open-login", cat.AutoStartLabel(), &a.openAtLogin) && !a.headless {
					_ = mygo.App.SetOpenAtLogin(a.openAtLogin)
				}
			})

			// Section 1.5: Unified Gateway & Traffic Takeover
			ui.Column(c).Gap(12).Padding(16).Radius(10).Background(p.card).Border(1, p.borderSubtle).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
					ui.Text(c, cat.GatewaySectionTitle()).FontSize(14).FontWeight(600).TextColor(p.text)
					if a.gateway != nil && a.state.GatewayEnabled {
						statusBadge(c, "Running :"+fmt.Sprint(a.state.GatewayPort), p.green, p.greenBg)
					} else {
						statusBadge(c, cat.StatusStopped(), p.textDim, p.elevated)
					}
				})

				if switchRow(c, p, "page-set-gateway-enable", cat.GatewayAutoStart(), &a.state.GatewayEnabled) {
					a.saveState()
					if a.state.GatewayEnabled {
						_ = a.startGateway()
					} else {
						a.stopGateway()
					}
				}

				if a.gatewayPortInput == "" && a.state.GatewayPort > 0 {
					a.gatewayPortInput = strconv.Itoa(a.state.GatewayPort)
				}
				if labeledInput(c, p, "page-set-gateway-port", cat.GatewayPortLabel(), &a.gatewayPortInput, cat.GatewayPortHint()).Changed() {
					if parsed, err := strconv.Atoi(a.gatewayPortInput); err == nil && parsed > 0 && parsed <= 65535 {
						a.state.GatewayPort = parsed
						a.saveState()
						if a.state.GatewayEnabled {
							_ = a.startGateway()
						}
					}
				}
			})

			// Section 2: Core & Geodata Management
			sbVer := "v1.14.4"
			if constant.Version != "" && constant.Version != "unknown" {
				sbVer = constant.Version
			}

			ui.Column(c).Gap(10).Padding(14).Radius(10).Background(p.card).Border(1, p.borderSubtle).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
					ui.Text(c, cat.TriCoreSectionTitle()).FontSize(14).FontWeight(600).TextColor(p.text)
					if actionChip(c.Key("page-btn-check-core"), p, iconRefresh, cat.CheckUpdates(), a.checkingUpdate || a.checkingXrayUpdate || a.checkingGeodataUpdate || a.updatingCore || a.updatingXrayCore || a.updatingGeoData).Clicked() {
						a.triggerCheckUpdate(true)
					}
				})

				// 1. In-process sing-box core
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Padding(10).Radius(8).
					Background(p.surface).Border(1, p.borderSubtle).Children(func() {
					ui.Column(c).Gap(2).Children(func() {
						ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
							ui.Text(c, "sing-box "+sbVer).FontSize(13).FontWeight(600).TextColor(p.text)
							statusBadge(c, cat.CoreSingBoxStatus(), p.green, p.greenBg)
						})
						ui.Text(c, cat.CoreSingBoxDesc()).FontSize(11).TextColor(p.textMuted)
					})
					tagPill(c, "gVisor TUN · TSNet · Ruleset", p.textDim, p.elevated)
				})

				// 2. Official NaiveProxy Sidecar
				ui.Column(c).Gap(6).Padding(10).Radius(8).Background(p.surface).Border(1, p.borderSubtle).Children(func() {
					ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(8).Children(func() {
						ui.Column(c).Grow(1).Gap(2).Children(func() {
							ui.Row(c).AlignItems(ui.Center).Wrap().Gap(8).Children(func() {
								ui.Text(c, cat.CoreNaiveTitle()).FontSize(13).FontWeight(600).TextColor(p.text)
								if a.localVersion == "" {
									statusBadge(c, cat.CoreNotInstalled(), p.amber, p.amberBg)
								} else {
									statusBadge(c, cat.CoreLocal()+a.localVersion, p.green, p.greenBg)
								}
								if a.hasUpdate && a.latestRelease != nil {
									tagPill(c, cat.CoreNewVersion(a.latestRelease.TagName), p.amber, p.amberBg)
								}
							})
							ui.Text(c, cat.CoreNaiveDesc()).FontSize(11).TextColor(p.textMuted)
						})

						if a.localVersion == "" || a.hasUpdate || a.updatingCore {
							updLabel := cat.InstallCore()
							if a.updatingCore {
								updLabel = cat.Updating()
							} else if a.latestRelease != nil && a.hasUpdate {
								updLabel = cat.CoreSeamlessUpdateTo(a.latestRelease.TagName)
							}
							if primaryPillButton(c.Key("btn-seamless-update"), p, iconDownload, updLabel, p.accent, a.updatingCore).Shrink(0).Clicked() {
								a.triggerSeamlessUpdate()
							}
						}
					})

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

				// 3. Official Xray-core Sidecar
				ui.Column(c).Gap(6).Padding(10).Radius(8).Background(p.surface).Border(1, p.borderSubtle).Children(func() {
					ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(8).Children(func() {
						ui.Column(c).Grow(1).Gap(2).Children(func() {
							ui.Row(c).AlignItems(ui.Center).Wrap().Gap(8).Children(func() {
								ui.Text(c, cat.CoreXrayTitle()).FontSize(13).FontWeight(600).TextColor(p.text)
								if a.localXrayVersion == "" {
									statusBadge(c, cat.XrayNotInstalled(), p.amber, p.amberBg)
								} else {
									statusBadge(c, cat.XrayLocal()+a.localXrayVersion, p.green, p.greenBg)
								}
								if a.hasXrayUpdate && a.latestXrayRelease != nil {
									tagPill(c, cat.CoreNewVersion(a.latestXrayRelease.TagName), p.amber, p.amberBg)
								}
							})
							ui.Text(c, cat.CoreXrayDesc()).FontSize(11).TextColor(p.textMuted)
						})

						if a.localXrayVersion == "" || a.hasXrayUpdate || a.updatingXrayCore {
							updLabel := cat.InstallXray()
							if a.updatingXrayCore {
								updLabel = cat.Updating()
							} else if a.latestXrayRelease != nil && a.hasXrayUpdate {
								updLabel = cat.CoreUpdateTo(a.latestXrayRelease.TagName)
							}
							if primaryPillButton(c.Key("btn-update-xray"), p, iconDownload, updLabel, p.accent, a.updatingXrayCore).Shrink(0).Clicked() {
								a.triggerSeamlessXrayUpdate()
							}
						}
					})

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

				// 4. Routing GeoData Database (Loyalsoldier)
				ui.Column(c).Gap(6).Padding(10).Radius(8).Background(p.surface).Border(1, p.borderSubtle).Children(func() {
					ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(8).Children(func() {
						ui.Column(c).Grow(1).Gap(3).Children(func() {
							ui.Row(c).AlignItems(ui.Center).Wrap().Gap(8).Children(func() {
								ui.Text(c, cat.GeodataSectionTitle()).FontSize(13).FontWeight(600).TextColor(p.text)
								if !a.hasGeoData() {
									statusBadge(c, cat.GeodataStatusMissing(), p.amber, p.amberBg)
								} else if a.localGeodataVersion != "" {
									statusBadge(c, cat.GeodataLocal()+a.localGeodataVersion, p.green, p.greenBg)
								} else {
									statusBadge(c, cat.GeodataStatusReady(), p.green, p.greenBg)
								}
								if a.hasGeodataUpdate && a.latestGeodataRelease != nil {
									tagPill(c, cat.CoreNewVersion(a.latestGeodataRelease.TagName), p.amber, p.amberBg)
								}
							})
							ui.Text(c, cat.GeodataDesc()).FontSize(11).TextColor(p.textMuted)
						})

						updLabel := cat.UpdateGeoData()
						if a.updatingGeoData {
							updLabel = cat.Updating()
						} else if a.latestGeodataRelease != nil && a.hasGeodataUpdate {
							updLabel = cat.CoreUpdateTo(a.latestGeodataRelease.TagName)
						}
						if primaryPillButton(c.Key("page-btn-update-geodata"), p, iconDownload, updLabel, p.accent, a.updatingGeoData).Shrink(0).Clicked() {
							a.triggerUpdateGeoData()
						}
					})
				})
			})

			// Section 2.8: Unified Resource Downloads & Update Channels
			ui.Column(c).Gap(12).Padding(16).Radius(10).Background(p.card).Border(1, p.borderSubtle).Children(func() {
				ui.Column(c).Gap(4).Children(func() {
					ui.Text(c, cat.DownloadChannelTitle()).FontSize(14).FontWeight(600).TextColor(p.text)
					ui.Text(c, cat.DownloadChannelDesc()).FontSize(11).TextColor(p.textDim)
				})

				if switchRow(c, p, "page-set-use-running", cat.CoreUseRunningProxy(), &a.state.UseRunningServiceForUpd) {
					a.saveState()
				}
				if labeledInput(c, p, "page-set-gh-mirror", cat.GitHubMirrorLabel(), &a.state.GitHubMirror, cat.GitHubMirrorHint()).Changed() {
					a.saveState()
				}
				if labeledInput(c, p, "page-set-upd-proxy", cat.UpdateProxyLabel(), &a.state.UpdateProxy, "socks://127.0.0.1:1080").Changed() {
					a.saveState()
				}
			})

			// Section 3: Telemetry & Network Testing
			ui.Column(c).Gap(12).Padding(16).Radius(10).Background(p.card).Border(1, p.borderSubtle).Children(func() {
				ui.Text(c, cat.TelemetrySectionTitle()).FontSize(14).FontWeight(600).TextColor(p.text)
				if switchRow(c, p, "page-set-auto-probe", cat.AutoProbeOnStart(), &a.state.AutoProbeOnStart) {
					a.saveState()
				}
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
				if labeledInput(c, p, "page-set-probe-url", cat.ProbeURLLabel(), &a.state.ProbeURL, defaultProbeURL).Changed() {
					a.saveState()
				}
				if labeledInput(c, p, "page-set-download-url", cat.DownloadURLLabel(), &a.state.DownloadTestURL, defaultDownloadURL).Changed() {
					a.saveState()
				}
			})

			// Section 3.5: Split-DoH & DNS Resolution
			ui.Column(c).Gap(12).Padding(16).Radius(10).Background(p.card).Border(1, p.borderSubtle).Children(func() {
				ui.Column(c).Gap(4).Children(func() {
					ui.Text(c, cat.DohSectionTitle()).FontSize(14).FontWeight(600).TextColor(p.text)
					ui.Text(c, cat.DohSectionDesc()).FontSize(11).TextColor(p.textDim)
				})

				if switchRow(c, p, "page-set-dns-prefer-ipv4", cat.DnsPreferIPv4Label(), &a.state.PreferIPv4) {
					a.saveState()
					a.initDNS()
				}
				if dnsSelectRow(c, p, "page-set-dns-domestic", cat.DnsDomesticLabel(), &a.state.DomesticDNS, boxengine.DefaultDomesticDoH[0], domesticDNSPresets, cat.DnsDomesticHint()) {
					a.saveState()
					a.initDNS()
				}
				if dnsSelectRow(c, p, "page-set-dns-remote", cat.DnsRemoteLabel(), &a.state.RemoteDNS, boxengine.DefaultRemoteDoH[0], remoteDNSPresets, cat.DnsRemoteHint()) {
					a.saveState()
					a.initDNS()
				}
				if dnsSelectRow(c, p, "page-set-dns-bootstrap", cat.DnsBootstrapLabel(), &a.state.BootstrapDNS, bootstrapDNSPresets[0], bootstrapDNSPresets, cat.DnsBootstrapHint()) {
					a.saveState()
					a.initDNS()
				}
			})
		})
}
