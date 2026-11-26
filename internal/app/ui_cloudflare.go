package app

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/egoist/mygo/ui"

	"naive-client/internal/config"
	"naive-client/internal/routing"
	"naive-client/internal/runner"
	"naive-client/internal/warp"
)

func (a *app) isCnDirectWarpEnabled() bool {
	for _, r := range a.state.RoutingRules {
		if r.ID == "preset-cn-direct" {
			return r.Enabled && r.Action.TargetsNode(config.BuiltinWarpServiceID)
		}
	}
	return false
}

func (a *app) setCnDirectWarpEnabled(enabled bool) {
	idx := -1
	for i := range a.state.RoutingRules {
		if a.state.RoutingRules[i].ID == "preset-cn-direct" {
			idx = i
			break
		}
	}
	if idx < 0 {
		for _, def := range routing.DefaultPresets() {
			if def.ID == "preset-cn-direct" {
				a.state.RoutingRules = append(a.state.RoutingRules, def)
				idx = len(a.state.RoutingRules) - 1
				break
			}
		}
	}
	if idx >= 0 {
		if enabled {
			a.state.RoutingRules[idx].Enabled = true
			a.state.RoutingRules[idx].Action = routing.NewWarpTargetAction()
		} else {
			a.state.RoutingRules[idx].Action = routing.RouteAction{Type: routing.ActionDirect}
		}
	}
	a.saveState()
}

func (a *app) renderCloudflarePage(c *ui.Context, p palette) {
	cat := a.catalog()

	ui.Column(c.Key("cloudflare-page")).Grow(1).Fill().MinHeight(0).Children(func() {
		// 1. Fixed Header row (single quiet status dot + summary, Segmented subtabs)
		dsPageHeader(c, p, "cloudflare-header", true, func() {
			ui.Row(c).AlignItems(ui.Center).Gap(10).Wrap().MinWidth(0).Shrink(1).Children(func() {
				dsPageTitle(c, p, cat.NavCloudflare())

				ui.Row(c).AlignItems(ui.Center).Gap(dsSpaceSM).MinWidth(0).Shrink(1).Children(func() {
					if a.cloudflareSubTab == 0 {
						acc := a.getCloudflareAccount()
						var statusParts []string
						switch {
						case acc.AccountType == "unlimited":
							statusDot(c, p.green)
							statusParts = append(statusParts, "WARP+")
						case acc.IsRegistered():
							statusDot(c, p.green)
							statusParts = append(statusParts, cat.CloudflareStatusReady())
						default:
							hollowStatusDot(c, p.textDim.Alpha(0.5))
							statusParts = append(statusParts, cat.CloudflareWarpAccountNotRegistered())
						}
						if a.isCnDirectWarpEnabled() {
							statusParts = append(statusParts, cat.CloudflareStatusDirectTakeover())
						}
						ui.Text(c, strings.Join(statusParts, " · ")).
							FontSize(dsFontBody).TextColor(p.textMuted).SingleLine().Ellipsis("…")
					} else {
						tunCfg := a.state.Cloudflare.Tunnel
						var tunText string
						switch {
						case !tunCfg.Enabled:
							hollowStatusDot(c, p.textDim.Alpha(0.5))
							tunText = cat.TailnetModeOff()
						case a.getGateway() != nil && strings.TrimSpace(tunCfg.Token) != "":
							statusDot(c, p.green)
							tunText = cat.CloudflareTunnelConnected()
						default:
							statusDot(c, p.amber)
							tunText = cat.CloudflareTunnelDisconnected()
						}
						ui.Text(c, tunText).FontSize(dsFontBody).TextColor(p.textMuted).SingleLine().Ellipsis("…")
					}
				})
			})
		}, func() {
			ui.Row(c).Shrink(0).Children(func() {
				subtabLabels := []string{cat.CloudflareSubtabWarp(), cat.CloudflareSubtabTunnel()}
				segmentedControl(c.Key("cloudflare-subtab-ctrl"), p, &a.cloudflareSubTab, subtabLabels)
			})
		})

		// 2. Body scrollable view
		ui.Scroll(c.Key("cloudflare-page-scroll")).
			TrackScroll(&a.cloudflareScroll).
			Grow(1).Fill().MinHeight(0).
			Padding(16, 18, 24, 18).Gap(14).
			Children(func() {
				if a.cloudflareSubTab == 0 {
					a.renderCloudflareWarpView(c, p)
				} else {
					a.renderCloudflareTunnelView(c, p)
				}
			})
	})
}

func (a *app) renderWarpTransportGuide(c *ui.Context, p palette, keyPrefix string, modeIdx int, compact bool) {
	cat := a.catalog()
	items := []struct {
		idx   int
		title string
		desc  string
	}{
		{0, cat.CloudflareWarpTransportMasqueShort(), cat.CloudflareWarpTransportMasqueDesc()},
		{1, cat.CloudflareWarpTransportWireGuardShort(), cat.CloudflareWarpTransportWireGuardDesc()},
	}

	if compact {
		cur := items[0]
		if modeIdx >= 0 && modeIdx < len(items) {
			cur = items[modeIdx]
		}
		ui.Column(c.Key(keyPrefix+"-guide")).
			Gap(3).Padding(8, 10, 8, 10).Radius(6).
			Background(p.surface).Border(1, p.borderSubtle).
			Children(func() {
				ui.Text(c, cur.title).FontSize(11).FontWeight(600).TextColor(p.accent)
				ui.Text(c, cur.desc).FontSize(11).TextColor(p.textMuted).LineHeight(1.4)
			})
		return
	}

	summary := cat.CloudflareWarpTransportMasqueSummary()
	if modeIdx == 1 {
		summary = cat.CloudflareWarpTransportWireGuardSummary()
	}
	ui.Text(c.Key(keyPrefix+"-summary"), summary).FontSize(11).TextColor(p.textMuted).LineHeight(1.4)
}

func warpScanProtocolLabel(proto string) string {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "wireguard":
		return "WireGuard"
	case "h3":
		return "MASQUE H3"
	case "h2":
		return "MASQUE H2"
	case "masque":
		return "MASQUE"
	default:
		return strings.ToUpper(strings.TrimSpace(proto))
	}
}

func (a *app) attachedWarpNodeMeta(svc config.Service) string {
	cat := a.catalog()
	if svc.EffectiveProtocol() == config.ProtoWARP {
		epLabel := ""
		if svc.WARPConfig != nil && strings.TrimSpace(svc.WARPConfig.Endpoint) != "" {
			epLabel = strings.TrimSpace(svc.WARPConfig.Endpoint)
		} else if ip := strings.TrimSpace(a.state.Cloudflare.CleanIP); ip != "" {
			if a.state.Cloudflare.CleanPort > 0 {
				epLabel = net.JoinHostPort(ip, strconv.Itoa(a.state.Cloudflare.CleanPort))
			} else {
				epLabel = ip
			}
		} else if svc.IsBuiltinWarp() {
			epLabel = "Built-in"
		} else {
			epLabel = cat.CloudflareWarpEndpointModeAuto()
		}
		return strings.Join([]string{cat.CloudflareWarpDirectBadge(), a.warpTransportPillLabel(svc), epLabel}, " · ")
	}

	parts := []string{nodeProtocolEngineLabel(svc) + " ➔ " + a.warpTransportPillLabel(svc)}
	ep := strings.TrimSuffix(svc.CompactRemoteEndpoint(), " → WARP")
	if idx := strings.Index(ep, "://"); idx >= 0 {
		ep = ep[idx+3:]
	}
	if ep = strings.TrimSpace(ep); ep != "" {
		parts = append(parts, ep)
	}
	return strings.Join(parts, " · ")
}

type warpTransportSegOption struct {
	modeKey warp.Mode
	a11y    string
	label   string
}

func (a *app) renderWarpTransportTile(
	c *ui.Context, p palette,
	tileKey, title string, currentMode warp.Mode, summary string,
	opts [2]warpTransportSegOption,
	onSelect func(mode warp.Mode),
) {
	activeIdx := 0
	if currentMode == opts[1].modeKey {
		activeIdx = 1
	}
	segOpts := []segmentedOption{
		{Label: opts[0].label, A11yLabel: opts[0].a11y},
		{Label: opts[1].label, A11yLabel: opts[1].a11y},
	}
	ui.Column(c.Key(tileKey)).
		Grow(1).MinWidth(220).MaxWidthPercent(100).Gap(6).
		Padding(10, 12, 10, 12).Radius(8).Background(p.surface).
		Children(func() {
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(8).Children(func() {
				ui.Text(c, title).FontSize(12).FontWeight(500).TextColor(p.text).SingleLine().Ellipsis("…")
				ui.Row(c).Shrink(0).Children(func() {
					if compactSegmentedOptions(c.Key(tileKey+"-seg"), p, &activeIdx, segOpts) {
						onSelect(opts[activeIdx].modeKey)
					}
				})
			})
			ui.Text(c, summary).FontSize(11).TextColor(p.textMuted).LineHeight(1.35)
		})
}

func (a *app) renderCloudflareWarpView(c *ui.Context, p palette) {
	cat := a.catalog()
	acc := a.getCloudflareAccount()

	// Card 1: WARP Device Credentials (HTML Card 1)
	ui.Column(c.Key("warp-account-card")).
		Gap(12).Padding(16).Radius(10).
		Background(p.card).Border(1, p.borderSubtle).
		Children(func() {
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(10).Wrap().Children(func() {
				ui.Row(c).AlignItems(ui.Center).Gap(8).MinWidth(0).Shrink(1).Children(func() {
					ui.Text(c, cat.CloudflareWarpAccountTitle()).FontSize(14).FontWeight(600).TextColor(p.text).SingleLine().Ellipsis("…")
					if acc.AccountType == "unlimited" {
						ui.Box(c).Padding(2, 6, 2, 6).Radius(4).Background(p.accentBg).Children(func() {
							ui.Text(c, cat.CloudflareWarpUnlimitedBadge()).FontSize(11).FontWeight(500).TextColor(p.accentText).NoWrap()
						})
					} else if acc.IsRegistered() {
						ui.Box(c).Padding(2, 6, 2, 6).Radius(4).Background(p.elevated).Children(func() {
							ui.Text(c, cat.CloudflareWarpFreeTierBadge()).FontSize(11).FontWeight(500).TextColor(p.textMuted).NoWrap()
						})
					}
				})

				ui.Row(c).AlignItems(ui.Center).Gap(6).Shrink(0).Children(func() {
					licBtn := ui.ButtonBase(c.Key("btn-toggle-warp-license")).
						Label(cat.CloudflareWarpLicenseToggleBtn()).
						Height(28).Padding(0, 10, 0, 10).Radius(6).
						Background(ui.Transparent)
					if licBtn.Hovered() {
						licBtn.Background(p.elevated)
					}
					licBtn.Children(func() {
						ui.Text(c, cat.CloudflareWarpLicenseToggleBtn()).FontSize(12).FontWeight(500).TextColor(p.textMuted).NoWrap()
					})
					if licBtn.Clicked() {
						a.warpShowLicenseForm = !a.warpShowLicenseForm
					}

					if !acc.IsRegistered() {
						regLabel := cat.CloudflareWarpAccountRegisterBtn()
						if a.warpRegistering {
							regLabel = cat.CloudflareWarpAccountRegistering()
						}
						regBtn := ui.ButtonBase(c.Key("btn-warp-register")).
							Label(regLabel).
							Height(28).Padding(0, 10, 0, 10).Radius(6).
							Background(p.accent).Disabled(a.warpRegistering)
						if !a.warpRegistering && regBtn.Hovered() {
							regBtn.Background(p.accent.Alpha(0.88))
						}
						regBtn.Children(func() {
							ui.Text(c, regLabel).FontSize(12).FontWeight(500).TextColor(ui.RGB(255, 255, 255)).NoWrap()
						})
						if regBtn.Clicked() {
							a.triggerWarpRegister()
						}
					} else {
						regLabel := cat.CloudflareWarpRefreshBtn()
						if a.warpRegistering {
							regLabel = cat.CloudflareWarpAccountRegistering()
						}
						regBtn := ui.ButtonBase(c.Key("btn-warp-register")).
							Label(regLabel).
							Height(28).Padding(0, 10, 0, 10).Radius(6).
							Background(p.elevated).Disabled(a.warpRegistering)
						if !a.warpRegistering && regBtn.Hovered() {
							regBtn.Background(p.cardHover)
						}
						regBtn.Children(func() {
							ui.Text(c, regLabel).FontSize(12).FontWeight(500).TextColor(p.text).NoWrap()
						})
						if regBtn.Clicked() {
							a.triggerWarpRegister()
						}
					}
				})
			})

			if acc.IsRegistered() {
				deviceID := strings.TrimSpace(acc.DeviceID)
				if deviceID == "" {
					deviceID = strings.TrimSpace(acc.MASQUEDeviceID)
				}
				if deviceID == "" {
					deviceID = "-"
				}
				ipv4 := strings.TrimSpace(acc.IPv4)
				if ipv4 == "" {
					ipv4 = strings.TrimSpace(acc.MASQUEIPv4)
				}
				if ipv4 == "" {
					ipv4 = "-"
				}
				ipv6 := strings.TrimSpace(acc.IPv6)
				if ipv6 == "" {
					ipv6 = strings.TrimSpace(acc.MASQUEIPv6)
				}
				if ipv6 == "" {
					ipv6 = "-"
				}

				ui.Grid(c.Key("warp-metrics-grid")).
					Columns(3).Gap(12).Padding(12).Radius(8).Background(p.surface).
					Children(func() {
						// Col 1: Whole cell clickable to copy Device ID
						copyDisabled := deviceID == "-"
						devBtn := ui.ButtonBase(c.Key("btn-copy-warp-device-id")).
							Label("btn-copy-warp-device-id").
							FillWidth().AlignItems(ui.Start).Justify(ui.Start).
							Padding(2, 4, 2, 4).Radius(6).
							Background(ui.Transparent).
							Disabled(copyDisabled)
						if !copyDisabled && devBtn.Hovered() {
							devBtn.Background(p.cardHover)
						}
						devBtn.Children(func() {
							ui.Column(c).Grow(1).MinWidth(0).FillWidth().Gap(3).Children(func() {
								ui.Text(c, cat.CloudflareWarpMetricDeviceCopy()).FontSize(11).TextColor(p.textDim).SingleLine().Ellipsis("…")
								ui.Text(c, deviceID).Font("monospace").FontSize(11).FontWeight(500).
									TextColor(p.text).SingleLine().Ellipsis("…")
							})
						})
						if !copyDisabled && devBtn.Clicked() {
							a.writeClipboard(deviceID, cat.CloudflareWarpToastCopiedDeviceID())
						}

						// Col 2: Virtual IPv4
						ui.Column(c).MinWidth(0).Padding(2, 4, 2, 4).Gap(3).Children(func() {
							ui.Text(c, cat.CloudflareWarpMetricIPv4()).FontSize(11).TextColor(p.textDim).SingleLine().Ellipsis("…")
							ui.Text(c, ipv4).Font("monospace").FontSize(11).FontWeight(500).FontFeatures("tnum").
								TextColor(p.text).SingleLine().Ellipsis("…")
						})

						// Col 3: Virtual IPv6
						ui.Column(c).MinWidth(0).Padding(2, 4, 2, 4).Gap(3).Children(func() {
							ui.Text(c, cat.CloudflareWarpMetricIPv6()).FontSize(11).TextColor(p.textDim).SingleLine().Ellipsis("…")
							ui.Text(c, ipv6).Font("monospace").FontSize(11).FontWeight(500).FontFeatures("tnum").
								TextColor(p.text).SingleLine().Ellipsis("…")
						})
					})
			} else {
				ui.Row(c.Key("warp-unregistered-banner")).
					Padding(8, 12, 8, 12).Radius(8).Background(p.surface).
					Children(func() {
						ui.Text(c, cat.CloudflareWarpUnregisteredHint()).FontSize(12).TextColor(p.textMuted).LineHeight(1.4)
					})
			}

			if a.warpShowLicenseForm {
				ui.Row(c.Key("warp-license-form")).
					AlignItems(ui.Center).Gap(8).
					Padding(8, 10, 8, 10).Radius(8).Background(p.surface).Border(1, p.borderSubtle).
					Children(func() {
						ui.TextInput(c.Key("input-warp-license"), &a.warpLicenseInput).
							Label(cat.CloudflareWarpLicenseTitle()).
							Placeholder(cat.CloudflareWarpLicensePlaceholder()).
							Background(p.card).
							Grow(1)

						bindLabel := cat.CloudflareWarpLicenseBindBtn()
						if a.warpBindingLicense {
							bindLabel = cat.CloudflareWarpLicenseBinding()
						}
						if actionChip(c.Key("btn-warp-bind-license"), p, nil, bindLabel, a.warpBindingLicense).Clicked() {
							a.triggerWarpBindLicense()
						}
					})
			}
		})

	// Card 2: Direct WARP + Side-by-Side 2-Col Transport Grid + Clean Endpoint Scan (HTML Card 2)
	ui.Column(c.Key("warp-direct-card")).
		Gap(12).Padding(16).Radius(10).
		Background(p.card).Border(1, p.borderSubtle).
		Children(func() {
			// Master Direct -> WARP switch
			cnWarp := a.isCnDirectWarpEnabled()
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Children(func() {
				ui.Column(c).Grow(1).Gap(3).MinWidth(0).Children(func() {
					ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
						if cnWarp {
							statusDot(c, p.green)
						} else {
							hollowStatusDot(c, p.textDim.Alpha(0.5))
						}
						ui.Text(c, cat.CloudflareDirectWarpTakeover()).FontSize(14).FontWeight(600).TextColor(p.text)
					})
					ui.Box(c).Padding(0, 0, 0, 15).Children(func() {
						ui.Text(c, cat.CloudflareDirectWarpTakeoverDesc()).FontSize(11).TextColor(p.textMuted).LineHeight(1.4)
					})
				})

				if ui.Switch(c.Key("toggle-direct-warp-takeover"), &cnWarp).Label("toggle-direct-warp-takeover").Changed() {
					a.setCnDirectWarpEnabled(cnWarp)
				}
			})

			ui.Box(c).FillWidth().Height(1).Background(p.borderSubtle)

			// Side-by-Side 2-Column Transport Grid (Direct Default | Chained Default)
			directMode := a.state.Cloudflare.EffectiveDirectMode()
			directSummary := cat.CloudflareWarpTransportMasqueSummary()
			if directMode == warp.ModeWireGuard {
				directSummary = cat.CloudflareWarpTransportWireGuardSummary()
			}
			chainedMode := a.state.Cloudflare.EffectiveChainedMode()
			chainedSummary := cat.CloudflareWarpTransportWireGuardSummary()
			if chainedMode == warp.ModeMASQUE {
				chainedSummary = cat.CloudflareWarpTransportMasqueSummary()
			}

			ui.Row(c.Key("warp-transport-grid")).Gap(12).Wrap().Children(func() {
				a.renderWarpTransportTile(
					c, p,
					"warp-direct-transport-tile",
					cat.CloudflareWarpTransport(),
					directMode,
					directSummary,
					[2]warpTransportSegOption{
						{warp.ModeMASQUE, cat.CloudflareWarpTransportMasque(), "MASQUE"},
						{warp.ModeWireGuard, cat.CloudflareWarpTransportWireGuard(), "WireGuard"},
					},
					func(mode warp.Mode) {
						a.state.Cloudflare.DefaultMode = mode
						a.saveState()
						a.resetWarpNodesHealth(true)
					},
				)

				a.renderWarpTransportTile(
					c, p,
					"warp-chained-transport-tile",
					cat.CloudflareWarpChainedTransport(),
					chainedMode,
					chainedSummary,
					[2]warpTransportSegOption{
						{warp.ModeMASQUE, "btn-warp-chained-masque", "MASQUE"},
						{warp.ModeWireGuard, "btn-warp-chained-wg", "WireGuard"},
					},
					func(mode warp.Mode) {
						a.state.Cloudflare.ChainedMode = mode
						a.saveState()
						a.resetWarpNodesHealth(true)
					},
				)
			})

			// Compact inline MASQUE Prefer HTTP/2 toggle
			if directMode == warp.ModeMASQUE || chainedMode == warp.ModeMASQUE {
				ui.Box(c.Key("warp-prefer-h2-box")).
					Padding(6, 10, 6, 10).Radius(8).Background(p.surface).
					Tooltip(cat.CloudflareWarpPreferH2Desc()).
					Children(func() {
						if switchRow(c, p, "toggle-warp-prefer-h2", cat.CloudflareWarpPreferH2(), &a.state.Cloudflare.MasquePreferH2) {
							a.saveState()
							a.resetWarpNodesHealth(true)
						}
					})
			}

			// Anycast Clean Endpoint & One-Click Scan
			ui.Column(c.Key("warp-clean-endpoint-section")).Gap(8).Children(func() {
				hasCustomEndpoint := strings.TrimSpace(a.warpCleanEndpointInput) != "" || strings.TrimSpace(a.state.Cloudflare.CleanIP) != ""
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(8).Wrap().Children(func() {
					ui.Row(c).AlignItems(ui.Center).Gap(8).MinWidth(0).Shrink(1).Children(func() {
						ui.Text(c, cat.CloudflareWarpCleanEndpoint()).FontSize(12).FontWeight(600).TextColor(p.text).SingleLine().Ellipsis("…")
						if hasCustomEndpoint {
							ui.Text(c, cat.CloudflareWarpEndpointModeManual()).FontSize(11).FontWeight(500).TextColor(p.accentText).NoWrap()
						} else {
							ui.Text(c, cat.CloudflareWarpEndpointModeAuto()).FontSize(11).TextColor(p.textDim).NoWrap()
						}
					})

					ui.Row(c).AlignItems(ui.Center).Gap(6).Shrink(0).Children(func() {
						scanLabel := cat.CloudflareWarpScanBtn()
						if a.warpScanning {
							scanLabel = cat.CloudflareWarpScanningBtn()
						}
						scanBtn := ui.ButtonBase(c.Key("btn-warp-scan-endpoint")).
							Label(scanLabel).
							Padding(3, 6, 3, 6).Radius(6).
							Background(ui.Transparent).
							Disabled(a.warpScanning)
						if !a.warpScanning && scanBtn.Hovered() {
							scanBtn.Background(p.accentBg)
						}
						scanBtn.Children(func() {
							ui.Row(c).AlignItems(ui.Center).Gap(4).Children(func() {
								ui.Icon(c, iconBolt).Size(12, 12).TextColor(p.accentText)
								ui.Text(c, scanLabel).FontSize(12).FontWeight(500).TextColor(p.accentText).NoWrap()
							})
						})
						if scanBtn.Clicked() {
							a.triggerWarpEndpointScan()
						}

						if hasCustomEndpoint {
							resetBtn := ui.ButtonBase(c.Key("btn-warp-reset-auto")).
								Label(cat.CloudflareWarpResetAutoBtn()).
								Padding(3, 6, 3, 6).Radius(6).
								Background(ui.Transparent)
							if resetBtn.Hovered() {
								resetBtn.Background(p.elevated)
							}
							resetBtn.Children(func() {
								ui.Text(c, cat.CloudflareWarpResetAutoBtn()).FontSize(11).TextColor(p.textMuted).NoWrap()
							})
							if resetBtn.Clicked() {
								a.applyWarpCleanEndpoint("")
								a.resetWarpNodesHealth(true)
							}
						}
					})
				})

				inp := ui.TextInput(c.Key("input-warp-clean-endpoint"), &a.warpCleanEndpointInput).
					Label(cat.CloudflareWarpCleanEndpoint()).
					Placeholder(cat.CloudflareWarpCleanEndpointPlaceholder()).
					Tooltip(cat.CloudflareWarpCleanEndpointDesc()).
					Font("monospace").FontSize(11).Height(30)
				if inp.Changed() {
					a.applyWarpCleanEndpoint(a.warpCleanEndpointInput)
				}

				if len(a.warpScanResults) > 0 {
					ui.Column(c.Key("warp-scan-results")).Gap(6).Children(func() {
						ui.Text(c, cat.CloudflareWarpScanResultsTitle()).FontSize(11).FontWeight(600).TextColor(p.textDim)
						ui.Column(c).Radius(8).Background(p.surface).Border(1, p.borderSubtle).Clip().Children(func() {
							for idx, res := range a.warpScanResults {
								selected := strings.TrimSpace(a.warpCleanEndpointInput) == res.Endpoint
								lossPct := int(res.LossRate*100 + 0.5)
								label := fmt.Sprintf("%s (%dms · %d%% loss · %s)", res.Endpoint, res.RTT.Milliseconds(), lossPct, res.Protocol)
								rowBtn := ui.ButtonBase(c.Key(fmt.Sprintf("btn-warp-candidate-%d", idx))).
									Label(label).
									FillWidth().Padding(8, 12, 8, 12).
									AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).
									Background(ui.Transparent)
								if idx > 0 {
									rowBtn.BorderWidth(1, 0, 0, 0).BorderColor(p.borderSubtle)
								}
								if selected {
									rowBtn.Background(p.accentBg.Alpha(0.55))
								} else if rowBtn.Hovered() {
									rowBtn.Background(p.cardHover)
								}
								rttMs := int(res.RTT.Milliseconds())
								if res.RTT > 0 && rttMs < 1 {
									rttMs = 1
								}
								rttCol := latencyThresholdColor(p, rttMs)
								rowBtn.Children(func() {
									ui.Row(c).AlignItems(ui.Center).Gap(8).Grow(1).Shrink(1).MinWidth(0).Children(func() {
										if selected {
											ui.Box(c).Size(8, 8).Radius(999).Background(p.accent).Shrink(0)
										} else {
											ui.Box(c).Size(8, 8).Radius(999).Border(1.5, p.textDim.Alpha(0.6)).Shrink(0)
										}
										epText := ui.Text(c, res.Endpoint).Font("monospace").FontSize(11).FontWeight(500).
											SingleLine().Ellipsis("…")
										if selected {
											epText.TextColor(p.accentText)
										} else {
											epText.TextColor(p.text)
										}
									})
									ui.Row(c).AlignItems(ui.Center).Gap(16).Shrink(0).Children(func() {
										ui.Text(c, warpScanProtocolLabel(res.Protocol)).FontSize(11).TextColor(p.textDim).
											Width(72).TextAlign(ui.End).NoWrap()
										ui.Text(c, fmt.Sprintf("%d%% loss", lossPct)).FontSize(11).FontFeatures("tnum").TextColor(p.textMuted).
											Width(54).TextAlign(ui.End).NoWrap()
										ui.Text(c, fmt.Sprintf("%d ms", rttMs)).FontSize(11).FontWeight(600).FontFeatures("tnum").
											TextColor(rttCol).Width(50).TextAlign(ui.End).NoWrap()
									})
								})
								if rowBtn.Clicked() {
									a.applyWarpCleanEndpoint(res.Endpoint)
									a.resetWarpNodesHealth(true)
								}
							}
						})
					})
				}
			})
		})

	// Card 3: Standalone Attached WARP Nodes (HTML Card 3)
	ui.Column(c.Key("warp-attached-card")).
		Gap(10).Padding(16).Radius(10).
		Background(p.card).Border(1, p.borderSubtle).
		Children(func() {
			var attached []config.Service
			for _, svc := range a.state.Services {
				if svc.EnableWARP || svc.EffectiveProtocol() == config.ProtoWARP {
					attached = append(attached, svc)
				}
			}

			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(8).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
					ui.Text(c, cat.CloudflareWarpAttachedNodes()).FontSize(14).FontWeight(600).TextColor(p.text)
					ui.Text(c, fmt.Sprintf("(%d)", len(attached))).FontSize(12).FontFeatures("tnum").TextColor(p.textDim)
				})
				if len(attached) > 0 {
					ui.Text(c, cat.CloudflareAttachedNodesHint()).FontSize(11).TextColor(p.textDim)
				}
			})

			if len(attached) == 0 {
				ui.Row(c).Justify(ui.Center).Padding(12, 0, 12, 0).Children(func() {
					ui.Text(c, cat.CloudflareWarpNoAttachedNodes()).FontSize(12).TextColor(p.textDim)
				})
			} else {
				ui.Column(c).Gap(6).Children(func() {
					for _, svc := range attached {
						svc := svc
						rt := a.mgr.StatusOf(svc.ID)
						unhealthy := a.isNodeUnhealthy(svc, rt)
						isRunning := rt.State == runner.StateRunning || rt.State == runner.StateStarting
						latText, latColor, latTip := a.serviceLatencyDisplay(p, svc, rt, isRunning, cat)

						rowBtn := ui.ButtonBase(c.Key("warp-attached-node-"+svc.ID)).
							Label(svc.Name).
							FillWidth().Padding(10, 12, 10, 12).Radius(8).
							AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).
							Background(p.surface).Border(1, p.borderSubtle)
						if rowBtn.Hovered() {
							rowBtn.Background(p.cardHover).Border(1, p.border)
						}
						rowBtn.Children(func() {
							ui.Column(c).Grow(1).Shrink(1).MinWidth(0).AlignItems(ui.Start).Gap(3).Children(func() {
								ui.Row(c).AlignItems(ui.Center).Gap(8).MinWidth(0).Children(func() {
									renderServiceStatusDot(c, p, rt, unhealthy)
									nameColor := p.textMuted
									if rt.State == runner.StateRunning || rt.State == runner.StateStarting || rt.State == runner.StateError {
										nameColor = p.text
									}
									ui.Text(c, svc.Name).FontSize(12).FontWeight(600).TextColor(nameColor).
										SingleLine().Ellipsis("…").Shrink(1).MinWidth(0)
									if svc.IsBuiltinWarp() {
										drawerInlineNeutralChip(c, p, cat.BuiltinTag())
									}
								})
								ui.Box(c).Padding(0, 0, 0, 15).Children(func() {
									ui.Text(c, a.attachedWarpNodeMeta(svc)).FontSize(11).TextColor(p.textMuted).
										SingleLine().Ellipsis("…")
								})
							})

							ui.Row(c).AlignItems(ui.Center).Gap(10).Shrink(0).Children(func() {
								if rt.State == runner.StateRunning && unhealthy {
									ui.Text(c, cat.StatusUnhealthy()).FontSize(11).FontWeight(600).TextColor(p.amberText).NoWrap()
								} else if rt.State == runner.StateError {
									ui.Text(c, cat.StatusError()).FontSize(11).FontWeight(600).TextColor(p.redText).NoWrap()
								}
								latWeight := 600
								if latText == "—" {
									latWeight = 500
								}
								latLabel := ui.Text(c, latText).FontSize(12).FontWeight(latWeight).FontFeatures("tnum").
									TextAlign(ui.End).TextColor(latColor).NoWrap()
								if latTip != "" {
									latLabel.Tooltip(latTip)
								}
								ui.Text(c, "›").FontSize(14).TextColor(p.textDim).NoWrap()
							})
						})
						if rowBtn.Clicked() {
							a.activeLogDrawerID = ""
							a.activeNodeDrawerID = svc.ID
						}
					}
				})
			}
		})

	// Card 4: Collapsible Advanced Network Parameters (collapsed by default)
	hasCustomProbe := strings.TrimSpace(a.state.Cloudflare.ProbeURL) != ""
	ui.Column(c.Key("warp-advanced-card")).
		Gap(10).Padding(14, 16, 14, 16).Radius(10).
		Background(p.card).Border(1, p.borderSubtle).
		Children(func() {
			toggleBtn := ui.ButtonBase(c.Key("btn-toggle-warp-advanced")).
				Label(cat.CloudflareWarpAdvancedTitle()).
				FillWidth().Padding(2, 0, 2, 0).
				AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(8).
				Background(ui.Transparent).
				Children(func() {
					ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
						ui.Text(c, cat.CloudflareWarpAdvancedTitle()).FontSize(13).FontWeight(600).TextColor(p.text)
						if hasCustomProbe {
							ui.Text(c, cat.CloudflareWarpCustomizedBadge()).FontSize(11).FontWeight(500).TextColor(p.accentText)
						}
					})
					chevIcon := iconChevronDown
					if a.warpShowAdvanced {
						chevIcon = iconChevronUp
					}
					ui.Icon(c, chevIcon).Size(15, 15).TextColor(p.textDim)
				})
			if toggleBtn.Clicked() {
				a.warpShowAdvanced = !a.warpShowAdvanced
			}

			if a.warpShowAdvanced {
				ui.Column(c).Gap(6).Padding(8, 0, 0, 0).BorderWidth(1, 0, 0, 0).BorderColor(p.borderSubtle).Children(func() {
					ui.Text(c, cat.CloudflareWarpProbeURL()).FontSize(12).FontWeight(500).TextColor(p.text)
					ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
						fieldBox, probeInp, chosen := comboboxField(
							c, p, "input-warp-probe-url",
							cat.CloudflareWarpProbeURL(), cat.ProbeURLDropdownLabel(),
							&a.state.Cloudflare.ProbeURL, &a.warpProbeURLHandle,
							cat.CloudflareWarpProbeURLPlaceholder(), warpProbeURLPresetOptions(cat),
						)
						fieldBox.Grow(1).Shrink(1).MinWidth(0)
						if chosen || probeInp.Changed() {
							a.saveState()
							a.resetWarpNodesHealth(false)
						}
						if hasCustomProbe {
							if subtleActionChip(c.Key("btn-reset-warp-probe-url"), p, nil, cat.CloudflareWarpResetDefaultBtn(), false).Clicked() {
								a.state.Cloudflare.ProbeURL = ""
								a.saveState()
								a.resetWarpNodesHealth(true)
							}
						}
					})
				})
			}
		})
}

func (a *app) renderCloudflareTunnelView(c *ui.Context, p palette) {
	cat := a.catalog()
	tunCfg := &a.state.Cloudflare.Tunnel

	// Single Unified Card (HTML Tunnel layout: Header+Switch | Conditional Hint | Token | 2-Col Bottom Tiles)
	ui.Column(c.Key("cloudflare-tunnel-card")).
		Gap(12).Padding(16).Radius(10).
		Background(p.card).Border(1, p.borderSubtle).
		Children(func() {
			// Header row: status dot + title + quiet status text | Enable Switch
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Gap(8).MinWidth(0).Shrink(1).Children(func() {
					switch {
					case !tunCfg.Enabled:
						hollowStatusDot(c, p.textDim.Alpha(0.5))
					case a.getGateway() != nil && strings.TrimSpace(tunCfg.Token) != "":
						statusDot(c, p.green)
					default:
						statusDot(c, p.amber)
					}
					ui.Text(c, cat.CloudflareTunnelTitle()).FontSize(14).FontWeight(600).TextColor(p.text).SingleLine().Ellipsis("…")
					if !tunCfg.Enabled {
						ui.Text(c, cat.TailnetModeOff()).FontSize(11).TextColor(p.textDim).NoWrap()
					} else if a.getGateway() != nil && strings.TrimSpace(tunCfg.Token) != "" {
						ui.Text(c, cat.CloudflareTunnelConnected()).FontSize(11).FontWeight(500).TextColor(p.greenText).NoWrap()
					} else {
						ui.Text(c, cat.CloudflareTunnelStatusWaiting()).FontSize(11).FontWeight(500).TextColor(p.amberText).NoWrap()
					}
				})

				if ui.Switch(c.Key("toggle-cf-tunnel-enabled"), &tunCfg.Enabled).Label(cat.CloudflareTunnelEnable()).Changed() {
					a.saveState()
				}
			})

			// Conditional amber banners when Tunnel needs Gateway or Token
			if tunCfg.Enabled && !a.state.GatewayEnabled {
				ui.Row(c.Key("tunnel-need-gateway-banner")).
					AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(10).Wrap().
					Padding(8, 12, 8, 12).Radius(8).
					Background(p.amberBg).Border(1, p.amber.Alpha(0.25)).
					Children(func() {
						ui.Row(c).AlignItems(ui.Center).Gap(8).Grow(1).MinWidth(0).Children(func() {
							ui.Icon(c, iconAlert).Size(15, 15).TextColor(p.amberText).Shrink(0)
							ui.Text(c, cat.CloudflareTunnelNeedGatewayHint()).FontSize(12).TextColor(p.amberText).Grow(1).Shrink(1).MinWidth(0)
						})
						if actionChip(c.Key("btn-tunnel-enable-gateway"), p, iconPlay, cat.CloudflareTunnelEnableGatewayBtn(), false).Clicked() {
							a.state.GatewayEnabled = true
							a.saveState()
							if err := a.startGatewayWithFallback(); err != nil {
								a.toast(cat.CloudflareTunnelGatewayStartFailed(err.Error()))
							}
						}
					})
			} else if tunCfg.Enabled && strings.TrimSpace(tunCfg.Token) == "" {
				ui.Row(c.Key("tunnel-need-token-banner")).
					AlignItems(ui.Center).Gap(8).
					Padding(8, 12, 8, 12).Radius(8).
					Background(p.amberBg).Border(1, p.amber.Alpha(0.25)).
					Children(func() {
						ui.Icon(c, iconAlert).Size(15, 15).TextColor(p.amberText).Shrink(0)
						ui.Text(c, cat.CloudflareTunnelNeedTokenHint()).FontSize(12).TextColor(p.amberText).Grow(1).Shrink(1).MinWidth(0)
					})
			}

			ui.Box(c).FillWidth().Height(1).Background(p.borderSubtle)

			// Tunnel Token label row + Show/Paste accent-text buttons + monospace input
			ui.Column(c).Gap(6).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
					ui.Text(c, cat.CloudflareTunnelToken()).FontSize(12).FontWeight(500).TextColor(p.textMuted)
					ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
						visLabel := cat.CloudflareTunnelShowToken()
						if a.tunnelTokenVisible {
							visLabel = cat.CloudflareTunnelHideToken()
						}
						visBtn := ui.ButtonBase(c.Key("btn-toggle-tunnel-token-vis")).
							Label(visLabel).
							Padding(2, 6, 2, 6).Radius(5).
							Background(ui.Transparent)
						if visBtn.Hovered() {
							visBtn.Background(p.accentBg)
						}
						visBtn.Children(func() {
							ui.Text(c, visLabel).FontSize(11).FontWeight(500).TextColor(p.accentText).NoWrap()
						})
						if visBtn.Clicked() {
							a.tunnelTokenVisible = !a.tunnelTokenVisible
						}

						pasteBtn := ui.ButtonBase(c.Key("btn-paste-tunnel-token")).
							Label(cat.CloudflareTunnelPasteToken()).
							Padding(2, 6, 2, 6).Radius(5).
							Background(ui.Transparent)
						if pasteBtn.Hovered() {
							pasteBtn.Background(p.accentBg)
						}
						pasteBtn.Children(func() {
							ui.Text(c, cat.CloudflareTunnelPasteToken()).FontSize(11).FontWeight(500).TextColor(p.accentText).NoWrap()
						})
						if pasteBtn.Clicked() {
							clip := a.readClipboard()
							if clip != "" {
								tunCfg.Token = strings.TrimSpace(clip)
								a.tunnelTokenInput = tunCfg.Token
								a.saveState()
								a.toast(cat.CloudflareTunnelToastPasted())
							}
						}
					})
				})

				tokenInp := ui.TextInput(c.Key("input-cf-tunnel-token"), &tunCfg.Token).
					Label(cat.CloudflareTunnelToken()).
					Placeholder(cat.CloudflareTunnelTokenPlaceholder()).
					Font("monospace").FontSize(12).Height(32).
					Background(p.surface)
				if !a.tunnelTokenVisible {
					tokenInp.Password()
				}
				if tokenInp.Changed() {
					a.saveState()
				}
			})

			// Bottom 2-Column Surface Tile Grid (Protocol | Post-Quantum)
			ui.Row(c.Key("tunnel-options-grid")).Gap(12).Wrap().Children(func() {
				ui.Row(c).
					Grow(1).MinWidth(220).MaxWidthPercent(100).
					Padding(10, 12, 10, 12).Radius(8).Background(p.surface).
					AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(8).
					Children(func() {
						ui.Text(c, cat.CloudflareTunnelProtocol()).FontSize(12).FontWeight(500).TextColor(p.text).SingleLine().Ellipsis("…")

						protoIdx := 0
						switch strings.ToLower(tunCfg.Protocol) {
						case "quic":
							protoIdx = 1
						case "http2":
							protoIdx = 2
						default:
							protoIdx = 0
						}
						protoLabels := []string{"Auto", "QUIC", "HTTP/2"}
						if compactSegmentedControl(c.Key("cf-tunnel-proto-segmented"), p, &protoIdx, protoLabels) {
							switch protoIdx {
							case 0:
								tunCfg.Protocol = "auto"
							case 1:
								tunCfg.Protocol = "quic"
							case 2:
								tunCfg.Protocol = "http2"
							}
							a.saveState()
						}
					})

				ui.Row(c).
					Grow(1).MinWidth(220).MaxWidthPercent(100).
					Padding(10, 12, 10, 12).Radius(8).Background(p.surface).
					AlignItems(ui.Center).
					Tooltip(cat.CloudflareTunnelPostQuantumDesc()).
					Children(func() {
						ui.Box(c).FillWidth().Children(func() {
							if switchRow(c, p, "toggle-cf-tunnel-pq", cat.CloudflareTunnelPostQuantum(), &tunCfg.PostQuantum) {
								a.saveState()
							}
						})
					})
			})
		})
}
