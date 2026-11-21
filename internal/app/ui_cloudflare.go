package app

import (
	"fmt"
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
		// 1. Fixed Header row (single quiet status dot + summary, no duplicate pills)
		ui.Row(c.Key("cloudflare-header")).
			Padding(14, 18, 14, 18).
			AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).
			Background(p.surface).
			BorderWidth(0, 0, 1, 0).BorderColor(p.borderSubtle).
			Children(func() {
				ui.Row(c).AlignItems(ui.Center).Gap(10).MinWidth(0).Shrink(1).Children(func() {
					ui.Text(c, cat.CloudflarePageTitle()).FontSize(17).FontWeight(700).TextColor(p.text).NoWrap()

					ui.Row(c).AlignItems(ui.Center).Gap(6).MinWidth(0).Shrink(1).Children(func() {
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
								FontSize(12).TextColor(p.textMuted).SingleLine().Ellipsis("…")
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
							ui.Text(c, tunText).FontSize(12).TextColor(p.textMuted).SingleLine().Ellipsis("…")
						}
					})
				})

				subtabLabels := []string{cat.CloudflareSubtabWarp(), cat.CloudflareSubtabTunnel()}
				segmentedControl(c.Key("cloudflare-subtab-ctrl"), p, &a.cloudflareSubTab, subtabLabels)
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

func (a *app) renderCloudflareMetricCol(c *ui.Context, p palette, label, value string, copyable bool) {
	cat := a.catalog()
	display := strings.TrimSpace(value)
	if display == "" {
		display = "-"
	}
	ui.Column(c).MinWidth(0).Gap(3).Children(func() {
		ui.Text(c, label).FontSize(11).TextColor(p.textDim).SingleLine().Ellipsis("…")
		ui.Row(c).AlignItems(ui.Center).Gap(4).MinWidth(0).Children(func() {
			ui.Text(c, display).Font("monospace").FontSize(11).FontWeight(500).FontFeatures("tnum").
				TextColor(p.text).SingleLine().Ellipsis("…").Shrink(1).MinWidth(0)
			if copyable && display != "-" {
				copyBtn := quietRowIconButton(c.Key("btn-copy-warp-device-id"), p, iconCopy, cat.BtnCopy(), false, false).
					Size(22, 22).Tooltip(cat.BtnCopy())
				if copyBtn.Clicked() {
					a.writeClipboard(display, cat.CloudflareWarpToastCopiedDeviceID())
				}
			}
		})
	})
}

func (a *app) renderCloudflareWarpView(c *ui.Context, p palette) {
	cat := a.catalog()
	acc := a.getCloudflareAccount()

	// Card 1: WARP Device & Credentials (3-column metrics + progressive License form)
	ui.Column(c.Key("warp-account-card")).
		Gap(12).Padding(16).Radius(10).
		Background(p.card).Border(1, p.borderSubtle).
		Children(func() {
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(10).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Gap(8).MinWidth(0).Shrink(1).Children(func() {
					ui.Icon(c, iconNavCloudflare).Size(15, 15).TextColor(p.accent).Shrink(0)
					ui.Text(c, cat.CloudflareWarpAccountTitle()).FontSize(14).FontWeight(600).TextColor(p.text).SingleLine().Ellipsis("…")
					if acc.AccountType == "unlimited" {
						drawerInlineAccentChip(c, p, cat.CloudflareWarpUnlimitedBadge())
					} else if acc.IsRegistered() {
						drawerInlineNeutralChip(c, p, cat.CloudflareWarpFreeTierBadge())
					}
				})

				ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
					if subtleActionChip(c.Key("btn-toggle-warp-license"), p, nil, cat.CloudflareWarpLicenseToggleBtn(), false).Clicked() {
						a.warpShowLicenseForm = !a.warpShowLicenseForm
					}

					if !acc.IsRegistered() {
						regLabel := cat.CloudflareWarpAccountRegisterBtn()
						if a.warpRegistering {
							regLabel = cat.CloudflareWarpAccountRegistering()
						}
						if primaryPillButton(c.Key("btn-warp-register"), p, nil, regLabel, p.accent, a.warpRegistering).Clicked() {
							a.triggerWarpRegister()
						}
					} else {
						regLabel := cat.CloudflareWarpRefreshBtn()
						if a.warpRegistering {
							regLabel = cat.CloudflareWarpAccountRegistering()
						}
						if actionChip(c.Key("btn-warp-register"), p, iconRefresh, regLabel, a.warpRegistering).Clicked() {
							a.triggerWarpRegister()
						}
					}
				})
			})

			if acc.IsRegistered() {
				deviceID := acc.DeviceID
				if deviceID == "" {
					deviceID = acc.MASQUEDeviceID
				}
				ipv4 := acc.IPv4
				if ipv4 == "" {
					ipv4 = acc.MASQUEIPv4
				}
				ipv6 := acc.IPv6
				if ipv6 == "" {
					ipv6 = acc.MASQUEIPv6
				}
				ui.Grid(c.Key("warp-metrics-grid")).
					Columns(3).Gap(16).Padding(10, 12, 10, 12).Radius(8).Background(p.surface).
					Children(func() {
						a.renderCloudflareMetricCol(c, p, cat.CloudflareWarpMetricDevice(), deviceID, true)
						a.renderCloudflareMetricCol(c, p, "IPv4", ipv4, false)
						a.renderCloudflareMetricCol(c, p, "IPv6", ipv6, false)
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

	// Card 2: Direct Local WARP (Direct ➔ WARP)
	ui.Column(c.Key("warp-direct-card")).
		Gap(12).Padding(16).Radius(10).
		Background(p.card).Border(1, p.borderSubtle).
		Children(func() {
			// Section title + Master Direct -> WARP switch (single source of truth on preset-cn-direct)
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

			ui.Box(c).Fill().Height(1).Background(p.borderSubtle)

			// Direct transport protocol
			curModeIdx := 0
			if a.state.Cloudflare.EffectiveDirectMode() == warp.ModeWireGuard {
				curModeIdx = 1
			}
			ui.Column(c).Gap(6).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Children(func() {
					ui.Text(c, cat.CloudflareWarpTransport()).FontSize(12).FontWeight(600).TextColor(p.text)
					transportLabels := []string{
						cat.CloudflareWarpTransportMasque(),
						cat.CloudflareWarpTransportWireGuard(),
					}
					if segmentedControl(c.Key("warp-mode-segmented"), p, &curModeIdx, transportLabels) {
						if curModeIdx == 1 {
							a.state.Cloudflare.DefaultMode = warp.ModeWireGuard
						} else {
							a.state.Cloudflare.DefaultMode = warp.ModeMASQUE
						}
						a.saveState()
					}
				})
				a.renderWarpTransportGuide(c, p, "warp-global-transport", curModeIdx, false)
			})

			// MASQUE Prefer HTTP/2 toggle (relevant when either direct or chained uses MASQUE)
			if a.state.Cloudflare.EffectiveDirectMode() == warp.ModeMASQUE || a.state.Cloudflare.EffectiveChainedMode() == warp.ModeMASQUE {
				ui.Column(c.Key("warp-prefer-h2-box")).Gap(3).Padding(8, 10, 8, 10).Radius(8).Background(p.surface).Children(func() {
					if switchRow(c, p, "toggle-warp-prefer-h2", cat.CloudflareWarpPreferH2(), &a.state.Cloudflare.MasquePreferH2) {
						a.saveState()
					}
					ui.Text(c, cat.CloudflareWarpPreferH2Desc()).FontSize(11).TextColor(p.textMuted).LineHeight(1.4)
				})
			}

			ui.Box(c).Fill().Height(1).Background(p.borderSubtle)

			// Anycast Clean Endpoint & One-Click Scan (only applies to Direct WARP)
			ui.Column(c.Key("warp-clean-endpoint-section")).Gap(8).Children(func() {
				hasCustomEndpoint := strings.TrimSpace(a.warpCleanEndpointInput) != "" || strings.TrimSpace(a.state.Cloudflare.CleanIP) != ""
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
					ui.Text(c, cat.CloudflareWarpCleanEndpoint()).FontSize(12).FontWeight(600).TextColor(p.text)
					if hasCustomEndpoint {
						ui.Text(c, cat.CloudflareWarpEndpointModeManual()).FontSize(11).FontWeight(500).TextColor(p.accentText)
					} else {
						ui.Text(c, cat.CloudflareWarpEndpointModeAuto()).FontSize(11).TextColor(p.textMuted)
					}
				})

				ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
					inp := ui.TextInput(c.Key("input-warp-clean-endpoint"), &a.warpCleanEndpointInput).
						Label(cat.CloudflareWarpCleanEndpoint()).
						Placeholder(cat.CloudflareWarpCleanEndpointPlaceholder()).
						Grow(1)
					if inp.Changed() {
						a.applyWarpCleanEndpoint(a.warpCleanEndpointInput)
					}

					scanLabel := cat.CloudflareWarpScanBtn()
					if a.warpScanning {
						scanLabel = cat.CloudflareWarpScanningBtn()
					}
					if actionChip(c.Key("btn-warp-scan-endpoint"), p, iconBolt, scanLabel, a.warpScanning).Clicked() {
						a.triggerWarpEndpointScan()
					}

					if hasCustomEndpoint {
						if subtleActionChip(c.Key("btn-warp-reset-auto"), p, nil, cat.CloudflareWarpResetAutoBtn(), false).Clicked() {
							a.applyWarpCleanEndpoint("")
						}
					}
				})

				ui.Text(c, cat.CloudflareWarpCleanEndpointDesc()).FontSize(11).TextColor(p.textMuted).LineHeight(1.4)

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
								rttCol := latencyThresholdColor(p, rttMs)
								rowBtn.Children(func() {
									ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(10).Children(func() {
										ui.Row(c).AlignItems(ui.Center).Gap(8).MinWidth(0).Shrink(1).Children(func() {
											if selected {
												statusDot(c, p.accent)
											} else {
												hollowStatusDot(c, p.textDim.Alpha(0.6))
											}
											epText := ui.Text(c, res.Endpoint).Font("monospace").FontSize(11).FontWeight(500).
												SingleLine().Ellipsis("…")
											if selected {
												epText.TextColor(p.accentText)
											} else {
												epText.TextColor(p.text)
											}
										})
										ui.Row(c).AlignItems(ui.Center).Gap(12).Shrink(0).Children(func() {
											ui.Text(c, strings.ToUpper(res.Protocol)).FontSize(11).TextColor(p.textDim).NoWrap()
											ui.Text(c, fmt.Sprintf("%d%% loss", lossPct)).FontSize(11).FontFeatures("tnum").TextColor(p.textMuted).NoWrap()
											ui.Text(c, fmt.Sprintf("%dms", rttMs)).FontSize(11).FontWeight(600).FontFeatures("tnum").
												TextColor(rttCol).Width(46).TextAlign(ui.End).NoWrap()
										})
									})
								})
								if rowBtn.Clicked() {
									a.applyWarpCleanEndpoint(res.Endpoint)
								}
							}
						})
					})
				}
			})
		})

	// Card 3: Chained Proxy WARP (Proxy ➔ WARP) + Interactive Attached Nodes List
	ui.Column(c.Key("warp-chained-card")).
		Gap(12).Padding(16).Radius(10).
		Background(p.card).Border(1, p.borderSubtle).
		Children(func() {
			ui.Text(c, cat.CloudflareWarpChainedSectionTitle()).FontSize(14).FontWeight(600).TextColor(p.text)

			// Chained default protocol with dynamic matching description
			chainedIdx := 1
			if a.state.Cloudflare.EffectiveChainedMode() == warp.ModeMASQUE {
				chainedIdx = 0
			}
			ui.Column(c.Key("warp-chained-mode-box")).Gap(6).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Children(func() {
					ui.Text(c, cat.CloudflareWarpChainedTransport()).FontSize(12).FontWeight(600).TextColor(p.text)
					if segmentedControl(c.Key("warp-chained-mode-segmented"), p, &chainedIdx, []string{"MASQUE", "WireGuard"}) {
						if chainedIdx == 0 {
							a.state.Cloudflare.ChainedMode = warp.ModeMASQUE
						} else {
							a.state.Cloudflare.ChainedMode = warp.ModeWireGuard
						}
						a.saveState()
					}
				})
				chainedSummary := cat.CloudflareWarpTransportWireGuardSummary()
				if chainedIdx == 0 {
					chainedSummary = cat.CloudflareWarpTransportMasqueSummary()
				}
				ui.Text(c, chainedSummary).FontSize(11).TextColor(p.textMuted).LineHeight(1.4)
			})

			ui.Box(c).Fill().Height(1).Background(p.borderSubtle)

			var attached []config.Service
			for _, svc := range a.state.Services {
				if svc.EnableWARP || svc.EffectiveProtocol() == config.ProtoWARP {
					attached = append(attached, svc)
				}
			}

			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
					ui.Text(c, cat.CloudflareWarpAttachedNodes()).FontSize(12).FontWeight(600).TextColor(p.text)
					ui.Text(c, fmt.Sprintf("%d", len(attached))).FontSize(11).FontFeatures("tnum").TextColor(p.textDim)
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
						isDirect := svc.EffectiveProtocol() == config.ProtoWARP
						rt := a.mgr.StatusOf(svc.ID)
						unhealthy := a.isNodeUnhealthy(svc, rt)

						metaParts := []string{}
						if isDirect {
							metaParts = append(metaParts, cat.CloudflareWarpDirectBadge(), a.warpTransportPillLabel(svc))
						} else {
							metaParts = append(metaParts, nodeProtocolEngineLabel(svc)+" ➔ "+a.warpTransportPillLabel(svc))
						}
						if ep := svc.CompactRemoteEndpoint(); ep != "" {
							metaParts = append(metaParts, ep)
						}
						metaLine := strings.Join(metaParts, " · ")

						rowBtn := ui.ButtonBase(c.Key("warp-attached-node-"+svc.ID)).
							Label(svc.Name).
							FillWidth().Padding(10, 12, 10, 12).Radius(8).
							Background(p.surface).Border(1, p.borderSubtle)
						if rowBtn.Hovered() {
							rowBtn.Background(p.cardHover).Border(1, p.border)
						}
						rowBtn.Children(func() {
							ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Children(func() {
								ui.Column(c).Grow(1).Shrink(1).MinWidth(0).Gap(3).Children(func() {
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
										ui.Text(c, metaLine).FontSize(11).TextColor(p.textMuted).
											SingleLine().Ellipsis("…")
									})
								})

								ui.Row(c).AlignItems(ui.Center).Gap(10).Shrink(0).Children(func() {
									if rt.State == runner.StateRunning && unhealthy {
										ui.Text(c, cat.StatusUnhealthy()).FontSize(11).FontWeight(600).TextColor(p.amber).NoWrap()
									} else if rt.State == runner.StateError {
										ui.Text(c, cat.StatusError()).FontSize(11).FontWeight(600).TextColor(p.red).NoWrap()
									}
									if rt.State == runner.StateRunning && rt.Latency > 0 {
										ms := max(1, int(rt.Latency.Milliseconds()))
										ui.Text(c, fmt.Sprintf("%dms", ms)).FontSize(12).FontWeight(600).FontFeatures("tnum").
											TextColor(latencyThresholdColor(p, ms)).NoWrap()
									}
									ui.Text(c, "›").FontSize(14).TextColor(p.textDim).NoWrap()
								})
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

	// Collapsible Card 4: Advanced Network Parameters (collapsed by default)
	hasCustomProbe := strings.TrimSpace(a.state.Cloudflare.ProbeURL) != ""
	ui.Column(c.Key("warp-advanced-card")).
		Gap(10).Padding(14, 16, 14, 16).Radius(10).
		Background(p.card).Border(1, p.borderSubtle).
		Children(func() {
			toggleBtn := ui.ButtonBase(c.Key("btn-toggle-warp-advanced")).
				Label(cat.CloudflareWarpAdvancedTitle()).
				Padding(2, 0, 2, 0).Background(ui.Transparent).
				Children(func() {
					ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
						ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
							ui.Text(c, cat.CloudflareWarpAdvancedTitle()).FontSize(13).FontWeight(600).TextColor(p.text)
							if hasCustomProbe {
								tagPill(c, cat.CloudflareWarpCustomizedBadge(), p.accentText, p.accentBg)
							}
						})
						chevIcon := iconChevronDown
						if a.warpShowAdvanced {
							chevIcon = iconChevronUp
						}
						ui.Icon(c, chevIcon).Size(15, 15).TextColor(p.textDim)
					})
				})
			if toggleBtn.Clicked() {
				a.warpShowAdvanced = !a.warpShowAdvanced
			}

			if a.warpShowAdvanced {
				ui.Column(c).Gap(6).Padding(8, 0, 0, 0).BorderWidth(1, 0, 0, 0).BorderColor(p.borderSubtle).Children(func() {
					ui.Text(c, cat.CloudflareWarpProbeURL()).FontSize(12).FontWeight(500).TextColor(p.text)
					ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
						probeInp := ui.TextInput(c.Key("input-warp-probe-url"), &a.state.Cloudflare.ProbeURL).
							Placeholder(cat.CloudflareWarpProbeURLPlaceholder()).
							Grow(1)
						if probeInp.Changed() {
							a.saveState()
						}
						if hasCustomProbe {
							if subtleActionChip(c.Key("btn-reset-warp-probe-url"), p, nil, cat.CloudflareWarpResetDefaultBtn(), false).Clicked() {
								a.state.Cloudflare.ProbeURL = ""
								a.saveState()
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

	// Card 1: Zero Trust Tunnel Status & Master Switch
	ui.Column(c.Key("cloudflare-tunnel-status-card")).
		Gap(10).Padding(16).Radius(10).
		Background(p.card).Border(1, p.borderSubtle).
		Children(func() {
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
					switch {
					case !tunCfg.Enabled:
						hollowStatusDot(c, p.textDim.Alpha(0.5))
					case a.getGateway() != nil && strings.TrimSpace(tunCfg.Token) != "":
						statusDot(c, p.green)
					default:
						statusDot(c, p.amber)
					}
					ui.Text(c, cat.CloudflareTunnelTitle()).FontSize(14).FontWeight(600).TextColor(p.text)
					if !tunCfg.Enabled {
						ui.Text(c, cat.TailnetModeOff()).FontSize(11).TextColor(p.textDim)
					} else if a.getGateway() != nil && strings.TrimSpace(tunCfg.Token) != "" {
						ui.Text(c, cat.CloudflareTunnelConnected()).FontSize(11).FontWeight(500).TextColor(p.green)
					} else {
						ui.Text(c, cat.CloudflareTunnelStatusWaiting()).FontSize(11).FontWeight(500).TextColor(p.amber)
					}
				})

				if switchRow(c, p, "toggle-cf-tunnel-enabled", cat.CloudflareTunnelEnable(), &tunCfg.Enabled) {
					a.saveState()
				}
			})

			if tunCfg.Enabled && !a.state.GatewayEnabled {
				ui.Row(c.Key("tunnel-need-gateway-banner")).
					AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(10).
					Padding(8, 12, 8, 12).Radius(8).
					Background(p.amberBg).Border(1, p.amber.Alpha(0.25)).
					Children(func() {
						ui.Row(c).AlignItems(ui.Center).Gap(8).Grow(1).Children(func() {
							ui.Icon(c, iconAlert).Size(15, 15).TextColor(p.amber)
							ui.Text(c, cat.CloudflareTunnelNeedGatewayHint()).FontSize(12).TextColor(p.amber).Grow(1)
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
						ui.Icon(c, iconAlert).Size(15, 15).TextColor(p.amber)
						ui.Text(c, cat.CloudflareTunnelNeedTokenHint()).FontSize(12).TextColor(p.amber).Grow(1)
					})
			}
		})

	// Card 2: Credentials & Transport Parameters
	ui.Column(c.Key("cloudflare-tunnel-card")).
		Gap(12).Padding(16).Radius(10).
		Background(p.card).Border(1, p.borderSubtle).
		Children(func() {
			// Token input + visibility toggle + paste chip
			ui.Column(c).Gap(6).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
					ui.Text(c, cat.CloudflareTunnelToken()).FontSize(12).FontWeight(600).TextColor(p.text)
					ui.Row(c).AlignItems(ui.Center).Gap(4).Children(func() {
						visLabel := cat.CloudflareTunnelShowToken()
						if a.tunnelTokenVisible {
							visLabel = cat.CloudflareTunnelHideToken()
						}
						if subtleActionChip(c.Key("btn-toggle-tunnel-token-vis"), p, nil, visLabel, false).Clicked() {
							a.tunnelTokenVisible = !a.tunnelTokenVisible
						}
						if subtleActionChip(c.Key("btn-paste-tunnel-token"), p, iconPaste, cat.CloudflareTunnelPasteToken(), false).Clicked() {
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
					Grow(1)
				if !a.tunnelTokenVisible {
					tokenInp.Password()
				}
				if tokenInp.Changed() {
					a.saveState()
				}
			})

			ui.Box(c).Fill().Height(1).Background(p.borderSubtle)

			// Protocol selector: [Auto] [QUIC] [HTTP/2]
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Children(func() {
				ui.Column(c).Gap(2).Children(func() {
					ui.Text(c, cat.CloudflareTunnelProtocol()).FontSize(13).FontWeight(500).TextColor(p.text)
					ui.Text(c, cat.CloudflareTunnelProtocolDesc()).FontSize(11).TextColor(p.textMuted)
				})

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
				if segmentedControl(c.Key("cf-tunnel-proto-segmented"), p, &protoIdx, protoLabels) {
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

			ui.Box(c).Fill().Height(1).Background(p.borderSubtle)

			// Post Quantum Cryptography switch
			ui.Column(c).Gap(2).Children(func() {
				if switchRow(c, p, "toggle-cf-tunnel-pq", cat.CloudflareTunnelPostQuantum(), &tunCfg.PostQuantum) {
					a.saveState()
				}
				ui.Text(c, cat.CloudflareTunnelPostQuantumDesc()).FontSize(11).TextColor(p.textMuted)
			})
		})
}
