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
		// 1. Header row (context-aware badge, zero duplication with cards)
		ui.Row(c.Key("cloudflare-header")).
			Padding(14, 18, 14, 18).
			AlignItems(ui.Center).
			BorderWidth(0, 0, 1, 0).BorderColor(p.borderSubtle).
			Children(func() {
				ui.Column(c).Gap(2).Children(func() {
					ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
						ui.Text(c, cat.CloudflarePageTitle()).FontSize(17).FontWeight(700).TextColor(p.text)

						if a.cloudflareSubTab == 0 {
							acc := a.getCloudflareAccount()
							if acc.AccountType == "unlimited" {
								statusBadge(c, "WARP+", p.accent, p.accentBg)
							} else if acc.IsRegistered() {
								statusBadge(c, cat.CloudflareWarpAccountRegistered(), p.green, p.greenBg)
							} else {
								statusBadge(c, cat.CloudflareWarpAccountNotRegistered(), p.textDim, p.elevated)
							}
							if a.isCnDirectWarpEnabled() {
								tagPill(c, "Direct ➔ WARP", p.green, p.greenBg)
							}
						} else {
							tunCfg := a.state.Cloudflare.Tunnel
							if !tunCfg.Enabled {
								statusBadge(c, cat.TailnetModeOff(), p.textDim, p.elevated)
							} else if a.getGateway() != nil && strings.TrimSpace(tunCfg.Token) != "" {
								statusBadge(c, cat.CloudflareTunnelConnected(), p.green, p.greenBg)
							} else {
								statusBadge(c, cat.CloudflareTunnelDisconnected(), p.amber, p.amberBg)
							}
						}
					})
					ui.Text(c, cat.CloudflarePageDesc()).FontSize(11).TextColor(p.textDim)
				})

				ui.Box(c).Grow(1)

				subtabLabels := []string{cat.CloudflareSubtabWarp(), cat.CloudflareSubtabTunnel()}
				segmentedControl(c.Key("cloudflare-subtab-ctrl"), p, &a.cloudflareSubTab, subtabLabels)
			})

		// 2. Body scrollable view
		ui.Scroll(c.Key("cloudflare-page-scroll")).
			TrackScroll(&a.cloudflareScroll).
			Grow(1).Fill().
			Padding(18, 20, 24, 20).Gap(14).
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
	ui.Column(c).Grow(1).MinWidth(0).Gap(2).Children(func() {
		ui.Text(c, label).FontSize(11).TextColor(p.textDim)
		ui.Row(c).AlignItems(ui.Center).Gap(4).Children(func() {
			ui.Text(c, display).FontSize(12).FontWeight(600).TextColor(p.text).NoWrap().Ellipsis("…")
			if copyable && display != "-" {
				copyBtn := subtleActionChip(c.Key("btn-copy-warp-device-id"), p, iconCopy, "", false).
					Tooltip(cat.BtnCopy())
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
				ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
					ui.Icon(c, iconNavCloudflare).Size(16, 16).TextColor(p.accent)
					ui.Text(c, cat.CloudflareWarpAccountTitle()).FontSize(14).FontWeight(600).TextColor(p.text)
					if acc.AccountType == "unlimited" {
						tagPill(c, cat.CloudflareWarpUnlimitedBadge(), p.accent, p.accentBg)
					} else if acc.IsRegistered() {
						tagPill(c, cat.CloudflareWarpFreeTierBadge(), p.textMuted, p.surface)
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
				ui.Row(c.Key("warp-metrics-grid")).
					Gap(24).Padding(10, 12, 10, 12).Radius(8).Background(p.surface).
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
				ui.Column(c).Grow(1).Gap(3).Children(func() {
					ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
						ui.Text(c, cat.CloudflareDirectWarpTakeover()).FontSize(14).FontWeight(600).TextColor(p.text)
						if cnWarp {
							tagPill(c, cat.RoutingWarp(), p.green, p.greenBg)
						} else {
							tagPill(c, cat.RoutingDirect(), p.textDim, p.surface)
						}
					})
					ui.Text(c, cat.CloudflareDirectWarpTakeoverDesc()).FontSize(11).TextColor(p.textMuted).LineHeight(1.4)
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
						tagPill(c, cat.CloudflareWarpEndpointModeManual(), p.accentText, p.accentBg)
					} else {
						tagPill(c, cat.CloudflareWarpEndpointModeAuto(), p.textMuted, p.surface)
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
					ui.Column(c.Key("warp-scan-results")).Gap(6).Padding(10).Radius(8).Background(p.surface).Border(1, p.borderSubtle).Children(func() {
						ui.Text(c, cat.CloudflareWarpScanResultsTitle()).FontSize(11).FontWeight(600).TextColor(p.textDim)
						ui.Row(c).Wrap().Gap(6).Children(func() {
							for idx, res := range a.warpScanResults {
								selected := strings.TrimSpace(a.warpCleanEndpointInput) == res.Endpoint
								bg := p.card
								border := p.border
								fg := p.text
								if selected {
									bg = p.accentBg
									border = p.accent.Alpha(0.5)
									fg = p.accent
								}
								lossPct := int(res.LossRate*100 + 0.5)
								label := fmt.Sprintf("%s (%dms · %d%% loss · %s)", res.Endpoint, res.RTT.Milliseconds(), lossPct, res.Protocol)
								pillBtn := ui.ButtonBase(c.Key(fmt.Sprintf("btn-warp-candidate-%d", idx))).
									Padding(4, 9, 4, 9).Radius(6).
									Background(bg).Border(1, border).
									Children(func() {
										ui.Text(c, label).FontSize(11).TextColor(fg)
									})
								if pillBtn.Clicked() {
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
					tagPill(c, fmt.Sprintf("%d", len(attached)), p.textMuted, p.surface)
				})
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

						dotColor := p.textDim.Alpha(0.4)
						if rt.State == runner.StateRunning {
							if unhealthy {
								dotColor = p.amber
							} else {
								dotColor = p.green
							}
						} else if rt.State == runner.StateError {
							dotColor = p.red
						}

						rowBtn := ui.ButtonBase(c.Key("warp-attached-node-"+svc.ID)).
							Label(svc.Name).
							Padding(8, 10, 8, 10).Radius(8).
							Background(p.surface).Border(1, p.borderSubtle)
						if rowBtn.Hovered() {
							rowBtn.Background(p.cardHover)
						}
						rowBtn.Children(func() {
							ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(10).Children(func() {
								ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
									ui.Box(c).Size(7, 7).Radius(999).Background(dotColor)
									ui.Text(c, svc.Name).FontSize(12).FontWeight(600).TextColor(p.text)
									if isDirect {
										tagPill(c, cat.CloudflareWarpDirectBadge(), p.accent, p.accentBg)
									} else {
										tagPill(c, fmt.Sprintf("%s ➔ WARP", strings.ToUpper(string(svc.EffectiveProtocol()))), p.green, p.greenBg)
									}
									if rt.State == runner.StateRunning {
										if unhealthy {
											tagPill(c, cat.StatusUnhealthy(), p.amber, p.amberBg)
										} else {
											tagPill(c, cat.StatusRunning(), p.green, p.greenBg)
										}
									} else if rt.State == runner.StateError {
										tagPill(c, cat.StatusError(), p.red, p.redBg)
									} else {
										tagPill(c, cat.StatusStopped(), p.textDim, p.card)
									}
								})

								ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
									if rt.State == runner.StateRunning && rt.Latency > 0 {
										tagPill(c, fmt.Sprintf("%dms", max(1, rt.Latency.Milliseconds())), p.textMuted, p.card)
									}
									ep := svc.CompactRemoteEndpoint()
									if ep != "" {
										ui.Text(c, ep).FontSize(11).TextColor(p.textDim)
									}
									ui.Icon(c, iconInfo).Size(13, 13).TextColor(p.textDim)
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
					ui.Text(c, cat.CloudflareTunnelTitle()).FontSize(14).FontWeight(600).TextColor(p.text)
					if !tunCfg.Enabled {
						statusBadge(c, cat.TailnetModeOff(), p.textDim, p.surface)
					} else if a.getGateway() != nil && strings.TrimSpace(tunCfg.Token) != "" {
						statusBadge(c, cat.CloudflareTunnelConnected(), p.green, p.greenBg)
					} else {
						statusBadge(c, cat.CloudflareTunnelStatusWaiting(), p.amber, p.amberBg)
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
