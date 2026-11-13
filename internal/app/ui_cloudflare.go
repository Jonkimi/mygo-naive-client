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

func (a *app) renderCloudflarePage(c *ui.Context, p palette) {
	cat := a.catalog()

	ui.Column(c.Key("cloudflare-page")).Grow(1).Fill().MinHeight(0).Children(func() {
		// 1. Header row
		ui.Row(c.Key("cloudflare-header")).
			Padding(14, 18, 14, 18).
			AlignItems(ui.Center).
			BorderWidth(0, 0, 1, 0).BorderColor(p.borderSubtle).
			Children(func() {
				ui.Column(c).Gap(2).Children(func() {
					ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
						ui.Text(c, cat.CloudflarePageTitle()).FontSize(17).FontWeight(700).TextColor(p.text)
						if a.state.Cloudflare.Account.IsRegistered() {
							tagPill(c, cat.CloudflareWarpAccountRegistered(), p.green, p.greenBg)
						} else {
							tagPill(c, cat.CloudflareWarpAccountNotRegistered(), p.textDim, p.card)
						}
						if a.state.Cloudflare.Account.AccountType == "unlimited" {
							tagPill(c, "WARP+", p.accent, p.accentBg)
						}
					})
					ui.Text(c, cat.CloudflarePageDesc()).FontSize(11).TextColor(p.textDim)
				})

				ui.Box(c).Grow(1)

				// Subtab selector: [WARP 出口匿名] [Tunnel 内网穿透]
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
		{0, cat.CloudflareWarpTransportAutoShort(), cat.CloudflareWarpTransportAutoDesc()},
		{1, cat.CloudflareWarpTransportMasqueShort(), cat.CloudflareWarpTransportMasqueDesc()},
		{2, cat.CloudflareWarpTransportWireGuardShort(), cat.CloudflareWarpTransportWireGuardDesc()},
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

	ui.Column(c.Key(keyPrefix+"-guide")).Gap(6).Children(func() {
		for _, item := range items {
			selected := item.idx == modeIdx
			bg := p.surface
			border := p.borderSubtle
			titleColor := p.text
			descColor := p.textMuted
			if selected {
				bg = p.accentBg
				border = p.accent.Alpha(0.3)
				titleColor = p.accent
				descColor = p.text
			}
			ui.Column(c.Key(fmt.Sprintf("%s-guide-%d", keyPrefix, item.idx))).
				Gap(3).Padding(8, 10, 8, 10).Radius(6).
				Background(bg).Border(1, border).
				Children(func() {
					ui.Text(c, item.title).FontSize(11).FontWeight(600).TextColor(titleColor)
					ui.Text(c, item.desc).FontSize(11).TextColor(descColor).LineHeight(1.4)
				})
		}
	})
}

func (a *app) renderCloudflareWarpView(c *ui.Context, p palette) {
	cat := a.catalog()
	acc := a.state.Cloudflare.Account

	// Card 1: Account & Credentials
	ui.Column(c.Key("warp-account-card")).
		Gap(12).Padding(16).Radius(10).
		Background(p.card).Border(1, p.borderSubtle).
		Children(func() {
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
					ui.Text(c, cat.CloudflareWarpAccountTitle()).FontSize(14).FontWeight(600).TextColor(p.text)
					if acc.IsRegistered() {
						tagPill(c, cat.CloudflareWarpAccountRegistered(), p.green, p.greenBg)
					} else {
						tagPill(c, cat.CloudflareWarpAccountNotRegistered(), p.textDim, p.surface)
					}
					if acc.AccountType == "unlimited" {
						tagPill(c, "WARP+ Unlimited", p.accent, p.accentBg)
					}
				})

				regBtnLabel := cat.CloudflareWarpAccountRegisterBtn()
				if a.warpRegistering {
					regBtnLabel = cat.CloudflareWarpAccountRegistering()
				}
				btn := ui.Button(c.Key("btn-warp-register"), regBtnLabel).
					FontSize(12).Radius(6).
					Background(p.accent).TextColor(ui.RGB(255, 255, 255)).
					Padding(6, 12, 6, 12).
					Disabled(a.warpRegistering)
				if btn.Clicked() {
					a.triggerWarpRegister()
				}
			})

			// Account Details
			if acc.IsRegistered() {
				ui.Column(c).Gap(6).Padding(10).Radius(6).Background(p.surface).Children(func() {
					if acc.DeviceID != "" {
						ui.Row(c).Gap(8).Children(func() {
							ui.Text(c, "Device ID:").FontSize(11).FontWeight(600).TextColor(p.textDim).Width(80)
							ui.Text(c, acc.DeviceID).FontSize(11).TextColor(p.text)
						})
					}
					if acc.IPv4 != "" {
						ui.Row(c).Gap(8).Children(func() {
							ui.Text(c, "IPv4:").FontSize(11).FontWeight(600).TextColor(p.textDim).Width(80)
							ui.Text(c, acc.IPv4).FontSize(11).TextColor(p.text)
						})
					}
					if acc.IPv6 != "" {
						ui.Row(c).Gap(8).Children(func() {
							ui.Text(c, "IPv6:").FontSize(11).FontWeight(600).TextColor(p.textDim).Width(80)
							ui.Text(c, acc.IPv6).FontSize(11).TextColor(p.text)
						})
					}
				})
			}

			// License Key binding
			ui.Row(c).AlignItems(ui.Center).Gap(10).Children(func() {
				ui.TextInput(c.Key("input-warp-license"), &a.warpLicenseInput).
					Label(cat.CloudflareWarpLicenseTitle()).
					Placeholder("26-character WARP+ License Key").
					Grow(1)

				bindBtnLabel := cat.CloudflareWarpLicenseBindBtn()
				if a.warpBindingLicense {
					bindBtnLabel = cat.CloudflareWarpLicenseBinding()
				}
				bindBtn := ui.Button(c.Key("btn-warp-bind-license"), bindBtnLabel).
					FontSize(12).Radius(6).
					Background(p.card).Border(1, p.border).TextColor(p.text).
					Padding(6, 12, 6, 12).
					Disabled(a.warpBindingLicense)
				if bindBtn.Clicked() {
					a.triggerWarpBindLicense()
				}
			})
		})

	// Card 1.5: Direct ➔ WARP Takeover Toggle
	ui.Column(c.Key("warp-direct-takeover-card")).
		Gap(10).Padding(16).Radius(10).
		Background(p.card).Border(1, p.borderSubtle).
		Children(func() {
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
					ui.Text(c, cat.CloudflareDirectWarpTakeover()).FontSize(14).FontWeight(600).TextColor(p.text)
					if a.state.Cloudflare.DirectWarpEnabled {
						tagPill(c, cat.RoutingWarp(), p.green, p.greenBg)
					} else {
						tagPill(c, cat.RoutingDirect(), p.textDim, p.surface)
					}
				})

				if switchRow(c, p, "toggle-direct-warp-takeover", "", &a.state.Cloudflare.DirectWarpEnabled) {
					for i := range a.state.RoutingRules {
						if a.state.RoutingRules[i].ID == "preset-lan-direct" {
							if a.state.Cloudflare.DirectWarpEnabled {
								a.state.RoutingRules[i].Action = routing.RouteAction{Type: routing.ActionWarp}
							} else {
								a.state.RoutingRules[i].Action = routing.RouteAction{Type: routing.ActionDirect}
							}
							break
						}
					}
					a.saveState()
				}
			})
			ui.Text(c, cat.CloudflareDirectWarpTakeoverDesc()).FontSize(11).TextColor(p.textMuted)
		})

	// Card 2: Transport & Clean Endpoint Settings
	ui.Column(c.Key("warp-transport-card")).
		Gap(12).Padding(16).Radius(10).
		Background(p.card).Border(1, p.borderSubtle).
		Children(func() {
			ui.Text(c, cat.CloudflareWarpTransport()).FontSize(14).FontWeight(600).TextColor(p.text)

			// Transport Mode
			curModeIdx := 0
			switch a.state.Cloudflare.DefaultMode {
			case warp.ModeAuto:
				curModeIdx = 0
			case warp.ModeMASQUE:
				curModeIdx = 1
			case warp.ModeWireGuard:
				curModeIdx = 2
			}

			transportLabels := []string{
				cat.CloudflareWarpTransportAuto(),
				cat.CloudflareWarpTransportMasque(),
				cat.CloudflareWarpTransportWireGuard(),
			}

			if segmentedControl(c.Key("warp-mode-segmented"), p, &curModeIdx, transportLabels) {
				switch curModeIdx {
				case 0:
					a.state.Cloudflare.DefaultMode = warp.ModeAuto
				case 1:
					a.state.Cloudflare.DefaultMode = warp.ModeMASQUE
				case 2:
					a.state.Cloudflare.DefaultMode = warp.ModeWireGuard
				}
				a.saveState()
			}

			a.renderWarpTransportGuide(c, p, "warp-global-transport", curModeIdx, false)

			// MASQUE Prefer HTTP/2 toggle (relevant for Auto and MASQUE modes)
			if a.state.Cloudflare.DefaultMode != warp.ModeWireGuard {
				ui.Column(c.Key("warp-prefer-h2-box")).Gap(4).Padding(10).Radius(8).Background(p.surface).Border(1, p.borderSubtle).Children(func() {
					if switchRow(c, p, "toggle-warp-prefer-h2", cat.CloudflareWarpPreferH2(), &a.state.Cloudflare.MasquePreferH2) {
						a.saveState()
					}
					ui.Text(c, cat.CloudflareWarpPreferH2Desc()).FontSize(11).TextColor(p.textMuted).LineHeight(1.4)
				})
			}

			// Clean Endpoint override + One-Click Anycast Scan
			ui.Column(c.Key("warp-clean-endpoint-section")).Gap(8).Children(func() {
				ui.Row(c).AlignItems(ui.End).Gap(8).Children(func() {
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
					scanBtn := ui.Button(c.Key("btn-warp-scan-endpoint"), scanLabel).
						FontSize(12).Radius(6).
						Background(p.accent).TextColor(ui.RGB(255, 255, 255)).
						Padding(7, 12, 7, 12).
						Disabled(a.warpScanning)
					if scanBtn.Clicked() {
						a.triggerWarpEndpointScan()
					}

					if strings.TrimSpace(a.warpCleanEndpointInput) != "" || strings.TrimSpace(a.state.Cloudflare.CleanIP) != "" {
						resetBtn := ui.Button(c.Key("btn-warp-reset-auto"), cat.CloudflareWarpResetAutoBtn()).
							FontSize(12).Radius(6).
							Background(p.surface).Border(1, p.border).TextColor(p.textMuted).
							Padding(7, 10, 7, 10)
						if resetBtn.Clicked() {
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
								label := fmt.Sprintf("%s (%dms · %s)", res.Endpoint, res.RTT.Milliseconds(), res.Protocol)
								pillBtn := ui.Button(c.Key(fmt.Sprintf("btn-warp-candidate-%d", idx)), label).
									FontSize(11).Radius(6).
									Background(bg).Border(1, border).TextColor(fg).
									Padding(4, 9, 4, 9)
								if pillBtn.Clicked() {
									a.applyWarpCleanEndpoint(res.Endpoint)
								}
							}
						})
					})
				}
			})

			// Probe URL override
			ui.Row(c).AlignItems(ui.Center).Gap(10).Children(func() {
				probeInp := ui.TextInput(c.Key("input-warp-probe-url"), &a.state.Cloudflare.ProbeURL).
					Label(cat.CloudflareWarpProbeURL()).
					Placeholder(cat.CloudflareWarpProbeURLPlaceholder()).
					Grow(1)
				if probeInp.Changed() {
					a.saveState()
				}
			})
		})

	// Card 3: Attached Nodes List
	ui.Column(c.Key("warp-attached-nodes-card")).
		Gap(12).Padding(16).Radius(10).
		Background(p.card).Border(1, p.borderSubtle).
		Children(func() {
			ui.Text(c, cat.CloudflareWarpAttachedNodes()).FontSize(14).FontWeight(600).TextColor(p.text)

			var attached []config.Service
			for _, svc := range a.state.Services {
				if svc.EnableWARP || svc.EffectiveProtocol() == config.ProtoWARP {
					attached = append(attached, svc)
				}
			}

			if len(attached) == 0 {
				ui.Text(c, cat.CloudflareWarpNoAttachedNodes()).FontSize(12).TextColor(p.textDim)
			} else {
				for _, svc := range attached {
					nodeTag := svc.Name
					isDirect := svc.EffectiveProtocol() == config.ProtoWARP
					rt := a.mgr.StatusOf(svc.ID)
					unhealthy := a.isNodeUnhealthy(svc, rt)

					ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).
						Padding(8, 10, 8, 10).Radius(6).Background(p.surface).
						Children(func() {
							ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
								ui.Text(c, nodeTag).FontSize(12).FontWeight(600).TextColor(p.text)
								if isDirect {
									tagPill(c, "WARP Direct", p.accent, p.accentBg)
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

							ui.Text(c, svc.CompactRemoteEndpoint()).FontSize(11).TextColor(p.textDim)
						})
				}
			}
		})
}

func (a *app) renderCloudflareTunnelView(c *ui.Context, p palette) {
	cat := a.catalog()
	tunCfg := &a.state.Cloudflare.Tunnel

	ui.Column(c.Key("cloudflare-tunnel-card")).
		Gap(14).Padding(16).Radius(10).
		Background(p.card).Border(1, p.borderSubtle).
		Children(func() {
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
					ui.Text(c, cat.CloudflareTunnelTitle()).FontSize(14).FontWeight(600).TextColor(p.text)
					if tunCfg.Enabled && a.gateway != nil && strings.TrimSpace(tunCfg.Token) != "" {
						tagPill(c, cat.CloudflareTunnelConnected(), p.green, p.greenBg)
					} else if tunCfg.Enabled {
						tagPill(c, cat.CloudflareTunnelDisconnected(), p.amber, p.amberBg)
					} else {
						tagPill(c, cat.TailnetModeOff(), p.textDim, p.surface)
					}
				})

				if switchRow(c, p, "toggle-cf-tunnel-enabled", cat.CloudflareTunnelEnable(), &tunCfg.Enabled) {
					a.saveState()
				}
			})

			// Token input
			ui.Column(c).Gap(6).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
					ui.Text(c, cat.CloudflareTunnelToken()).FontSize(12).FontWeight(500).TextColor(p.text)
					if actionChip(c.Key("btn-paste-tunnel-token"), p, iconCopy, "粘贴 Token", false).Clicked() {
						clip := a.readClipboard()
						if clip != "" {
							tunCfg.Token = strings.TrimSpace(clip)
							a.tunnelTokenInput = tunCfg.Token
							a.saveState()
							a.toast("已粘贴 Tunnel Token")
						}
					}
				})

				tokenInp := ui.TextInput(c.Key("input-cf-tunnel-token"), &tunCfg.Token).
					Label(cat.CloudflareTunnelToken()).
					Placeholder(cat.CloudflareTunnelTokenPlaceholder()).
					Password().
					Grow(1)
				if tokenInp.Changed() {
					a.saveState()
				}
			})

			// Protocol selector: [Auto] [QUIC] [HTTP/2]
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Children(func() {
				ui.Column(c).Gap(2).Children(func() {
					ui.Text(c, cat.CloudflareTunnelProtocol()).FontSize(13).FontWeight(500).TextColor(p.text)
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

			// Post Quantum Cryptography switch
			if switchRow(c, p, "toggle-cf-tunnel-pq", cat.CloudflareTunnelPostQuantum(), &tunCfg.PostQuantum) {
				a.saveState()
			}
		})
}
