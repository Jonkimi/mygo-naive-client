package app

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/egoist/mygo/ui"

	"naive-client/internal/tailnet"
)

func (a *app) renderTailnetPage(c *ui.Context, p palette) {
	cat := a.catalog()

	var st tailnet.Status
	if a.tailnetMgr != nil {
		st = a.tailnetMgr.Status()
	}

	onlineCount := 0
	for _, peer := range st.Peers {
		if peer.Online {
			onlineCount++
		}
	}

	ui.Column(c.Key("tailnet-page")).Grow(1).Fill().MinHeight(0).Children(func() {
		// 1. Fixed Header with quiet dot status summary & Segmented mode switch
		dsPageHeader(c, p, "tailnet-header", true, func() {
			ui.Column(c).MinWidth(0).Shrink(1).Gap(2).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Gap(10).Wrap().Children(func() {
					dsPageTitle(c, p, cat.TailnetTitle())

					ui.Row(c).AlignItems(ui.Center).Gap(dsSpaceSM).Children(func() {
						if !a.state.TailnetEnabled || a.state.TailnetMode == string(tailnet.ModeOff) {
							hollowStatusDot(c, p.textDim.Alpha(0.5))
							ui.Text(c, cat.TailnetModeOff()).FontSize(dsFontBody).TextColor(p.textMuted).NoWrap()
						} else {
							switch st.BackendState {
							case "Running":
								statusDot(c, p.green)
							case "NeedsLogin", "Starting":
								statusDot(c, p.amber)
							default:
								statusDot(c, p.textDim)
							}
							modeLabel := cat.TailnetModeAuto()
							if st.ActiveMode == tailnet.ModeHost {
								modeLabel = cat.TailnetModeHost()
							} else if st.ActiveMode == tailnet.ModeEmbedded {
								modeLabel = cat.TailnetModeEmbedded()
							} else {
								switch tailnet.Mode(a.state.TailnetMode) {
								case tailnet.ModeHost:
									modeLabel = cat.TailnetModeHost()
								case tailnet.ModeEmbedded:
									modeLabel = cat.TailnetModeEmbedded()
								}
							}
							ui.Text(c, modeLabel).FontSize(dsFontBody).TextColor(p.textMuted).NoWrap()
							ui.Text(c, "·").FontSize(dsFontBody).TextColor(p.textDim).NoWrap()
							ui.Text(c, cat.TailnetOnlinePeersSummary(onlineCount, len(st.Peers))).
								FontSize(dsFontBody).FontFeatures("tnum").TextColor(p.textMuted).NoWrap()
						}
					})
				})
				ui.Text(c, cat.TailnetSubtitle()).FontSize(dsFontCaption).TextColor(p.textDim).SingleLine().Ellipsis("…")
			})
		}, func() {
			// Mode selector segmented control
			modeIdx := 0
			switch tailnet.Mode(a.state.TailnetMode) {
			case tailnet.ModeAuto:
				modeIdx = 0
			case tailnet.ModeHost:
				modeIdx = 1
			case tailnet.ModeEmbedded:
				modeIdx = 2
			case tailnet.ModeOff:
				modeIdx = 3
			}
			if !a.state.TailnetEnabled {
				modeIdx = 3
			}

			modeLabels := []string{
				cat.TailnetModeAuto(),
				cat.TailnetModeHost(),
				cat.TailnetModeEmbedded(),
				cat.TailnetModeOff(),
			}

			ui.Row(c).Shrink(0).Children(func() {
				if segmentedControl(c.Key("tailnet-mode-switch"), p, &modeIdx, modeLabels) {
					var newMode tailnet.Mode
					switch modeIdx {
					case 0:
						newMode = tailnet.ModeAuto
						a.state.TailnetEnabled = true
					case 1:
						newMode = tailnet.ModeHost
						a.state.TailnetEnabled = true
					case 2:
						newMode = tailnet.ModeEmbedded
						a.state.TailnetEnabled = true
					case 3:
						newMode = tailnet.ModeOff
						a.state.TailnetEnabled = false
					}
					a.state.TailnetMode = string(newMode)
					a.saveState()
					if a.tailnetMgr != nil {
						a.tailnetMgr.RefreshAsync()
					}
					a.restartGatewayIfRunning()
				}
			})
		})

		// 2. Scrollable Body (full width preserved so Sharing switches remain aligned)
		ui.Scroll(c.Key("tailnet-scroll")).Grow(1).Fill().Children(func() {
			ui.Column(c.Key("tailnet-scroll-body")).
				Padding(16).Gap(14).
				Children(func() {
					// Auth notification banner
					if st.BackendState == "NeedsLogin" && st.AuthURL != "" {
						a.renderTailnetAuthBanner(c, p, st.AuthURL)
					}

					// Error banner
					if st.Error != "" {
						a.renderTailnetErrorBanner(c, p, st.Error)
					}

					// Current Node Info
					a.renderTailnetNodeCard(c, p, st)

					// Inbound Sharing Options
					a.renderTailnetSharingCard(c, p)

					// Discovered Peers
					a.renderTailnetPeersCard(c, p, st)

					// Advanced Embedded Settings (Only shown in Embedded mode or when Auto falls back to Embedded)
					if a.state.TailnetMode == string(tailnet.ModeEmbedded) || st.ActiveMode == tailnet.ModeEmbedded {
						a.renderTailnetAdvancedCard(c, p)
					}
				})
		})
	})
}

func (a *app) renderTailnetAuthBanner(c *ui.Context, p palette, authURL string) {
	cat := a.catalog()

	ui.Row(c.Key("tailnet-auth-banner")).
		Padding(12, 16, 12, 16).Radius(10).
		Background(p.accentBg).Border(1, p.accent.Alpha(0.3)).
		AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Wrap().
		Children(func() {
			ui.Row(c).AlignItems(ui.Center).Gap(10).Grow(1).Shrink(1).MinWidth(0).Children(func() {
				ui.Icon(c, iconAlert).Size(16, 16).TextColor(p.accent).Shrink(0)
				ui.Column(c).Grow(1).Shrink(1).MinWidth(0).Gap(2).Children(func() {
					ui.Text(c, cat.TailnetStatusNeedsLogin()).FontSize(13).FontWeight(600).TextColor(p.text)
					ui.Text(c, authURL).Font("monospace").FontSize(11).TextColor(p.textDim).SingleLine().Ellipsis("…")
				})
			})
			ui.Row(c).AlignItems(ui.Center).Gap(6).Shrink(0).Children(func() {
				btnOpen := ui.ButtonBase(c.Key("btn-open-auth-url")).
					Label("btn-open-auth-url").
					Height(28).Padding(0, 12, 0, 12).Radius(7).
					Background(p.accent).
					Children(func() {
						ui.Text(c, cat.TailnetLoginBtn()).FontSize(12).FontWeight(600).TextColor(ui.RGB(255, 255, 255)).NoWrap()
					})
				if btnOpen.Clicked() {
					openBrowserURL(authURL)
				}

				btnCopy := quietToolbarButton(c.Key("btn-copy-auth-url"), p, iconCopy, cat.BtnCopy(), false).
					Label("btn-copy-auth-url").Height(28)
				if btnCopy.Clicked() {
					a.writeClipboard(authURL, cat.TailnetCopiedAuthURL())
				}
			})
		})
}

func (a *app) renderTailnetErrorBanner(c *ui.Context, p palette, errText string) {
	cat := a.catalog()
	ui.Row(c.Key("tailnet-error-banner")).
		Padding(10, 14, 10, 14).Radius(8).
		Background(p.redBg).Border(1, p.red.Alpha(0.25)).
		AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(10).Wrap().
		Children(func() {
			ui.Row(c).AlignItems(ui.Center).Gap(8).Grow(1).Shrink(1).MinWidth(0).Children(func() {
				ui.Icon(c, iconAlert).Size(15, 15).TextColor(p.redText).Shrink(0)
				ui.Text(c, errText).FontSize(12).TextColor(p.redText).Grow(1).Shrink(1).MinWidth(0)
			})

			btnCopy := compactStripButton(c.Key("btn-copy-tailnet-error"), p, "btn-copy-tailnet-error", cat.BtnCopy(), p.textMuted).
				Tooltip(cat.ActionCopyError())
			if btnCopy.Clicked() {
				a.writeClipboard(errText, cat.ToastErrorCopied())
			}
		})
}

func (a *app) renderTailnetNodeCard(c *ui.Context, p palette, st tailnet.Status) {
	cat := a.catalog()

	copyAddr := ""
	if len(st.Self.IPs) > 0 && strings.TrimSpace(st.Self.IPs[0]) != "" {
		copyAddr = st.Self.IPs[0]
	} else if st.Self.Hostname != "" {
		copyAddr = st.Self.Hostname
	}

	ui.Column(c.Key("tailnet-node-card")).
		Padding(16).Radius(10).
		Background(p.card).Border(1, p.borderSubtle).Gap(12).
		Children(func() {
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(8).Wrap().Children(func() {
				ui.Row(c).AlignItems(ui.Center).Gap(10).Wrap().Children(func() {
					ui.Text(c, cat.TailnetNodeInfo()).FontSize(14).FontWeight(600).TextColor(p.text).NoWrap()
					ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
						switch st.BackendState {
						case "Running":
							statusDot(c, p.green)
							ui.Text(c, cat.TailnetStatusConnected()).FontSize(12).FontWeight(500).TextColor(p.greenText).NoWrap()
						case "NeedsLogin":
							statusDot(c, p.amber)
							ui.Text(c, cat.TailnetStatusNeedsLogin()).FontSize(12).FontWeight(500).TextColor(p.amberText).NoWrap()
						case "Starting":
							statusDot(c, p.amber)
							ui.Text(c, cat.TailnetStarting()).FontSize(12).TextColor(p.textMuted).NoWrap()
						default:
							hollowStatusDot(c, p.textDim.Alpha(0.5))
							ui.Text(c, cat.TailnetStatusOffline()).FontSize(12).TextColor(p.textDim).NoWrap()
						}
					})
				})

				copyDisabled := copyAddr == ""
				btnCopyAddr := quietToolbarButton(c.Key("btn-copy-tailnet-addr"), p, iconCopy, cat.TailnetCopyAddress(), copyDisabled).
					Label("btn-copy-tailnet-addr").
					Height(28).
					Disabled(copyDisabled).DimDisabled(false)
				if !copyDisabled && btnCopyAddr.Clicked() {
					a.writeClipboard(copyAddr, cat.TailnetAddressCopied())
				}
			})

			hostname := st.Self.Hostname
			if hostname == "" {
				hostname = "-"
			}
			ips := strings.Join(st.Self.IPs, "  /  ")
			if ips == "" {
				ips = "-"
			}
			magicDNS := st.MagicDNSSuffix
			if magicDNS == "" {
				magicDNS = "-"
			}

			ui.Row(c.Key("tailnet-metrics-grid")).Gap(12).Wrap().Children(func() {
				metricBox := func(label, val string, tnum bool) {
					ui.Column(c).
						Grow(1).MinWidth(140).Gap(3).
						Padding(10, 12, 10, 12).Radius(8).
						Background(p.surface).Border(1, p.borderSubtle).
						Children(func() {
							ui.Text(c, label).FontSize(11).TextColor(p.textDim).NoWrap()
							txt := ui.Text(c, val).Font("monospace").FontSize(13).FontWeight(600).TextColor(p.text).SingleLine().Ellipsis("…")
							if tnum {
								txt.FontFeatures("tnum")
							}
						})
				}
				metricBox(cat.TailnetHostname(), hostname, false)
				metricBox(cat.TailnetIPs(), ips, true)
				metricBox(cat.TailnetMagicDNS(), magicDNS, false)
			})
		})
}

func (a *app) renderTailnetSharingCard(c *ui.Context, p palette) {
	cat := a.catalog()

	ui.Column(c.Key("tailnet-sharing-card")).
		Padding(16).Radius(10).
		Background(p.card).Border(1, p.borderSubtle).Gap(10).
		Children(func() {
			ui.Column(c).Gap(2).Children(func() {
				ui.Text(c, cat.TailnetSharingTitle()).FontSize(14).FontWeight(600).TextColor(p.text)
				ui.Text(c, cat.TailnetAdvertiseExitDesc()).FontSize(11).TextColor(p.textDim)
			})

			if switchRow(c, p, "switch-tailnet-expose-mixed", cat.TailnetExposeMixed(), &a.state.TailnetExposeMixedPort) {
				a.saveState()
				a.restartGatewayIfRunning()
			}

			ui.Box(c).FillWidth().Height(1).Background(p.borderSubtle)

			if switchRow(c, p, "switch-tailnet-advertise-exit", cat.TailnetAdvertiseExit(), &a.state.TailnetAdvertiseExit) {
				a.saveState()
				a.restartGatewayIfRunning()
			}

			ui.Box(c).FillWidth().Height(1).Background(p.borderSubtle)

			if switchRow(c, p, "switch-tailnet-accept-routes", cat.TailnetAcceptRoutes(), &a.state.TailnetAcceptRoutes) {
				a.saveState()
				a.restartGatewayIfRunning()
			}
		})
}

func (a *app) renderTailnetPeersCard(c *ui.Context, p palette, st tailnet.Status) {
	cat := a.catalog()

	ui.Column(c.Key("tailnet-peers-card")).
		Padding(16).Radius(10).
		Background(p.card).Border(1, p.borderSubtle).Gap(10).
		Children(func() {
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(8).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
					ui.Text(c, cat.TailnetPeersTitle()).FontSize(14).FontWeight(600).TextColor(p.text)
					ui.Text(c, fmt.Sprintf("(%d)", len(st.Peers))).FontSize(12).FontFeatures("tnum").TextColor(p.textDim)
				})

				btnRefresh := quietToolbarButton(c.Key("btn-refresh-tailnet"), p, iconRefresh, cat.BtnRefresh(), false).
					Label("btn-refresh-tailnet").Height(28)
				if btnRefresh.Clicked() && a.tailnetMgr != nil {
					a.tailnetMgr.RefreshAsync()
				}
			})

			if len(st.Peers) == 0 {
				ui.Row(c).Justify(ui.Center).Padding(16, 0, 16, 0).Children(func() {
					ui.Text(c, cat.TailnetNoPeers()).FontSize(12).TextColor(p.textDim)
				})
				return
			}

			ui.Column(c).Gap(0).Children(func() {
				for i, peer := range st.Peers {
					if i > 0 {
						ui.Box(c).FillWidth().Height(1).Background(p.borderSubtle)
					}
					peerKey := peer.ID
					if peerKey == "" {
						peerKey = fmt.Sprintf("peer-row-%d", i)
					} else {
						peerKey = "peer-row-" + peerKey
					}
					isCurrentExit := peer.ExitNode || (st.CurrentExitNode != "" && st.CurrentExitNode == peer.ID)

					ui.Row(c.Key(peerKey)).
						Padding(10, 0, 10, 0).
						AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(10).
						Children(func() {
							// Left: Status dot + Hostname + monospace metadata line
							ui.Row(c).AlignItems(ui.Center).Gap(10).Grow(1).Shrink(1).MinWidth(0).Children(func() {
								if peer.Online {
									statusDot(c, p.green)
								} else {
									hollowStatusDot(c, p.textDim.Alpha(0.5))
								}

								ui.Column(c).Gap(2).Grow(1).Shrink(1).MinWidth(0).Children(func() {
									ui.Text(c, peer.Hostname).FontSize(13).FontWeight(600).TextColor(p.text).SingleLine().Ellipsis("…")

									var metaParts []string
									if ipStr := strings.Join(peer.IPs, ", "); ipStr != "" {
										metaParts = append(metaParts, ipStr)
									}
									if peer.OS != "" {
										metaParts = append(metaParts, peer.OS)
									}
									if !peer.Online {
										metaParts = append(metaParts, cat.TailnetPeerOffline())
									}
									if len(metaParts) > 0 {
										ui.Text(c, strings.Join(metaParts, " · ")).
											Font("monospace").FontSize(11).FontFeatures("tnum").
											TextColor(p.textDim).SingleLine().Ellipsis("…")
									}
								})
							})

							// Right: Exit Node Action
							ui.Row(c).Shrink(0).Children(func() {
								if isCurrentExit {
									btnExit := ui.ButtonBase(c.Key("btn-exit-active-"+peer.ID)).
										Label("btn-exit-active").
										Padding(5, 10, 5, 10).Radius(6).
										Background(p.accentBg).Border(1, p.accent.Alpha(0.35)).
										Tooltip(cat.TailnetPeerClearExitNode()).
										Children(func() {
											ui.Text(c, cat.TailnetPeerActiveExitNode()).FontSize(11).FontWeight(600).TextColor(p.accentText).NoWrap()
										})
									if btnExit.Clicked() && a.tailnetMgr != nil {
										_ = a.tailnetMgr.SetExitNode(context.Background(), "")
										c.Toast(cat.TailnetExitNodeDisconnected())
									}
								} else if peer.ExitNodeOption {
									btnUse := quietToolbarButton(c.Key("btn-exit-use-"+peer.ID), p, nil, cat.TailnetPeerUseExitNode(), false).
										Label("btn-exit-use").
										Height(28).
										Tooltip(cat.TailnetPeerUseExitNode())
									if btnUse.Clicked() && a.tailnetMgr != nil {
										_ = a.tailnetMgr.SetExitNode(context.Background(), peer.ID)
										c.Toast(cat.TailnetExitNodeSwitched(peer.Hostname))
									}
								}
							})
						})
				}
			})
		})
}

func (a *app) renderTailnetAdvancedCard(c *ui.Context, p palette) {
	cat := a.catalog()

	ui.Column(c.Key("tailnet-advanced-card")).
		Padding(16).Radius(10).
		Background(p.card).Border(1, p.borderSubtle).Gap(12).
		Children(func() {
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(8).Children(func() {
				ui.Text(c, cat.TailnetAdvancedTitle()).FontSize(14).FontWeight(600).TextColor(p.text)

				if a.state.TailnetMode == string(tailnet.ModeEmbedded) {
					btnApply := ui.ButtonBase(c.Key("btn-tailnet-apply-reconnect")).
						Label("btn-tailnet-apply-reconnect").
						Padding(5, 10, 5, 10).Radius(6).
						Background(p.accentBg).Border(1, p.accent.Alpha(0.3)).
						Children(func() {
							ui.Text(c, cat.TailnetApplyReconnect()).FontSize(11).FontWeight(600).TextColor(p.accentText).NoWrap()
						})
					if btnApply.Clicked() {
						a.saveState()
						a.restartGatewayIfRunning()
						c.Toast(cat.TailnetAppliedRestarted())
					}
				}
			})

			ui.Row(c).Gap(12).Wrap().Children(func() {
				ui.Column(c).Grow(1).MinWidth(200).Children(func() {
					if labeledInput(c, p, "inp-tailnet-control-url", cat.TailnetControlURL(), &a.state.TailnetControlURL, "https://controlplane.tailscale.com").Changed() {
						a.saveState()
					}
				})
				ui.Column(c).Grow(1).MinWidth(200).Children(func() {
					if labeledInput(c, p, "inp-tailnet-hostname", cat.TailnetCustomHostname(), &a.state.TailnetHostname, "NaiveClient").Changed() {
						a.saveState()
					}
				})
			})
			if labeledInput(c, p, "inp-tailnet-auth-key", cat.TailnetAuthKey(), &a.state.TailnetAuthKey, "tskey-auth-...").Changed() {
				a.saveState()
			}
		})
}

func (a *app) restartGatewayIfRunning() {
	if a.state.GatewayEnabled || a.state.TailnetMode == string(tailnet.ModeEmbedded) {
		a.state.GatewayEnabled = true
		if err := a.startGatewayWithFallback(); err != nil {
			if a.tailnetMgr != nil {
				a.tailnetMgr.SetError(err.Error())
			}
		} else if a.tailnetMgr != nil {
			a.tailnetMgr.SetError("")
		}
	}
}

func openBrowserURL(rawURL string) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", rawURL)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL)
	default:
		cmd = exec.Command("xdg-open", rawURL)
	}
	_ = cmd.Start()
}
