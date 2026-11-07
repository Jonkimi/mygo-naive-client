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

	ui.Column(c.Key("tailnet-page")).Grow(1).Fill().MinHeight(0).Children(func() {
		// 1. Header row
		ui.Row(c.Key("tailnet-header")).
			Padding(14, 18, 14, 18).
			AlignItems(ui.Center).
			BorderWidth(0, 0, 1, 0).BorderColor(p.borderSubtle).
			Children(func() {
				ui.Column(c).Gap(2).Children(func() {
					ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
						ui.Text(c, cat.TailnetTitle()).FontSize(17).FontWeight(700).TextColor(p.text)
						if !a.state.TailnetEnabled || a.state.TailnetMode == string(tailnet.ModeOff) {
							tagPill(c, cat.TailnetModeOff(), p.textDim, p.card)
						} else if st.ActiveMode == tailnet.ModeHost {
							tagPill(c, cat.TailnetModeHost(), p.accent, p.accentBg)
						} else if st.ActiveMode == tailnet.ModeEmbedded {
							tagPill(c, cat.TailnetModeEmbedded(), p.green, p.greenBg)
						}
					})
					ui.Text(c, cat.TailnetSubtitle()).FontSize(11).TextColor(p.textDim)
				})

				ui.Box(c).Grow(1)

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
						a.tailnetMgr.UpdateConfig(a.state.tailnetConfig())
						a.tailnetMgr.Refresh(context.Background())
					}
					a.restartGatewayIfRunning()
				}
			})

		// 2. Scrollable Body
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

					// Advanced Embedded Settings
					a.renderTailnetAdvancedCard(c, p)
				})
		})
	})
}

func (a *app) renderTailnetAuthBanner(c *ui.Context, p palette, authURL string) {
	cat := a.catalog()

	ui.Row(c.Key("tailnet-auth-banner")).
		Padding(12, 16, 12, 16).Radius(10).
		Background(p.accentBg).Border(1, p.accent.Alpha(0.3)).
		AlignItems(ui.Center).Gap(12).
		Children(func() {
			ui.Icon(c, iconAlert).Size(18, 18).TextColor(p.accent)
			ui.Column(c).Grow(1).Gap(2).Children(func() {
				ui.Text(c, cat.TailnetStatusNeedsLogin()).FontSize(13).FontWeight(600).TextColor(p.text)
				ui.Text(c, authURL).FontSize(11).TextColor(p.textDim).NoWrap()
			})
			btnOpen := ui.ButtonBase(c.Key("btn-open-auth-url")).
				Label("btn-open-auth-url").
				Padding(6, 14, 6, 14).Radius(6).
				Background(p.accent).
				Children(func() {
					ui.Text(c, cat.TailnetLoginBtn()).FontSize(12).FontWeight(600).TextColor(ui.RGB(255, 255, 255))
				})
			if btnOpen.Clicked() {
				openBrowserURL(authURL)
			}

			btnCopy := ui.ButtonBase(c.Key("btn-copy-auth-url")).
				Label("btn-copy-auth-url").
				Padding(6, 10, 6, 10).Radius(6).
				Background(p.card).Border(1, p.borderSubtle).
				Children(func() {
					ui.Icon(c, iconCopy).Size(14, 14).TextColor(p.textDim)
				})
			if btnCopy.Clicked() {
				a.writeClipboard(authURL, "已复制登录授权链接")
			}
		})
}

func (a *app) renderTailnetErrorBanner(c *ui.Context, p palette, errText string) {
	ui.Row(c.Key("tailnet-error-banner")).
		Padding(10, 14, 10, 14).Radius(8).
		Background(p.redBg).Border(1, p.red.Alpha(0.2)).
		AlignItems(ui.Center).Gap(10).
		Children(func() {
			ui.Icon(c, iconAlert).Size(16, 16).TextColor(p.red)
			ui.Text(c, errText).FontSize(12).TextColor(p.red)
		})
}

func (a *app) renderTailnetNodeCard(c *ui.Context, p palette, st tailnet.Status) {
	cat := a.catalog()

	ui.Column(c.Key("tailnet-node-card")).
		Padding(16).Radius(10).
		Background(p.card).Border(1, p.borderSubtle).Gap(10).
		Children(func() {
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
					ui.Icon(c, iconNavTailnet).Size(16, 16).TextColor(p.accent)
					ui.Text(c, cat.TailnetNodeInfo()).FontSize(14).FontWeight(600).TextColor(p.text)
				})

				switch st.BackendState {
				case "Running":
					tagPill(c, cat.TailnetStatusConnected(), p.green, p.greenBg)
				case "NeedsLogin":
					tagPill(c, cat.TailnetStatusNeedsLogin(), p.accent, p.accentBg)
				case "Starting":
					tagPill(c, "启动中...", p.textDim, p.surface)
				default:
					tagPill(c, cat.TailnetStatusOffline(), p.textDim, p.surface)
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

			ui.Row(c).Gap(24).Children(func() {
				ui.Column(c).Gap(2).Children(func() {
					ui.Text(c, cat.TailnetHostname()).FontSize(11).TextColor(p.textDim)
					ui.Text(c, hostname).FontSize(13).FontWeight(600).TextColor(p.text)
				})
				ui.Column(c).Gap(2).Children(func() {
					ui.Text(c, cat.TailnetIPs()).FontSize(11).TextColor(p.textDim)
					ui.Text(c, ips).FontSize(13).FontWeight(600).TextColor(p.text)
				})
				ui.Column(c).Gap(2).Children(func() {
					ui.Text(c, cat.TailnetMagicDNS()).FontSize(11).TextColor(p.textDim)
					ui.Text(c, magicDNS).FontSize(13).FontWeight(600).TextColor(p.text)
				})
			})
		})
}

func (a *app) renderTailnetSharingCard(c *ui.Context, p palette) {
	cat := a.catalog()

	ui.Column(c.Key("tailnet-sharing-card")).
		Padding(16).Radius(10).
		Background(p.card).Border(1, p.borderSubtle).Gap(12).
		Children(func() {
			ui.Column(c).Gap(2).Children(func() {
				ui.Text(c, cat.TailnetSharingTitle()).FontSize(14).FontWeight(600).TextColor(p.text)
				ui.Text(c, cat.TailnetAdvertiseExitDesc()).FontSize(11).TextColor(p.textDim)
			})

			if switchRow(c, p, "switch-tailnet-expose-mixed", cat.TailnetExposeMixed(), &a.state.TailnetExposeMixedPort) {
				a.saveState()
				a.restartGatewayIfRunning()
			}

			if switchRow(c, p, "switch-tailnet-advertise-exit", cat.TailnetAdvertiseExit(), &a.state.TailnetAdvertiseExit) {
				a.saveState()
				a.restartGatewayIfRunning()
			}

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
		Background(p.card).Border(1, p.borderSubtle).Gap(12).
		Children(func() {
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
				ui.Text(c, fmt.Sprintf("%s (%d)", cat.TailnetPeersTitle(), len(st.Peers))).
					FontSize(14).FontWeight(600).TextColor(p.text)

				btnRefresh := ui.ButtonBase(c.Key("btn-refresh-tailnet")).
					Label("btn-refresh-tailnet").
					Padding(4, 10, 4, 10).Radius(6).
					Background(p.surface).Border(1, p.borderSubtle).
					Children(func() {
						ui.Row(c).AlignItems(ui.Center).Gap(4).Children(func() {
							ui.Icon(c, iconRefresh).Size(12, 12).TextColor(p.textDim)
							ui.Text(c, "刷新").FontSize(11).TextColor(p.textDim)
						})
					})
				if btnRefresh.Clicked() && a.tailnetMgr != nil {
					a.tailnetMgr.Refresh(context.Background())
				}
			})

			if len(st.Peers) == 0 {
				ui.Row(c).Justify(ui.Center).Padding(16, 0, 16, 0).Children(func() {
					ui.Text(c, cat.TailnetNoPeers()).FontSize(12).TextColor(p.textDim)
				})
				return
			}

			for i, peer := range st.Peers {
				peerKey := fmt.Sprintf("peer-row-%d-%s", i, peer.ID)
				isCurrentExit := peer.ExitNode || (st.CurrentExitNode != "" && st.CurrentExitNode == peer.ID)

				ui.Row(c.Key(peerKey)).
					Padding(8, 10, 8, 10).Radius(8).
					Background(p.surface).AlignItems(ui.Center).Justify(ui.SpaceBetween).
					Children(func() {
						// Left: Online indicator + Hostname + IP
						ui.Row(c).AlignItems(ui.Center).Gap(10).Children(func() {
							dotColor := p.green
							if !peer.Online {
								dotColor = p.textDim.Alpha(0.4)
							}
							ui.Box(c).Size(8, 8).Radius(4).Background(dotColor)

							ui.Column(c).Gap(2).Children(func() {
								ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
									ui.Text(c, peer.Hostname).FontSize(13).FontWeight(600).TextColor(p.text)
									if peer.OS != "" {
										tagPill(c, peer.OS, p.textDim, p.card)
									}
								})
								ipStr := strings.Join(peer.IPs, ", ")
								ui.Text(c, ipStr).FontSize(11).TextColor(p.textDim)
							})
						})

						// Right: Exit Node Action
						if isCurrentExit {
							btnExit := ui.ButtonBase(c.Key("btn-exit-active-"+peer.ID)).
								Label("btn-exit-active").
								Padding(4, 10, 4, 10).Radius(6).
								Background(p.accentBg).Border(1, p.accent.Alpha(0.3)).
								Tooltip(cat.TailnetPeerClearExitNode()).
								Children(func() {
									ui.Text(c, cat.TailnetPeerActiveExitNode()).FontSize(11).FontWeight(600).TextColor(p.accent)
								})
							if btnExit.Clicked() && a.tailnetMgr != nil {
								_ = a.tailnetMgr.SetExitNode(context.Background(), "")
								c.Toast("已断开出口节点")
							}
						} else if peer.ExitNodeOption {
							btnUse := ui.ButtonBase(c.Key("btn-exit-use-"+peer.ID)).
								Label("btn-exit-use").
								Padding(4, 10, 4, 10).Radius(6).
								Background(p.card).Border(1, p.borderSubtle).
								Tooltip(cat.TailnetPeerUseExitNode()).
								Children(func() {
									ui.Text(c, cat.TailnetPeerUseExitNode()).FontSize(11).TextColor(p.text)
								})
							if btnUse.Clicked() && a.tailnetMgr != nil {
								_ = a.tailnetMgr.SetExitNode(context.Background(), peer.ID)
								c.Toast(fmt.Sprintf("已切换至出口节点 %s", peer.Hostname))
							}
						}
					})
			}
		})
}

func (a *app) renderTailnetAdvancedCard(c *ui.Context, p palette) {
	cat := a.catalog()

	ui.Column(c.Key("tailnet-advanced-card")).
		Padding(16).Radius(10).
		Background(p.card).Border(1, p.borderSubtle).Gap(12).
		Children(func() {
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
				ui.Text(c, cat.TailnetAdvancedTitle()).FontSize(14).FontWeight(600).TextColor(p.text)

				if a.state.TailnetMode == string(tailnet.ModeEmbedded) {
					btnApply := ui.ButtonBase(c.Key("btn-tailnet-apply-reconnect")).
						Label("btn-tailnet-apply-reconnect").
						Padding(4, 10, 4, 10).Radius(6).
						Background(p.accentBg).Border(1, p.accent.Alpha(0.3)).
						Children(func() {
							ui.Text(c, "应用并重新连接").FontSize(11).FontWeight(600).TextColor(p.accent)
						})
					if btnApply.Clicked() {
						a.saveState()
						if a.tailnetMgr != nil {
							a.tailnetMgr.UpdateConfig(a.state.tailnetConfig())
						}
						a.restartGatewayIfRunning()
						c.Toast("已应用并重启内嵌节点")
					}
				}
			})

			if labeledInput(c, p, "inp-tailnet-control-url", cat.TailnetControlURL(), &a.state.TailnetControlURL, "https://controlplane.tailscale.com").Changed() {
				a.saveState()
				if a.tailnetMgr != nil {
					a.tailnetMgr.UpdateConfig(a.state.tailnetConfig())
				}
			}
			if labeledInput(c, p, "inp-tailnet-auth-key", cat.TailnetAuthKey(), &a.state.TailnetAuthKey, "tskey-auth-...").Changed() {
				a.saveState()
				if a.tailnetMgr != nil {
					a.tailnetMgr.UpdateConfig(a.state.tailnetConfig())
				}
			}
			if labeledInput(c, p, "inp-tailnet-hostname", cat.TailnetCustomHostname(), &a.state.TailnetHostname, "NaiveClient").Changed() {
				a.saveState()
				if a.tailnetMgr != nil {
					a.tailnetMgr.UpdateConfig(a.state.tailnetConfig())
				}
			}
		})
}

func (a *app) restartGatewayIfRunning() {
	if a.state.GatewayEnabled || a.state.TailnetMode == string(tailnet.ModeEmbedded) {
		a.state.GatewayEnabled = true
		a.stopGateway()
		if err := a.startGateway(); err != nil {
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
