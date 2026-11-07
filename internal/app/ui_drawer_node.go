package app

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/egoist/mygo/ui"

	"naive-client/internal/boxengine"
	"naive-client/internal/config"
	"naive-client/internal/runner"
)

func (a *app) renderNodeDrawer(c *ui.Context, p palette) {
	if a.activeNodeDrawerID == "" {
		return
	}

	cat := a.catalog()
	svc, ok := a.findService(a.activeNodeDrawerID)
	if !ok {
		a.activeNodeDrawerID = ""
		return
	}

	rt := a.mgr.StatusOf(svc.ID)

	// Backdrop (fades in and out, click to dismiss)
	backdrop := ui.Box(c.Key("node-drawer-backdrop")).
		Absolute().Top(0).Left(0).Right(0).Bottom(0).
		Background(ui.RGBA(0, 0, 0, 0.3)).
		Transition(ui.ElementTransition{
			Enter: &ui.Motion{Opacity: 0},
			Exit:  &ui.Motion{Opacity: 0},
		})
	if backdrop.Clicked() {
		a.activeNodeDrawerID = ""
	}

	// Slide-over drawer panel anchored to right edge
	ui.Column(c.Key("node-drawer-panel")).
		Absolute().Top(0).Right(0).Bottom(0).Width(460).
		Transition(ui.ElementTransition{
			Enter: &ui.Motion{X: 460},
			Exit:  &ui.Motion{X: 460},
		}).
		Padding(20).Gap(16).
		Background(p.drawerBg).
		BorderWidth(0, 0, 0, 1).BorderColor(p.border).
		Shadow(0, 8, 36, 0, ui.RGBA(0, 0, 0, 0.4)).
		Children(func() {
			// Header
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
					ui.Text(c, cat.NodeDrawerTitle()).FontSize(15).FontWeight(700).TextColor(p.text)
					a.renderRuntimeStatusBadge(c, p, rt.State)
				})

				ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
					if subtleActionChip(c.Key("btn-drawer-logs-node"), p, iconList, cat.NodeDrawerLogs(), false).Clicked() {
						targetID := a.activeNodeDrawerID
						a.activeNodeDrawerID = ""
						a.activeLogDrawerID = targetID
					}
					if subtleActionChip(c.Key("btn-drawer-edit-node"), p, iconEdit, cat.NodeDrawerEdit(), false).Clicked() {
						a.activeNodeDrawerID = ""
						a.openEditServiceDialog(svc)
					}
					if subtleActionChip(c.Key("btn-drawer-close-node"), p, iconClose, cat.NodeDrawerClose(), false).Clicked() {
						a.activeNodeDrawerID = ""
					}
				})
			})

			// Body: Scrollable content
			ui.Scroll(c.Key("node-drawer-scroll")).Grow(1).Fill().Children(func() {
				ui.Column(c).Gap(16).Children(func() {
					// 1. Process & Runtime Status (Prominently displaying PID here!)
					ui.Column(c).Gap(10).Padding(14).Radius(10).
						Background(p.card).Border(1, p.borderSubtle).
						Children(func() {
							ui.Text(c, cat.NodeDrawerRuntime()).FontSize(12).FontWeight(700).TextColor(p.textDim)

							// Row for PID
							ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
								ui.Text(c, cat.NodeDrawerPID()).FontSize(12).TextColor(p.textMuted)
								if rt.State == runner.StateRunning && rt.PID > 0 {
									tagPill(c, fmt.Sprintf("PID %d", rt.PID), p.green, p.greenBg)
								} else {
									ui.Text(c, cat.NodeDrawerPIDNone()).FontSize(12).FontWeight(500).TextColor(p.textDim)
								}
							})

							// Row for State
							ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
								ui.Text(c, cat.NodeDrawerState()).FontSize(12).TextColor(p.textMuted)
								a.renderRuntimeStatusBadge(c, p, rt.State)
							})

							if rt.Restarts > 0 {
								ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
									ui.Text(c, cat.NodeDrawerRestarts()).FontSize(12).TextColor(p.textMuted)
									tagPill(c, cat.RestartsPill(rt.Restarts), p.amber, p.amberBg)
								})
							}

							if rt.LastError != "" {
								ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Padding(6, 8, 6, 8).Radius(6).
									Background(p.redBg).Border(1, p.red.Alpha(0.2)).Children(func() {
									ui.Text(c, rt.LastError).FontSize(11).TextColor(p.red).Grow(1)
									if subtleActionChip(c.Key("btn-copy-drawer-err"), p, iconCopy, "", false).Clicked() {
										a.writeClipboard(rt.LastError, cat.ToastErrorCopied())
									}
								})
							}
						})

					// 2. Latency & Telemetry (Explaining both Probe Latency and Real EWMA Latency)
					canTest := rt.State == runner.StateRunning
					ui.Column(c).Gap(12).Padding(14).Radius(10).
						Background(p.card).Border(1, p.borderSubtle).
						Children(func() {
							ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
								ui.Text(c, cat.NodeDrawerTelemetry()).FontSize(12).FontWeight(700).TextColor(p.textDim)
								probeBtn := subtleActionChip(c.Key("btn-drawer-probe"), p, iconBolt, cat.ActionLatency(), !canTest || rt.Probing)
								if !canTest {
									probeBtn.Tooltip(cat.TestRequiresRunning())
								}
								if probeBtn.Clicked() {
									a.triggerServiceProbe(svc)
								}
							})

							// A: Probe Latency (主动测速延迟)
							ui.Column(c).Gap(3).Children(func() {
								ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
									ui.Text(c, cat.NodeDrawerProbeLatency()).FontSize(12).FontWeight(600).TextColor(p.text)
									if rt.Probing {
										tagPill(c, cat.LatencyTesting(), p.amber, p.amberBg)
									} else if rt.ProbeError != "" {
										tagPill(c, cat.LatencyFailed(), p.red, p.redBg)
									} else if rt.Latency > 0 {
										tagPill(c, fmt.Sprintf("%d ms", max(1, rt.Latency.Milliseconds())), p.green, p.greenBg)
									} else {
										ui.Text(c, cat.NodeDrawerNotTested()).FontSize(12).TextColor(p.textDim)
									}
								})
								ui.Text(c, cat.NodeDrawerProbeLatencyDesc()).FontSize(11).TextColor(p.textDim).LineHeight(1.3)
							})

							// B: Real Traffic Latency EWMA (真实业务延迟)
							ui.Column(c).Gap(3).Children(func() {
								ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
									ui.Text(c, cat.NodeDrawerRealLatency()).FontSize(12).FontWeight(600).TextColor(p.text)
									if a.tracker != nil && rt.State == runner.StateRunning {
										sc := a.tracker.GetScore(svc.ID)
										if sc.EWMA > 0 {
											tagPill(c, cat.LatencyPill(int(max(1, sc.EWMA.Milliseconds()))), p.accentText, p.accentBg)
										} else {
											ui.Text(c, cat.NodeDrawerAwaitingSample()).FontSize(12).TextColor(p.textDim)
										}
									} else {
										ui.Text(c, cat.NodeDrawerPIDNone()).FontSize(12).TextColor(p.textDim)
									}
								})
								ui.Text(c, cat.NodeDrawerRealLatencyDesc()).FontSize(11).TextColor(p.textDim).LineHeight(1.3)
							})

							// C: Download Bandwidth (下载测速)
							ui.Column(c).Gap(3).Children(func() {
								ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
									ui.Text(c, cat.NodeDrawerDownloadSpeed()).FontSize(12).FontWeight(600).TextColor(p.text)
									if rt.SpeedTesting {
										if rt.DownloadSpeed > 0 {
											tagPill(c, cat.DownloadTesting()+" "+runner.FormatSpeed(rt.DownloadSpeed), p.amber, p.amberBg)
										} else {
											tagPill(c, cat.DownloadTesting(), p.amber, p.amberBg)
										}
									} else if rt.SpeedError != "" {
										tagPill(c, cat.DownloadFailed(), p.red, p.redBg)
									} else if rt.DownloadSpeed > 0 {
										tagPill(c, "↓ "+runner.FormatSpeed(rt.DownloadSpeed), p.green, p.greenBg)
									} else {
										ui.Text(c, cat.NodeDrawerNotTested()).FontSize(12).TextColor(p.textDim)
									}
								})
							})
						})

					// 3. Basic & Protocol Information
					ui.Column(c).Gap(10).Padding(14).Radius(10).
						Background(p.card).Border(1, p.borderSubtle).
						Children(func() {
							ui.Text(c, cat.NodeDrawerBasic()).FontSize(12).FontWeight(700).TextColor(p.textDim)
							ui.Text(c, svc.Name).FontSize(16).FontWeight(700).TextColor(p.text)

							ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
								ui.Text(c, "ID:").FontSize(11).TextColor(p.textDim)
								ui.Text(c, svc.ID).FontSize(11).TextColor(p.textMuted)
							})

							protoStr := strings.ToUpper(string(svc.EffectiveProtocol()))
							engineStr := "SING-BOX"
							if svc.EffectiveEngine() == config.EngineSidecar {
								engineStr = "SIDECAR"
							}

							ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
								tagPill(c, protoStr+" · "+engineStr, p.accentText, p.accentBg)
								if svc.AutoStart {
									tagPill(c, cat.TagAutoStart(), p.accentText, p.accentBg)
								}
								if svc.InsecureConcurrency > 1 {
									tagPill(c, cat.ConcurrencyPill(svc.InsecureConcurrency), p.textMuted, p.elevated)
								}
								if svc.NoPostQuantum {
									tagPill(c, "No-PQ", p.textMuted, p.elevated)
								}
							})

							if len(svc.Tags) > 0 {
								ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
									for _, tag := range svc.Tags {
										if tag != "" {
											tagPill(c, "#"+tag, p.accentText, p.accentBg)
										}
									}
								})
							}
						})

					// 4. Network Inbound & Outbound (内置节点没有独立本地链接)
					ui.Column(c).Gap(10).Padding(14).Radius(10).
						Background(p.card).Border(1, p.borderSubtle).
						Children(func() {
							ui.Text(c, cat.NodeDrawerNetwork()).FontSize(12).FontWeight(700).TextColor(p.textDim)

							// Inbound
							ui.Column(c).Gap(3).Children(func() {
								ui.Text(c, cat.NodeDrawerLocalListen()).FontSize(11).TextColor(p.textDim)
								listenSummary := cat.NodeDrawerLocalListenInProcess()
								if svc.EffectiveEngine() == config.EngineSidecar {
									listens := strings.Join(svc.Listens, ", ")
									if listens == "" || svc.PrimaryListen() == "socks://127.0.0.1:0" {
										if rt.State == runner.StateRunning && rt.PID > 0 {
											listens = svc.PrimaryListen()
										} else {
											listens = "Auto Loopback (:0)"
										}
									}
									listenSummary = listens
								}
								ui.Text(c, listenSummary).FontSize(13).FontWeight(600).TextColor(p.text)
							})

							// Outbound
							ui.Column(c).Gap(3).Children(func() {
								ui.Text(c, cat.NodeDrawerRemoteEndpoint()).FontSize(11).TextColor(p.textDim)
								remote := svc.RedactedProxy()
								if remote == "" {
									remote = svc.CompactRemoteEndpoint()
								}
								if remote == "" {
									remote = cat.NoRemoteConfigured()
								}
								ui.Text(c, remote).FontSize(12).TextColor(p.textMuted).LineHeight(1.3)
							})
						})

					// 5. Configuration Preview (配置预览项)
					ui.Column(c).Gap(10).Padding(14).Radius(10).
						Background(p.card).Border(1, p.borderSubtle).
						Children(func() {
							ui.Text(c, cat.NodeDrawerConfigPreview()).FontSize(12).FontWeight(700).TextColor(p.textDim)

							// A: Share Link Preview (all protocols)
							shareURI := svc.ShareURI()
							if shareURI != "" {
								ui.Column(c).Gap(4).Padding(10).Radius(8).Background(p.codeBg).Border(1, p.borderSubtle).Children(func() {
									ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
										ui.Text(c, cat.PreviewNaiveShareLink()).FontSize(11).FontWeight(600).TextColor(p.textMuted)
										if subtleActionChip(c.Key("drawer-preview-copy-share"), p, iconCopy, cat.BtnCopy(), false).Clicked() {
											a.writeClipboard(shareURI, cat.CopiedNaiveShareLink())
										}
									})
									ui.Text(c, shareURI).FontSize(11).TextColor(p.text).LineHeight(1.3)
								})
							}

							// B: Local Link (Sidecar only, 内置节点没有独立本地链接)
							if svc.EffectiveEngine() == config.EngineSidecar {
								localURI := svc.V2rayNSocksURI()
								ui.Column(c).Gap(4).Padding(10).Radius(8).Background(p.codeBg).Border(1, p.borderSubtle).Children(func() {
									ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
										ui.Text(c, cat.PreviewLocalLink()).FontSize(11).FontWeight(600).TextColor(p.textMuted)
										if subtleActionChip(c.Key("drawer-preview-copy-local"), p, iconCopy, cat.BtnCopy(), false).Clicked() {
											a.writeClipboard(localURI, cat.CopiedLocalLink())
										}
									})
									ui.Text(c, localURI).FontSize(11).TextColor(p.accent)
								})
							}

							// C: Core Engine JSON Configuration Preview
							if svc.EffectiveEngine() == config.EngineSidecar && svc.EffectiveProtocol() == config.ProtoNaive {
								rawJSON, _ := svc.ToConfigJSON()
								ui.Column(c).Gap(6).Padding(10).Radius(8).Background(p.codeBg).Border(1, p.borderSubtle).Children(func() {
									ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
										ui.Text(c, cat.PreviewNaiveJSON()).FontSize(11).FontWeight(600).TextColor(p.textMuted)
										if subtleActionChip(c.Key("drawer-preview-copy-json"), p, iconCopy, cat.BtnCopyJSON(), false).Clicked() {
											a.writeClipboard(string(rawJSON), cat.CopiedConfigJSON())
										}
									})
									ui.Text(c, string(rawJSON)).FontSize(11).TextColor(p.text).LineHeight(1.3)
								})
							} else if svc.EffectiveEngine() == config.EngineSidecar {
								cfgBytes, _ := runner.GenerateXrayConfig(svc, 1080)
								ui.Column(c).Gap(6).Padding(10).Radius(8).Background(p.codeBg).Border(1, p.borderSubtle).Children(func() {
									ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
										ui.Text(c, cat.PreviewXrayJSON()).FontSize(11).FontWeight(600).TextColor(p.textMuted)
										if subtleActionChip(c.Key("drawer-preview-copy-xray-json"), p, iconCopy, cat.BtnCopyJSON(), false).Clicked() {
											a.writeClipboard(string(cfgBytes), cat.CopiedXrayJSON())
										}
									})
									ui.Text(c, string(cfgBytes)).FontSize(11).TextColor(p.text).LineHeight(1.3)
								})
							} else {
								obMap := boxengine.BuildNativeOutbound(svc)
								obJSON, _ := json.MarshalIndent(obMap, "", "  ")
								ui.Column(c).Gap(6).Padding(10).Radius(8).Background(p.codeBg).Border(1, p.borderSubtle).Children(func() {
									ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
										ui.Text(c, cat.PreviewSingBoxJSON()).FontSize(11).FontWeight(600).TextColor(p.textMuted)
										if subtleActionChip(c.Key("drawer-preview-copy-sb-json"), p, iconCopy, cat.BtnCopyJSON(), false).Clicked() {
											a.writeClipboard(string(obJSON), cat.CopiedSingBoxJSON())
										}
									})
									ui.Text(c, string(obJSON)).FontSize(11).TextColor(p.text).LineHeight(1.3)
								})
							}
						})

					// 6. Quick Actions (内置节点不提供本地链接复制)
					ui.Column(c).Gap(10).Padding(14).Radius(10).
						Background(p.card).Border(1, p.borderSubtle).
						Children(func() {
							ui.Text(c, cat.NodeDrawerQuickActions()).FontSize(12).FontWeight(700).TextColor(p.textDim)

							// Start / Stop toggle
							isRunning := rt.State == runner.StateRunning || rt.State == runner.StateStarting
							toggleLabel := cat.ActionStart()
							toggleIcon := iconPlay
							toggleColor := p.accent
							if isRunning {
								toggleLabel = cat.ActionStop()
								toggleIcon = iconStop
								toggleColor = p.red
							}
							if primaryPillButton(c.Key("drawer-toggle"), p, toggleIcon, toggleLabel, toggleColor, false).Clicked() {
								a.toggleService(svc)
							}

							ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
								if svc.EffectiveEngine() == config.EngineSidecar {
									if subtleActionChip(c.Key("drawer-copy-local"), p, iconCopy, cat.ActionCopyV2rayN(), false).Clicked() {
										a.copyV2rayNLink(svc)
									}
								}
								if subtleActionChip(c.Key("drawer-copy-share"), p, iconCopy, cat.ActionCopyNaive(), false).Clicked() {
									a.copyShareLink(svc)
								}
							})
						})
				})
			})
		})
}
