package app

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/egoist/mygo/ui"

	"naive-client/internal/boxengine"
	"naive-client/internal/config"
	"naive-client/internal/runner"
	"naive-client/internal/telemetry"
	"naive-client/locales"
)

func (a *app) renderNodeDrawer(c *ui.Context, p palette) {
	if a.activeNodeDrawerID == "" {
		a.nodeDrawerLastID = ""
		a.nodeDrawerHelpOpen = false
		return
	}

	svc, ok := a.findService(a.activeNodeDrawerID)
	if !ok {
		a.activeNodeDrawerID = ""
		a.nodeDrawerLastID = ""
		a.nodeDrawerHelpOpen = false
		return
	}

	if a.activeNodeDrawerID != a.nodeDrawerLastID {
		a.nodeDrawerLastID = a.activeNodeDrawerID
		a.nodeDrawerHelpOpen = false
		a.nodeDrawerJSONOpen = false
	}

	rt := a.mgr.StatusOf(svc.ID)
	unhealthy := a.isNodeUnhealthy(svc, rt)

	dsDrawerShell(c, p, dsDrawerSpec{
		BackdropKey: "node-drawer-backdrop",
		PanelKey:    "node-drawer-panel",
		OnDismiss: func() {
			a.activeNodeDrawerID = ""
			a.nodeDrawerHelpOpen = false
		},
	}, func() {
		a.renderNodeDrawerHeader(c, p, svc, rt, unhealthy)

		dsDetailBody(c, p, "node-drawer-scroll", nil, func() {
			a.renderNodeDrawerDiagnosticBanner(c, p, svc, rt, unhealthy)
			a.renderNodeDrawerTelemetryCard(c, p, svc, rt, unhealthy)
			a.renderNodeDrawerParamsCard(c, p, svc, rt)
			a.renderNodeDrawerConfigCard(c, p, svc)
		})
	})
}

func (a *app) renderNodeDrawerHeader(c *ui.Context, p palette, svc config.Service, rt runner.Status, unhealthy bool) {
	cat := a.catalog()
	statusText, statusColor := runtimeStatusTextAndColor(cat, p, rt.State, unhealthy)
	isRunning := rt.State == runner.StateRunning || rt.State == runner.StateStarting

	ui.Row(c).
		AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(10).
		Padding(14, 20, 14, 20).
		BorderWidth(0, 0, 1, 0).BorderColor(p.borderSubtle).
		Children(func() {
			// Left: eyebrow + status dot & name + compact meta line
			ui.Column(c).Grow(1).Shrink(1).MinWidth(0).Gap(4).Children(func() {
				dsDetailHeaderEyebrow(c, p, cat.NodeDrawerTitle(), statusText, statusColor)

				ui.Row(c).AlignItems(ui.Center).Gap(8).MinWidth(0).Children(func() {
					renderServiceStatusDot(c, p, rt, unhealthy)
					ui.Text(c, svc.Name).FontSize(15).FontWeight(700).TextColor(p.text).
						SingleLine().Ellipsis("…").Shrink(1).MinWidth(0)
				})

				ui.Row(c).AlignItems(ui.Center).Gap(6).Padding(0, 0, 0, 15).MinWidth(0).Children(func() {
					ui.Text(c, nodeProtocolEngineLabel(svc)).FontSize(11).FontWeight(500).TextColor(p.textMuted).NoWrap().Shrink(0)
					if svc.EffectiveProtocol() == config.ProtoWARP {
						if svc.IsBuiltinWarp() {
							drawerInlineNeutralChip(c, p, cat.BuiltinTag())
						}
						drawerInlineNeutralChip(c, p, a.warpTransportPillLabel(svc))
					} else if svc.EnableWARP {
						drawerInlineAccentChip(c, p, "➔ "+a.warpTransportPillLabel(svc))
					}
					for i, tag := range svc.Tags {
						if i >= 2 || strings.TrimSpace(tag) == "" {
							continue
						}
						drawerInlineNeutralChip(c, p, "#"+strings.TrimSpace(tag))
					}
				})
			})

			// Right: Logs + Edit | Start/Stop Switch + Close
			ui.Row(c).AlignItems(ui.Center).Gap(4).Shrink(0).Children(func() {
				logsBtn := subtleActionChip(c.Key("btn-drawer-logs-node"), p, iconList, cat.NodeDrawerLogsShort(), false).
					Label(cat.NodeDrawerLogs()).
					Tooltip(cat.NodeDrawerLogs())
				if logsBtn.Clicked() {
					targetID := a.activeNodeDrawerID
					a.activeNodeDrawerID = ""
					a.nodeDrawerHelpOpen = false
					a.activeLogDrawerID = targetID
				}

				editLocked := svc.IsBuiltinWarp() && isRunning
				editBtn := subtleActionChip(c.Key("btn-drawer-edit-node"), p, iconEdit, cat.ActionEdit(), editLocked).
					Label(cat.NodeDrawerEdit()).
					Tooltip(cat.NodeDrawerEdit())
				if editBtn.Clicked() && !editLocked {
					a.openEditServiceFromDrawer(svc)
				}

				ui.Box(c).Size(1, 16).Background(p.borderSubtle).Margin(0, 4, 0, 4).Shrink(0)

				toggleTip := cat.ActionStartNode()
				if isRunning {
					toggleTip = cat.ActionStopNode()
				}
				swVal := isRunning
				if ui.Switch(c.Key("drawer-toggle"), &swVal).Label(toggleTip).Tooltip(toggleTip).Changed() {
					a.toggleService(svc)
				}

				closeBtn := quietRowIconButton(c.Key("btn-drawer-close-node"), p, iconClose, cat.NodeDrawerClose(), false, false).
					Tooltip(cat.NodeDrawerClose())
				if closeBtn.Clicked() {
					a.activeNodeDrawerID = ""
					a.nodeDrawerHelpOpen = false
				}
			})
		})
}

func (a *app) renderNodeDrawerDiagnosticBanner(c *ui.Context, p palette, svc config.Service, rt runner.Status, unhealthy bool) {
	cat := a.catalog()
	if rt.LastError != "" {
		ui.Column(c.Key("drawer-error-diag")).Gap(8).Padding(12).Radius(10).
			Background(p.redBg).Border(1, p.red.Alpha(0.24)).
			Children(func() {
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(8).Children(func() {
					ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
						ui.Icon(c, iconAlert).Size(13, 13).TextColor(p.red)
						ui.Text(c, cat.StatusError()).FontSize(12).FontWeight(700).TextColor(p.red)
					})
					if subtleActionChip(c.Key("btn-copy-drawer-err"), p, iconCopy, cat.BtnCopy(), false).Tooltip(cat.ActionCopyError()).Clicked() {
						a.writeClipboard(rt.LastError, cat.ToastErrorCopied())
					}
				})
				ui.Text(c, rt.LastError).FontSize(11).TextColor(p.red).LineHeight(1.4)
			})
		return
	}

	if unhealthy {
		hint, _, _ := a.diagnoseNodeUnhealthy(svc, rt)
		if hint == "" {
			return
		}
		ui.Column(c.Key("drawer-unhealthy-diag")).Gap(6).Padding(12).Radius(10).
			Background(p.amberBg).Border(1, p.amber.Alpha(0.28)).
			Children(func() {
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(8).Children(func() {
					ui.Text(c, cat.NodeUnhealthyDiagnosticTitle()).FontSize(12).FontWeight(700).TextColor(p.amber)
					if svc.EffectiveProtocol() == config.ProtoWARP || svc.EnableWARP {
						if compactStripButton(c.Key("btn-drawer-goto-cf"), p, cat.ActionGoToCloudflare(), cat.ActionGoToCloudflare(), p.text).Clicked() {
							a.activeNodeDrawerID = ""
							a.nodeDrawerHelpOpen = false
							a.activeTab = TabCloudflare
						}
					}
				})
				ui.Text(c, hint).FontSize(11).TextColor(p.textMuted).LineHeight(1.4)
			})
	}
}

func (a *app) renderNodeDrawerTelemetryCard(c *ui.Context, p palette, svc config.Service, rt runner.Status, unhealthy bool) {
	cat := a.catalog()
	running := rt.State == runner.StateRunning
	canTest := running

	dsDetailCard(c, p, func() {
		// Card Header: Section label + ? Help Popover + Immediate Ping/Speed actions
		ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
			ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
				dsDetailSectionTitle(c, p, cat.NodeDrawerTelemetry())

					helpBtn := ui.ButtonBase(c.Key("btn-drawer-telemetry-help")).
						Label(cat.NodeDrawerMetricsHelpButton()).
						Size(18, 18).Radius(999).
						AlignItems(ui.Center).Justify(ui.Center).
						Background(p.elevated).
						Tooltip(cat.NodeDrawerMetricsHelpButton())
					if helpBtn.Hovered() {
						helpBtn.Background(p.cardHover)
					}
					helpBtn.Children(func() {
						ui.Text(c, "?").FontSize(10).FontWeight(600).TextColor(p.textMuted)
					})
					if helpBtn.Clicked() {
						a.nodeDrawerHelpOpen = !a.nodeDrawerHelpOpen
					}
					a.renderNodeDrawerHelpPopover(c, helpBtn, p)
				})

				ui.Row(c).AlignItems(ui.Center).Gap(4).Children(func() {
					manualProbing := rt.Probing && !rt.AutoProbing
					probeBtn := compactSubtleActionChip(c.Key("btn-drawer-probe"), p, iconBolt, cat.ActionLatency(), !canTest || manualProbing)
					if !canTest {
						probeBtn.Tooltip(cat.TestRequiresRunning())
					} else if rt.Probing && rt.AutoProbing {
						probeBtn.Tooltip(cat.AutoProbingActionHint())
					}
					if probeBtn.Clicked() {
						a.triggerServiceProbe(svc)
					}

					var speedBtn ui.Element
					if rt.SpeedTesting {
						speedBtn = compactDangerActionChip(c.Key("btn-drawer-speed"), p, iconStop, cat.ActionCancelSpeed())
						speedBtn.Tooltip(cat.ActionCancelSpeed())
					} else {
						speedBtn = compactSubtleActionChip(c.Key("btn-drawer-speed"), p, iconDownload, cat.ActionDownload(), !canTest)
						if !canTest {
							speedBtn.Tooltip(cat.TestRequiresRunning())
						}
					}
					if speedBtn.Clicked() {
						if rt.SpeedTesting {
							a.cancelServiceDownloadTest(svc)
						} else {
							a.triggerServiceDownloadTest(svc)
						}
					}
				})
			})

			// 2x2 Tabular Metrics Grid
			ewmaText, ewmaColor, ewmaSub := "—", p.textDim, ""
			probeText, probeColor, probeTip := "—", p.textDim, ""
			rateText, rateColor := "—", p.textDim
			scoreText, scoreColor := "—", p.textDim

			if running && a.tracker != nil {
				sc := a.tracker.GetScore(svc.ID)
				if sc.EWMA > 0 {
					ms := int(max(1, sc.EWMA.Milliseconds()))
					ewmaText = fmt.Sprintf("%d ms", ms)
					ewmaColor = latencyThresholdColor(p, ms)
				} else {
					ewmaText = cat.NodeDrawerAwaitingSample()
					ewmaColor = p.textDim
					ewmaSub = "small"
				}
				if sc.TotalDials > 0 {
					pct := sc.SuccessRate * 100
					rateText = fmt.Sprintf("%.1f%% (%d/%d)", pct, sc.SuccessfulDials, sc.TotalDials)
					switch {
					case pct >= 95:
						rateColor = p.text
					case pct >= 75:
						rateColor = p.amber
					default:
						rateColor = p.red
					}
				} else {
					rateText = cat.NodeDrawerAwaitingSample()
					rateColor = p.textDim
				}
				scoreText = cat.NodeDrawerScorePts(fmt.Sprintf("%.1f", sc.Score))
				scoreColor = p.text
			}

			if rt.Probing {
				if rt.AutoProbing {
					probeText = cat.AutoProbingShort()
					probeColor = p.textMuted
					probeTip = cat.AutoProbing()
				} else {
					probeText = cat.LatencyTestingShort()
					probeColor = p.amber
				}
			} else if rt.ProbeError != "" {
				probeText = cat.LatencyFailed()
				probeColor = p.red
				probeTip = rt.ProbeError
			} else if rt.Latency > 0 {
				ms := int(max(1, rt.Latency.Milliseconds()))
				probeText = fmt.Sprintf("%d ms", ms)
				probeColor = latencyThresholdColor(p, ms)
			} else if running {
				probeText = cat.NodeDrawerNotTested()
				probeColor = p.textDim
			}

			ui.Grid(c.Key("drawer-telemetry-grid")).Columns(2).Gap(8).Children(func() {
				dsDetailMetricTile(c, p, cat.NodeDrawerRealLatency(), ewmaText, ewmaColor, ewmaSub == "small", "")
				dsDetailMetricTile(c, p, cat.NodeDrawerProbeLatency(), probeText, probeColor, rt.Latency <= 0 && !rt.Probing && rt.ProbeError == "" && running, probeTip)
				dsDetailMetricTile(c, p, cat.NodeDrawerSuccessRate(), rateText, rateColor, rateText == cat.NodeDrawerAwaitingSample(), "")
				dsDetailMetricTile(c, p, cat.NodeDrawerFinalScore(), scoreText, scoreColor, false, "")
			})

			if rt.ProbeError != "" {
				ui.Text(c, rt.ProbeError).FontSize(11).TextColor(p.red).LineHeight(1.35)
			}
			if rt.SpeedError != "" {
				ui.Text(c, rt.SpeedError).FontSize(11).TextColor(p.red).LineHeight(1.35)
			}

			// Compact Circuit + Bandwidth footer
			circuitText, circuitColor := "—", p.textDim
			if running {
				if a.tracker != nil {
					sc := a.tracker.GetScore(svc.ID)
					switch {
					case sc.CircuitState == telemetry.CircuitHalfOpen:
						circuitText, circuitColor = circuitLabelForScore(cat, sc), p.amber
					case sc.IsBroken || sc.CircuitState == telemetry.CircuitOpen:
						circuitText, circuitColor = circuitLabelForScore(cat, sc), p.red
					case sc.ConsecutiveFailures > 0:
						circuitText, circuitColor = fmt.Sprintf("%d", sc.ConsecutiveFailures), p.amber
					case unhealthy:
						circuitText, circuitColor = cat.StatusUnhealthy(), p.amber
					default:
						circuitText, circuitColor = cat.NodeDrawerCircuitNormal(), p.green
					}
				} else if unhealthy {
					circuitText, circuitColor = cat.StatusUnhealthy(), p.amber
				} else {
					circuitText, circuitColor = cat.NodeDrawerCircuitNormal(), p.green
				}
			}

			bwText, bwColor, bwTip := "—", p.textDim, ""
			switch {
			case rt.SpeedTesting && rt.DownloadSpeed > 0:
				bwText, bwColor = "↓ "+runner.FormatSpeed(rt.DownloadSpeed), p.amber
			case rt.SpeedTesting:
				bwText, bwColor = "—", p.amber
			case rt.SpeedError != "":
				bwText, bwColor, bwTip = cat.DownloadFailed(), p.red, rt.SpeedError
			case rt.DownloadSpeed > 0:
				bwText, bwColor = "↓ "+runner.FormatSpeed(rt.DownloadSpeed), p.text
			}

			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(8).
				Padding(9, 0, 0, 0).BorderWidth(1, 0, 0, 0).BorderColor(p.borderSubtle).
				Children(func() {
					ui.Row(c).AlignItems(ui.Center).Gap(4).Children(func() {
						ui.Text(c, cat.NodeDrawerCircuitLabel()+":").FontSize(11).TextColor(p.textMuted)
						ui.Text(c, circuitText).FontSize(11).FontWeight(500).TextColor(circuitColor).NoWrap()
					})
					ui.Row(c).AlignItems(ui.Center).Gap(4).Children(func() {
						ui.Text(c, cat.NodeDrawerBandwidthLabel()+":").FontSize(11).TextColor(p.textMuted)
						bw := ui.Text(c, bwText).FontSize(11).FontWeight(500).FontFeatures("tnum").TextColor(bwColor).NoWrap()
						if bwTip != "" {
							bw.Tooltip(bwTip)
						}
					})
				})
		})
}

func (a *app) renderNodeDrawerHelpPopover(c *ui.Context, anchor ui.Element, p palette) {
	cat := a.catalog()
	ui.PopoverBase(c, anchor, &a.nodeDrawerHelpOpen, func(panel ui.Element) {
		panel.Column().
			AttachTo(anchor, ui.AnchorBottomStart, ui.AnchorTopStart).
			Margin(6, 0, 0, 0).
			Width(320).Padding(12).Gap(8).Radius(10).
			Background(p.card).Border(1, p.border).
			Shadow(0, 10, 28, 0, ui.RGBA(0, 0, 0, 0.22)).
			Children(func() {
				ui.Text(c, cat.NodeDrawerTelemetryHelp()).FontSize(12).FontWeight(700).TextColor(p.text)
				ui.Text(c, cat.NodeDrawerProbeLatencyDesc()).FontSize(11).TextColor(p.textMuted).LineHeight(1.35)
				ui.Text(c, cat.NodeDrawerRealLatencyDesc()).FontSize(11).TextColor(p.textMuted).LineHeight(1.35)
				ui.Text(c, cat.NodeDrawerSuccessRateDesc()).FontSize(11).TextColor(p.textMuted).LineHeight(1.35)
				ui.Text(c, cat.NodeDrawerCircuitDesc()).FontSize(11).TextColor(p.textMuted).LineHeight(1.35)
				ui.Text(c, cat.NodeDrawerFinalScoreDesc()).FontSize(11).TextColor(p.textMuted).LineHeight(1.35)
			})
	})
}

func (a *app) renderNodeDrawerParamsCard(c *ui.Context, p palette, svc config.Service, rt runner.Status) {
	cat := a.catalog()
	dsDetailCard(c, p, func() {
		dsDetailSectionTitle(c, p, cat.NodeDrawerNetwork())

		dsDetailKvGroup(c, func() {
			// PID
			pidText, pidColor := cat.NodeDrawerPIDNone(), p.textDim
			if rt.State == runner.StateRunning {
				if rt.PID > 0 {
					pidText, pidColor = fmt.Sprintf("PID %d", rt.PID), p.text
				} else if svc.EffectiveEngine() == config.EngineSingBox {
					pidText, pidColor = cat.NodeDrawerPIDEmbedded(), p.textMuted
				}
			}
			dsDetailKvRow(c, p, cat.NodeDrawerPID(), pidText, false, true, pidColor, "")

			// Local Listen
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
			dsDetailKvRow(c, p, cat.NodeDrawerLocalListen(), listenSummary, svc.EffectiveEngine() == config.EngineSidecar, false, p.text, listenSummary)

			// Remote Endpoint
			remote := svc.RedactedProxy()
			if remote == "" {
				remote = svc.CompactRemoteEndpoint()
			}
			if remote == "" {
				remote = cat.NoRemoteConfigured()
			}
			dsDetailKvRow(c, p, cat.NodeDrawerRemoteEndpoint(), remote, true, false, p.textMuted, remote)

			// AutoStart
			autoText, autoColor := cat.NodeDrawerDisabled(), p.textDim
			if svc.AutoStart {
				autoText, autoColor = cat.NodeDrawerEnabled(), p.text
			}
			dsDetailKvRow(c, p, cat.NodeDrawerAutoStart(), autoText, false, false, autoColor, "")

			if svc.InsecureConcurrency > 1 {
				dsDetailKvRow(c, p, cat.NodeDrawerConcurrency(), fmt.Sprintf("%dx", svc.InsecureConcurrency), false, true, p.text, "")
			}
			if svc.EnableWARP && svc.EffectiveProtocol() != config.ProtoWARP {
				dsDetailKvRow(c, p, cat.NodeDrawerWarpChain(), a.warpTransportPillLabel(svc), false, false, p.text, "")
			}
			if rt.Restarts > 0 {
				dsDetailKvRow(c, p, cat.NodeDrawerRestarts(), cat.RestartsPill(rt.Restarts), false, true, p.amber, "")
			}
			if len(svc.Tags) > 2 {
				dsDetailKvRow(c, p, cat.TagsLabel(), strings.Join(svc.Tags, ", "), false, false, p.textMuted, "")
			}
		})

		// Subtle ID metadata footer
		ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Padding(6, 0, 0, 0).
			BorderWidth(1, 0, 0, 0).BorderColor(p.borderSubtle).
			Children(func() {
				ui.Text(c, "ID").FontSize(11).TextColor(p.textDim)
				ui.Text(c, svc.ID).Font("monospace").FontSize(11).TextColor(p.textDim)
			})
	})
}

func (a *app) renderNodeDrawerConfigCard(c *ui.Context, p palette, svc config.Service) {
	cat := a.catalog()
	dsDetailCard(c, p, func() {
		dsDetailSectionTitle(c, p, cat.NodeDrawerConfigPreview())

		shareURI := svc.ShareURI()
		if shareURI != "" {
			dsDetailInsetBlock(c, p, 5, func() {
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
					ui.Text(c, cat.PreviewNaiveShareLink()).FontSize(11).FontWeight(500).TextColor(p.textMuted)
					if compactSubtleActionChip(c.Key("drawer-preview-copy-share"), p, iconCopy, cat.BtnCopy(), false).Clicked() {
						a.writeClipboard(shareURI, cat.CopiedNaiveShareLink())
					}
				})
				ui.Text(c, shareURI).Font("monospace").FontSize(11).TextColor(p.text).
					SingleLine().Ellipsis("…").Tooltip(shareURI)
			})
		}

		if svc.EffectiveEngine() == config.EngineSidecar {
			localURI := svc.V2rayNSocksURI()
			dsDetailInsetBlock(c, p, 5, func() {
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
					ui.Text(c, cat.PreviewLocalLink()).FontSize(11).FontWeight(500).TextColor(p.textMuted)
					if compactSubtleActionChip(c.Key("drawer-preview-copy-local"), p, iconCopy, cat.BtnCopy(), false).Clicked() {
						a.writeClipboard(localURI, cat.CopiedLocalLink())
					}
				})
				ui.Text(c, localURI).Font("monospace").FontSize(11).TextColor(p.accent).
					SingleLine().Ellipsis("…").Tooltip(localURI)
			})
		}

		// Collapsible Core Engine JSON Preview
		jsonTitle, copyKey := nodeCoreJSONMeta(cat, svc)
		col := ui.CollapsibleBase(c.Key("drawer-json-collapsible"), &a.nodeDrawerJSONOpen)
		toggleLabel := cat.NodeDrawerExpandPreview()
		chevIcon := iconChevronDown
		if a.nodeDrawerJSONOpen {
			toggleLabel = cat.NodeDrawerCollapsePreview()
			chevIcon = iconChevronUp
		}
		col.Trigger.FillWidth().AlignItems(ui.Center).Justify(ui.SpaceBetween).
			Padding(6, 4, 6, 4).Radius(6).
			Children(func() {
				ui.Text(c, jsonTitle).FontSize(11).FontWeight(500).TextColor(p.textMuted).
					SingleLine().Ellipsis("…").Shrink(1).MinWidth(0)
				ui.Row(c).AlignItems(ui.Center).Gap(4).Shrink(0).Children(func() {
					ui.Text(c, toggleLabel).FontSize(11).FontWeight(500).TextColor(p.accentText).NoWrap()
					ui.Icon(c, chevIcon).Size(12, 12).TextColor(p.accentText)
				})
			})
		if col.Trigger.Hovered() {
			col.Trigger.Background(p.elevated)
		}
		if panel := col.Panel(func() {
			rawJSON, toastMsg := buildNodeCoreConfigJSON(cat, svc)
			dsDetailInsetBlock(c, p, 6, func() {
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
					ui.Text(c, "JSON").FontSize(11).FontWeight(500).TextColor(p.textDim)
					if compactSubtleActionChip(c.Key(copyKey), p, iconCopy, cat.BtnCopyJSON(), false).Clicked() {
						a.writeClipboard(rawJSON, toastMsg)
					}
				})
				ui.Text(c, rawJSON).Font("monospace").FontSize(11).TextColor(p.text).LineHeight(1.35)
			})
		}); panel.Valid() {
			panel.Padding(4, 0, 0, 0)
		}
	})
}

func runtimeStatusTextAndColor(cat locales.Messages, p palette, st runner.State, unhealthy bool) (string, ui.Color) {
	if unhealthy && st == runner.StateRunning {
		return cat.StatusUnhealthy(), p.amber
	}
	switch st {
	case runner.StateRunning:
		return cat.StatusRunning(), p.green
	case runner.StateStarting:
		return cat.StatusStarting(), p.amber
	case runner.StateError:
		return cat.StatusError(), p.red
	default:
		return cat.StatusStopped(), p.textMuted
	}
}

func drawerInlineNeutralChip(c *ui.Context, p palette, label string) {
	ui.Row(c).AlignItems(ui.Center).Shrink(0).PaddingX(6).PaddingY(1).Radius(4).Background(p.elevated).Children(func() {
		ui.Text(c, label).FontSize(10).FontWeight(500).TextColor(p.textMuted).NoWrap()
	})
}

func drawerInlineAccentChip(c *ui.Context, p palette, label string) {
	ui.Row(c).AlignItems(ui.Center).Shrink(0).PaddingX(6).PaddingY(1).Radius(4).Background(p.accentBg).Children(func() {
		ui.Text(c, label).FontSize(10).FontWeight(500).TextColor(p.accentText).NoWrap()
	})
}

func nodeCoreJSONMeta(cat locales.Messages, svc config.Service) (title, copyKey string) {
	if svc.EffectiveEngine() == config.EngineSidecar && svc.EffectiveProtocol() == config.ProtoNaive {
		return cat.PreviewNaiveJSON(), "drawer-preview-copy-json"
	}
	if svc.EffectiveEngine() == config.EngineSidecar {
		return cat.PreviewXrayJSON(), "drawer-preview-copy-xray-json"
	}
	return cat.PreviewSingBoxJSON(), "drawer-preview-copy-sb-json"
}

func buildNodeCoreConfigJSON(cat locales.Messages, svc config.Service) (rawJSON, copiedToast string) {
	if svc.EffectiveEngine() == config.EngineSidecar && svc.EffectiveProtocol() == config.ProtoNaive {
		b, _ := svc.ToConfigJSON()
		return string(b), cat.CopiedConfigJSON()
	}
	if svc.EffectiveEngine() == config.EngineSidecar {
		b, _ := runner.GenerateXrayConfig(svc, 1080)
		return string(b), cat.CopiedXrayJSON()
	}
	obMap := boxengine.BuildNativeOutbound(svc)
	b, _ := json.MarshalIndent(obMap, "", "  ")
	return string(b), cat.CopiedSingBoxJSON()
}
