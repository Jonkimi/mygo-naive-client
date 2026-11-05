package app

import (
	"fmt"
	"strings"

	"github.com/egoist/mygo/ui"

	"naive-client/internal/config"
	"naive-client/internal/runner"
)

func (a *app) view(c *ui.Context) {
	a.applyThemeToContext(c)
	p := paletteFor(c.Theme())

	c.OnShortcut(0, ui.KeyEscape, func() {
		if a.activeLogDrawerID != "" {
			a.activeLogDrawerID = ""
		}
	})
	c.OnShortcut(ui.Cmd, ui.Key1, func() { a.activeTab = TabNodes })
	c.OnShortcut(ui.Cmd, ui.Key2, func() { a.activeTab = TabRouting })
	c.OnShortcut(ui.Cmd, ui.Key3, func() { a.activeTab = TabInsights })
	c.OnShortcut(ui.Cmd, ui.Key4, func() { a.activeTab = TabTailnet })
	c.OnShortcut(ui.Cmd, ui.Key5, func() { a.activeTab = TabSettings })

	ui.Row(c).Fill().AlignItems(ui.Stretch).Children(func() {
		a.renderSidebar(c, p)

		ui.Column(c.Key("main")).Grow(1).Background(p.surface).Children(func() {
			a.renderTopControlBar(c, p)
			switch a.activeTab {
			case TabNodes:
				a.renderToolbar(c, p)
				a.renderServiceList(c, p)
			case TabSettings:
				a.renderSettingsPage(c, p)
			case TabRouting:
				a.renderPlaceholderPage(c, p, a.catalog().NavRouting(), "分流规则引擎将在阶段二就绪")
			case TabInsights:
				a.renderPlaceholderPage(c, p, a.catalog().NavInsights(), "洞察与拦截看板将在阶段三就绪")
			case TabTailnet:
				a.renderPlaceholderPage(c, p, a.catalog().NavTailnet(), "Tailnet 组网将在阶段五就绪")
			}
		})
	})

	a.renderLogDrawer(c, p)

	a.renderEditorDialog(c, p)
	a.renderImportDialog(c, p)
	a.renderDeleteDialog(c, p)

	if a.pendingToast != "" {
		c.Toast(a.pendingToast)
		a.pendingToast = ""
	}
}

func (a *app) renderTopControlBar(c *ui.Context, p palette) {
	cat := a.catalog()
	ui.Row(c).
		AlignItems(ui.Center).Justify(ui.SpaceBetween).
		PaddingX(20).PaddingY(10).
		Background(p.surface).
		BorderWidth(0, 0, 1, 0).BorderColor(p.borderSubtle).
		Children(func() {
			// Left: Gateway master switch
			ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
				ui.Box(c).Size(8, 8).Radius(999).Background(p.green)
				ui.Text(c, cat.MasterGateway()).FontSize(13).FontWeight(600).TextColor(p.text)
			})

			// Center: 3 Modes
			ui.Row(c).AlignItems(ui.Center).Gap(4).Padding(2).Radius(6).Background(p.elevated).Children(func() {
				tagPill(c, cat.ModePortOnly(), p.accentText, p.accentBg)
				tagPill(c, cat.ModeSysProxy(), p.textMuted, ui.Transparent)
				tagPill(c, cat.ModeTun(), p.textMuted, ui.Transparent)
			})

			// Right: Tailnet status capsule
			ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
				tagPill(c, "Tailnet: "+cat.TailnetNotConnected(), p.textDim, p.elevated)
			})
		})
}

func (a *app) renderPlaceholderPage(c *ui.Context, p palette, title, desc string) {
	ui.Column(c).
		AlignItems(ui.Center).Justify(ui.Center).
		Grow(1).Fill().Gap(10).
		Children(func() {
			ui.Text(c, title).FontSize(16).FontWeight(700).TextColor(p.text)
			ui.Text(c, desc).FontSize(12).TextColor(p.textMuted)
		})
}

func (a *app) applyThemeToContext(c *ui.Context) {
	switch a.state.Appearance {
	case appearanceDark:
		c.SetTheme(ui.DarkTheme())
	case appearanceLight:
		c.SetTheme(ui.LightTheme())
	}
}

func (a *app) renderToolbar(c *ui.Context, p palette) {
	cat := a.catalog()
	runningCount := 0
	for _, svc := range a.state.Services {
		st := a.mgr.StatusOf(svc.ID).State
		if st == runner.StateRunning || st == runner.StateStarting {
			runningCount++
		}
	}

	ui.Column(c).
		PaddingX(20).PaddingY(10).Gap(8).
		Background(p.bg).
		Children(func() {
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Gap(10).Children(func() {
					ui.Text(c, cat.LocalServicesLabel(len(a.state.Services))).
						FontSize(14).FontWeight(600).TextColor(p.text)
					if runningCount > 0 {
						statusBadge(c, cat.RunningCountBadge(runningCount), p.green, p.greenBg)
					} else {
						tagPill(c, cat.AllStoppedBadge(), p.textMuted, p.elevated)
					}
				})

				ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
					if len(a.state.Services) > 0 {
						if actionChip(c.Key("btn-start-all"), p, iconPlay, cat.ActionStartAll(), runningCount == len(a.state.Services)).Clicked() {
							a.startAllServices()
						}
						if actionChip(c.Key("btn-stop-all"), p, iconStop, cat.ActionStopAll(), runningCount == 0).Clicked() {
							a.stopAllServices()
						}
						batchLabel := cat.ActionBatchTest()
						if a.batchTesting && a.batchStage != "" {
							batchLabel = a.batchStage
						}
						batchDisabled := runningCount == 0 && !a.batchTesting
						if actionChip(c.Key("btn-batch-test"), p, iconBolt, batchLabel, batchDisabled).Clicked() {
							a.triggerBatchTest()
						}
					}
				})
			})

			ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
				if primaryPillButton(c.Key("btn-new-service"), p, iconPlus, cat.NewService(), p.accent, false).Clicked() {
					a.openCreateServiceDialog()
				}
				if actionChip(c.Key("btn-import-service"), p, iconPaste, cat.ImportClipboard(), false).Clicked() {
					a.openImportDialog()
				}
			})
		})
}

func (a *app) renderServiceList(c *ui.Context, p palette) {
	ui.Scroll(c.Key("service-scroll")).
		TrackScroll(&a.mainScroll).
		Fill().
		Padding(0, 20, 20, 20).
		Gap(12).
		Children(func() {
			if len(a.state.Services) == 0 {
				a.renderEmptyState(c, p)
				return
			}
			for i := range a.state.Services {
				svc := a.state.Services[i]
				a.renderServiceCard(c.Key(svc.ID), p, svc)
			}
		})
}

func (a *app) renderEmptyState(c *ui.Context, p palette) {
	cat := a.catalog()
	ui.Column(c).
		AlignItems(ui.Center).Justify(ui.Center).
		PaddingX(32).PaddingY(48).Gap(12).
		Radius(12).Background(p.card).Border(1, p.border).
		Children(func() {
			ui.Row(c).AlignItems(ui.Center).Justify(ui.Center).
				Size(48, 48).Radius(999).Background(p.accentBg).TextColor(p.accent).
				Children(func() {
					ui.Icon(c, iconShield).Size(24, 24)
				})
			ui.Text(c, cat.NoNodes()).FontSize(15).FontWeight(600).TextColor(p.text)
			ui.Text(c, cat.NoNodesDesc()).FontSize(12).TextColor(p.textMuted)
			ui.Row(c).AlignItems(ui.Center).Gap(10).Padding(8, 0, 0, 0).Children(func() {
				if primaryPillButton(c.Key("empty-new-btn"), p, iconPlus, cat.AddNode(), p.accent, false).Clicked() {
					a.openCreateServiceDialog()
				}
				if actionChip(c.Key("empty-import-btn"), p, iconPaste, cat.ImportFromClipboard(), false).Clicked() {
					a.openImportDialog()
				}
			})
		})
}

func (a *app) renderServiceCard(c *ui.Context, p palette, svc config.Service) {
	cat := a.catalog()
	rt := a.mgr.StatusOf(svc.ID)
	logsOpen := a.expandedLogs[svc.ID]

	ui.Column(c).
		Padding(16, 16, 14, 16).Gap(11).
		Radius(12).Background(p.card).
		Border(1, a.cardBorderColor(p, rt.State)).
		Children(func() {
			// Row 1: Status badge + Service Name + metadata badges + Start/Stop button
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
					a.renderRuntimeStatusBadge(c, p, rt.State)
					ui.Text(c, svc.Name).FontSize(15).FontWeight(700).TextColor(p.text)

					if svc.EffectiveKind() == config.KindExternalProxy {
						tagPill(c, cat.TagExternalProxy(), p.accentText, p.accentBg)
					} else {
						tagPill(c, cat.TagManagedNaive(), p.textMuted, p.elevated)
					}
					for _, tag := range svc.Tags {
						if tag != "" {
							tagPill(c, "#"+tag, p.accentText, p.accentBg)
						}
					}

					if svc.AutoStart {
						tagPill(c, cat.TagAutoStart(), p.accentText, p.accentBg)
					}
					if svc.InsecureConcurrency > 1 {
						tagPill(c, fmt.Sprintf("%dx 并发", svc.InsecureConcurrency), p.textMuted, p.elevated)
					}
					if svc.NoPostQuantum {
						tagPill(c, "No-PQ", p.textMuted, p.elevated)
					}
					if rt.State == runner.StateRunning && rt.PID > 0 {
						tagPill(c, fmt.Sprintf("PID %d", rt.PID), p.green, p.greenBg)
					}
					if rt.Restarts > 0 {
						tagPill(c, fmt.Sprintf("已重试 %d 次", rt.Restarts), p.amber, p.amberBg)
					}
					if rt.Probing {
						tagPill(c, cat.LatencyTesting(), p.amber, p.amberBg)
					} else if rt.ProbeError != "" {
						tagPill(c, cat.LatencyFailed(), p.red, p.redBg)
					} else if rt.Latency > 0 {
						tagPill(c, fmt.Sprintf("%d ms", max(1, rt.Latency.Milliseconds())), p.green, p.greenBg)
					}
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
					}
				})

				// Primary Start/Stop toggle button
				isRunning := rt.State == runner.StateRunning || rt.State == runner.StateStarting
				toggleLabel := cat.ActionStart()
				toggleIcon := iconPlay
				toggleColor := p.accent
				if isRunning {
					toggleLabel = cat.ActionStop()
					toggleIcon = iconStop
					toggleColor = p.red
				}
				if primaryPillButton(c.Key("toggle"), p, toggleIcon, toggleLabel, toggleColor, false).Clicked() {
					a.toggleService(svc)
				}
			})

			// Row 2: Local listen endpoint(s) & Remote proxy summary + Edit/Delete
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(10).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Gap(12).Children(func() {
					listens := strings.Join(svc.Listens, ", ")
					if listens == "" {
						listens = svc.PrimaryListen()
					}
					ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
						ui.Text(c, cat.LabelLocalListen()).FontSize(12).TextColor(p.textMuted)
						ui.Text(c, listens).FontSize(12).FontWeight(600).TextColor(p.text)
					})

					remoteProxy := svc.RedactedProxy()
					if svc.EffectiveKind() == config.KindExternalProxy && svc.ExternalURI != "" {
						remoteProxy = svc.ExternalURI
					}
					if remoteProxy != "" {
						ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
							ui.Text(c, cat.LabelRemoteNode()).FontSize(12).TextColor(p.textMuted)
							ui.Text(c, remoteProxy).FontSize(12).FontWeight(500).TextColor(p.text)
						})
					}
				})

				ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
					if actionChip(c.Key("edit-btn"), p, iconEdit, cat.ActionEdit(), false).Clicked() {
						a.openEditServiceDialog(svc)
					}
					if actionChip(c.Key("delete-btn"), p, iconTrash, cat.ActionDelete(), false).Clicked() {
						a.openDeleteServiceDialog(svc)
					}
				})
			})

			// Error Banner if process failed or crashed
			if rt.LastError != "" {
				ui.Row(c).AlignItems(ui.Center).PaddingX(10).PaddingY(7).Radius(7).Background(p.redBg).Children(func() {
					ui.Text(c, "Error: "+rt.LastError).FontSize(12).FontWeight(500).TextColor(p.red)
				})
			}

			// Row 3: Action chips row
			canTest := rt.State == runner.StateRunning
			ui.Row(c).AlignItems(ui.Center).Gap(6).Padding(2, 0, 0, 0).Children(func() {
				localLink := svc.V2rayNSocksURI()
				if actionChip(c.Key("copy-local"), p, iconCopy, cat.ActionCopyV2rayN(), false).Tooltip(localLink).Clicked() {
					a.copyV2rayNLink(svc)
				}
				naiveTip := svc.NaiveShareURI()
				if naiveTip == "" {
					naiveTip = cat.NoRemoteConfigured()
				}
				if actionChip(c.Key("copy-naive"), p, iconCopy, cat.ActionCopyNaive(), false).Tooltip(naiveTip).Clicked() {
					a.copyNaiveShareLink(svc)
				}
				if actionChip(c.Key("probe-btn"), p, iconBolt, cat.ActionLatency(), !canTest || rt.Probing).Clicked() {
					a.triggerServiceProbe(svc)
				}
				if actionChip(c.Key("speed-btn"), p, iconDownload, cat.ActionDownload(), !canTest || rt.SpeedTesting).Clicked() {
					a.triggerServiceDownloadTest(svc)
				}
				if actionChip(c.Key("drawer-logs"), p, iconList, cat.ActionLogs(), false).Clicked() {
					if a.activeLogDrawerID == svc.ID {
						a.activeLogDrawerID = ""
					} else {
						a.activeLogDrawerID = svc.ID
					}
				}
			})

			// Row 4: Collapsible Real-time Log Viewer
			if logsOpen {
				a.renderServiceLogPanel(c.Key("logs"), p, svc)
			}
		})
}

func (a *app) renderRuntimeStatusBadge(c *ui.Context, p palette, st runner.State) {
	cat := a.catalog()
	switch st {
	case runner.StateRunning:
		statusBadge(c, cat.StatusRunning(), p.green, p.greenBg)
	case runner.StateStarting:
		statusBadge(c, cat.StatusStarting(), p.amber, p.amberBg)
	case runner.StateError:
		statusBadge(c, cat.StatusError(), p.red, p.redBg)
	default:
		statusBadge(c, cat.StatusStopped(), p.textMuted, p.elevated)
	}
}

func (a *app) cardBorderColor(p palette, st runner.State) ui.Color {
	switch st {
	case runner.StateRunning:
		return p.green.Alpha(0.45)
	case runner.StateError:
		return p.red.Alpha(0.55)
	default:
		return p.border
	}
}

func (a *app) renderServiceLogPanel(c *ui.Context, p palette, svc config.Service) {
	logBuf := a.mgr.LogsOf(svc.ID)
	lines := logBuf.Lines()
	ui.Column(c).
		Padding(10, 12, 10, 12).Gap(8).
		Radius(8).Background(p.codeBg).Border(1, p.borderSubtle).
		Children(func() {
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Gap(6).TextColor(p.textMuted).Children(func() {
					ui.Icon(c, iconTerminal).Size(13, 13)
					ui.Text(c, fmt.Sprintf("实时运行日志 (%d 行)", len(lines))).
						FontSize(11).FontWeight(600)
				})
				ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
					if actionChip(c.Key("copy-logs"), p, iconCopy, "复制日志", len(lines) == 0).Clicked() {
						a.writeClipboard(strings.Join(lines, "\n"), "已复制服务运行日志")
					}
					if actionChip(c.Key("clear-logs"), p, iconTrash, "清空日志", len(lines) == 0).Clicked() {
						logBuf.Clear()
					}
				})
			})

			if len(lines) == 0 {
				ui.Text(c, "暂无日志输出（如未开启日志参数，将在启动/停止或异常时记录状态）").
					FontSize(11).TextColor(p.textDim)
				return
			}

			start := 0
			if len(lines) > 25 {
				start = len(lines) - 25
			}
			ui.Column(c).Gap(3).Children(func() {
				for _, line := range lines[start:] {
					ui.Text(c, line).FontSize(11).TextColor(p.textMuted)
				}
			})
		})
}
