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

	ui.Column(c).Fill().Background(p.bg).Children(func() {
		a.renderHeaderBanner(c, p)
		a.renderToolbar(c, p)
		a.renderServiceList(c, p)
	})

	a.renderEditorDialog(c, p)
	a.renderImportDialog(c, p)
	a.renderDeleteDialog(c, p)
	a.renderSettingsDialog(c, p)

	if a.pendingToast != "" {
		c.Toast(a.pendingToast)
		a.pendingToast = ""
	}
}

func (a *app) applyThemeToContext(c *ui.Context) {
	switch a.state.Appearance {
	case appearanceDark:
		c.SetTheme(ui.DarkTheme())
	case appearanceLight:
		c.SetTheme(ui.LightTheme())
	}
}

func (a *app) renderHeaderBanner(c *ui.Context, p palette) {
	ui.Column(c).
		PaddingX(20).PaddingY(14).Gap(10).
		Background(p.surface).
		BorderWidth(0, 0, 1, 0).BorderColor(p.border).
		Children(func() {
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Children(func() {
				// Left: App title + Naive core version & remote status
				ui.Row(c).AlignItems(ui.Center).Gap(10).Children(func() {
					ui.Row(c).AlignItems(ui.Center).Justify(ui.Center).
						Size(34, 34).Radius(9).Background(p.accentBg).
						Children(func() {
							ui.Image(c, iconBrandFor(p.dark)).Size(18, 18)
						})

					ui.Column(c).Gap(3).Children(func() {
						ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
							ui.Text(c, "NaiveClient").FontSize(16).FontWeight(700).TextColor(p.text)

							if a.localVersion == "" {
								statusBadge(c, "未安装 naive 核心", p.amber, p.amberBg)
							} else {
								statusBadge(c, "本地核心 "+a.localVersion, p.green, p.greenBg)
							}

							if a.hasUpdate && a.latestRelease != nil {
								tagPill(c, "发现新版本 "+a.latestRelease.TagName, p.amber, p.amberBg)
							} else if a.latestRelease != nil && a.localVersion != "" {
								tagPill(c, "已是最新 ("+a.latestRelease.TagName+")", p.accentText, p.accentBg)
							}
						})

						subText := a.coreStatusSubtitle()
						ui.Text(c, subText).FontSize(12).TextColor(p.textMuted)
					})
				})

				// Right: Check update & One-click seamless update buttons
				ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
					checkLabel := "检查更新"
					if a.checkingUpdate {
						checkLabel = "检查中..."
					}
					if actionChip(c.Key("btn-check-update"), p, iconRefresh, checkLabel, a.checkingUpdate || a.updatingCore).Clicked() {
						a.triggerCheckUpdate(true)
					}

					if a.localVersion == "" || a.hasUpdate || a.updatingCore {
						updLabel := "下载并无感更新"
						if a.localVersion == "" {
							updLabel = "一键下载核心"
						}
						if a.updatingCore {
							updLabel = "更新中..."
						} else if a.latestRelease != nil && a.hasUpdate {
							updLabel = fmt.Sprintf("无感更新至 %s", a.latestRelease.TagName)
						}
						if primaryPillButton(c.Key("btn-seamless-update"), p, iconDownload, updLabel, p.accent, a.updatingCore).Clicked() {
							a.triggerSeamlessUpdate()
						}
					}
				})
			})

			// Seamless update progress bar
			if a.updatingCore || a.updateStageText != "" {
				ui.Column(c).Gap(6).PaddingX(12).PaddingY(9).Radius(8).Background(p.elevated).Children(func() {
					ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
						stage := a.updateStageText
						if stage == "" {
							stage = "正在准备更新..."
						}
						ui.Text(c, stage).FontSize(12).FontWeight(500).TextColor(p.text)
						if a.updatePercent > 0 {
							ui.Text(c, fmt.Sprintf("%.0f%%", a.updatePercent)).FontSize(12).FontWeight(600).TextColor(p.accent)
						}
					})
					if a.updatingCore {
						pct := a.updatePercent
						if pct < 4 {
							pct = 4
						}
						if pct > 100 {
							pct = 100
						}
						ui.Row(c).Height(6).Radius(999).Background(p.border).Children(func() {
							ui.Box(c).HeightPercent(100).WidthPercent(float32(pct)).Radius(999).Background(p.accent)
						})
					}
				})
			}
		})
}

func (a *app) coreStatusSubtitle() string {
	if a.updateError != "" {
		return "更新状态: " + a.updateError
	}
	if a.localVersion == "" {
		return "尚未检测到本地 naive 可执行文件，点击右侧按钮将从 klzgrad/naiveproxy/releases 自动下载"
	}
	if a.hasUpdate && a.latestRelease != nil {
		return fmt.Sprintf("GitHub 最新版本 %s 已发布，支持自动下载、SHA256 校验并无感热替换重启运行中的服务", a.latestRelease.TagName)
	}
	return fmt.Sprintf("核心路径: %s · 跟踪 klzgrad/naiveproxy/releases", a.resolveBinaryPath())
}

func (a *app) renderToolbar(c *ui.Context, p palette) {
	runningCount := 0
	for _, svc := range a.state.Services {
		st := a.mgr.StatusOf(svc.ID).State
		if st == runner.StateRunning || st == runner.StateStarting {
			runningCount++
		}
	}

	ui.Row(c).
		AlignItems(ui.Center).Justify(ui.SpaceBetween).
		PaddingX(20).PaddingY(12).
		Background(p.bg).
		Children(func() {
			ui.Row(c).AlignItems(ui.Center).Gap(10).Children(func() {
				ui.Text(c, fmt.Sprintf("本地服务 (%d)", len(a.state.Services))).
					FontSize(14).FontWeight(600).TextColor(p.text)
				if runningCount > 0 {
					statusBadge(c, fmt.Sprintf("%d 个运行中", runningCount), p.green, p.greenBg)
				} else {
					tagPill(c, "全部已停止", p.textMuted, p.elevated)
				}
			})

			ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
				if primaryPillButton(c.Key("btn-new-service"), p, iconPlus, "新建服务", p.accent, false).Clicked() {
					a.openCreateServiceDialog()
				}
				if actionChip(c.Key("btn-import-service"), p, iconPaste, "剪贴板导入", false).Clicked() {
					a.openImportDialog()
				}
				if len(a.state.Services) > 0 {
					if actionChip(c.Key("btn-start-all"), p, iconPlay, "全部启动", runningCount == len(a.state.Services)).Clicked() {
						a.startAllServices()
					}
					if actionChip(c.Key("btn-stop-all"), p, iconStop, "全部停止", runningCount == 0).Clicked() {
						a.stopAllServices()
					}
					batchLabel := "一键测速"
					if a.batchTesting && a.batchStage != "" {
						batchLabel = a.batchStage
					}
					batchDisabled := runningCount == 0 && !a.batchTesting
					if actionChip(c.Key("btn-batch-test"), p, iconBolt, batchLabel, batchDisabled).Clicked() {
						a.triggerBatchTest()
					}
				}
				if actionChip(c.Key("btn-open-settings"), p, iconSettings, "设置", false).Clicked() {
					a.openSettingsDialog()
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
			ui.Text(c, "尚未配置本地 NaiveProxy 服务").FontSize(15).FontWeight(600).TextColor(p.text)
			ui.Text(c, "支持同时配置并独立运行多个本地 SOCKS5 / HTTP 代理端口，一键导出 V2rayN 格式 (socks://address:port#alias)").
				FontSize(12).TextColor(p.textMuted)
			ui.Row(c).AlignItems(ui.Center).Gap(10).Padding(8, 0, 0, 0).Children(func() {
				if primaryPillButton(c.Key("empty-new-btn"), p, iconPlus, "新建第一个服务", p.accent, false).Clicked() {
					a.openCreateServiceDialog()
				}
				if actionChip(c.Key("empty-import-btn"), p, iconPaste, "从剪贴板导入", false).Clicked() {
					a.openImportDialog()
				}
			})
		})
}

func (a *app) renderServiceCard(c *ui.Context, p palette, svc config.Service) {
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

					if svc.AutoStart {
						tagPill(c, "自启动", p.accentText, p.accentBg)
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
						tagPill(c, "延迟测速中...", p.amber, p.amberBg)
					} else if rt.ProbeError != "" {
						tagPill(c, "延迟测速失败", p.red, p.redBg)
					} else if rt.Latency > 0 {
						tagPill(c, fmt.Sprintf("%d ms", max(1, rt.Latency.Milliseconds())), p.green, p.greenBg)
					}
					if rt.SpeedTesting {
						if rt.DownloadSpeed > 0 {
							tagPill(c, "下载测速中 "+runner.FormatSpeed(rt.DownloadSpeed), p.amber, p.amberBg)
						} else {
							tagPill(c, "下载测速中...", p.amber, p.amberBg)
						}
					} else if rt.SpeedError != "" {
						tagPill(c, "下载测速失败", p.red, p.redBg)
					} else if rt.DownloadSpeed > 0 {
						tagPill(c, "↓ "+runner.FormatSpeed(rt.DownloadSpeed), p.green, p.greenBg)
					}
				})

				// Primary Start/Stop toggle button
				isRunning := rt.State == runner.StateRunning || rt.State == runner.StateStarting
				toggleLabel := "启动"
				toggleIcon := iconPlay
				toggleColor := p.accent
				if isRunning {
					toggleLabel = "停止"
					toggleIcon = iconStop
					toggleColor = p.red
				}
				if primaryPillButton(c.Key("toggle"), p, toggleIcon, toggleLabel, toggleColor, false).Clicked() {
					a.toggleService(svc)
				}
			})

			// Row 2: Local listen endpoint(s) & Remote proxy summary
			ui.Row(c).AlignItems(ui.Center).Gap(16).Children(func() {
				listens := strings.Join(svc.Listens, ", ")
				if listens == "" {
					listens = svc.PrimaryListen()
				}
				ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
					ui.Text(c, "本地监听:").FontSize(12).TextColor(p.textMuted)
					ui.Text(c, listens).FontSize(12).FontWeight(600).TextColor(p.text)
				})

				ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
					ui.Text(c, "远端节点:").FontSize(12).TextColor(p.textMuted)
					ui.Text(c, svc.RedactedProxy()).FontSize(12).FontWeight(500).TextColor(p.text)
				})
			})

			// Error Banner if process failed or crashed
			if rt.LastError != "" {
				ui.Row(c).AlignItems(ui.Center).PaddingX(10).PaddingY(7).Radius(7).Background(p.redBg).Children(func() {
					ui.Text(c, "运行异常: "+rt.LastError).FontSize(12).FontWeight(500).TextColor(p.red)
				})
			}

			// Row 3: Quick Actions bar
			canTest := rt.State == runner.StateRunning
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Padding(2, 0, 0, 0).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
					localLink := svc.V2rayNSocksURI()
					if actionChip(c.Key("copy-local"), p, iconCopy, "复制本地链接", false).Tooltip(localLink).Clicked() {
						a.copyV2rayNLink(svc)
					}
					naiveTip := svc.NaiveShareURI()
					if naiveTip == "" {
						naiveTip = "未配置可导出的远端节点"
					}
					if actionChip(c.Key("copy-naive"), p, iconCopy, "复制 Naive 链接", false).Tooltip(naiveTip).Clicked() {
						a.copyNaiveShareLink(svc)
					}
					if actionChip(c.Key("probe-btn"), p, iconBolt, "延迟测速", !canTest || rt.Probing).Clicked() {
						a.triggerServiceProbe(svc)
					}
					if actionChip(c.Key("speed-btn"), p, iconDownload, "下载测速", !canTest || rt.SpeedTesting).Clicked() {
						a.triggerServiceDownloadTest(svc)
					}
					logIcon := iconChevronDown
					logLabel := "实时日志"
					if logsOpen {
						logIcon = iconChevronUp
						logLabel = "收起日志"
					}
					if actionChip(c.Key("toggle-logs"), p, logIcon, logLabel, false).Clicked() {
						a.expandedLogs[svc.ID] = !logsOpen
					}
				})

				ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
					if actionChip(c.Key("edit-btn"), p, iconEdit, "编辑", false).Clicked() {
						a.openEditServiceDialog(svc)
					}
					if actionChip(c.Key("delete-btn"), p, iconTrash, "删除", false).Clicked() {
						a.openDeleteServiceDialog(svc)
					}
				})
			})

			// Row 4: Collapsible Real-time Log Viewer
			if logsOpen {
				a.renderServiceLogPanel(c.Key("logs"), p, svc)
			}
		})
}

func (a *app) renderRuntimeStatusBadge(c *ui.Context, p palette, st runner.State) {
	switch st {
	case runner.StateRunning:
		statusBadge(c, "运行中", p.green, p.greenBg)
	case runner.StateStarting:
		statusBadge(c, "启动中", p.amber, p.amberBg)
	case runner.StateError:
		statusBadge(c, "异常", p.red, p.redBg)
	default:
		statusBadge(c, "已停止", p.textMuted, p.elevated)
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
