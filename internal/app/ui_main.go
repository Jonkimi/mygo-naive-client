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
		if a.activeRuleDrawerID != "" {
			a.activeRuleDrawerID = ""
		}
	})
	c.OnShortcut(ui.Cmd, ui.Key1, func() { a.activeTab = TabNodes })
	c.OnShortcut(ui.Cmd, ui.Key2, func() { a.activeTab = TabRouting })
	c.OnShortcut(ui.Cmd, ui.Key3, func() { a.activeTab = TabInsights })
	c.OnShortcut(ui.Cmd, ui.Key4, func() { a.activeTab = TabTailnet })
	c.OnShortcut(ui.Cmd, ui.Key5, func() { a.activeTab = TabSettings })
	c.OnShortcut(ui.Cmd, ui.KeyComma, func() { a.activeTab = TabSettings })
	c.OnShortcut(ui.Cmd, ui.KeyB, func() { a.toggleSidebar() })

	ui.Row(c).Fill().AlignItems(ui.Stretch).Children(func() {
		a.renderSidebar(c, p)

		ui.Column(c.Key("main")).Grow(1).Background(p.surface).Children(func() {
			a.renderTopControlBar(c, p)
			switch a.activeTab {
			case TabNodes:
				a.renderToolbar(c, p)
				a.renderTagFilterBar(c, p)
				a.renderServiceList(c, p)
			case TabSettings:
				a.renderSettingsPage(c, p)
			case TabRouting:
				a.renderRoutingPage(c, p)
			case TabInsights:
				a.renderInsightsPage(c, p)
			case TabTailnet:
				a.renderTailnetPage(c, p)
			}
		})
	})

	a.renderLogDrawer(c, p)
	a.renderRuleDrawer(c, p)

	a.renderEditorDialog(c, p)
	a.renderImportDialog(c, p)
	a.renderDeleteDialog(c, p)
	a.renderRuleEditorDialog(c, p)

	if a.pendingToast != "" {
		c.Toast(a.pendingToast)
		a.pendingToast = ""
	}
}

func (a *app) activeRunningCount() int {
	if a.mgr == nil {
		return 0
	}
	return a.mgr.RunningOrStartingCount()
}

func (a *app) gatewayEndpointLabel() string {
	cat := a.catalog()
	port := a.state.GatewayPort
	if port <= 0 {
		port = 10809
	}
	return fmt.Sprintf("%s 127.0.0.1:%d", cat.MasterGateway(), port)
}

func (a *app) primaryGatewayPortLabel() string {
	return a.catalog().ModePortOnly()
}

func (a *app) renderTopControlBar(c *ui.Context, p palette) {
	cat := a.catalog()
	runningCount := a.activeRunningCount()
	dotColor := p.textDim
	if (a.gateway != nil && a.state.GatewayEnabled) || runningCount > 0 {
		dotColor = p.green
	}

	ui.Row(c).
		AlignItems(ui.Center).Justify(ui.SpaceBetween).
		PaddingX(20).PaddingY(10).
		Background(p.surface).
		BorderWidth(0, 0, 1, 0).BorderColor(p.borderSubtle).
		Children(func() {
			// Left: Gateway live status indicator
			ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
				ui.Box(c).Size(8, 8).Radius(999).Background(dotColor)
				ui.Text(c, a.gatewayEndpointLabel()).FontSize(12).FontWeight(400).TextColor(p.textMuted)
			})

			// Center: Active mode dropdown selector with label
			activeMode := a.state.TrafficMode
			if activeMode == "" {
				activeMode = "port"
			}
			var activeLabel string
			switch activeMode {
			case "sysproxy":
				activeLabel = cat.ModeSysProxy()
			case "tun":
				activeLabel = cat.ModeTun()
			default:
				activeLabel = cat.ModePortOnly()
			}

			ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
				ui.Text(c, cat.TrafficModeLabel()).FontSize(11).FontWeight(400).TextColor(p.textMuted)

				selectedMode := activeMode
				sel := ui.SelectBase(c.Key("select-traffic-mode"), &selectedMode)
				sel.Trigger.
					Gap(6).PaddingX(10).PaddingY(4).Radius(6).
					Background(p.elevated).Border(1, p.borderSubtle).
					AlignItems(ui.Center).
					Children(func() {
						ui.Text(c, activeLabel).FontSize(11).FontWeight(400).TextColor(p.textMuted)
						ui.Icon(c, iconChevronDown).Size(11, 11).TextColor(p.textDim)
					})
				if sel.Trigger.Hovered() {
					sel.Trigger.Background(p.cardHover)
				}

				sel.Popup(func(panel ui.Element) {
					panel.Margin(4, 0, 0, 0).Padding(4).Radius(8).
						Background(p.card).Border(1, p.borderSubtle).
						Shadow(0, 8, 20, 0, ui.RGBA(0, 0, 0, 0.18))

					modes := []struct {
						id    string
						label string
						tip   string
					}{
						{id: "port", label: cat.ModePortOnly(), tip: ""},
						{id: "sysproxy", label: cat.ModeSysProxy(), tip: ""},
						{id: "tun", label: cat.ModeTun(), tip: ""},
					}

					for _, m := range modes {
						item := sel.Item(m.id).Gap(8).PaddingX(10).PaddingY(6).Radius(6).AlignItems(ui.Center)
						if item.Highlighted() {
							item.Background(p.accentBg)
						}
						item.Children(func() {
							fg := p.textMuted
							if item.Highlighted() {
								fg = p.accentText
							} else if m.id == activeMode {
								fg = p.text
							}
							ui.Text(c, m.label).FontSize(12).FontWeight(400).TextColor(fg)
							if m.tip != "" {
								ui.Text(c, "("+m.tip+")").FontSize(10).TextColor(p.textDim)
							}
						})
					}
				})

				if sel.Trigger.Changed() {
					if selectedMode != a.state.TrafficMode {
						_ = a.setTrafficMode(selectedMode)
					}
				}
			})

			// Right: Core status capsule (clickable to jump to Settings)
			coreBtn := ui.ButtonBase(c.Key("top-core-status")).
				Radius(999).Background(ui.Transparent).
				Children(func() {
					if a.localVersion == "" {
						statusBadge(c, cat.CoreNotInstalled(), p.amber, p.amberBg)
					} else if (a.hasUpdate && a.latestRelease != nil) || (a.hasXrayUpdate && a.latestXrayRelease != nil) {
						statusBadge(c, cat.CoreLocal()+a.localVersion+" ↑", p.amber, p.amberBg)
					} else {
						tagPill(c, cat.CoreLocal()+a.localVersion, p.textMuted, p.elevated)
					}
				})
			if coreBtn.Clicked() {
				a.activeTab = TabSettings
			}
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
	runningCount := a.activeRunningCount()

	ui.Row(c).
		AlignItems(ui.Center).Justify(ui.SpaceBetween).
		Padding(14, 20, 12, 20).
		Background(p.surface).
		Children(func() {
			// Left: Section title & live running badge
			ui.Row(c).AlignItems(ui.Center).Gap(10).Children(func() {
				ui.Text(c, cat.LocalServicesLabel(len(a.state.Services))).
					FontSize(15).FontWeight(700).TextColor(p.text)
				if runningCount > 0 {
					statusBadge(c, cat.RunningCountBadge(runningCount), p.green, p.greenBg)
				} else {
					tagPill(c, cat.AllStoppedBadge(), p.textMuted, p.elevated)
				}
			})

			// Right: Unified toolbar actions (batch controls + create/import)
			ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
				if len(a.state.Services) > 0 {
					if len(a.state.Services) > 1 {
						allRunning := runningCount == len(a.state.Services)
						startAllBtn := actionChip(c.Key("btn-start-all"), p, iconPlay, cat.ActionStartAll(), allRunning)
						if allRunning {
							startAllBtn.Tooltip(cat.AllRunningTip())
						}
						if startAllBtn.Clicked() {
							a.startAllServices()
						}

						allStopped := runningCount == 0
						stopAllBtn := actionChip(c.Key("btn-stop-all"), p, iconStop, cat.ActionStopAll(), allStopped)
						if allStopped {
							stopAllBtn.Tooltip(cat.AllStoppedTip())
						}
						if stopAllBtn.Clicked() {
							a.stopAllServices()
						}
					}
					batchLabel := cat.ActionBatchTest()
					if a.batchTesting && a.batchStage != "" {
						batchLabel = a.batchStage
					}
					batchDisabled := runningCount == 0 && !a.batchTesting
					batchBtn := actionChip(c.Key("btn-batch-test"), p, iconBolt, batchLabel, batchDisabled)
					if batchDisabled {
						batchBtn.Tooltip(cat.TestRequiresRunning())
					}
					if batchBtn.Clicked() {
						a.triggerBatchTest()
					}

					ui.Box(c).Size(1, 16).Background(p.borderSubtle)
				}

				if actionChip(c.Key("btn-import-service"), p, iconPaste, cat.ImportClipboard(), false).Clicked() {
					a.openImportDialog()
				}
				if primaryPillButton(c.Key("btn-new-service"), p, iconPlus, cat.NewService(), p.accent, false).Clicked() {
					a.openCreateServiceDialog()
				}
			})
		})
}

func (a *app) filteredServices() []config.Service {
	if a.activeTagFilter == "" {
		return a.state.Services
	}
	var filtered []config.Service
	for _, svc := range a.state.Services {
		for _, t := range svc.Tags {
			if strings.EqualFold(strings.TrimSpace(t), a.activeTagFilter) {
				filtered = append(filtered, svc)
				break
			}
		}
	}
	return filtered
}

func (a *app) renderTagFilterBar(c *ui.Context, p palette) {
	tags := a.allKnownServiceTags()
	if len(tags) == 0 {
		return
	}
	cat := a.catalog()

	ui.Row(c.Key("tag-filter-bar")).
		AlignItems(ui.Center).Gap(6).Wrap().
		Padding(0, 20, 10, 20).
		Children(func() {
			// "全部" (All) chip
			allActive := a.activeTagFilter == ""
			allBg := p.card
			allFg := p.textMuted
			allBorder := p.borderSubtle
			if allActive {
				allBg = p.accentBg
				allFg = p.accentText
				allBorder = p.accent.Alpha(0.3)
			}
			allBtn := ui.ButtonBase(c.Key("filter-tag-all")).
				PaddingX(10).PaddingY(4).Radius(999).
				Background(allBg).Border(1, allBorder)
			allBtn.Children(func() {
				ui.Row(c).AlignItems(ui.Center).Gap(5).Children(func() {
					ui.Text(c, cat.TagFilterAll()).FontSize(11).FontWeight(600).TextColor(allFg)
					ui.Text(c, fmt.Sprint(len(a.state.Services))).FontSize(10).TextColor(allFg.Alpha(0.7))
				})
			})
			if allBtn.Clicked() {
				a.activeTagFilter = ""
			}

			// Individual tag chips
			for _, t := range tags {
				tag := t
				count := 0
				for _, s := range a.state.Services {
					for _, st := range s.Tags {
						if strings.EqualFold(strings.TrimSpace(st), tag) {
							count++
							break
						}
					}
				}

				isActive := strings.EqualFold(a.activeTagFilter, tag)
				chipBg := p.card
				chipFg := p.textMuted
				chipBorder := p.borderSubtle
				if isActive {
					chipBg = p.accentBg
					chipFg = p.accentText
					chipBorder = p.accent.Alpha(0.3)
				}
				tagBtn := ui.ButtonBase(c.Key("filter-tag-"+strings.ToLower(tag))).
					PaddingX(10).PaddingY(4).Radius(999).
					Background(chipBg).Border(1, chipBorder)
				tagBtn.Children(func() {
					ui.Row(c).AlignItems(ui.Center).Gap(5).Children(func() {
						ui.Text(c, "#"+tag).FontSize(11).FontWeight(600).TextColor(chipFg)
						ui.Text(c, fmt.Sprint(count)).FontSize(10).TextColor(chipFg.Alpha(0.7))
					})
				})
				if tagBtn.Clicked() {
					if isActive {
						a.activeTagFilter = ""
					} else {
						a.activeTagFilter = tag
					}
				}
			}
		})
}

func (a *app) renderServiceList(c *ui.Context, p palette) {
	services := a.filteredServices()
	cat := a.catalog()

	ui.Scroll(c.Key("service-scroll")).
		Fill().
		Padding(0, 20, 20, 20).
		Gap(12).
		Children(func() {
			if len(a.state.Services) == 0 {
				a.renderEmptyState(c, p)
				return
			}
			if len(services) == 0 {
				ui.Column(c.Key("filter-empty-state")).
					AlignItems(ui.Center).Justify(ui.Center).
					Padding(32).Gap(12).
					Radius(12).Background(p.card).Border(1, p.borderSubtle).
					Children(func() {
						ui.Text(c, cat.EmptyNodesWithTag(a.activeTagFilter)).
							FontSize(13).FontWeight(600).TextColor(p.textMuted)
						if subtleActionChip(c.Key("btn-clear-tag-filter"), p, nil, cat.ViewAllNodes(), false).Clicked() {
							a.activeTagFilter = ""
						}
					})
				return
			}
			for i := range services {
				svc := services[i]
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

	ui.Column(c).
		Padding(16, 16, 12, 16).Gap(12).
		Radius(12).Background(p.card).
		Border(1, a.cardBorderColor(p, rt.State)).
		Children(func() {
			// Upper section: Left (Title + Badges + Route summary) | Right (Primary Start/Stop button)
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(16).Children(func() {
				ui.Column(c).Grow(1).Gap(7).Children(func() {
					// Line 1: Runtime status + Service Name + Tags & Telemetry badges
					ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
						a.renderRuntimeStatusBadge(c, p, rt.State)
						ui.Text(c, svc.Name).FontSize(15).FontWeight(700).TextColor(p.text)

						// Protocol and Engine capsule
						protoStr := strings.ToUpper(string(svc.EffectiveProtocol()))
						engineStr := "SING-BOX"
						if svc.EffectiveEngine() == config.EngineSidecar {
							engineStr = "SIDECAR"
						}
						tagPill(c, protoStr+" · "+engineStr, p.accentText, p.accentBg)

						for _, tag := range svc.Tags {
							if tag != "" {
								tagPill(c, "#"+tag, p.accentText, p.accentBg)
							}
						}

						if svc.AutoStart {
							tagPill(c, cat.TagAutoStart(), p.accentText, p.accentBg)
						}
						if svc.InsecureConcurrency > 1 {
							tagPill(c, cat.ConcurrencyPill(svc.InsecureConcurrency), p.textMuted, p.elevated)
						}
						if svc.NoPostQuantum {
							tagPill(c, "No-PQ", p.textMuted, p.elevated)
						}
						if rt.State == runner.StateRunning && rt.PID > 0 {
							tagPill(c, fmt.Sprintf("PID %d", rt.PID), p.green, p.greenBg)
						}
						if rt.Restarts > 0 {
							tagPill(c, cat.RestartsPill(rt.Restarts), p.amber, p.amberBg)
						}
						if rt.Probing {
							tagPill(c, cat.LatencyTesting(), p.amber, p.amberBg)
						} else if rt.ProbeError != "" {
							tagPill(c, cat.LatencyFailed(), p.red, p.redBg)
						} else if rt.Latency > 0 {
							tagPill(c, fmt.Sprintf("%d ms", max(1, rt.Latency.Milliseconds())), p.green, p.greenBg)
						}
						if a.tracker != nil && rt.State == runner.StateRunning {
							sc := a.tracker.GetScore(svc.ID)
							if sc.EWMA > 0 {
								tagPill(c, cat.LatencyPill(int(max(1, sc.EWMA.Milliseconds()))), p.accentText, p.accentBg)
							}
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

					// Line 2: Clean Local -> Remote endpoint route summary
					ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
						listenSummary := "sing-box (in-process)"
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
						} else if len(svc.Listens) > 0 && svc.PrimaryListen() != "socks://127.0.0.1:0" {
							listenSummary = svc.PrimaryListen()
						}
						ui.Text(c, listenSummary).FontSize(12).FontWeight(600).TextColor(p.textMuted)

						compactRemote := svc.CompactRemoteEndpoint()
						if compactRemote != "" {
							ui.Text(c, "→").FontSize(12).TextColor(p.textDim)
							ui.Row(c).AlignItems(ui.Center).Tooltip(svc.RedactedProxy()).Children(func() {
								ui.Text(c, compactRemote).FontSize(12).FontWeight(500).TextColor(p.text)
							})
						}
					})
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

			// Error Banner if process failed or crashed
			if rt.LastError != "" {
				isMissingCore, isXray := isMissingCoreError(rt.LastError)
				if !isMissingCore {
					if svc.EffectiveProtocol() == config.ProtoNaive && (a.localVersion == "" || !a.mgr.BinaryExists()) {
						isMissingCore = true
						isXray = false
					} else if svc.EffectiveProtocol() != config.ProtoNaive && (a.localXrayVersion == "" || !a.mgr.XrayBinaryExists()) {
						isMissingCore = true
						isXray = true
					}
				}

				displayErr := rt.LastError
				if isMissingCore {
					if isXray {
						displayErr = cat.CoreMissingXrayError()
					} else {
						displayErr = cat.CoreMissingNaiveError()
					}
				} else if !strings.HasPrefix(rt.LastError, cat.ErrorPrefix()) && !strings.HasPrefix(rt.LastError, "Error:") && !strings.HasPrefix(rt.LastError, "错误:") {
					displayErr = cat.ErrorPrefix() + rt.LastError
				}

				ui.Row(c.Key("error-banner-" + svc.ID)).
					AlignItems(ui.Center).Justify(ui.SpaceBetween).
					Padding(8, 10, 8, 10).Radius(7).
					Background(p.redBg).Border(1, p.red.Alpha(0.2)).
					Children(func() {
						ui.Row(c).AlignItems(ui.Center).Gap(6).Grow(1).Children(func() {
							ui.Icon(c, iconAlert).Size(14, 14).TextColor(p.red)
							ui.Text(c, displayErr).FontSize(12).FontWeight(500).TextColor(p.red).Grow(1)
						})

						ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
							if isMissingCore {
								isUpdating := a.updatingCore
								if isXray {
									isUpdating = a.updatingXrayCore
								}
								btnLabel := cat.ActionInstallCoreShort()
								if isUpdating {
									btnLabel = cat.CoreDownloading()
								}
								btnInstall := ui.ButtonBase(c.Key("btn-install-core-" + svc.ID)).
									Label("btn-install-core-" + svc.ID).
									Padding(3, 8, 3, 8).Radius(5).
									Background(p.accent).
									Tooltip(cat.EngineStatusPillHint()).
									Children(func() {
										ui.Row(c).AlignItems(ui.Center).Gap(4).Children(func() {
											ui.Icon(c, iconDownload).Size(11, 11).TextColor(ui.RGB(255, 255, 255))
											ui.Text(c, btnLabel).FontSize(11).FontWeight(600).TextColor(ui.RGB(255, 255, 255))
										})
									})
								if !isUpdating && btnInstall.Clicked() {
									if isXray {
										a.triggerSeamlessXrayUpdate()
									} else {
										a.triggerSeamlessUpdate()
									}
								}

								btnSettings := ui.ButtonBase(c.Key("btn-goto-settings-" + svc.ID)).
									Label("btn-goto-settings-" + svc.ID).
									Padding(3, 8, 3, 8).Radius(5).
									Background(p.card).Border(1, p.borderSubtle).
									Tooltip(cat.ActionGoToSettings()).
									Children(func() {
										ui.Row(c).AlignItems(ui.Center).Gap(4).Children(func() {
											ui.Icon(c, iconSettings).Size(11, 11).TextColor(p.text)
											ui.Text(c, cat.ActionGoToSettings()).FontSize(11).TextColor(p.text)
										})
									})
								if btnSettings.Clicked() {
									a.activeTab = TabSettings
								}
							}

							btnCopy := ui.ButtonBase(c.Key("btn-copy-error-" + svc.ID)).
								Label("btn-copy-error-" + svc.ID).
								Padding(3, 8, 3, 8).Radius(5).
								Background(p.card).Border(1, p.borderSubtle).
								Tooltip(cat.ActionCopyError()).
								Children(func() {
									ui.Row(c).AlignItems(ui.Center).Gap(4).Children(func() {
										ui.Icon(c, iconCopy).Size(11, 11).TextColor(p.textDim)
										ui.Text(c, cat.BtnCopy()).FontSize(11).TextColor(p.textDim)
									})
								})
							if btnCopy.Clicked() {
								copyText := rt.LastError
								if isMissingCore && displayErr != "" {
									copyText = displayErr
								}
								a.writeClipboard(copyText, cat.ToastErrorCopied())
							}
						})
					})
			}

			// Lower section: Card Action Footer (Left: Diagnostics & Share | Right: Edit & Delete)
			canTest := rt.State == runner.StateRunning
			ui.Row(c).
				AlignItems(ui.Center).Justify(ui.SpaceBetween).
				Padding(10, 0, 0, 0).
				BorderWidth(1, 0, 0, 0).BorderColor(p.borderSubtle).
				Children(func() {
					ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
						probeBtn := actionChip(c.Key("probe-btn"), p, iconBolt, cat.ActionLatency(), !canTest || rt.Probing)
						if !canTest {
							probeBtn.Tooltip(cat.TestRequiresRunning())
						}
						if probeBtn.Clicked() {
							a.triggerServiceProbe(svc)
						}

						speedBtn := actionChip(c.Key("speed-btn"), p, iconDownload, cat.ActionDownload(), !canTest || rt.SpeedTesting)
						if !canTest {
							speedBtn.Tooltip(cat.TestRequiresRunning())
						}
						if speedBtn.Clicked() {
							a.triggerServiceDownloadTest(svc)
						}

						if actionChip(c.Key("drawer-logs"), p, iconList, cat.ActionLogs(), false).Clicked() {
							if a.activeLogDrawerID == svc.ID {
								a.activeLogDrawerID = ""
							} else {
								a.activeLogDrawerID = svc.ID
							}
						}

						ui.Box(c).Size(1, 14).Background(p.borderSubtle)

						localLink := svc.V2rayNSocksURI()
						if subtleActionChip(c.Key("copy-local"), p, iconCopy, cat.ActionCopyV2rayN(), false).Tooltip(localLink).Clicked() {
							a.copyV2rayNLink(svc)
						}
						naiveTip := svc.NaiveShareURI()
						if naiveTip == "" {
							naiveTip = cat.NoRemoteConfigured()
						}
						if subtleActionChip(c.Key("copy-naive"), p, iconCopy, cat.ActionCopyNaive(), false).Tooltip(naiveTip).Clicked() {
							a.copyNaiveShareLink(svc)
						}
					})

					ui.Row(c).AlignItems(ui.Center).Gap(4).Children(func() {
						if subtleActionChip(c.Key("edit-btn"), p, iconEdit, cat.ActionEdit(), false).Clicked() {
							a.openEditServiceDialog(svc)
						}
						if dangerActionChip(c.Key("delete-btn"), p, iconTrash, cat.ActionDelete(), false).Clicked() {
							a.openDeleteServiceDialog(svc)
						}
					})
				})
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

func isMissingCoreError(errText string) (missing bool, isXray bool) {
	if errText == "" {
		return false, false
	}
	lower := strings.ToLower(errText)
	if strings.Contains(errText, "xray 核心") || strings.Contains(lower, "xray core") || (strings.Contains(lower, "xray") && (strings.Contains(errText, "不存在") || strings.Contains(errText, "未找到") || strings.Contains(lower, "not found"))) {
		return true, true
	}
	if strings.Contains(errText, "naive 核心") || strings.Contains(lower, "naive core") || (strings.Contains(lower, "naive") && (strings.Contains(errText, "不存在") || strings.Contains(errText, "未找到") || strings.Contains(lower, "not found"))) {
		return true, false
	}
	return false, false
}
