package app

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/egoist/mygo/ui"

	"naive-client/internal/boxengine"
	"naive-client/internal/config"
	"naive-client/internal/runner"
	"naive-client/internal/warp"
	"naive-client/locales"
)

func (a *app) view(c *ui.Context) {
	if a.win == nil {
		a.setUIServices(c.Services())
		a.drainUI()
	}
	a.applyThemeToContext(c)
	p := paletteFor(c.Theme())

	if a.activeTab != TabNodes {
		a.openNodeMenuID = ""
		a.openBatchMenu = false
	}
	if a.activeTab != TabRouting {
		a.openRoutingMoreMenu = false
		a.showRoutingStrategyHelp = false
	}
	if a.activeTab != TabInsights {
		a.insightsShowManageRules = false
	}
	if a.activeTab != TabSettings {
		a.dnsStrategyHelpOpen = false
		a.dnsOptimisticHelpOpen = false
	}

	c.OnShortcut(0, ui.KeyEscape, func() {
		if a.activeLogDrawerID != "" {
			a.activeLogDrawerID = ""
		}
		if a.activeRuleDrawerID != "" {
			a.activeRuleDrawerID = ""
		}
		if a.activeNodeDrawerID != "" {
			a.activeNodeDrawerID = ""
			a.nodeDrawerHelpOpen = false
		}
		a.openRoutingMoreMenu = false
		a.showRoutingStrategyHelp = false
		a.dnsStrategyHelpOpen = false
		a.dnsOptimisticHelpOpen = false
	})
	c.OnShortcut(ui.Cmd, ui.Key1, func() { a.activeTab = TabNodes })
	c.OnShortcut(ui.Cmd, ui.Key2, func() { a.activeTab = TabRouting })
	c.OnShortcut(ui.Cmd, ui.Key3, func() { a.activeTab = TabInsights })
	c.OnShortcut(ui.Cmd, ui.Key4, func() { a.activeTab = TabTailnet })
	c.OnShortcut(ui.Cmd, ui.Key5, func() { a.activeTab = TabCloudflare })
	c.OnShortcut(ui.Cmd, ui.Key6, func() { a.activeTab = TabLogs })
	c.OnShortcut(ui.Cmd, ui.Key7, func() { a.activeTab = TabSettings })
	c.OnShortcut(ui.Cmd, ui.KeyComma, func() { a.activeTab = TabSettings })
	c.OnShortcut(ui.Cmd, ui.KeyB, func() { a.toggleSidebar() })

	ui.Row(c).Fill().AlignItems(ui.Stretch).Children(func() {
		a.renderSidebar(c, p)

		ui.Column(c.Key("main")).Grow(1).MinWidth(0).Background(p.surface).Children(func() {
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
			case TabCloudflare:
				a.renderCloudflarePage(c, p)
			case TabLogs:
				a.renderLogsPage(c, p)
			}
		})
	})

	a.renderLogDrawer(c, p)
	a.renderRuleDrawer(c, p)
	a.renderNodeDrawer(c, p)

	a.renderEditorDrawer(c, p)
	a.renderImportDialog(c, p)
	a.renderDeleteDialog(c, p)
	a.renderRuleEditorDrawer(c, p)
	a.renderInsightsManageRulesDrawer(c, p)

	if msg := a.consumePendingToast(); msg != "" {
		c.Toast(msg)
	}
}

func (a *app) activeRunningCount() int {
	if a.mgr == nil {
		return 0
	}
	return a.mgr.RunningOrStartingCount()
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
	var t *ui.Theme
	switch a.state.Appearance {
	case appearanceDark:
		t = ui.DarkTheme()
	case appearanceLight:
		t = ui.LightTheme()
	default:
		if cur := c.Theme(); cur != nil {
			cp := *cur
			t = &cp
		} else {
			t = ui.LightTheme()
		}
	}
	p := paletteFor(t)
	p.applyToTheme(t)
	c.SetTheme(t)
}

func (a *app) renderToolbar(c *ui.Context, p palette) {
	cat := a.catalog()
	runningCount := a.activeRunningCount()
	totalCount := len(a.state.Services)

	ui.Row(c.Key("nodes-header")).
		AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).
		Padding(14, 18, 14, 18).
		Background(p.surface).
		BorderWidth(0, 0, 1, 0).BorderColor(p.borderSubtle).
		Children(func() {
			// Left: Page title & quiet tabular running summary
			ui.Row(c).AlignItems(ui.Center).Gap(10).MinWidth(0).Shrink(1).Children(func() {
				ui.Text(c, cat.NavNodes()).FontSize(17).FontWeight(700).TextColor(p.text).NoWrap()
				if totalCount > 0 {
					ui.Text(c, cat.NodesRunningSummary(runningCount, totalCount)).
						FontSize(12).FontFeatures("tnum").TextColor(p.textMuted).NoWrap()
				}
			})

			// Right: Search + quiet secondary actions + optional batch overflow + single primary CTA
			ui.Row(c).AlignItems(ui.Center).Gap(6).Shrink(0).Children(func() {
				if totalCount > 0 {
					ui.SearchField(c.Key("input-nodes-search"), &a.searchQuery).
						Placeholder(cat.SearchPlaceholder()).
						Label(cat.SearchPlaceholder()).
						Width(164).Height(32).Radius(8).FontSize(12).
						Background(p.card)

					batchLabel := cat.ActionBatchTestShort()
					if a.batchTesting && a.batchStage != "" {
						batchLabel = a.batchStage
					}
					batchDimmed := runningCount == 0 && !a.batchTesting
					batchTip := cat.BatchTestTooltip()
					if batchDimmed {
						batchTip = cat.TestRequiresRunning()
					}
					batchProbeBtn := quietToolbarButton(c.Key("btn-batch-test"), p, iconBolt, batchLabel, batchDimmed).
						Tooltip(batchTip)
					if batchProbeBtn.Clicked() {
						a.openNodeMenuID = ""
						a.openBatchMenu = false
						a.triggerBatchTest()
					}
				}

				importBtn := quietToolbarButton(c.Key("btn-import-service"), p, nil, cat.ActionImportShort(), false).
					Tooltip(cat.ImportFromClipboard())
				if importBtn.Clicked() {
					a.openNodeMenuID = ""
					a.openBatchMenu = false
					a.openImportDialog()
				}

				if totalCount > 1 {
					batchMoreBtn := quietToolbarIconButton(c.Key("btn-batch-actions"), p, iconMore, cat.BatchActionsLabel(), a.openBatchMenu).
						Tooltip(cat.BatchActionsLabel())
					if batchMoreBtn.Clicked() {
						a.openNodeMenuID = ""
						a.openBatchMenu = !a.openBatchMenu
					}
					ui.PopoverBase(c, batchMoreBtn, &a.openBatchMenu, func(panel ui.Element) {
						styleMenuPopoverPanel(panel, batchMoreBtn, p, 156)
						panel.Children(func() {
							allRunning := runningCount == totalCount
							startAllItem := popoverMenuItem(c.Key("menu-start-all"), p, cat.ActionStartAll(), p.text, allRunning, false)
							if allRunning {
								startAllItem.Tooltip(cat.AllRunningTip())
							}
							if startAllItem.Clicked() {
								a.openBatchMenu = false
								a.startAllServices()
							}

							allStopped := runningCount == 0
							stopAllItem := popoverMenuItem(c.Key("menu-stop-all"), p, cat.ActionStopAll(), p.text, allStopped, false)
							if allStopped {
								stopAllItem.Tooltip(cat.AllStoppedTip())
							}
							if stopAllItem.Clicked() {
								a.openBatchMenu = false
								a.stopAllServices()
							}
						})
					})
				}

				if primaryPillButton(c.Key("btn-new-service"), p, iconPlus, cat.NewNode(), p.accent, false).Clicked() {
					a.openNodeMenuID = ""
					a.openBatchMenu = false
					a.openCreateServiceDialog()
				}
			})
		})
}

func (a *app) filteredServices() []config.Service {
	q := strings.ToLower(strings.TrimSpace(a.searchQuery))
	if a.activeTagFilter == "" && !a.onlyRunningFilter && q == "" {
		return a.state.Services
	}
	var filtered []config.Service
	for _, svc := range a.state.Services {
		if a.activeTagFilter != "" && !serviceHasTag(svc, a.activeTagFilter) {
			continue
		}
		if a.onlyRunningFilter && !a.isServiceActive(svc.ID) {
			continue
		}
		if q != "" && !serviceMatchesQuery(a.resolveDisplayService(svc), q) {
			continue
		}
		filtered = append(filtered, svc)
	}
	return filtered
}

func serviceHasTag(svc config.Service, target string) bool {
	for _, t := range svc.Tags {
		if strings.EqualFold(strings.TrimSpace(t), target) {
			return true
		}
	}
	return false
}

func serviceMatchesQuery(svc config.Service, lowerQuery string) bool {
	if strings.Contains(strings.ToLower(svc.Name), lowerQuery) ||
		strings.Contains(strings.ToLower(svc.CompactRemoteEndpoint()), lowerQuery) ||
		strings.Contains(strings.ToLower(svc.Server), lowerQuery) ||
		strings.Contains(strings.ToLower(nodeCompactMeta(svc)), lowerQuery) ||
		strings.Contains(strings.ToLower(string(svc.EffectiveProtocol())), lowerQuery) ||
		strings.Contains(strings.ToLower(svc.PrimaryListen()), lowerQuery) {
		return true
	}
	for _, t := range svc.Tags {
		if strings.Contains(strings.ToLower(strings.TrimSpace(t)), lowerQuery) {
			return true
		}
	}
	return false
}

func (a *app) renderTagFilterBar(c *ui.Context, p palette) {
	if len(a.state.Services) == 0 {
		return
	}
	tags := a.allKnownServiceTags()
	cat := a.catalog()

	ui.Row(c.Key("tag-filter-bar")).
		AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).
		Padding(8, 18, 8, 18).
		Background(p.surface).
		BorderWidth(0, 0, 1, 0).BorderColor(p.borderSubtle).
		Children(func() {
			// Left: Tag filter chips
			ui.Row(c).AlignItems(ui.Center).Gap(4).Wrap().Grow(1).MinWidth(0).Children(func() {
				if filterTagChip(c.Key("filter-tag-all"), p, cat.TagFilterAll(), len(a.state.Services), a.activeTagFilter == "").Clicked() {
					a.activeTagFilter = ""
				}
				for _, t := range tags {
					tag := t
					count := 0
					for _, s := range a.state.Services {
						if serviceHasTag(s, tag) {
							count++
						}
					}
					isActive := strings.EqualFold(a.activeTagFilter, tag)
					if filterTagChip(c.Key("filter-tag-"+strings.ToLower(tag)), p, "#"+tag, count, isActive).Clicked() {
						if isActive {
							a.activeTagFilter = ""
						} else {
							a.activeTagFilter = tag
						}
					}
				}
			})

			// Right: Running-only filter toggle
			ui.Row(c).AlignItems(ui.Center).Shrink(0).Children(func() {
				ui.Checkbox(c.Key("filter-only-running"), &a.onlyRunningFilter, cat.FilterOnlyRunning()).
					FontSize(12).TextColor(p.textMuted)
			})
		})
}

func filterTagChip(c *ui.Context, p palette, label string, count int, active bool) ui.Element {
	bg := ui.Transparent
	fg := p.textMuted
	weight := 500
	if active {
		bg = p.accentBg
		fg = p.accentText
		weight = 600
	}
	btn := ui.ButtonBase(c).
		PaddingX(10).PaddingY(4).Radius(6).
		Background(bg)
	if !active && btn.Hovered() {
		btn.Background(p.elevated)
		fg = p.text
	}
	return btn.Children(func() {
		ui.Row(c).AlignItems(ui.Center).Gap(5).Children(func() {
			ui.Text(c, label).FontSize(12).FontWeight(weight).TextColor(fg).NoWrap()
			ui.Text(c, fmt.Sprint(count)).FontSize(11).FontFeatures("tnum").TextColor(fg.Alpha(0.7)).NoWrap()
		})
	})
}

func (a *app) renderServiceList(c *ui.Context, p palette) {
	services := a.filteredServices()
	cat := a.catalog()

	ui.Scroll(c.Key("service-scroll")).
		Grow(1).Fill().MinHeight(0).
		Padding(14, 18, 18, 18).
		Gap(8).
		Children(func() {
			if len(a.state.Services) == 0 {
				a.renderEmptyState(c, p)
				return
			}
			if len(services) == 0 {
				emptyMsg := cat.EmptyFilteredNodes()
				if a.activeTagFilter != "" && strings.TrimSpace(a.searchQuery) == "" && !a.onlyRunningFilter {
					emptyMsg = cat.EmptyNodesWithTag(a.activeTagFilter)
				}
				ui.Column(c.Key("filter-empty-state")).
					AlignItems(ui.Center).Justify(ui.Center).
					Padding(36).Gap(10).
					Radius(12).Background(p.card).Border(1, p.borderSubtle).
					Children(func() {
						ui.Text(c, emptyMsg).FontSize(13).FontWeight(600).TextColor(p.textMuted)
						resetBtn := ui.ButtonBase(c.Key("btn-clear-tag-filter")).
							PaddingX(10).PaddingY(4).Radius(6).
							Background(ui.Transparent)
						if resetBtn.Hovered() {
							resetBtn.Background(p.accentBg)
						}
						resetBtn.Children(func() {
							ui.Text(c, cat.ResetFilters()).FontSize(12).FontWeight(500).TextColor(p.accentText)
						})
						if resetBtn.Clicked() {
							a.activeTagFilter = ""
							a.searchQuery = ""
							a.onlyRunningFilter = false
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
		Radius(12).Background(p.card).Border(1, p.borderSubtle).
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
				if quietToolbarButton(c.Key("empty-import-btn"), p, iconPaste, cat.ImportFromClipboard(), false).Clicked() {
					a.openImportDialog()
				}
			})
		})
}

func (a *app) renderServiceCard(c *ui.Context, p palette, svc config.Service) {
	cat := a.catalog()
	rt := a.mgr.StatusOf(svc.ID)
	unhealthy := a.isNodeUnhealthy(svc, rt)
	isRunning := rt.State == runner.StateRunning || rt.State == runner.StateStarting

	card := ui.Column(c).
		Padding(12, 16, 12, 16).Gap(10).
		Radius(12).Background(p.card).
		Border(1, p.borderSubtle)
	if card.Hovered() || a.openNodeMenuID == svc.ID {
		card.Background(p.cardHover).Border(1, p.border)
	}

	card.Children(func() {
		// Upper row: Left (Status dot + Name + Neutral Tags + Clean Metadata) | Right (Telemetry + Actions + Switch)
		ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(16).Children(func() {
			ui.Column(c).Grow(1).Shrink(1).MinWidth(0).Gap(4).Children(func() {
				// Line 1: 7px Status dot + Node Name + 0~2 Neutral Pills
				ui.Row(c).AlignItems(ui.Center).Gap(8).MinWidth(0).Children(func() {
					renderServiceStatusDot(c, p, rt, unhealthy)

					titleColor := p.textMuted
					if isRunning || rt.LastError != "" || rt.State == runner.StateError {
						titleColor = p.text
					}
					ui.Text(c, svc.Name).FontSize(14).FontWeight(600).TextColor(titleColor).
						SingleLine().Ellipsis("…").Shrink(1).MinWidth(0)

					renderServiceNeutralPills(c, p, svc, cat)
				})

				// Line 2: Clean Metadata (Protocol · Engine · compact endpoint)
				displaySvc := resolveRuntimeService(svc, rt)
				ui.Row(c).AlignItems(ui.Center).Gap(5).Padding(0, 0, 0, 15).MinWidth(0).Children(func() {
					ui.Text(c, nodeCompactMeta(displaySvc)).FontSize(12).FontWeight(500).TextColor(p.textMuted).NoWrap().Shrink(0)
					if compactRemote := stripEndpointSchemes(svc.CompactRemoteEndpoint()); compactRemote != "" {
						ui.Text(c, "·").FontSize(12).TextColor(p.textDim).NoWrap().Shrink(0)
						ui.Text(c, compactRemote).Font("monospace").FontSize(11).TextColor(p.textDim).
							SingleLine().Ellipsis("…").Shrink(1).MinWidth(0).
							Tooltip(svc.RedactedProxy())
					}
				})
			})

			// Right: Fixed-width tabular telemetry + quiet icon actions + overflow + switch
			ui.Row(c).AlignItems(ui.Center).Gap(10).Shrink(0).Children(func() {
				a.renderServiceTelemetryColumn(c, p, svc, rt, isRunning)

				canTest := rt.State == runner.StateRunning
				ui.Row(c).AlignItems(ui.Center).Gap(2).Shrink(0).Children(func() {
					manualProbing := rt.Probing && !rt.AutoProbing
					probeTip := cat.ActionLatency()
					if manualProbing {
						probeTip = cat.LatencyTesting()
					} else if rt.Probing && rt.AutoProbing {
						probeTip = cat.AutoProbingActionHint()
					} else if !canTest {
						probeTip = cat.TestRequiresRunning()
					}
					probeBtn := quietRowIconButton(c.Key("probe-btn"), p, iconBolt, cat.ActionLatency(), !canTest || manualProbing, false).
						Tooltip(probeTip)
					if probeBtn.Clicked() && !manualProbing {
						a.openNodeMenuID = ""
						a.openBatchMenu = false
						a.triggerServiceProbe(svc)
					}

					editLocked := svc.IsBuiltinWarp() && isRunning
					editBtn := quietRowIconButton(c.Key("edit-btn"), p, iconEdit, cat.ActionEdit(), editLocked, false).
						Tooltip(cat.ActionEdit())
					if editBtn.Clicked() && !editLocked {
						a.openNodeMenuID = ""
						a.openBatchMenu = false
						a.openEditServiceDialog(svc)
					}

					menuOpen := a.openNodeMenuID == svc.ID
					moreBtn := quietRowIconButton(c.Key("more-btn"), p, iconMore, cat.MoreActionsForNode(svc.Name), false, menuOpen).
						Tooltip(cat.ActionMore())
					if moreBtn.Clicked() {
						a.openBatchMenu = false
						if a.openNodeMenuID == svc.ID {
							a.openNodeMenuID = ""
						} else {
							a.openNodeMenuID = svc.ID
						}
					}

					menuOpen = a.openNodeMenuID == svc.ID
					ui.PopoverBase(c, moreBtn, &menuOpen, func(panel ui.Element) {
						a.renderNodeOverflowMenu(c, panel, moreBtn, p, svc, rt, canTest)
					})
					if !menuOpen && a.openNodeMenuID == svc.ID {
						a.openNodeMenuID = ""
					}
				})

				ui.Box(c).Size(1, 16).Background(p.borderSubtle).Shrink(0)

				toggleKey := "toggle-node-" + svc.ID
				toggleTip := cat.ActionStartNode()
				if isRunning {
					toggleTip = cat.ActionStopNode()
				}
				swVal := isRunning
				if ui.Switch(c.Key(toggleKey), &swVal).Label(toggleKey).Tooltip(toggleTip).Changed() {
					a.openNodeMenuID = ""
					a.openBatchMenu = false
					a.toggleService(svc)
				}
			})
		})

		// Contextual inline diagnostic strip (only when error or unhealthy)
		if rt.LastError != "" {
			a.renderServiceErrorStrip(c, p, svc, rt)
		} else if unhealthy {
			a.renderServiceUnhealthyStrip(c, p, svc, rt)
		}
	})

	if card.Clicked() {
		a.openNodeMenuID = ""
		a.openBatchMenu = false
		a.activeLogDrawerID = ""
		a.activeNodeDrawerID = svc.ID
	}
}

func renderServiceStatusDot(c *ui.Context, p palette, rt runner.Status, unhealthy bool) {
	dot := ui.Box(c).Size(7, 7).Radius(999).Shrink(0)
	switch {
	case rt.LastError != "" || rt.State == runner.StateError:
		dot.Background(p.red)
	case unhealthy && rt.State == runner.StateRunning:
		dot.Background(p.amber)
	case rt.State == runner.StateStarting:
		dot.Background(p.amber)
	case rt.State == runner.StateRunning:
		dot.Background(p.green)
	default:
		dot.Border(1.5, p.textDim)
	}
}

func renderServiceNeutralPills(c *ui.Context, p palette, svc config.Service, cat locales.Messages) {
	var pills []string
	if svc.IsBuiltinWarp() {
		pills = append(pills, cat.BuiltinTag())
	}
	var tags []string
	for _, t := range svc.Tags {
		if trimmed := strings.TrimSpace(t); trimmed != "" {
			tags = append(tags, trimmed)
		}
	}
	limit := min(2, len(tags))
	for i := 0; i < limit; i++ {
		pills = append(pills, "#"+tags[i])
	}
	if len(tags) > 2 {
		pills = append(pills, fmt.Sprintf("+%d", len(tags)-2))
	}
	if len(pills) == 0 {
		return
	}
	ui.Row(c).AlignItems(ui.Center).Gap(4).Shrink(0).Children(func() {
		for _, label := range pills {
			ui.Row(c).AlignItems(ui.Center).Shrink(0).
				PaddingX(6).PaddingY(2).Radius(4).Background(p.elevated).
				Children(func() {
					ui.Text(c, label).FontSize(11).FontWeight(500).TextColor(p.textMuted).NoWrap()
				})
		}
	})
}

func (a *app) renderServiceTelemetryColumn(c *ui.Context, p palette, svc config.Service, rt runner.Status, isRunning bool) {
	cat := a.catalog()
	latText, latColor, latTip := a.serviceLatencyDisplay(p, svc, rt, isRunning, cat)

	ui.Column(c).Width(84).AlignItems(ui.End).Gap(2).Shrink(0).Children(func() {
		latLabel := ui.Text(c, latText).FontSize(13).FontWeight(600).FontFeatures("tnum").TextAlign(ui.End).TextColor(latColor).NoWrap()
		if latText == "—" {
			latLabel.FontSize(12).FontWeight(500)
		}
		if latTip != "" {
			latLabel.Tooltip(latTip)
		}

		if isRunning {
			if rt.SpeedTesting {
				txt := cat.DownloadTesting()
				if rt.DownloadSpeed > 0 {
					txt = "↓ " + runner.FormatSpeed(rt.DownloadSpeed)
				}
				ui.Text(c, txt).FontSize(11).FontFeatures("tnum").TextAlign(ui.End).TextColor(p.amber).NoWrap()
			} else if rt.SpeedError != "" {
				txt := cat.DownloadFailed()
				if isWarpUnreachable(rt.SpeedError) {
					txt = cat.WarpServerUnreachablePill()
				}
				ui.Text(c, txt).FontSize(11).TextAlign(ui.End).TextColor(p.red).NoWrap().Tooltip(rt.SpeedError)
			} else if rt.DownloadSpeed > 0 {
				ui.Text(c, "↓ "+runner.FormatSpeed(rt.DownloadSpeed)).FontSize(11).FontFeatures("tnum").TextAlign(ui.End).TextColor(p.textDim).NoWrap()
			}
		}
	})
}

func (a *app) serviceLatencyDisplay(p palette, svc config.Service, rt runner.Status, isRunning bool, cat locales.Messages) (string, ui.Color, string) {
	if !isRunning {
		return "—", p.textDim, ""
	}
	if rt.Probing {
		if rt.AutoProbing {
			return cat.AutoProbingShort(), p.textMuted, cat.AutoProbing()
		}
		return cat.LatencyTestingShort(), p.amber, cat.LatencyTesting()
	}
	if rt.ProbeError != "" {
		txt := cat.LatencyFailed()
		if isWarpUnreachable(rt.ProbeError) {
			txt = cat.WarpServerUnreachablePill()
		}
		return txt, p.red, rt.ProbeError
	}

	ms, ewmaMs, probeMs := a.nodeLatencyMs(svc.ID, rt)
	if ms <= 0 {
		return "—", p.textDim, ""
	}

	fg := latencyThresholdColor(p, ms)

	tip := ""
	switch {
	case ewmaMs > 0 && probeMs > 0:
		tip = cat.LatencyTooltipBoth(ewmaMs, probeMs)
	case ewmaMs > 0:
		tip = cat.LatencyTooltipEWMA(ewmaMs)
	case probeMs > 0:
		tip = cat.LatencyTooltipProbe(probeMs)
	}
	return fmt.Sprintf("%d ms", ms), fg, tip
}

func latencyThresholdColor(p palette, ms int) ui.Color {
	if ms >= 250 {
		return p.red
	}
	if ms >= 120 {
		return p.amber
	}
	return p.green
}

func (a *app) renderNodeOverflowMenu(c *ui.Context, panel, anchor ui.Element, p palette, svc config.Service, rt runner.Status, canTest bool) {
	cat := a.catalog()
	styleMenuPopoverPanel(panel, anchor, p, 176)

	panel.Children(func() {
		if popoverMenuItem(c.Key("menu-details"), p, cat.ActionDetailsTelemetry(), p.text, false, false).Clicked() {
			a.openNodeMenuID = ""
			a.activeLogDrawerID = ""
			a.activeNodeDrawerID = svc.ID
		}

		if popoverMenuItem(c.Key("menu-logs"), p, cat.NodeDrawerLogs(), p.text, false, false).Clicked() {
			a.openNodeMenuID = ""
			a.activeNodeDrawerID = ""
			a.activeLogDrawerID = svc.ID
		}

		speedDimmed := !canTest || rt.SpeedTesting
		speedItem := popoverMenuItem(c.Key("menu-speed"), p, cat.ActionDownload(), p.text, speedDimmed, false)
		if !canTest {
			speedItem.Tooltip(cat.TestRequiresRunning())
		}
		if speedItem.Clicked() {
			a.openNodeMenuID = ""
			if !rt.SpeedTesting {
				a.triggerServiceDownloadTest(svc)
			}
		}

		if svc.IsNaiveHTTP2Sidecar() {
			restartItem := popoverMenuItem(c.Key("menu-restart-h2"), p, cat.ActionRestartNode(), p.text, !canTest, false)
			if !canTest {
				restartItem.Tooltip(cat.TestRequiresRunning())
			} else {
				restartItem.Tooltip(cat.ActionRestartH2Tooltip())
			}
			if restartItem.Clicked() && canTest {
				a.openNodeMenuID = ""
				a.restartService(svc)
			}
		}

		ui.Box(c).Height(1).Margin(4, 6, 4, 6).Background(p.borderSubtle)

		shareTip := svc.ShareURI()
		if shareTip == "" {
			shareTip = cat.NoRemoteConfigured()
		}
		if popoverMenuItem(c.Key("menu-copy-share"), p, cat.ActionCopyNaive(), p.text, false, false).Tooltip(shareTip).Clicked() {
			a.openNodeMenuID = ""
			a.copyShareLink(svc)
		}

		if svc.EffectiveEngine() == config.EngineSidecar {
			displaySvc := resolveRuntimeService(svc, rt)
			localLink := displaySvc.V2rayNSocksURI()
			if popoverMenuItem(c.Key("menu-copy-local"), p, cat.ActionCopyV2rayN(), p.text, false, false).Tooltip(localLink).Clicked() {
				a.openNodeMenuID = ""
				a.copyV2rayNLink(displaySvc)
			}
		}

		if popoverMenuItem(c.Key("menu-clone"), p, cat.ActionClone(), p.text, false, false).Clicked() {
			a.openNodeMenuID = ""
			a.cloneServiceNode(svc)
		}

		ui.Box(c).Height(1).Margin(4, 6, 4, 6).Background(p.borderSubtle)

		if svc.IsBuiltinWarp() {
			popoverMenuItem(c.Key("menu-delete"), p, cat.ActionDeleteNode(), p.red, true, true).
				Tooltip(cat.BuiltinWarpDeleteTooltip())
		} else {
			if popoverMenuItem(c.Key("menu-delete"), p, cat.ActionDeleteNode(), p.red, false, true).Clicked() {
				a.openNodeMenuID = ""
				a.openDeleteServiceDialog(svc)
			}
		}
	})
}

func (a *app) renderServiceErrorStrip(c *ui.Context, p palette, svc config.Service, rt runner.Status) {
	cat := a.catalog()
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

	strip := ui.Row(c.Key("error-banner-" + svc.ID)).
		AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(10).
		Padding(8, 0, 0, 0).
		BorderWidth(1, 0, 0, 0).BorderColor(p.borderSubtle)

	strip.Children(func() {
		ui.Row(c).AlignItems(ui.Center).Gap(6).Grow(1).Shrink(1).MinWidth(0).Children(func() {
			ui.Icon(c, iconAlert).Size(13, 13).TextColor(p.red).Shrink(0)
			ui.Text(c, displayErr).FontSize(11).FontWeight(500).TextColor(p.red).
				Grow(1).Shrink(1).MinWidth(0).SingleLine().Ellipsis("…").Tooltip(displayErr)
		})

		ui.Row(c).AlignItems(ui.Center).Gap(6).Shrink(0).Children(func() {
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
					Padding(4, 8, 4, 8).Radius(6).
					Background(p.accent).
					Tooltip(cat.EngineStatusPillHint()).
					Children(func() {
						ui.Text(c, btnLabel).FontSize(11).FontWeight(600).TextColor(ui.RGB(255, 255, 255)).NoWrap()
					})
				if !isUpdating && btnInstall.Clicked() {
					if isXray {
						a.triggerSeamlessXrayUpdate()
					} else {
						a.triggerSeamlessUpdate()
					}
				}

				btnSettings := compactStripButton(c.Key("btn-goto-settings-"+svc.ID), p, "btn-goto-settings-"+svc.ID, cat.ActionGoToSettings(), p.text).
					Tooltip(cat.ActionGoToSettings())
				if btnSettings.Clicked() {
					a.activeTab = TabSettings
					a.settingsSubTab = 2
				}
			}

			if compactStripButton(c.Key("btn-error-logs-"+svc.ID), p, "", cat.ActionLogs(), p.text).Clicked() {
				a.openNodeMenuID = ""
				a.activeNodeDrawerID = ""
				a.activeLogDrawerID = svc.ID
			}

			btnCopy := ui.ButtonBase(c.Key("btn-copy-error-" + svc.ID)).
				Label("btn-copy-error-" + svc.ID).
				Size(24, 24).Radius(6).
				Background(ui.Transparent).
				Tooltip(cat.ActionCopyError())
			if btnCopy.Hovered() {
				btnCopy.Background(p.elevated)
			}
			btnCopy.Children(func() {
				ui.Icon(c, iconCopy).Size(13, 13).TextColor(p.textMuted)
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
	_ = strip.Clicked()
}

func (a *app) renderServiceUnhealthyStrip(c *ui.Context, p palette, svc config.Service, rt runner.Status) {
	cat := a.catalog()
	hint, isWarp, _ := a.diagnoseNodeUnhealthy(svc, rt)

	strip := ui.Row(c.Key("unhealthy-banner-" + svc.ID)).
		AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(10).
		Padding(8, 0, 0, 0).
		BorderWidth(1, 0, 0, 0).BorderColor(p.borderSubtle)

	strip.Children(func() {
		ui.Row(c).AlignItems(ui.Center).Gap(6).Grow(1).Shrink(1).MinWidth(0).Children(func() {
			ui.Icon(c, iconAlert).Size(13, 13).TextColor(p.amber).Shrink(0)
			ui.Text(c, cat.StatusUnhealthy()).FontSize(11).FontWeight(700).TextColor(p.amber).NoWrap().Shrink(0)
			ui.Text(c, "·").FontSize(11).TextColor(p.amber.Alpha(0.6)).NoWrap().Shrink(0)
			ui.Text(c, cat.NodeUnhealthyDiagnosticTitle()).FontSize(11).FontWeight(600).TextColor(p.amber).NoWrap().Shrink(0)
			ui.Text(c, hint).FontSize(11).TextColor(p.textMuted).
				Grow(1).Shrink(1).MinWidth(0).SingleLine().Ellipsis("…").Tooltip(hint)
		})

		ui.Row(c).AlignItems(ui.Center).Gap(6).Shrink(0).Children(func() {
			if compactStripButton(c.Key("btn-unhealthy-logs-"+svc.ID), p, "", cat.ActionLogs(), p.textMuted).Clicked() {
				a.openNodeMenuID = ""
				a.activeNodeDrawerID = ""
				a.activeLogDrawerID = svc.ID
			}

			if isWarp {
				btnCF := compactStripButton(c.Key("btn-goto-cloudflare-"+svc.ID), p, "btn-goto-cloudflare-"+svc.ID, cat.ActionGoToCloudflare(), p.text).
					Tooltip(cat.ActionGoToCloudflare())
				if btnCF.Clicked() {
					a.activeTab = TabCloudflare
				}
			}
		})
	})
	_ = strip.Clicked()
}

func (a *app) renderRuntimeStatusBadge(c *ui.Context, p palette, st runner.State, isUnhealthy ...bool) {
	cat := a.catalog()
	if len(isUnhealthy) > 0 && isUnhealthy[0] && st == runner.StateRunning {
		statusBadge(c, cat.StatusUnhealthy(), p.amber, p.amberBg)
		return
	}
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

func nodeProtocolDisplayName(p config.Protocol) string {
	switch p {
	case config.ProtoNaive:
		return "Naive"
	case config.ProtoVLESS:
		return "VLESS"
	case config.ProtoVMess:
		return "VMess"
	case config.ProtoTrojan:
		return "Trojan"
	case config.ProtoShadowsocks:
		return "Shadowsocks"
	case config.ProtoHysteria2:
		return "Hysteria2"
	case config.ProtoTUIC:
		return "TUIC"
	case config.ProtoSOCKS5:
		return "SOCKS5"
	case config.ProtoHTTP:
		return "HTTP"
	case config.ProtoWARP:
		return "WARP"
	default:
		return strings.ToUpper(string(p))
	}
}

// resolveRuntimeService substitutes an active sidecar's auto-allocated loopback
// port (:0 or empty listen) with rt.AllocatedPort for UI display and link copy.
func resolveRuntimeService(svc config.Service, rt runner.Status) config.Service {
	if svc.EffectiveEngine() != config.EngineSidecar {
		return svc
	}
	isActive := rt.State == runner.StateRunning || rt.State == runner.StateStarting
	if !isActive || rt.AllocatedPort <= 0 {
		return svc
	}
	primary := svc.PrimaryListen()
	ep, parseErr := config.ParseListenURI(primary)
	if parseErr == nil && ep.Port > 0 {
		return svc
	}
	proto := "socks"
	host := "127.0.0.1"
	auth := ""
	if parseErr == nil {
		if ep.Proto != "" {
			proto = ep.Proto
		}
		if ep.Addr != "" && ep.Addr != "0.0.0.0" && ep.Addr != "::" {
			host = ep.Addr
		}
		if ep.User != "" || ep.Pass != "" {
			if ep.Pass != "" {
				auth = url.UserPassword(ep.User, ep.Pass).String() + "@"
			} else {
				auth = url.PathEscape(ep.User) + "@"
			}
		}
	}
	resolved := fmt.Sprintf("%s://%s%s", proto, auth, net.JoinHostPort(host, strconv.Itoa(rt.AllocatedPort)))
	if len(svc.Listens) == 0 {
		svc.Listens = []string{resolved}
	} else {
		listens := make([]string, len(svc.Listens))
		copy(listens, svc.Listens)
		listens[0] = resolved
		svc.Listens = listens
	}
	return svc
}

func (a *app) resolveDisplayService(svc config.Service) config.Service {
	if a == nil || a.mgr == nil {
		return svc
	}
	return resolveRuntimeService(svc, a.mgr.StatusOf(svc.ID))
}

func nodeCompactMeta(svc config.Service) string {
	engine := "Sing-Box"
	if svc.EffectiveEngine() == config.EngineSidecar {
		engine = "Sidecar"
	}
	meta := nodeProtocolDisplayName(svc.EffectiveProtocol()) + " · " + engine
	if svc.EffectiveEngine() == config.EngineSidecar {
		if ep, err := config.ParseListenURI(svc.PrimaryListen()); err == nil && ep.Port > 0 {
			meta += fmt.Sprintf(" (:%d)", ep.Port)
		}
	}
	return meta
}

func nodeProtocolEngineLabel(svc config.Service) string {
	protoStr := strings.ToUpper(string(svc.EffectiveProtocol()))
	engineStr := "SING-BOX"
	if svc.EffectiveEngine() == config.EngineSidecar {
		engineStr = "SIDECAR"
	}
	return protoStr + " · " + engineStr
}

func (a *app) warpTransportPillLabel(svc config.Service) string {
	if svc.EffectiveProtocol() == config.ProtoWARP && svc.WARPConfig != nil && svc.WARPConfig.Transport == config.WarpTransportAuto {
		return "WARP · AUTO"
	}
	if svc.EffectiveProtocol() != config.ProtoWARP && svc.IsTCPOnlyProxy() {
		return "WARP · MASQUE H2"
	}
	if boxengine.ResolveServiceWarpMode(svc, &a.state.Cloudflare) == warp.ModeWireGuard {
		return "WARP · WG"
	}
	return "WARP · MASQUE"
}

func isWarpUnreachable(errText string) bool {
	return isWarpTunnelError(errText)
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

// stripEndpointSchemes removes "scheme://" from every hop of a compact endpoint
// chain ("a://h:1 → b://h:2 → WARP"), leaving host:port. The protocol is
// already shown in the metadata label next to it.
func stripEndpointSchemes(ep string) string {
	parts := strings.Split(ep, " → ")
	for i, part := range parts {
		if idx := strings.Index(part, "://"); idx >= 0 {
			parts[i] = part[idx+3:]
		}
	}
	return strings.Join(parts, " → ")
}
