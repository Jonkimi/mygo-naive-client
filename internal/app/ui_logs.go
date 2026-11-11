package app

import (
	"fmt"
	"strings"

	"github.com/egoist/mygo/ui"

	"naive-client/internal/runner"
)

func (a *app) renderLogsPage(c *ui.Context, p palette) {
	cat := a.catalog()

	a.ensureSelectedLogNode()

	rawLines := a.currentLogLines()
	filteredLines := filterLogLines(rawLines, a.logsLevelFilter, a.effectiveSourceFilter(), a.logsSearchQuery)

	ui.Column(c.Key("logs-page")).Grow(1).Fill().MinHeight(0).Children(func() {
		// 1. Page Header with Title, Live Status Pill, and Action Buttons
		ui.Row(c.Key("logs-header")).
			Padding(14, 18, 14, 18).
			AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).
			BorderWidth(0, 0, 1, 0).BorderColor(p.borderSubtle).
			Children(func() {
				ui.Column(c).Shrink(1).MinWidth(0).Gap(2).Children(func() {
					ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
						ui.Text(c, cat.LogsPageTitle()).FontSize(17).FontWeight(700).TextColor(p.text)
						if a.logsPaused {
							statusBadge(c, cat.LogsStatusPaused(), p.amber, p.amberBg)
						} else {
							statusBadge(c, cat.LogsStatusLive(), p.green, p.greenBg)
						}
						tagPill(c, cat.LogsLineCount(len(filteredLines), len(rawLines)), p.textMuted, p.card)
					})
					ui.Text(c, cat.LogsPageDesc()).FontSize(11).TextColor(p.textDim).SingleLine().Ellipsis("…")
				})

				// Right header controls: Pause / Copy / Clear
				ui.Row(c).AlignItems(ui.Center).Shrink(0).Gap(6).Children(func() {
					// Pause / Resume button
					pauseIcon := iconStop
					pauseLabel := cat.LogsActionPause()
					if a.logsPaused {
						pauseIcon = iconPlay
						pauseLabel = cat.LogsActionResume()
					}
					if actionChip(c.Key("btn-logs-pause"), p, pauseIcon, pauseLabel, false).Clicked() {
						a.toggleLogsPause()
					}

					// Copy button
					if actionChip(c.Key("btn-logs-copy"), p, iconCopy, cat.LogCopy(), len(filteredLines) == 0).Clicked() {
						a.writeClipboard(strings.Join(filteredLines, "\n"), cat.CopiedServiceLogs())
					}

					// Clear button
					if actionChip(c.Key("btn-logs-clear"), p, iconTrash, cat.LogClear(), len(rawLines) == 0).Clicked() {
						a.clearCurrentLogs()
					}
				})
			})

		// 2. Main Body Container
		ui.Column(c.Key("logs-body")).
			Grow(1).Fill().MinHeight(0).
			Padding(14, 18, 18, 18).Gap(10).
			Children(func() {
				// 2a. Primary Sub-Tab Bar: Gateway & System vs Node Processes
				a.renderLogsSubTabBar(c, p, len(filteredLines), len(rawLines))

				// 2b. Context Bar: Source filter (for Gateway & System) OR Node selector pills (for Node Processes)
				if a.logsSubTab == 0 {
					a.renderGatewaySourceBar(c, p)
				} else {
					a.renderNodeSelectorBar(c, p)
				}

				// 2c. Filter Bar: Keyword search + Log Level filter pills
				a.renderLogsFilterToolbar(c, p)

				// 2d. Terminal Log Stream Viewport
				ui.Scroll(c.Key("logs-scroll")).
					Grow(1).Fill().MinHeight(0).
					Padding(12).Radius(8).
					Background(p.codeBg).
					Border(1, p.borderSubtle).
					Children(func() {
						if a.logsSubTab == 1 && len(a.state.Services) == 0 {
							ui.Text(c, cat.LogsNoNodes()).FontSize(12).TextColor(p.textDim)
							return
						}
						if len(rawLines) == 0 {
							ui.Text(c, cat.LogsEmpty()).FontSize(12).TextColor(p.textDim)
							return
						}
						if len(filteredLines) == 0 {
							ui.Text(c, cat.LogsNoMatch()).FontSize(12).TextColor(p.textDim)
							return
						}

						ui.Column(c.Key("logs-lines-col")).Fill().Gap(3).Children(func() {
							for i, line := range filteredLines {
								fg := logLineColor(line, p)
								ui.Text(c.Key(fmt.Sprintf("log-line-%d", i)), line).
									FontSize(11).
									LineHeight(1.45).
									TextColor(fg)
							}
						})
					})
			})
	})
}

func (a *app) renderLogsSubTabBar(c *ui.Context, p palette, matchedCount, totalCount int) {
	cat := a.catalog()
	gwCount := 0
	if a.gatewayLogs != nil {
		gwCount = len(a.gatewayLogs.Lines())
	}
	runningNodes := a.activeRunningCount()
	totalNodes := len(a.state.Services)

	ui.Row(c.Key("logs-subtab-bar")).
		AlignItems(ui.Center).Justify(ui.SpaceBetween).
		Children(func() {
			ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
				// Tab 0: Gateway & System
				gwActive := a.logsSubTab == 0
				gwBg := p.card
				gwFg := p.textMuted
				gwBorder := p.borderSubtle
				if gwActive {
					gwBg = p.accentBg
					gwFg = p.accentText
					gwBorder = p.accent
				}
				btnGw := ui.ButtonBase(c.Key("btn-logs-tab-gateway")).
					Label(cat.LogsTabGateway()).
					Padding(7, 14, 7, 14).Radius(8).
					Background(gwBg).Border(1, gwBorder).
					Children(func() {
						ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
							ui.Icon(c, iconShield).Size(14, 14).TextColor(gwFg)
							ui.Text(c, cat.LogsTabGateway()).FontSize(12).FontWeight(700).TextColor(gwFg)
							tagPill(c, fmt.Sprintf("%d", gwCount), gwFg, p.surface)
						})
					})
				if btnGw.Clicked() && a.logsSubTab != 0 {
					a.logsSubTab = 0
					a.logsPaused = false
					a.logsFrozenLines = nil
				}

				// Tab 1: Node Processes
				nodesActive := a.logsSubTab == 1
				nodesBg := p.card
				nodesFg := p.textMuted
				nodesBorder := p.borderSubtle
				if nodesActive {
					nodesBg = p.accentBg
					nodesFg = p.accentText
					nodesBorder = p.accent
				}
				btnNodes := ui.ButtonBase(c.Key("btn-logs-tab-nodes")).
					Label(cat.LogsTabNodes()).
					Padding(7, 14, 7, 14).Radius(8).
					Background(nodesBg).Border(1, nodesBorder).
					Children(func() {
						ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
							ui.Icon(c, iconTerminal).Size(14, 14).TextColor(nodesFg)
							ui.Text(c, cat.LogsTabNodes()).FontSize(12).FontWeight(700).TextColor(nodesFg)
							tagPill(c, fmt.Sprintf("%d/%d", runningNodes, totalNodes), nodesFg, p.surface)
						})
					})
				if btnNodes.Clicked() && a.logsSubTab != 1 {
					a.logsSubTab = 1
					a.logsPaused = false
					a.logsFrozenLines = nil
					a.ensureSelectedLogNode()
				}
			})

			// Engine Log Level selector pill group on right side of Sub-Tab bar
			ui.Row(c.Key("logs-engine-level-group")).
				AlignItems(ui.Center).Gap(4).
				Padding(3, 6, 3, 8).Radius(6).
				Background(p.card).Border(1, p.borderSubtle).
				Children(func() {
					ui.Text(c, cat.LogsEngineLevelLabel()).FontSize(11).TextColor(p.textMuted)
					activeLvl := normalizeLogLevel(a.state.LogLevel)
					levels := []struct {
						key   string
						label string
					}{
						{"debug", cat.LogsLevelDebug()},
						{"info", cat.LogsLevelInfo()},
						{"warn", cat.LogsLevelWarn()},
						{"error", cat.LogsLevelError()},
					}
					for _, item := range levels {
						lvl := item.key
						isActive := activeLvl == lvl
						bg := ui.Transparent
						fg := p.textDim
						if isActive {
							bg = p.accentBg
							fg = p.accentText
						}
						btn := ui.ButtonBase(c.Key("btn-engine-level-" + lvl)).
							Label("btn-engine-level-" + lvl).
							Padding(3, 8, 3, 8).Radius(4).
							Background(bg).
							Children(func() {
								ui.Text(c, item.label).FontSize(11).FontWeight(600).TextColor(fg)
							})
						if btn.Clicked() {
							a.setLogLevel(lvl)
						}
					}
				})
		})
}

func (a *app) renderGatewaySourceBar(c *ui.Context, p palette) {
	cat := a.catalog()
	sources := []struct {
		key   string
		label string
	}{
		{"", cat.LogsSourceAll()},
		{"gateway", cat.LogsSourceGateway()},
		{"system", cat.LogsSourceSystem()},
	}

	ui.Row(c.Key("logs-source-bar")).
		AlignItems(ui.Center).Gap(6).
		Children(func() {
			for _, item := range sources {
				src := item.key
				active := a.logsSourceFilter == src
				bg := p.card
				fg := p.textMuted
				if active {
					bg = p.elevated
					fg = p.text
				}
				btnKey := "btn-logs-src-" + src
				if src == "" {
					btnKey = "btn-logs-src-all"
				}
				btn := ui.ButtonBase(c.Key(btnKey)).
					Label(item.label).
					Padding(4, 10, 4, 10).Radius(6).
					Background(bg).Border(1, p.borderSubtle).
					Children(func() {
						ui.Text(c, item.label).FontSize(11).FontWeight(600).TextColor(fg)
					})
				if btn.Clicked() {
					a.logsSourceFilter = src
				}
			}
		})
}

func (a *app) renderNodeSelectorBar(c *ui.Context, p palette) {
	cat := a.catalog()
	if len(a.state.Services) == 0 {
		ui.Row(c.Key("logs-node-bar-empty")).
			Padding(6, 10, 6, 10).Radius(6).
			Background(p.card).Border(1, p.borderSubtle).
			Children(func() {
				ui.Text(c, cat.LogsNoNodes()).FontSize(11).TextColor(p.textDim)
			})
		return
	}

	ui.Row(c.Key("logs-node-bar")).
		AlignItems(ui.Center).Wrap().Gap(6).
		Children(func() {
			for _, svc := range a.state.Services {
				svcID := svc.ID
				svcName := svc.Name
				if svcName == "" {
					svcName = svcID
				}
				selected := a.logsSelectedNodeID == svcID
				st := runner.Status{State: runner.StateStopped}
				if a.mgr != nil {
					st = a.mgr.StatusOf(svcID)
				}

				dotColor := p.textDim
				switch st.State {
				case runner.StateRunning:
					dotColor = p.green
				case runner.StateStarting:
					dotColor = p.amber
				case runner.StateError:
					dotColor = p.red
				}

				bg := p.card
				fg := p.textMuted
				borderColor := p.borderSubtle
				if selected {
					bg = p.accentBg
					fg = p.accentText
					borderColor = p.accent
				}

				btn := ui.ButtonBase(c.Key("btn-logs-node-" + svcID)).
					Label("btn-logs-node-" + svcID).
					Padding(5, 10, 5, 10).Radius(6).
					Background(bg).Border(1, borderColor).
					Children(func() {
						ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
							ui.Box(c).Size(7, 7).Radius(999).Background(dotColor)
							ui.Text(c, svcName).FontSize(11).FontWeight(600).TextColor(fg)
							protoLabel := strings.ToUpper(string(svc.EffectiveProtocol()))
							tagPill(c, protoLabel, p.textDim, p.surface)
						})
					})
				if btn.Clicked() && a.logsSelectedNodeID != svcID {
					a.logsSelectedNodeID = svcID
					a.logsPaused = false
					a.logsFrozenLines = nil
				}
			}
		})
}

func (a *app) renderLogsFilterToolbar(c *ui.Context, p palette) {
	cat := a.catalog()

	ui.Row(c.Key("logs-filter-toolbar")).
		AlignItems(ui.Center).Gap(10).
		Children(func() {
			// Keyword Search Input
			ui.Row(c).Grow(1).Children(func() {
				ui.TextInput(c.Key("input-logs-search"), &a.logsSearchQuery).
					Placeholder(cat.LogsSearchPlaceholder()).
					FontSize(11).
					Padding(5, 10, 5, 10).Radius(6).
					Background(p.card).Border(1, p.borderSubtle)
			})

			// Level Filter Pills
			levels := []struct {
				key      string
				label    string
				activeFg ui.Color
				activeBg ui.Color
			}{
				{"", cat.LogsLevelAll(), p.text, p.elevated},
				{"debug", cat.LogsLevelDebug(), p.textMuted, p.elevated},
				{"info", cat.LogsLevelInfo(), p.accentText, p.accentBg},
				{"warn", cat.LogsLevelWarn(), p.amber, p.amberBg},
				{"error", cat.LogsLevelError(), p.red, p.redBg},
			}

			ui.Row(c.Key("logs-level-filter-pills")).
				AlignItems(ui.Center).Gap(4).
				Children(func() {
					for _, item := range levels {
						lvl := item.key
						active := a.logsLevelFilter == lvl
						bg := p.card
						fg := p.textDim
						if active {
							bg = item.activeBg
							fg = item.activeFg
						}
						btnKey := "btn-logs-filter-" + lvl
						if lvl == "" {
							btnKey = "btn-logs-filter-all"
						}
						btn := ui.ButtonBase(c.Key(btnKey)).
							Label(btnKey).
							Padding(4, 9, 4, 9).Radius(5).
							Background(bg).Border(1, p.borderSubtle).
							Children(func() {
								ui.Text(c, item.label).FontSize(11).FontWeight(600).TextColor(fg)
							})
						if btn.Clicked() {
							a.logsLevelFilter = lvl
						}
					}
				})
		})
}

func (a *app) ensureSelectedLogNode() {
	if len(a.state.Services) == 0 {
		a.logsSelectedNodeID = ""
		return
	}
	if a.logsSelectedNodeID != "" {
		if _, ok := a.findService(a.logsSelectedNodeID); ok {
			return
		}
	}
	if a.mgr != nil {
		for _, svc := range a.state.Services {
			st := a.mgr.StatusOf(svc.ID)
			if st.State == runner.StateRunning || st.State == runner.StateStarting {
				a.logsSelectedNodeID = svc.ID
				return
			}
		}
	}
	a.logsSelectedNodeID = a.state.Services[0].ID
}

func (a *app) currentLogBuffer() *runner.LogBuffer {
	if a.logsSubTab == 0 {
		return a.gatewayLogs
	}
	if a.mgr == nil || a.logsSelectedNodeID == "" {
		return nil
	}
	return a.mgr.LogsOf(a.logsSelectedNodeID)
}

func (a *app) currentLogLines() []string {
	if a.logsPaused && a.logsFrozenLines != nil {
		return a.logsFrozenLines
	}
	buf := a.currentLogBuffer()
	if buf == nil {
		return nil
	}
	return buf.Lines()
}

func (a *app) toggleLogsPause() {
	if a.logsPaused {
		a.logsPaused = false
		a.logsFrozenLines = nil
		return
	}
	buf := a.currentLogBuffer()
	if buf != nil {
		a.logsFrozenLines = buf.Lines()
	} else {
		a.logsFrozenLines = []string{}
	}
	a.logsPaused = true
}

func (a *app) clearCurrentLogs() {
	buf := a.currentLogBuffer()
	if buf != nil {
		buf.Clear()
	}
	if a.logsPaused {
		a.logsFrozenLines = []string{}
	}
}

func (a *app) effectiveSourceFilter() string {
	if a.logsSubTab != 0 {
		return ""
	}
	return a.logsSourceFilter
}

func detectLogLineLevel(line string) string {
	upper := strings.ToUpper(line)
	if strings.Contains(upper, "[ERROR]") || strings.Contains(upper, "[FATAL]") || strings.Contains(upper, "ERROR:") || strings.Contains(line, "异常") || strings.Contains(line, "失败") {
		return "error"
	}
	if strings.Contains(upper, "[WARN]") || strings.Contains(upper, "[WARNING]") || strings.Contains(upper, "WARNING:") || strings.Contains(line, "警告") || strings.Contains(line, "回退") {
		return "warn"
	}
	if strings.Contains(upper, "[DEBUG]") || strings.Contains(upper, "[TRACE]") || strings.Contains(upper, "DEBUG:") {
		return "debug"
	}
	return "info"
}

func detectLogLineSource(line string) string {
	if strings.Contains(line, "[sing-box]") {
		return "gateway"
	}
	if strings.Contains(line, "[system]") {
		return "system"
	}
	return "other"
}

func filterLogLines(lines []string, levelFilter, sourceFilter, query string) []string {
	levelFilter = strings.ToLower(strings.TrimSpace(levelFilter))
	sourceFilter = strings.ToLower(strings.TrimSpace(sourceFilter))
	queryLower := strings.ToLower(strings.TrimSpace(query))

	if levelFilter == "" && sourceFilter == "" && queryLower == "" {
		return lines
	}

	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if sourceFilter != "" && detectLogLineSource(line) != sourceFilter {
			continue
		}
		if levelFilter != "" && detectLogLineLevel(line) != levelFilter {
			continue
		}
		if queryLower != "" && !strings.Contains(strings.ToLower(line), queryLower) {
			continue
		}
		out = append(out, line)
	}
	return out
}

func logLineColor(line string, p palette) ui.Color {
	switch detectLogLineLevel(line) {
	case "error":
		return p.red
	case "warn":
		return p.amber
	case "debug":
		return p.textDim
	default:
		return p.text
	}
}
