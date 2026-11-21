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

	rawEntries := a.currentLogEntries()
	filteredEntries := filterLogEntries(rawEntries, a.logsLevelFilter, a.effectiveSourceFilter(), a.logsSearchQuery)

	ui.Column(c.Key("logs-page")).Grow(1).Fill().MinHeight(0).Children(func() {
		// Layer 1: Unified Header (Title + Segmented Sub-Tab + Live Status | Engine Level Select + Actions)
		ui.Row(c.Key("logs-header")).
			Padding(12, 18, 12, 18).
			AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(10).Wrap().
			Background(p.surface).
			BorderWidth(0, 0, 1, 0).BorderColor(p.borderSubtle).
			Children(func() {
				ui.Row(c).AlignItems(ui.Center).Gap(10).Wrap().MinWidth(0).Shrink(1).Children(func() {
					ui.Text(c, cat.LogsPageTitle()).FontSize(17).FontWeight(700).TextColor(p.text).NoWrap()

					if segmentedControl(c.Key("logs-subtab-ctrl"), p, &a.logsSubTab, []string{cat.LogsTabGateway(), cat.LogsTabNodes()}) {
						a.logsPaused = false
						a.logsFrozenLines = nil
						if a.logsSubTab == 1 {
							a.ensureSelectedLogNode()
						}
					}

					ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
						if a.logsPaused {
							statusDot(c, p.amber)
							ui.Text(c, cat.LogsStatusPaused()).FontSize(12).TextColor(p.amber).NoWrap()
						} else {
							statusDot(c, p.green)
							ui.Text(c, cat.LogsStatusLive()).FontSize(12).TextColor(p.textMuted).NoWrap()
						}
						ui.Text(c, "·").FontSize(12).TextColor(p.textDim).NoWrap()
						ui.Text(c, cat.LogsLineCount(len(filteredEntries), len(rawEntries))).
							FontSize(12).FontFeatures("tnum").TextColor(p.textMuted).NoWrap()
					})
				})

				// Right header controls: Engine Log Level Select + Pause / Copy / Clear
				ui.Row(c).AlignItems(ui.Center).Shrink(0).Gap(6).Wrap().Children(func() {
					a.renderLogsEngineLevelSelect(c, p)

					pauseIcon := iconStop
					pauseLabel := cat.LogsActionPause()
					if a.logsPaused {
						pauseIcon = iconPlay
						pauseLabel = cat.LogsActionResume()
					}
					btnPause := quietToolbarButton(c.Key("btn-logs-pause"), p, pauseIcon, pauseLabel, false).
						Label(pauseLabel)
					if btnPause.Clicked() {
						a.toggleLogsPause()
					}

					copyDimmed := len(filteredEntries) == 0
					btnCopy := quietToolbarButton(c.Key("btn-logs-copy"), p, iconCopy, cat.LogCopy(), copyDimmed).
						Label(cat.LogCopy())
					if !copyDimmed && btnCopy.Clicked() {
						a.writeClipboard(joinLogEntries(filteredEntries), cat.CopiedServiceLogs())
					}

					clearDimmed := len(rawEntries) == 0
					btnClear := quietToolbarButton(c.Key("btn-logs-clear"), p, iconTrash, cat.LogClear(), clearDimmed).
						Label(cat.LogClear())
					if !clearDimmed && btnClear.Clicked() {
						a.clearCurrentLogs()
					}
				})
			})

		// 2. Main Body Container
		ui.Column(c.Key("logs-body")).
			Grow(1).Fill().MinHeight(0).
			Padding(12, 18, 16, 18).Gap(10).
			Children(func() {
				// Layer 2: Unified Filter Toolbar (Source or Node Select + Search | Level Filter Track)
				a.renderLogsFilterToolbar(c, p)

				// Terminal Log Stream Viewport (mouse-selectable across lines)
				scroll := ui.Scroll(c.Key("logs-scroll")).
					Grow(1).Fill().MinHeight(0).
					Padding(12).Radius(8).
					Background(p.codeBg).
					Border(1, p.borderSubtle).
					Gap(3)
				if len(filteredEntries) > 0 {
					scroll.Selectable()
				}
				scroll.Children(func() {
					if a.logsSubTab == 1 && len(a.state.Services) == 0 {
						ui.Text(c, cat.LogsNoNodes()).FontSize(12).TextColor(p.textDim)
						return
					}
					if len(rawEntries) == 0 {
						ui.Text(c, cat.LogsEmpty()).FontSize(12).TextColor(p.textDim)
						return
					}
					if len(filteredEntries) == 0 {
						ui.Text(c, cat.LogsNoMatch()).FontSize(12).TextColor(p.textDim)
						return
					}

					for _, entry := range filteredEntries {
						fg := logLineColor(entry.Text, p)
						ui.Text(c.Key(fmt.Sprintf("log-entry-%d", entry.Seq)), entry.Text).
							Font("monospace").
							FontSize(11).
							LineHeight(1.45).
							TextColor(fg).
							Shrink(0)
					}
				})
			})
	})
}

func (a *app) renderLogsEngineLevelSelect(c *ui.Context, p palette) {
	cat := a.catalog()
	if a.logsEngineLevel == "" {
		a.logsEngineLevel = normalizeLogLevel(a.state.LogLevel)
	}
	levels := []struct {
		key   string
		label string
	}{
		{"debug", cat.LogsLevelDebug()},
		{"info", cat.LogsLevelInfo()},
		{"warn", cat.LogsLevelWarn()},
		{"error", cat.LogsLevelError()},
	}

	activeKey := normalizeLogLevel(a.logsEngineLevel)
	activeLabel := cat.LogsLevelInfo()
	for _, item := range levels {
		if item.key == activeKey {
			activeLabel = item.label
			break
		}
	}

	sel := ui.SelectBase(c.Key("select-engine-level"), &a.logsEngineLevel)
	sel.Trigger.
		Label("select-engine-level").
		Tooltip(cat.LogsEngineLevelLabel()).
		Height(32).Padding(0, 10, 0, 10).Radius(8).
		Background(p.card).Border(1, p.border).
		Children(func() {
			ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
				ui.Text(c, cat.LogsEngineLevelLabel()).FontSize(11).TextColor(p.textDim).NoWrap()
				ui.Text(c, activeLabel).FontSize(12).FontWeight(500).TextColor(p.text).NoWrap()
				ui.Icon(c, iconChevronDown).Size(12, 12).TextColor(p.textMuted)
			})
		})
	if sel.Trigger.Hovered() {
		sel.Trigger.Background(p.cardHover)
	}

	sel.Popup(func(panel ui.Element) {
		panel.Column().Gap(2).MinWidth(136).
			AttachTo(sel.Trigger, ui.AnchorBottomEnd, ui.AnchorTopEnd).
			Margin(4, 0, 0, 0).
			Padding(4).Radius(10).
			Background(p.card).Border(1, p.border).
			Shadow(0, 10, 28, 0, ui.RGBA(0, 0, 0, 0.18))
		for _, item := range levels {
			selected := item.key == activeKey
			opt := sel.Item(item.key).
				Label("btn-engine-level-" + item.key).
				FillWidth().Height(28).PaddingX(10).Radius(6).
				AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(8)
			if opt.Highlighted() {
				opt.Background(p.elevated)
			}
			opt.Children(func() {
				fg := p.textMuted
				if selected || opt.Highlighted() {
					fg = p.text
				}
				ui.Text(c, item.label).FontSize(12).FontWeight(500).TextColor(fg).NoWrap()
				if selected {
					statusDot(c, p.accent)
				}
			})
		}
	})

	if sel.Trigger.Changed() {
		a.setLogLevel(a.logsEngineLevel)
	} else if norm := normalizeLogLevel(a.state.LogLevel); a.logsEngineLevel != norm {
		a.logsEngineLevel = norm
	}
}

func (a *app) renderLogsFilterToolbar(c *ui.Context, p palette) {
	cat := a.catalog()

	ui.Row(c.Key("logs-filter-toolbar")).
		AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(8).Wrap().
		Children(func() {
			// Left: Gateway/System Source segmented track OR Node Select + SearchField
			ui.Row(c).AlignItems(ui.Center).Gap(8).Grow(1).MinWidth(0).Wrap().Children(func() {
				if a.logsSubTab == 0 {
					a.renderGatewaySourceTrack(c, p)
				} else {
					a.renderNodeLogSelect(c, p)
				}

				ui.SearchField(c.Key("input-logs-search"), &a.logsSearchQuery).
					Placeholder(cat.LogsSearchPlaceholder()).
					Label(cat.LogsSearchPlaceholder()).
					Height(28).Radius(7).FontSize(11).
					MinWidth(100).Grow(1).MaxWidth(260).
					Background(p.card)
			})

			// Right: Level Filter Segmented Track
			levels := []struct {
				key      string
				a11y     string
				label    string
				activeFg ui.Color
			}{
				{"", "btn-logs-filter-all", cat.LogsLevelAll(), p.text},
				{"info", "btn-logs-filter-info", cat.LogsLevelInfo(), p.accentText},
				{"warn", "btn-logs-filter-warn", cat.LogsLevelWarn(), p.amber},
				{"error", "btn-logs-filter-error", cat.LogsLevelError(), p.red},
				{"debug", "btn-logs-filter-debug", cat.LogsLevelDebug(), p.textMuted},
			}

			lvlIdx := 0
			lvlOpts := make([]segmentedOption, len(levels))
			for i, item := range levels {
				if a.logsLevelFilter == item.key {
					lvlIdx = i
				}
				lvlOpts[i] = segmentedOption{
					Label:       item.label,
					A11yLabel:   item.a11y,
					ActiveColor: item.activeFg,
				}
			}
			ui.Row(c).Shrink(0).Children(func() {
				if compactSegmentedOptions(c.Key("logs-level-filter-pills"), p, &lvlIdx, lvlOpts) {
					a.logsLevelFilter = levels[lvlIdx].key
				}
			})
		})
}

func (a *app) renderGatewaySourceTrack(c *ui.Context, p palette) {
	cat := a.catalog()
	sources := []struct {
		key   string
		label string
	}{
		{"", cat.LogsSourceAll()},
		{"gateway", cat.LogsSourceGateway()},
		{"system", cat.LogsSourceSystem()},
	}

	srcIdx := 0
	srcOpts := make([]segmentedOption, len(sources))
	for i, item := range sources {
		if a.logsSourceFilter == item.key {
			srcIdx = i
		}
		srcOpts[i] = segmentedOption{Label: item.label}
	}
	ui.Row(c).Shrink(0).Children(func() {
		if compactSegmentedOptions(c.Key("logs-source-bar"), p, &srcIdx, srcOpts) {
			a.logsSourceFilter = sources[srcIdx].key
		}
	})
}

func (a *app) nodeLogStatusDotColor(svcID string, p palette) ui.Color {
	if a.mgr == nil {
		return p.textDim
	}
	switch a.mgr.StatusOf(svcID).State {
	case runner.StateRunning:
		return p.green
	case runner.StateStarting:
		return p.amber
	case runner.StateError:
		return p.red
	default:
		return p.textDim
	}
}

func (a *app) renderNodeLogSelect(c *ui.Context, p palette) {
	cat := a.catalog()
	if len(a.state.Services) == 0 {
		ui.Row(c.Key("logs-node-bar-empty")).
			Padding(4, 10, 4, 10).Radius(7).
			Background(p.card).Border(1, p.borderSubtle).
			Children(func() {
				ui.Text(c, cat.LogsNoNodes()).FontSize(11).TextColor(p.textDim)
			})
		return
	}

	selSvc, ok := a.findService(a.logsSelectedNodeID)
	if !ok {
		selSvc = a.state.Services[0]
		a.logsSelectedNodeID = selSvc.ID
	}
	selName := selSvc.Name
	if selName == "" {
		selName = selSvc.ID
	}
	selDotCol := a.nodeLogStatusDotColor(selSvc.ID, p)

	sel := ui.SelectBase(c.Key("select-logs-node"), &a.logsSelectedNodeID)
	sel.Trigger.
		Label("select-logs-node").
		Tooltip(cat.LogsNodeSelectorLabel()).
		Height(28).Padding(0, 10, 0, 10).Radius(7).
		Background(p.card).Border(1, p.border).
		Children(func() {
			ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
				statusDot(c, selDotCol)
				ui.Text(c, selName).FontSize(11).FontWeight(600).TextColor(p.text).SingleLine().Ellipsis("…").MaxWidth(150)
				ui.Text(c, nodeCompactMeta(selSvc)).FontSize(11).FontFeatures("tnum").TextColor(p.textDim).NoWrap()
				ui.Icon(c, iconChevronDown).Size(12, 12).TextColor(p.textMuted)
			})
		})
	if sel.Trigger.Hovered() {
		sel.Trigger.Background(p.cardHover)
	}

	sel.Popup(func(panel ui.Element) {
		panel.Column().Gap(2).MinWidth(230).
			AttachTo(sel.Trigger, ui.AnchorBottomStart, ui.AnchorTopStart).
			Margin(4, 0, 0, 0).
			Padding(4).Radius(10).
			Background(p.card).Border(1, p.border).
			Shadow(0, 10, 28, 0, ui.RGBA(0, 0, 0, 0.18))
		for _, svc := range a.state.Services {
			svcName := svc.Name
			if svcName == "" {
				svcName = svc.ID
			}
			dotCol := a.nodeLogStatusDotColor(svc.ID, p)
			selected := a.logsSelectedNodeID == svc.ID
			opt := sel.Item(svc.ID).
				Label("btn-logs-node-" + svc.ID).
				FillWidth().Padding(6, 10, 6, 10).Radius(6).
				AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(10)
			if opt.Highlighted() {
				opt.Background(p.elevated)
			}
			opt.Children(func() {
				ui.Row(c).AlignItems(ui.Center).Gap(6).MinWidth(0).Shrink(1).Children(func() {
					statusDot(c, dotCol)
					fg := p.textMuted
					if selected || opt.Highlighted() {
						fg = p.text
					}
					ui.Text(c, svcName).FontSize(12).FontWeight(500).TextColor(fg).SingleLine().Ellipsis("…")
				})
				ui.Text(c, nodeCompactMeta(svc)).FontSize(11).FontFeatures("tnum").TextColor(p.textDim).NoWrap().Shrink(0)
			})
		}
	})

	if sel.Trigger.Changed() {
		a.logsPaused = false
		a.logsFrozenLines = nil
	}
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

func (a *app) currentLogEntries() []runner.LogEntry {
	if a.logsPaused && a.logsFrozenLines != nil {
		out := make([]runner.LogEntry, len(a.logsFrozenLines))
		for i, line := range a.logsFrozenLines {
			out[i] = runner.LogEntry{Seq: uint64(i + 1), Text: line}
		}
		return out
	}
	buf := a.currentLogBuffer()
	if buf == nil {
		return nil
	}
	return buf.Entries()
}

func filterLogEntries(entries []runner.LogEntry, levelFilter, sourceFilter, query string) []runner.LogEntry {
	levelFilter = strings.ToLower(strings.TrimSpace(levelFilter))
	sourceFilter = strings.ToLower(strings.TrimSpace(sourceFilter))
	queryLower := strings.ToLower(strings.TrimSpace(query))

	if levelFilter == "" && sourceFilter == "" && queryLower == "" {
		return entries
	}

	out := make([]runner.LogEntry, 0, len(entries))
	for _, entry := range entries {
		if sourceFilter != "" && detectLogLineSource(entry.Text) != sourceFilter {
			continue
		}
		if levelFilter != "" && detectLogLineLevel(entry.Text) != levelFilter {
			continue
		}
		if queryLower != "" && !strings.Contains(strings.ToLower(entry.Text), queryLower) {
			continue
		}
		out = append(out, entry)
	}
	return out
}

func joinLogEntries(entries []runner.LogEntry) string {
	lines := make([]string, len(entries))
	for i, e := range entries {
		lines[i] = e.Text
	}
	return strings.Join(lines, "\n")
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
