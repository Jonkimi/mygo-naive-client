package app

import (
	"fmt"
	"math"

	"github.com/egoist/mygo/ui"

	"naive-client/internal/config"
	"naive-client/internal/runner"
)

func (a *app) resetLogDrawerState() {
	a.logDrawerLastID = ""
	a.logDrawerSearch = ""
	a.logDrawerLevel = ""
	a.logDrawerPaused = false
	a.logDrawerFrozenEntries = nil
	a.logDrawerFollow = true
	a.logDrawerLastMaxSeq = 0
}

func (a *app) dismissLogDrawer() {
	a.activeLogDrawerID = ""
	a.resetLogDrawerState()
}

func (a *app) renderLogDrawer(c *ui.Context, p palette) {
	if a.activeLogDrawerID == "" {
		a.resetLogDrawerState()
		return
	}

	if a.activeLogDrawerID != a.logDrawerLastID {
		a.resetLogDrawerState()
		a.logDrawerLastID = a.activeLogDrawerID
		a.logDrawerScroll.Y = 0
	}

	svc, svcOK := a.findService(a.activeLogDrawerID)
	name := a.activeLogDrawerID
	var rt runner.Status
	unhealthy := false
	if svcOK {
		if svc.Name != "" {
			name = svc.Name
		}
		rt = a.mgr.StatusOf(svc.ID)
		unhealthy = a.isNodeUnhealthy(svc, rt)
	}

	logs := a.mgr.LogsOf(a.activeLogDrawerID)
	var rawEntries []runner.LogEntry
	if a.logDrawerPaused && a.logDrawerFrozenEntries != nil {
		rawEntries = a.logDrawerFrozenEntries
	} else {
		rawEntries = logs.Entries()
	}
	filtered := filterLogEntries(rawEntries, a.logDrawerLevel, "", a.logDrawerSearch)

	var latestSeq uint64
	if n := len(rawEntries); n > 0 {
		latestSeq = rawEntries[n-1].Seq
	}
	// Pause auto-tail when the user scrolls up manually so log reading and mouse selection stay steady.
	if a.logDrawerScroll.MaxY > 0 && a.logDrawerScroll.Y < a.logDrawerScroll.MaxY-12 {
		a.logDrawerFollow = false
	}
	if a.logDrawerFollow && !a.logDrawerPaused && len(filtered) > 0 && latestSeq != a.logDrawerLastMaxSeq {
		a.logDrawerScroll.Y = math.MaxFloat32
	}
	a.logDrawerLastMaxSeq = latestSeq

	// Backdrop (fades in and out, click to dismiss)
	backdrop := ui.Box(c.Key("drawer-backdrop")).
		Absolute().Top(0).Left(0).Right(0).Bottom(0).
		Background(ui.RGBA(0, 0, 0, 0.3)).
		Transition(ui.ElementTransition{
			Enter: &ui.Motion{Opacity: 0},
			Exit:  &ui.Motion{Opacity: 0},
		})
	if backdrop.Clicked() {
		a.dismissLogDrawer()
	}

	// Slide-over drawer panel anchored to right edge (460px unified width)
	ui.Column(c.Key("drawer-panel")).
		Absolute().Top(0).Right(0).Bottom(0).Width(460).
		Transition(ui.ElementTransition{
			Enter: &ui.Motion{X: 460},
			Exit:  &ui.Motion{X: 460},
		}).
		Background(p.drawerBg).
		BorderWidth(0, 0, 0, 1).BorderColor(p.border).
		Shadow(0, 8, 36, 0, ui.RGBA(0, 0, 0, 0.4)).
		Children(func() {
			a.renderLogDrawerHeader(c, p, svc, svcOK, name, rt, unhealthy, logs, rawEntries, filtered)
			a.renderLogDrawerToolbar(c, p, filtered)
			a.renderLogDrawerViewport(c, p, rawEntries, filtered)
		})
}

func (a *app) renderLogDrawerHeader(
	c *ui.Context,
	p palette,
	svc config.Service,
	svcOK bool,
	name string,
	rt runner.Status,
	unhealthy bool,
	logs *runner.LogBuffer,
	rawEntries []runner.LogEntry,
	filtered []runner.LogEntry,
) {
	cat := a.catalog()

	liveText := cat.LogsStatusLive()
	liveColor := p.green
	if a.logDrawerPaused {
		liveText = cat.LogsStatusPaused()
		liveColor = p.amber
	}

	ui.Row(c).
		AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(8).
		Padding(14, 20, 12, 20).
		BorderWidth(0, 0, 1, 0).BorderColor(p.borderSubtle).
		Children(func() {
			// Left: eyebrow (LogDrawerTitle · LIVE · lines) + service dot & name
			ui.Column(c).Grow(1).Shrink(1).MinWidth(0).Gap(3).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
					ui.Text(c, cat.LogDrawerTitle()).FontSize(11).FontWeight(600).TextColor(p.textDim).NoWrap()
					ui.Text(c, "·").FontSize(11).TextColor(p.textDim)
					ui.Text(c, liveText).FontSize(11).FontWeight(600).TextColor(liveColor).NoWrap()
					ui.Text(c, "·").FontSize(11).TextColor(p.textDim)
					ui.Text(c, cat.LogsLineCount(len(filtered), len(rawEntries))).
						FontSize(11).FontFeatures("tnum").TextColor(p.textDim).NoWrap()
				})

				ui.Row(c).AlignItems(ui.Center).Gap(8).MinWidth(0).Children(func() {
					if svcOK {
						renderServiceStatusDot(c, p, rt, unhealthy)
					} else {
						ui.Box(c).Size(7, 7).Radius(999).Background(p.textDim).Shrink(0)
					}
					ui.Text(c, name).FontSize(15).FontWeight(700).TextColor(p.text).
						SingleLine().Ellipsis("…").Shrink(1).MinWidth(0)
				})
			})

			// Right: Pause/Resume, Details, Full View | Copy, Clear, Close
			ui.Row(c).AlignItems(ui.Center).Gap(2).Shrink(0).Children(func() {
				pauseIcon := iconStop
				pauseLabel := cat.LogsActionPause()
				if a.logDrawerPaused {
					pauseIcon = iconPlay
					pauseLabel = cat.LogsActionResume()
				}
				pauseBtn := quietRowIconButton(c.Key("btn-drawer-pause"), p, pauseIcon, pauseLabel, false, a.logDrawerPaused).
					Tooltip(pauseLabel)
				if pauseBtn.Clicked() {
					if a.logDrawerPaused {
						a.logDrawerPaused = false
						a.logDrawerFrozenEntries = nil
						a.logDrawerFollow = true
						a.logDrawerScroll.Y = math.MaxFloat32
					} else {
						a.logDrawerFrozenEntries = logs.Entries()
						a.logDrawerPaused = true
					}
				}

				if svcOK {
					detailsBtn := quietRowIconButton(c.Key("btn-drawer-details-from-logs"), p, iconInfo, cat.NodeDrawerTitle(), false, false).
						Tooltip(cat.NodeDrawerTitle())
					if detailsBtn.Clicked() {
						targetID := svc.ID
						a.dismissLogDrawer()
						a.activeNodeDrawerID = targetID
					}
				}

				fullBtn := quietRowIconButton(c.Key("btn-drawer-open-full-logs"), p, iconTerminal, cat.LogsOpenFullPage(), false, false).
					Tooltip(cat.LogsOpenFullPage())
				if fullBtn.Clicked() {
					a.logsSelectedNodeID = a.activeLogDrawerID
					a.logsSubTab = 1
					a.dismissLogDrawer()
					a.activeTab = TabLogs
				}

				ui.Box(c).Size(1, 16).Background(p.borderSubtle).Margin(0, 4, 0, 4).Shrink(0)

				copyBtn := subtleActionChip(c.Key("btn-drawer-copy"), p, iconCopy, cat.BtnCopy(), len(filtered) == 0).
					Label(cat.LogCopy()).
					Tooltip(cat.LogDrawerCopyTooltip())
				if copyBtn.Clicked() {
					a.writeClipboard(joinLogEntries(filtered), cat.CopiedServiceLogs())
				}

				clearBtn := quietRowIconButton(c.Key("btn-drawer-clear"), p, iconTrash, cat.LogClear(), len(rawEntries) == 0, false).
					Tooltip(cat.LogClear())
				if clearBtn.Clicked() && len(rawEntries) > 0 {
					logs.Clear()
					if a.logDrawerPaused {
						a.logDrawerFrozenEntries = []runner.LogEntry{}
					}
				}

				closeBtn := quietRowIconButton(c.Key("btn-drawer-close"), p, iconClose, cat.LogClose(), false, false).
					Tooltip(cat.LogClose())
				if closeBtn.Clicked() {
					a.dismissLogDrawer()
				}
			})
		})
}

func (a *app) renderLogDrawerToolbar(c *ui.Context, p palette, filtered []runner.LogEntry) {
	cat := a.catalog()
	levels := []struct {
		key      string
		label    string
		activeFg ui.Color
		activeBg ui.Color
	}{
		{"", cat.LogsLevelAll(), p.text, p.elevated},
		{"info", cat.LogsLevelInfo(), p.accentText, p.accentBg},
		{"warn", cat.LogsLevelWarn(), p.amber, p.amberBg},
		{"error", cat.LogsLevelError(), p.red, p.redBg},
		{"debug", cat.LogsLevelDebug(), p.textMuted, p.elevated},
	}

	ui.Column(c.Key("drawer-log-toolbar")).
		Padding(10, 20, 10, 20).Gap(8).
		Background(p.surface).
		BorderWidth(0, 0, 1, 0).BorderColor(p.borderSubtle).
		Children(func() {
			ui.SearchField(c.Key("drawer-log-search"), &a.logDrawerSearch).
				Placeholder(cat.LogsSearchPlaceholder()).
				Label(cat.LogsSearchPlaceholder()).
				Height(30).Radius(8).FontSize(12).
				Background(p.card).
				FillWidth()

			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(6).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Gap(4).Shrink(0).Children(func() {
					for _, item := range levels {
						lvl := item.key
						active := a.logDrawerLevel == lvl
						bg := ui.Transparent
						fg := p.textMuted
						if active {
							bg = item.activeBg
							fg = item.activeFg
						}
						btnKey := "btn-drawer-level-" + lvl
						if lvl == "" {
							btnKey = "btn-drawer-level-all"
						}
						btn := ui.ButtonBase(c.Key(btnKey)).
							Label(btnKey).
							Padding(3, 8, 3, 8).Radius(6).
							Background(bg)
						if !active && btn.Hovered() {
							fg = p.text
							btn.Background(p.elevated)
						}
						btn.Children(func() {
							ui.Text(c, item.label).FontSize(11).FontWeight(600).TextColor(fg).NoWrap()
						})
						if btn.Clicked() {
							a.logDrawerLevel = lvl
						}
					}
				})

				if !a.logDrawerFollow && len(filtered) > 0 && a.logDrawerScroll.MaxY > 0 {
					if compactStripButton(c.Key("btn-drawer-jump-bottom"), p, cat.LogJumpToLatest(), cat.LogJumpToLatest(), p.accentText).Clicked() {
						a.logDrawerFollow = true
						a.logDrawerScroll.Y = math.MaxFloat32
					}
				} else if len(filtered) > 0 {
					ui.Text(c, cat.LogDrawerSelectionHint()).
						FontSize(10).TextColor(p.textDim).NoWrap()
				}
			})
		})
}

func (a *app) renderLogDrawerViewport(c *ui.Context, p palette, rawEntries, filtered []runner.LogEntry) {
	cat := a.catalog()

	ui.Column(c.Key("drawer-log-body")).
		Grow(1).Fill().MinHeight(0).
		Padding(12, 20, 18, 20).
		Background(p.surface).
		Children(func() {
			frame := ui.Column(c.Key("drawer-log-frame")).
				Grow(1).Fill().MinHeight(0).
				Radius(10).
				Background(p.codeBg).
				Border(1, p.borderSubtle)

			if len(rawEntries) == 0 {
				frame.AlignItems(ui.Center).Justify(ui.Center).Padding(24).Gap(8).Children(func() {
					ui.Icon(c, iconTerminal).Size(20, 20).TextColor(p.textDim)
					ui.Text(c, cat.LogEmpty()).FontSize(12).TextColor(p.textDim).TextAlign(ui.Center)
				})
				return
			}

			if len(filtered) == 0 {
				frame.AlignItems(ui.Center).Justify(ui.Center).Padding(24).Gap(10).Children(func() {
					ui.Text(c, cat.LogsNoMatch()).FontSize(12).TextColor(p.textDim).TextAlign(ui.Center)
					if compactStripButton(c.Key("btn-drawer-log-reset-filter"), p, cat.ResetFilters(), cat.ResetFilters(), p.accentText).Clicked() {
						a.logDrawerSearch = ""
						a.logDrawerLevel = ""
					}
				})
				return
			}

			frame.Children(func() {
				// Native multi-paragraph mouse selection: drag, double/triple click, Cmd+C, and right-click Copy.
				ui.Scroll(c.Key("drawer-scroll")).
					Selectable().
					TrackScroll(&a.logDrawerScroll).
					Grow(1).Fill().MinHeight(0).
					Padding(10, 12, 10, 12).
					Gap(3).
					Children(func() {
						for _, entry := range filtered {
							fg := logLineColor(entry.Text, p)
							ui.Text(c.Key(fmt.Sprintf("drawer-log-seq-%d", entry.Seq)), entry.Text).
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
