package app

import (
	"strings"
	"time"

	"github.com/egoist/mygo/ui"
)

func (a *app) renderLogDrawer(c *ui.Context, p palette) {
	if a.activeLogDrawerID == "" && !a.logDrawerClosing {
		return
	}

	if a.headless {
		if a.logDrawerClosing {
			a.activeLogDrawerID = ""
			a.logDrawerClosing = false
			a.logDrawerProgress = 0
			return
		}
		a.logDrawerProgress = 1
	} else if a.logDrawerAnim {
		const duration = 220 * time.Millisecond
		elapsed := time.Since(a.logDrawerStart)
		if elapsed >= duration {
			a.logDrawerProgress = a.logDrawerTo
			a.logDrawerAnim = false
			if a.logDrawerClosing {
				a.activeLogDrawerID = ""
				a.logDrawerClosing = false
				return
			}
		} else {
			t := float32(elapsed) / float32(duration)
			// Smooth cubic ease out
			eased := 1 - (1-t)*(1-t)*(1-t)
			a.logDrawerProgress = a.logDrawerFrom + (a.logDrawerTo-a.logDrawerFrom)*eased
			c.AnimationFrame()
		}
	}

	if a.logDrawerProgress <= 0.001 && a.logDrawerClosing {
		a.activeLogDrawerID = ""
		a.logDrawerClosing = false
		return
	}

	cat := a.catalog()
	svc, ok := a.findService(a.activeLogDrawerID)
	name := a.activeLogDrawerID
	if ok {
		name = svc.Name
	}

	logs := a.mgr.LogsOf(a.activeLogDrawerID)
	lines := logs.Lines()

	offset := float32(440) * (1 - a.logDrawerProgress)
	backdropAlpha := 0.3 * a.logDrawerProgress
	shadowAlpha := 0.4 * a.logDrawerProgress

	// Backdrop (click to dismiss drawer)
	backdrop := ui.Box(c.Key("drawer-backdrop")).
		Absolute().Top(0).Left(0).Right(0).Bottom(0).
		Background(ui.RGBA(0, 0, 0, backdropAlpha))
	if backdrop.Clicked() {
		a.closeLogDrawer()
	}

	// Slide-over drawer panel anchored to right edge
	ui.Column(c.Key("drawer-panel")).
		Absolute().Top(0).Right(-offset).Bottom(0).Width(440).
		Padding(16).Gap(12).
		Background(p.drawerBg).
		BorderWidth(0, 0, 0, 1).BorderColor(p.border).
		Shadow(0, 8, 36, 0, ui.RGBA(0, 0, 0, shadowAlpha)).
		Children(func() {
			// Header
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
					ui.Text(c, cat.LogDrawerTitle()).FontSize(14).FontWeight(700).TextColor(p.text)
					tagPill(c, name, p.accentText, p.accentBg)
				})

				ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
					if actionChip(c.Key("btn-drawer-clear"), p, iconTrash, cat.LogClear(), false).Clicked() {
						logs.Clear()
					}
					if actionChip(c.Key("btn-drawer-close"), p, iconClose, cat.LogClose(), false).Clicked() {
						a.closeLogDrawer()
					}
				})
			})

			// Monospace log stream
			ui.Scroll(c.Key("drawer-scroll")).
				Grow(1).Fill().
				Padding(10).Radius(6).
				Background(p.codeBg).
				BorderWidth(1, 1, 1, 1).BorderColor(p.borderSubtle).
				Children(func() {
					if len(lines) == 0 {
						ui.Text(c, "No logs recorded yet...").FontSize(11).TextColor(p.textDim)
					} else {
						joined := strings.Join(lines, "\n")
						ui.Text(c, joined).FontSize(11).TextColor(p.text).LineHeight(1.4)
					}
				})
		})
}
