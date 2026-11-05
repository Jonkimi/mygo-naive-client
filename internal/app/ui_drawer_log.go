package app

import (
	"strings"

	"github.com/egoist/mygo/ui"
)

func (a *app) renderLogDrawer(c *ui.Context, p palette) {
	if a.activeLogDrawerID == "" {
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

	// Backdrop (click to dismiss drawer)
	backdrop := ui.Box(c.Key("drawer-backdrop")).
		Absolute().Top(0).Left(0).Right(0).Bottom(0).
		Background(ui.RGBA(0, 0, 0, 0.25))
	if backdrop.Clicked() {
		a.activeLogDrawerID = ""
	}

	// Slide-over drawer panel anchored to right edge
	ui.Column(c.Key("drawer-panel")).
		Absolute().Top(0).Right(0).Bottom(0).Width(440).
		Padding(16).Gap(12).
		Background(p.drawerBg).
		BorderWidth(0, 0, 0, 1).BorderColor(p.border).
		Shadow(0, 8, 36, 0, ui.RGBA(0, 0, 0, 0.4)).
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
						a.activeLogDrawerID = ""
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
