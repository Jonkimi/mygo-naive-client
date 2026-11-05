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

	ui.Column(c).
		Width(380).
		Padding(14).Gap(10).
		Background(p.drawerBg).
		BorderWidth(0, 0, 0, 1).BorderColor(p.borderSubtle).
		Children(func() {
			// Header
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
					ui.Text(c, cat.LogDrawerTitle).FontSize(14).FontWeight(700).TextColor(p.text)
					ui.Text(c, name).FontSize(12).TextColor(p.textMuted)
				})

				ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
					if actionChip(c.Key("btn-drawer-clear"), p, iconTrash, cat.LogClear, false).Clicked() {
						logs.Clear()
					}
					if actionChip(c.Key("btn-drawer-close"), p, iconClose, cat.LogClose, false).Clicked() {
						a.activeLogDrawerID = ""
					}
				})
			})

			// Log content
			ui.Column(c).
				Grow(1).Fill().
				Padding(10).Radius(6).
				Background(p.codeBg).
				BorderWidth(1, 1, 1, 1).BorderColor(p.borderSubtle).
				Children(func() {
					if len(lines) == 0 {
						ui.Text(c, "暂无运行日志...").FontSize(11).TextColor(p.textDim)
					} else {
						// Render last lines
						joined := strings.Join(lines, "\n")
						ui.Text(c, joined).FontSize(11).TextColor(p.text).LineHeight(1.4)
					}
				})
		})
}
