package app

import (
	"github.com/egoist/mygo/ui"
)

type palette struct {
	dark bool

	bg        ui.Color
	sidebarBg ui.Color
	surface   ui.Color
	card      ui.Color
	cardHover ui.Color
	elevated  ui.Color
	drawerBg  ui.Color
	codeBg    ui.Color

	border       ui.Color
	borderSubtle ui.Color

	text      ui.Color
	textMuted ui.Color
	textDim   ui.Color

	accent     ui.Color
	accentBg   ui.Color
	accentText ui.Color

	green   ui.Color
	greenBg ui.Color
	amber   ui.Color
	amberBg ui.Color
	red     ui.Color
	redBg   ui.Color
}

var lightPalette = palette{
	dark:         false,
	bg:           ui.RGB(242, 244, 248),
	sidebarBg:    ui.RGB(242, 244, 248),
	surface:      ui.RGB(248, 250, 252),
	card:         ui.RGB(255, 255, 255),
	cardHover:    ui.RGB(245, 247, 250),
	elevated:     ui.RGB(241, 243, 247),
	drawerBg:     ui.RGB(255, 255, 255),
	codeBg:       ui.RGB(242, 244, 248),
	border:       ui.RGB(224, 228, 235),
	borderSubtle: ui.RGB(235, 238, 244),
	text:         ui.RGB(20, 24, 33),
	textMuted:    ui.RGB(94, 102, 117),
	textDim:      ui.RGB(145, 153, 168),
	accent:       ui.RGB(37, 99, 235),
	accentBg:     ui.RGB(239, 246, 255),
	accentText:   ui.RGB(29, 78, 216),
	green:        ui.RGB(22, 163, 74),
	greenBg:      ui.RGB(220, 252, 231),
	amber:        ui.RGB(217, 119, 6),
	amberBg:      ui.RGB(254, 243, 199),
	red:          ui.RGB(220, 38, 38),
	redBg:        ui.RGB(254, 226, 226),
}

var darkPalette = palette{
	dark:         true,
	bg:           ui.RGB(11, 13, 19),
	sidebarBg:    ui.RGB(11, 13, 19),
	surface:      ui.RGB(17, 20, 29),
	card:         ui.RGB(24, 28, 40),
	cardHover:    ui.RGB(32, 38, 54),
	elevated:     ui.RGB(30, 35, 50),
	drawerBg:     ui.RGB(26, 31, 44),
	codeBg:       ui.RGB(14, 16, 24),
	border:       ui.RGB(38, 44, 62),
	borderSubtle: ui.RGB(28, 33, 47),
	text:         ui.RGB(241, 245, 249),
	textMuted:    ui.RGB(148, 163, 184),
	textDim:      ui.RGB(100, 116, 139),
	accent:       ui.RGB(59, 130, 246),
	accentBg:     ui.RGBA(59, 130, 246, 0.15),
	accentText:   ui.RGB(147, 197, 253),
	green:        ui.RGB(34, 197, 94),
	greenBg:      ui.RGBA(34, 197, 94, 0.15),
	amber:        ui.RGB(245, 158, 11),
	amberBg:      ui.RGBA(245, 158, 11, 0.15),
	red:          ui.RGB(239, 68, 68),
	redBg:        ui.RGBA(239, 68, 68, 0.15),
}

func paletteFor(t *ui.Theme) palette {
	if t != nil && t.Dark {
		return darkPalette
	}
	return lightPalette
}

func statusBadge(c *ui.Context, label string, fg, bg ui.Color) {
	ui.Row(c).AlignItems(ui.Center).Gap(6).
		PaddingX(9).PaddingY(4).Radius(999).Background(bg).
		Children(func() {
			ui.Box(c).Size(7, 7).Radius(999).Background(fg)
			ui.Text(c, label).FontSize(11).FontWeight(600).TextColor(fg)
		})
}

func tagPill(c *ui.Context, label string, fg, bg ui.Color) {
	ui.Row(c).AlignItems(ui.Center).
		PaddingX(8).PaddingY(3).Radius(6).Background(bg).
		Children(func() {
			ui.Text(c, label).FontSize(11).FontWeight(500).TextColor(fg)
		})
}

func actionChip(c *ui.Context, p palette, iconSVG *ui.SVG, label string, disabled bool) ui.Element {
	fg := p.text
	bg := p.elevated
	if disabled {
		fg = p.textDim
		bg = p.elevated.Alpha(0.5)
	}
	btn := ui.ButtonBase(c).
		Height(28).PaddingX(10).Radius(6).
		Background(bg).
		Border(1, p.borderSubtle)
	if !disabled && btn.Hovered() {
		btn.Background(p.cardHover)
	}
	return btn.Children(func() {
		ui.Row(c).AlignItems(ui.Center).Gap(5).TextColor(fg).Children(func() {
			if iconSVG != nil {
				ui.Icon(c, iconSVG).Size(13, 13)
			}
			ui.Text(c, label).FontSize(12).FontWeight(500)
		})
	})
}

func subtleActionChip(c *ui.Context, p palette, iconSVG *ui.SVG, label string, disabled bool) ui.Element {
	fg := p.textMuted
	bg := ui.Transparent
	if disabled {
		fg = p.textDim
	}
	btn := ui.ButtonBase(c).
		Height(28).PaddingX(8).Radius(6).
		Background(bg).
		Disabled(disabled)
	if !disabled && btn.Hovered() {
		fg = p.text
		btn.Background(p.elevated)
	}
	return btn.Children(func() {
		ui.Row(c).AlignItems(ui.Center).Gap(5).TextColor(fg).Children(func() {
			if iconSVG != nil {
				ui.Icon(c, iconSVG).Size(13, 13)
			}
			ui.Text(c, label).FontSize(12).FontWeight(500)
		})
	})
}

func dangerActionChip(c *ui.Context, p palette, iconSVG *ui.SVG, label string, disabled bool) ui.Element {
	fg := p.textMuted
	bg := ui.Transparent
	if disabled {
		fg = p.textDim
	}
	btn := ui.ButtonBase(c).
		Height(28).PaddingX(8).Radius(6).
		Background(bg).
		Disabled(disabled)
	if !disabled && btn.Hovered() {
		fg = p.red
		btn.Background(p.redBg)
	}
	return btn.Children(func() {
		ui.Row(c).AlignItems(ui.Center).Gap(5).TextColor(fg).Children(func() {
			if iconSVG != nil {
				ui.Icon(c, iconSVG).Size(13, 13)
			}
			ui.Text(c, label).FontSize(12).FontWeight(500)
		})
	})
}

func primaryPillButton(c *ui.Context, p palette, iconSVG *ui.SVG, label string, bg ui.Color, disabled bool) ui.Element {
	fg := ui.RGB(255, 255, 255)
	fillBg := bg
	if disabled {
		fg = fg.Alpha(0.55)
		fillBg = bg.Alpha(0.5)
	}
	btn := ui.ButtonBase(c).
		Height(32).PaddingX(13).Radius(8).
		Background(fillBg).
		Disabled(disabled)
	if !disabled && btn.Hovered() {
		btn.Background(bg.Alpha(0.88))
	}
	return btn.Children(func() {
		ui.Row(c).AlignItems(ui.Center).Gap(6).TextColor(fg).Children(func() {
			if iconSVG != nil {
				ui.Icon(c, iconSVG).Size(14, 14)
			}
			ui.Text(c, label).FontSize(12).FontWeight(600)
		})
	})
}

func segmentedControl(c *ui.Context, _ palette, selected *int, labels []string) bool {
	return ui.Segmented(c, selected, labels...).Changed()
}

func labeledInput(c *ui.Context, p palette, key, label string, value *string, placeholder string) ui.Element {
	var inp ui.Element
	ui.Column(c).Gap(5).Children(func() {
		ui.Text(c, label).FontSize(12).FontWeight(500).TextColor(p.text)
		inp = ui.TextInput(c.Key(key), value).
			Label(label).
			Placeholder(placeholder)
	})
	return inp
}

func labeledTextArea(c *ui.Context, p palette, key, label string, value *string, placeholder string, minLines, maxLines int) ui.Element {
	var area ui.Element
	ui.Column(c).Gap(5).Children(func() {
		ui.Text(c, label).FontSize(12).FontWeight(500).TextColor(p.text)
		area = ui.TextArea(c.Key(key), value).
			Lines(minLines, maxLines).
			Label(label).
			Placeholder(placeholder)
	})
	return area
}

func switchRow(c *ui.Context, p palette, key, label string, value *bool) bool {
	changed := false
	ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Children(func() {
		ui.Text(c, label).FontSize(12).TextColor(p.text)
		if ui.Switch(c.Key(key), value).Label(label).Changed() {
			changed = true
		}
	})
	return changed
}

