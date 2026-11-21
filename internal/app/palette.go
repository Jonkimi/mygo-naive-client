package app

import (
	"strings"

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
	switchOff    ui.Color

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
	switchOff:    ui.RGB(209, 213, 219),
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
	switchOff:    ui.RGB(51, 65, 85),
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

// applyToTheme synchronizes MyGo's global ui.Theme tokens with this palette
// so all built-in widgets (TextInput, TextArea, Switch, Combobox, etc.) share
// the same visual language as custom palette-styled containers.
func (p palette) applyToTheme(t *ui.Theme) {
	t.Background = p.card
	t.Surface = p.surface
	t.SurfaceHover = p.cardHover
	t.SurfacePressed = p.switchOff
	t.Border = p.border
	t.Text = p.text
	t.TextMuted = p.textMuted
	t.Accent = p.accent
	t.Danger = p.red
	t.Warning = p.amber
	t.Success = p.green
}

func (p palette) navActiveColor() ui.Color {
	if !p.dark {
		return p.accent
	}
	return p.accentText
}

func statusBadge(c *ui.Context, label string, fg, bg ui.Color) {
	ui.Row(c).AlignItems(ui.Center).Gap(6).Shrink(0).
		PaddingX(9).PaddingY(4).Radius(999).Background(bg).
		Children(func() {
			ui.Box(c).Size(7, 7).Radius(999).Background(fg)
			ui.Text(c, label).FontSize(11).FontWeight(600).TextColor(fg)
		})
}

func tagPill(c *ui.Context, label string, fg, bg ui.Color) {
	ui.Row(c).AlignItems(ui.Center).Shrink(0).
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
		fg = p.textDim.Alpha(0.6)
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
		fg = p.textDim.Alpha(0.6)
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

type segmentedOption struct {
	Label       string
	A11yLabel   string
	ActiveColor ui.Color
}

func segmentedOptionsFromStrings(labels []string) []segmentedOption {
	opts := make([]segmentedOption, len(labels))
	for i, lbl := range labels {
		opts[i] = segmentedOption{Label: lbl}
	}
	return opts
}

func renderSegmentedTrack(c *ui.Context, p palette, selected *int, opts []segmentedOption, compact bool) bool {
	if selected == nil || len(opts) == 0 {
		return false
	}

	parts := ui.SegmentedBase(c, selected, len(opts))
	track := parts.Track

	trackRadius := float32(8)
	segPadV, segPadH, segRadius := float32(4), float32(10), float32(6)
	fontSize := float32(12)
	shBlur, shAlpha := float32(2), float32(0.08)
	if compact {
		trackRadius = 6
		segPadV, segPadH, segRadius = 2, 8, 4
		fontSize = 11
		shBlur, shAlpha = 1, 0.06
	}

	track.AlignItems(ui.Stretch).Padding(2).Gap(2).Radius(trackRadius)
	if p.dark {
		track.Background(p.codeBg)
	} else {
		track.Background(p.elevated)
	}

	cur := *selected
	track.Children(func() {
		for i, opt := range opts {
			opt := opt
			active := cur == i
			a11y := opt.A11yLabel
			if a11y == "" {
				a11y = opt.Label
			}
			seg := parts.Segment(i).
				Label(a11y).
				Padding(segPadV, segPadH, segPadV, segPadH).
				Radius(segRadius)

			fg := p.textMuted
			weight := 400
			if active {
				weight = 600
				if opt.ActiveColor.A > 0 {
					fg = opt.ActiveColor
				} else {
					fg = p.text
				}
				if p.dark {
					seg.Background(p.elevated).
						Shadow(0, 1, 2, 0, ui.RGBA(0, 0, 0, 0.28))
				} else {
					seg.Background(p.card).
						Shadow(0, 1, shBlur, 0, ui.RGBA(0, 0, 0, shAlpha))
				}
			} else if seg.Hovered() {
				fg = p.text
				if p.dark {
					seg.Background(p.card)
				} else {
					seg.Background(ui.RGBA(255, 255, 255, 0.55))
				}
			}

			seg.Children(func() {
				ui.Text(c, opt.Label).FontSize(fontSize).FontWeight(weight).TextColor(fg).SingleLine()
			})
		}
	})
	return track.Changed()
}

// segmentedControl renders a standard (~28px) palette-driven segmented control for page headers,
// drawer top tabs, Settings general rows, and Logs filter bars.
func segmentedControl(c *ui.Context, p palette, selected *int, labels []string) bool {
	return renderSegmentedTrack(c, p, selected, segmentedOptionsFromStrings(labels), false)
}

// segmentedOptions renders a standard (~28px) palette-driven segmented control with custom a11y labels and active colors.
func segmentedOptions(c *ui.Context, p palette, selected *int, opts []segmentedOption) bool {
	return renderSegmentedTrack(c, p, selected, opts, false)
}

// compactSegmentedControl renders a compact (~24px) palette-driven segmented control for embedded card tiles and form enums.
func compactSegmentedControl(c *ui.Context, p palette, selected *int, labels []string) bool {
	return renderSegmentedTrack(c, p, selected, segmentedOptionsFromStrings(labels), true)
}

// compactSegmentedOptions renders a compact (~24px) palette-driven segmented control supporting custom a11y labels and active colors.
func compactSegmentedOptions(c *ui.Context, p palette, selected *int, opts []segmentedOption) bool {
	return renderSegmentedTrack(c, p, selected, opts, true)
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

type comboboxOption struct {
	Value string
	Label string
}

// labeledCombobox builds an editable text input with a dropdown list of preset
// candidates. Clicking the field or trailing chevron opens all options; typing
// filters options while still preserving custom comma-separated input on blur.
func labeledCombobox(c *ui.Context, p palette, key, label, toggleLabel string, value *string, handle *ui.Handle, placeholder string, options []comboboxOption) ui.Element {
	var inp ui.Element
	ui.Column(c).Gap(5).Children(func() {
		ui.Text(c, label).FontSize(12).FontWeight(500).TextColor(p.text)
		ui.Column(c).Children(func() {
			t := c.Theme()
			cb := ui.ComboboxBase(c.Key(key), value)
			inp = cb.Input

			borderCol := t.Border
			if handle != nil && handle.Focused(c) {
				borderCol = t.Accent
			} else if inp.Hovered() {
				borderCol = p.textDim
			}
			inp.Label(label).
				Placeholder(placeholder).
				Padding(t.Space(1.5), t.Space(2.5)).
				PaddingEnd(t.Space(7)).
				Radius(t.Radius).
				Background(t.Surface).
				Border(1, borderCol)
			if handle != nil {
				inp.Bind(handle)
			}

			shown := options
			if cb.Filtering() {
				q := strings.ToLower(strings.TrimSpace(*value))
				if q != "" {
					var starts, contains []comboboxOption
					for _, opt := range options {
						if opt.Value == "" {
							continue
						}
						lv := strings.ToLower(opt.Value)
						switch {
						case strings.HasPrefix(lv, q):
							starts = append(starts, opt)
						case strings.Contains(lv, q):
							contains = append(contains, opt)
						}
					}
					shown = append(starts, contains...)
				}
			}

			cb.Popup(func(panel ui.Element) {
				panel.Margin(4, 0, 0, 0).
					Padding(4).
					Radius(t.Radius+2).
					Background(p.card).
					Border(1, p.border).
					Shadow(0, 6, 20, 0, ui.RGBA(0, 0, 0, 0.18)).
					Children(func() {
						cur := strings.TrimSpace(*value)
						for _, opt := range shown {
							item := cb.Item(opt.Value).
								PaddingX(10).PaddingY(6).
								Radius(t.Radius)
							isCurrent := opt.Value == cur
							switch {
							case item.Highlighted():
								item.Background(p.accent).TextColor(t.AccentText)
							case isCurrent:
								item.Background(p.elevated)
							}
							item.Children(func() {
								fg := p.text
								if item.Highlighted() {
									fg = t.AccentText
								} else if opt.Value == "" {
									fg = p.textMuted
								}
								ui.Text(c, opt.Label).FontSize(12).TextColor(fg).NoWrap()
							})
						}
					})
			})

			chevIcon := iconChevronDown
			if cb.Open() {
				chevIcon = iconChevronUp
			}
			toggleBtn := ui.ButtonBase(c.Key(key+"-toggle")).
				KeepFocus().
				Absolute().Top(0).Bottom(0).Right(2).Width(26).
				AlignItems(ui.Center).Justify(ui.Center).
				Label(toggleLabel).
				Children(func() {
					ui.Icon(c, chevIcon).Size(12, 12).TextColor(p.textMuted)
				})
			if toggleBtn.Clicked() {
				if cb.Open() {
					cb.SetOpen(false)
				} else {
					inp.Focus()
					cb.SetOpen(true)
				}
			}

			if chosen, ok := cb.Chosen(); ok {
				*value = chosen
			}
		})
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
		if ui.Text(c, label).FontSize(12).TextColor(p.text).Clicked() {
			*value = !*value
			changed = true
		}
		if ui.Switch(c.Key(key), value).Label(label).Changed() {
			changed = true
		}
	})
	return changed
}

func statusDot(c *ui.Context, col ui.Color) {
	ui.Box(c).Size(7, 7).Radius(999).Background(col).Shrink(0)
}

func hollowStatusDot(c *ui.Context, borderCol ui.Color) {
	ui.Box(c).Size(7, 7).Radius(999).Border(1.5, borderCol).Shrink(0)
}

func editorSectionCard(c *ui.Context, p palette, children func()) {
	ui.Column(c).Gap(10).Padding(14).Radius(10).
		Background(p.card).Border(1, p.borderSubtle).
		Children(children)
}

func quietToolbarButton(c *ui.Context, p palette, iconSVG *ui.SVG, label string, dimmed bool) ui.Element {
	fg := p.text
	if dimmed {
		fg = p.textDim
	}
	btn := ui.ButtonBase(c).
		Height(32).PaddingX(10).Radius(8).
		Background(p.card).Border(1, p.border)
	if !dimmed && btn.Hovered() {
		btn.Background(p.cardHover)
	}
	return btn.Children(func() {
		ui.Row(c).AlignItems(ui.Center).Gap(5).TextColor(fg).Children(func() {
			if iconSVG != nil {
				iconCol := p.textMuted
				if dimmed {
					iconCol = p.textDim
				}
				ui.Icon(c, iconSVG).Size(13, 13).TextColor(iconCol)
			}
			ui.Text(c, label).FontSize(12).FontWeight(500).NoWrap()
		})
	})
}

func quietToolbarIconButton(c *ui.Context, p palette, iconSVG *ui.SVG, label string, active bool) ui.Element {
	bg := p.card
	fg := p.textMuted
	if active {
		bg = p.cardHover
		fg = p.text
	}
	btn := ui.ButtonBase(c).
		Label(label).
		Size(32, 32).Radius(8).
		Background(bg).Border(1, p.border)
	if btn.Hovered() {
		btn.Background(p.cardHover)
		fg = p.text
	}
	return btn.Children(func() {
		ui.Icon(c, iconSVG).Size(15, 15).TextColor(fg)
	})
}

func quietRowIconButton(c *ui.Context, p palette, iconSVG *ui.SVG, label string, dimmed, active bool) ui.Element {
	fg := p.textMuted
	bg := ui.Transparent
	if active {
		fg = p.text
		bg = p.elevated
	} else if dimmed {
		fg = p.textDim.Alpha(0.45)
	}
	btn := ui.ButtonBase(c).
		Label(label).
		Size(28, 28).Radius(6).
		Background(bg)
	if !dimmed && btn.Hovered() {
		fg = p.text
		btn.Background(p.elevated)
	}
	return btn.Children(func() {
		ui.Icon(c, iconSVG).Size(14, 14).TextColor(fg)
	})
}

func compactStripButton(c *ui.Context, p palette, a11yLabel, text string, fg ui.Color) ui.Element {
	btn := ui.ButtonBase(c).
		Padding(4, 8, 4, 8).Radius(6).
		Background(p.elevated)
	if a11yLabel != "" {
		btn.Label(a11yLabel)
	}
	if btn.Hovered() {
		btn.Background(p.cardHover)
	}
	return btn.Children(func() {
		ui.Text(c, text).FontSize(11).FontWeight(500).TextColor(fg).NoWrap()
	})
}

func styleMenuPopoverPanel(panel, anchor ui.Element, p palette, width float32) {
	panel.Column().
		AttachTo(anchor, ui.AnchorBottomEnd, ui.AnchorTopEnd).
		Margin(4, 0, 0, 0).
		Width(width).Padding(4).Radius(10).
		Background(p.card).Border(1, p.border).
		Shadow(0, 10, 28, 0, ui.RGBA(0, 0, 0, 0.18))
}

func popoverMenuItem(c *ui.Context, p palette, label string, fg ui.Color, dimmed, danger bool) ui.Element {
	textCol := fg
	if dimmed {
		textCol = p.textDim.Alpha(0.5)
	}
	btn := ui.ButtonBase(c).
		FillWidth().Height(30).PaddingX(10).Radius(6).
		Justify(ui.Start).AlignItems(ui.Center).
		Background(ui.Transparent)
	if danger && dimmed {
		btn.Disabled(true)
	}
	if !dimmed && btn.Hovered() {
		if danger {
			btn.Background(p.redBg)
		} else {
			btn.Background(p.elevated)
		}
	}
	return btn.Children(func() {
		ui.Text(c, label).FontSize(12).FontWeight(500).TextColor(textCol).NoWrap()
	})
}

