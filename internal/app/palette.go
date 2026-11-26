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

	accent        ui.Color
	accentHover   ui.Color
	accentPressed ui.Color
	accentBg      ui.Color
	accentText    ui.Color

	green     ui.Color
	greenBg   ui.Color
	greenText ui.Color
	amber     ui.Color
	amberBg   ui.Color
	amberText ui.Color
	red       ui.Color
	redBg     ui.Color
	redText   ui.Color
	redFill   ui.Color
}

var lightPalette = palette{
	dark:          false,
	bg:            ui.RGB(242, 244, 248),
	sidebarBg:     ui.RGB(242, 244, 248),
	surface:       ui.RGB(248, 250, 252),
	card:          ui.RGB(255, 255, 255),
	cardHover:     ui.RGB(245, 247, 250),
	elevated:      ui.RGB(241, 243, 247),
	drawerBg:      ui.RGB(255, 255, 255),
	codeBg:        ui.RGB(242, 244, 248),
	border:        ui.RGB(209, 215, 224),
	borderSubtle:  ui.RGB(229, 233, 240),
	switchOff:     ui.RGB(184, 191, 204),
	text:          ui.RGB(20, 24, 33),
	textMuted:     ui.RGB(76, 85, 101),
	textDim:       ui.RGB(100, 109, 124),
	accent:        ui.RGB(37, 99, 235),
	accentHover:   ui.RGB(29, 78, 216),
	accentPressed: ui.RGB(30, 64, 175),
	accentBg:      ui.RGB(239, 246, 255),
	accentText:    ui.RGB(29, 78, 216),
	green:         ui.RGB(22, 163, 74),
	greenBg:       ui.RGB(240, 253, 244),
	greenText:     ui.RGB(21, 128, 61),
	amber:         ui.RGB(217, 119, 6),
	amberBg:       ui.RGB(255, 251, 235),
	amberText:     ui.RGB(180, 83, 9),
	red:           ui.RGB(220, 38, 38),
	redBg:         ui.RGB(254, 245, 245),
	redText:       ui.RGB(220, 38, 38),
	redFill:       ui.RGB(220, 38, 38),
}

var darkPalette = palette{
	dark:          true,
	bg:            ui.RGB(11, 13, 19),
	sidebarBg:     ui.RGB(11, 13, 19),
	surface:       ui.RGB(17, 20, 29),
	card:          ui.RGB(24, 28, 40),
	cardHover:     ui.RGB(32, 38, 54),
	elevated:      ui.RGB(30, 35, 50),
	drawerBg:      ui.RGB(26, 31, 44),
	codeBg:        ui.RGB(14, 16, 24),
	border:        ui.RGB(48, 56, 78),
	borderSubtle:  ui.RGB(36, 42, 60),
	switchOff:     ui.RGB(64, 78, 102),
	text:          ui.RGB(241, 245, 249),
	textMuted:     ui.RGB(158, 172, 193),
	textDim:       ui.RGB(132, 146, 169),
	accent:        ui.RGB(37, 99, 235),
	accentHover:   ui.RGB(59, 130, 246),
	accentPressed: ui.RGB(29, 78, 216),
	accentBg:      ui.RGBA(59, 130, 246, 0.16),
	accentText:    ui.RGB(147, 197, 253),
	green:         ui.RGB(34, 197, 94),
	greenBg:       ui.RGBA(34, 197, 94, 0.16),
	greenText:     ui.RGB(34, 197, 94),
	amber:         ui.RGB(245, 158, 11),
	amberBg:       ui.RGBA(245, 158, 11, 0.16),
	amberText:     ui.RGB(245, 158, 11),
	red:           ui.RGB(248, 113, 113),
	redBg:         ui.RGBA(239, 68, 68, 0.16),
	redText:       ui.RGB(248, 113, 113),
	redFill:       ui.RGB(220, 38, 38),
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
	t.SurfacePressed = p.elevated
	t.Border = p.border
	t.Text = p.text
	t.TextMuted = p.textMuted
	t.Accent = p.accent
	t.AccentHover = p.accentHover
	t.AccentPressed = p.accentPressed
	t.AccentText = ui.RGB(255, 255, 255)
	t.Danger = p.redFill
	t.Warning = p.amber
	t.Success = p.green
	if p.dark {
		t.Focus = p.accentHover.Alpha(0.65)
		t.Selection = p.accentHover.Alpha(0.35)
		t.Inverse = lightPalette.card
		t.InverseText = lightPalette.text
	} else {
		t.Focus = p.accent.Alpha(0.55)
		t.Selection = p.accent.Alpha(0.22)
		t.Inverse = darkPalette.card
		t.InverseText = darkPalette.text
	}
	t.Radius = dsRadiusMD
	t.Spacing = dsSpaceXS
	t.FontSize = dsFontBody
}

func (p palette) navActiveColor() ui.Color {
	if !p.dark {
		return p.accent
	}
	return p.accentText
}

func (p palette) popoverShadow() (float32, float32, float32, float32, ui.Color) {
	if p.dark {
		return 0, 12, 32, 0, ui.RGBA(0, 0, 0, 0.52)
	}
	return 0, 10, 28, 0, ui.RGBA(0, 0, 0, 0.18)
}

func (p palette) dropdownShadow() (float32, float32, float32, float32, ui.Color) {
	if p.dark {
		return 0, 8, 24, 0, ui.RGBA(0, 0, 0, 0.48)
	}
	return 0, 6, 20, 0, ui.RGBA(0, 0, 0, 0.16)
}

func (p palette) modalShadow() (float32, float32, float32, float32, ui.Color) {
	if p.dark {
		return 0, 16, 44, 0, ui.RGBA(0, 0, 0, 0.62)
	}
	return 0, 12, 36, 0, ui.RGBA(0, 0, 0, 0.28)
}

func (p palette) drawerShadow() (float32, float32, float32, float32, ui.Color) {
	if p.dark {
		return 0, 8, 40, 0, ui.RGBA(0, 0, 0, 0.58)
	}
	return 0, 8, 36, 0, ui.RGBA(0, 0, 0, 0.30)
}

func (p palette) modalBackdrop() ui.Color {
	if p.dark {
		return ui.RGBA(0, 0, 0, 0.60)
	}
	return ui.RGBA(0, 0, 0, 0.42)
}

func (p palette) drawerBackdrop(modal bool) ui.Color {
	if p.dark {
		if modal {
			return ui.RGBA(0, 0, 0, 0.55)
		}
		return ui.RGBA(0, 0, 0, 0.45)
	}
	if modal {
		return ui.RGBA(0, 0, 0, 0.34)
	}
	return ui.RGBA(0, 0, 0, 0.26)
}

func tagPill(c *ui.Context, label string, fg, bg ui.Color) {
	ui.Row(c).AlignItems(ui.Center).Shrink(0).
		PaddingX(dsSpaceMD).PaddingY(3).Radius(dsRadiusSM).Background(bg).
		Children(func() {
			ui.Text(c, label).FontSize(dsFontCaption).FontWeight(500).TextColor(fg)
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
		Height(dsHeightRowAction).PaddingX(10).Radius(dsRadiusSM).
		Background(bg).
		Border(1, p.borderSubtle).
		Disabled(disabled).DimDisabled(false)
	if !disabled {
		if btn.Pressed() {
			btn.Background(p.borderSubtle)
		} else if btn.Hovered() {
			btn.Background(p.cardHover)
		}
	}
	return btn.Children(func() {
		ui.Row(c).AlignItems(ui.Center).Gap(5).TextColor(fg).Children(func() {
			if iconSVG != nil {
				ui.Icon(c, iconSVG).Size(13, 13)
			}
			ui.Text(c, label).FontSize(dsFontBody).FontWeight(500)
		})
	})
}

func styledActionChip(c *ui.Context, p palette, iconSVG *ui.SVG, label string, fg, bg, hoverFg, hoverBg ui.Color, disabled, compact bool) ui.Element {
	if disabled {
		fg = p.textDim.Alpha(0.6)
	}
	height := dsHeightRowAction
	padX := dsSpaceMD
	gap := float32(5)
	iconSize := float32(13)
	fontSize := dsFontBody
	if compact {
		height = dsHeightCompact
		padX = 7
		gap = 4
		iconSize = 12
		fontSize = dsFontCaption
	}
	btn := ui.ButtonBase(c).
		Height(height).PaddingX(padX).Radius(dsRadiusSM).
		Background(bg).
		Disabled(disabled).DimDisabled(false)
	if !disabled {
		if btn.Pressed() {
			fg = hoverFg
			btn.Background(p.borderSubtle)
		} else if btn.Hovered() {
			fg = hoverFg
			btn.Background(hoverBg)
		}
	}
	return btn.Children(func() {
		ui.Row(c).AlignItems(ui.Center).Gap(gap).TextColor(fg).Children(func() {
			if iconSVG != nil {
				ui.Icon(c, iconSVG).Size(iconSize, iconSize)
			}
			ui.Text(c, label).FontSize(fontSize).FontWeight(500)
		})
	})
}

func subtleActionChip(c *ui.Context, p palette, iconSVG *ui.SVG, label string, disabled bool) ui.Element {
	return styledActionChip(c, p, iconSVG, label, p.textMuted, ui.Transparent, p.text, p.elevated, disabled, false)
}

func compactSubtleActionChip(c *ui.Context, p palette, iconSVG *ui.SVG, label string, disabled bool) ui.Element {
	return styledActionChip(c, p, iconSVG, label, p.textMuted, ui.Transparent, p.text, p.elevated, disabled, true)
}

func compactDangerActionChip(c *ui.Context, p palette, iconSVG *ui.SVG, label string) ui.Element {
	return styledActionChip(c, p, iconSVG, label, p.redText, p.redBg, p.redText, p.red.Alpha(0.22), false, true)
}

func dangerActionChip(c *ui.Context, p palette, iconSVG *ui.SVG, label string, disabled bool) ui.Element {
	return styledActionChip(c, p, iconSVG, label, p.textMuted, ui.Transparent, p.redText, p.redBg, disabled, false)
}

func primaryPillButton(c *ui.Context, p palette, iconSVG *ui.SVG, label string, bg ui.Color, disabled bool) ui.Element {
	fg := ui.RGB(255, 255, 255)
	fillBg := bg
	if disabled {
		fg = fg.Alpha(0.55)
		fillBg = bg.Alpha(0.5)
	}
	btn := ui.ButtonBase(c).
		Height(dsHeightControl).PaddingX(13).Radius(dsRadiusMD).
		Background(fillBg).
		Disabled(disabled).DimDisabled(false)
	if !disabled {
		if btn.Pressed() {
			if bg == p.accent {
				btn.Background(p.accentPressed)
			} else {
				btn.Background(bg.Alpha(0.76))
			}
		} else if btn.Hovered() {
			if bg == p.accent {
				btn.Background(p.accentHover)
			} else {
				btn.Background(bg.Alpha(0.88))
			}
		}
	}
	return btn.Children(func() {
		ui.Row(c).AlignItems(ui.Center).Gap(dsSpaceSM).TextColor(fg).Children(func() {
			if iconSVG != nil {
				ui.Icon(c, iconSVG).Size(14, 14)
			}
			ui.Text(c, label).FontSize(dsFontBody).FontWeight(600)
		})
	})
}

func amberOutlineButton(c *ui.Context, p palette, iconSVG *ui.SVG, label string, disabled bool) ui.Element {
	fg := p.amberText
	borderCol := p.amber.Alpha(0.45)
	bg := p.card
	if disabled {
		fg = p.amberText.Alpha(0.5)
		borderCol = p.amber.Alpha(0.25)
	}
	btn := ui.ButtonBase(c).
		Height(dsHeightControl).PaddingX(dsSpaceLG).Radius(dsRadiusMD).
		Background(bg).Border(1, borderCol).
		Disabled(disabled).DimDisabled(false)
	if !disabled {
		if btn.Pressed() {
			btn.Background(p.amber.Alpha(0.18))
		} else if btn.Hovered() {
			btn.Background(p.amberBg).Border(1, p.amber.Alpha(0.65))
		}
	}
	return btn.Children(func() {
		ui.Row(c).AlignItems(ui.Center).Gap(dsSpaceSM).TextColor(fg).Children(func() {
			if iconSVG != nil {
				ui.Icon(c, iconSVG).Size(14, 14)
			}
			ui.Text(c, label).FontSize(dsFontBody).FontWeight(600).NoWrap()
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

type segmentedStyle uint8

const (
	segmentedStandard segmentedStyle = iota
	segmentedCompact
	segmentedFullWidth
)

func renderSegmentedTrack(c *ui.Context, p palette, selected *int, opts []segmentedOption, style segmentedStyle) bool {
	if selected == nil || len(opts) == 0 {
		return false
	}

	parts := ui.SegmentedBase(c, selected, len(opts))
	track := parts.Track

	trackPad, trackGap, trackRadius := float32(3), float32(3), dsRadiusMD
	segPadV, segPadH, segRadius := float32(5), float32(10), dsRadiusSM
	fontSize := dsFontBody
	shBlur, shAlpha := float32(2), float32(0.08)
	if style == segmentedCompact {
		trackPad, trackGap, trackRadius = 2, 2, dsRadiusSM
		segPadV, segPadH, segRadius = 3.5, dsSpaceMD, dsRadiusXS
		fontSize = dsFontCaption
		shBlur, shAlpha = 1, 0.06
	}

	track.AlignItems(ui.Stretch).Padding(trackPad).Gap(trackGap).Radius(trackRadius)
	if style == segmentedFullWidth {
		track.FillWidth()
	}
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
			if style == segmentedFullWidth {
				seg.Grow(1).Basis(0).MinWidth(0)
			}

			fg := p.textMuted
			const weight = 500
			if active {
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
			} else if seg.Pressed() {
				fg = p.text
				seg.Background(p.borderSubtle)
			} else if seg.Hovered() {
				fg = p.text
				if p.dark {
					seg.Background(p.card)
				} else {
					seg.Background(ui.RGBA(255, 255, 255, 0.55))
				}
			}

			seg.Children(func() {
				txt := ui.Text(c, opt.Label).FontSize(fontSize).FontWeight(weight).TextColor(fg).SingleLine()
				if style == segmentedFullWidth {
					txt.Ellipsis("…")
				}
			})
		}
	})
	return track.Changed()
}

// segmentedControl renders a standard (~30px) palette-driven segmented control for page headers,
// drawer top tabs, Settings general rows, and Logs filter bars.
func segmentedControl(c *ui.Context, p palette, selected *int, labels []string) bool {
	return renderSegmentedTrack(c, p, selected, segmentedOptionsFromStrings(labels), segmentedStandard)
}

// segmentedOptions renders a standard (~30px) palette-driven segmented control with custom a11y labels and active colors.
func segmentedOptions(c *ui.Context, p palette, selected *int, opts []segmentedOption) bool {
	return renderSegmentedTrack(c, p, selected, opts, segmentedStandard)
}

// compactSegmentedControl renders a compact (~24px) palette-driven segmented control for embedded card tiles and form enums.
func compactSegmentedControl(c *ui.Context, p palette, selected *int, labels []string) bool {
	return renderSegmentedTrack(c, p, selected, segmentedOptionsFromStrings(labels), segmentedCompact)
}

// compactSegmentedOptions renders a compact (~24px) palette-driven segmented control supporting custom a11y labels and active colors.
func compactSegmentedOptions(c *ui.Context, p palette, selected *int, opts []segmentedOption) bool {
	return renderSegmentedTrack(c, p, selected, opts, segmentedCompact)
}

// fullWidthSegmentedOptions renders an equal-width standard (~30px) segmented control for prominent form choices.
func fullWidthSegmentedOptions(c *ui.Context, p palette, selected *int, opts []segmentedOption) bool {
	return renderSegmentedTrack(c, p, selected, opts, segmentedFullWidth)
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

// comboboxField renders an editable text input with a dropdown list of preset candidates.
// It returns the outer container element, the underlying input element, and whether a
// preset option was chosen in the current frame.
func comboboxField(c *ui.Context, p palette, key, label, toggleLabel string, value *string, handle *ui.Handle, placeholder string, options []comboboxOption) (container ui.Element, inp ui.Element, chosen bool) {
	container = ui.Column(c).Children(func() {
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
					ll := strings.ToLower(opt.Label)
					switch {
					case strings.HasPrefix(lv, q) || strings.HasPrefix(ll, q):
						starts = append(starts, opt)
					case strings.Contains(lv, q) || strings.Contains(ll, q):
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
				Shadow(p.dropdownShadow()).
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

		if cVal, ok := cb.Chosen(); ok {
			*value = cVal
			chosen = true
		}
	})
	return container, inp, chosen
}

// labeledCombobox builds an editable text input with a dropdown list of preset
// candidates. Clicking the field or trailing chevron opens all options; typing
// filters options while still preserving custom input on blur.
func labeledCombobox(c *ui.Context, p palette, key, label, toggleLabel string, value *string, handle *ui.Handle, placeholder string, options []comboboxOption) ui.Element {
	var inp ui.Element
	ui.Column(c).Gap(5).Children(func() {
		ui.Text(c, label).FontSize(12).FontWeight(500).TextColor(p.text)
		_, inp, _ = comboboxField(c, p, key, label, toggleLabel, value, handle, placeholder, options)
	})
	return inp
}

// labeledComboboxChanged renders labeledCombobox and reports true when the user edits the text
// or chooses a preset from the dropdown list.
func labeledComboboxChanged(c *ui.Context, p palette, key, label, toggleLabel string, value *string, handle *ui.Handle, placeholder string, options []comboboxOption) bool {
	var inp ui.Element
	var chosen bool
	ui.Column(c).Gap(5).Children(func() {
		ui.Text(c, label).FontSize(12).FontWeight(500).TextColor(p.text)
		_, inp, chosen = comboboxField(c, p, key, label, toggleLabel, value, handle, placeholder, options)
	})
	return chosen || inp.Changed()
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
	dsCard(c, p, children)
}

func quietToolbarButton(c *ui.Context, p palette, iconSVG *ui.SVG, label string, dimmed bool) ui.Element {
	fg := p.text
	if dimmed {
		fg = p.textDim
	}
	btn := ui.ButtonBase(c).
		Height(dsHeightControl).PaddingX(10).Radius(dsRadiusMD).
		Background(p.card).Border(1, p.border).
		AccessDisabled(dimmed)
	if !dimmed {
		if btn.Pressed() {
			btn.Background(p.elevated)
		} else if btn.Hovered() {
			btn.Background(p.cardHover)
		}
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
			ui.Text(c, label).FontSize(dsFontBody).FontWeight(500).NoWrap()
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
		Size(dsHeightControl, dsHeightControl).Radius(dsRadiusMD).
		Background(bg).Border(1, p.border)
	if btn.Pressed() {
		btn.Background(p.elevated)
		fg = p.text
	} else if btn.Hovered() {
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
		Size(dsHeightRowAction, dsHeightRowAction).Radius(dsRadiusSM).
		Background(bg).
		AccessDisabled(dimmed)
	if !dimmed {
		if btn.Pressed() {
			fg = p.text
			btn.Background(p.borderSubtle)
		} else if btn.Hovered() {
			fg = p.text
			btn.Background(p.elevated)
		}
	}
	return btn.Children(func() {
		ui.Icon(c, iconSVG).Size(14, 14).TextColor(fg)
	})
}

func compactStripButton(c *ui.Context, p palette, a11yLabel, text string, fg ui.Color) ui.Element {
	btn := ui.ButtonBase(c).
		Padding(4, 8, 4, 8).Radius(dsRadiusSM).
		Background(p.elevated)
	if a11yLabel != "" {
		btn.Label(a11yLabel)
	}
	if btn.Pressed() {
		btn.Background(p.borderSubtle)
	} else if btn.Hovered() {
		btn.Background(p.cardHover)
	}
	return btn.Children(func() {
		ui.Text(c, text).FontSize(dsFontCaption).FontWeight(500).TextColor(fg).NoWrap()
	})
}

func styleMenuPopoverPanel(panel, anchor ui.Element, p palette, width float32) {
	panel.Column().
		AttachTo(anchor, ui.AnchorBottomEnd, ui.AnchorTopEnd).
		Margin(dsSpaceXS, 0, 0, 0).
		Width(width).Padding(dsSpaceXS).Radius(dsRadiusLG).
		Background(p.card).Border(1, p.border).
		Shadow(p.popoverShadow())
}

func popoverMenuItem(c *ui.Context, p palette, label string, fg ui.Color, dimmed, danger bool) ui.Element {
	textCol := fg
	if dimmed {
		textCol = p.textDim.Alpha(0.5)
	}
	btn := ui.ButtonBase(c).
		FillWidth().Height(30).PaddingX(10).Radius(dsRadiusSM).
		Justify(ui.Start).AlignItems(ui.Center).
		Background(ui.Transparent)
	if danger && dimmed {
		btn.Disabled(true).DimDisabled(false)
	} else if dimmed {
		btn.AccessDisabled(true)
	}
	if !dimmed {
		if btn.Pressed() {
			if danger {
				btn.Background(p.red.Alpha(0.24))
			} else {
				btn.Background(p.borderSubtle)
			}
		} else if btn.Hovered() {
			if danger {
				btn.Background(p.redBg)
			} else {
				btn.Background(p.elevated)
			}
		}
	}
	return btn.Children(func() {
		ui.Text(c, label).FontSize(dsFontBody).FontWeight(500).TextColor(textCol).NoWrap()
	})
}

