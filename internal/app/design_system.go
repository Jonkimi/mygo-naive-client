package app

import "github.com/egoist/mygo/ui"

// Design system typography, spacing, radius, control height, and drawer layout tokens.
// Keep visual rhythm consistent across pages, forms, cards, and slide-over drawers by
// referencing these tokens instead of scattering ad-hoc pixel literals.
const (
	// Typography scale (pt/px)
	dsFontPageTitle    float32 = 17
	dsFontDialogTitle  float32 = 16
	dsFontDrawerTitle  float32 = 15
	dsFontCardTitle    float32 = 14
	dsFontSectionTitle float32 = 13
	dsFontLabel        float32 = 12
	dsFontBody         float32 = 12
	dsFontCaption      float32 = 11
	dsFontMicro        float32 = 10

	dsLineHeightBody float32 = 1.35

	// Spacing scale (4px base grid)
	dsSpaceXS  float32 = 4
	dsSpaceSM  float32 = 6
	dsSpaceMD  float32 = 8
	dsSpaceLG  float32 = 12
	dsSpaceXL  float32 = 16
	dsSpace2XL float32 = 20

	// Corner radius scale
	dsRadiusXS   float32 = 4
	dsRadiusSM   float32 = 6
	dsRadiusMD   float32 = 8
	dsRadiusLG   float32 = 10
	dsRadiusXL   float32 = 12
	dsRadiusPill float32 = 999

	// Control height scale
	dsHeightCompact   float32 = 24
	dsHeightRowAction float32 = 28
	dsHeightControl   float32 = 32

	// Page header rhythm
	dsPageHeaderPadV float32 = 12
	dsPageHeaderPadH float32 = 18

	// Drawer & card layout rhythm
	dsDrawerWidth        float32 = 460
	dsDrawerPadH         float32 = 20
	dsDrawerHeaderPadV   float32 = 14
	dsDrawerBodyPadTop   float32 = 12
	dsDrawerBodyGap      float32 = 10
	dsDrawerFooterPadTop float32 = 12
	dsDrawerFooterPadBot float32 = 14

	dsCardPad  float32 = 12
	dsCardGap  float32 = 8
	dsInsetPad float32 = 10
	dsInsetGap float32 = 8

	// Read-only detail drawer rhythm (shared across node & rule detail drawers)
	dsDetailBodyPadTop float32 = 14
	dsDetailCardPad    float32 = 14
	dsDetailCardGap    float32 = 10
	dsDetailGroupGap   float32 = 8
)

// dsPageHeader renders the unified fixed top header bar across workbench pages.
func dsPageHeader(c *ui.Context, p palette, key string, wrap bool, left, right func()) {
	row := ui.Row(c.Key(key)).
		Padding(dsPageHeaderPadV, dsPageHeaderPadH, dsPageHeaderPadV, dsPageHeaderPadH).
		AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(dsSpaceLG).
		Background(p.surface).
		BorderWidth(0, 0, 1, 0).BorderColor(p.borderSubtle)
	if wrap {
		row.Wrap()
	}
	row.Children(func() {
		if left != nil {
			left()
		}
		if right != nil {
			right()
		}
	})
}

// dsPageTitle renders the unified primary page heading inside dsPageHeader.
func dsPageTitle(c *ui.Context, p palette, title string) {
	ui.Text(c, title).FontSize(dsFontPageTitle).FontWeight(700).TextColor(p.text).NoWrap()
}

// dsHelpPopover renders a standardized anchored help popover for inline '?' and strategy help triggers.
func dsHelpPopover(c *ui.Context, p palette, anchor ui.Element, open *bool, width float32, anchorEdge, panelEdge ui.Anchor, children func()) {
	ui.PopoverBase(c, anchor, open, func(panel ui.Element) {
		panel.Column().
			AttachTo(anchor, anchorEdge, panelEdge).
			Margin(dsSpaceSM, 0, 0, 0).
			Width(width).Padding(dsCardPad).Gap(dsSpaceMD).Radius(dsRadiusLG).
			Background(p.card).Border(1, p.border).
			Shadow(p.popoverShadow()).
			Children(children)
	})
}

// dsModalDialog renders a standardized centered modal dialog for focused import and destructive confirmations.
func dsModalDialog(c *ui.Context, p palette, key string, open *bool, width float32, build func()) {
	ui.DialogBase(c.Key(key), open, func(backdrop, panel ui.Element) {
		backdrop.Background(p.modalBackdrop())
		panel.Column().
			Width(width).
			Padding(dsSpace2XL).Gap(14).
			Radius(dsRadiusXL).Background(p.card).Border(1, p.border).
			Shadow(p.modalShadow()).
			Children(build)
	})
}

// dsDrawerSpec configures a unified 460px right-edge slide-over drawer.
type dsDrawerSpec struct {
	BackdropKey string
	PanelKey    string
	Modal       bool
	OnDismiss   func()
}

// dsDrawerShell renders the standardized right-edge slide-over drawer backdrop, panel geometry,
// transition, border, shadow, and optional modal Escape handling.
func dsDrawerShell(c *ui.Context, p palette, spec dsDrawerSpec, build func()) {
	backdrop := ui.Box(c.Key(spec.BackdropKey)).
		Absolute().Top(0).Left(0).Right(0).Bottom(0).
		Background(p.drawerBackdrop(spec.Modal)).
		Transition(ui.ElementTransition{
			Enter: &ui.Motion{Opacity: 0},
			Exit:  &ui.Motion{Opacity: 0},
		})
	if backdrop.Clicked() && spec.OnDismiss != nil {
		spec.OnDismiss()
	}

	panel := ui.Column(c.Key(spec.PanelKey)).
		Absolute().Top(0).Right(0).Bottom(0).Width(dsDrawerWidth).MaxWidthPercent(100).
		Transition(ui.ElementTransition{
			Enter: &ui.Motion{X: dsDrawerWidth},
			Exit:  &ui.Motion{X: dsDrawerWidth},
		}).
		Background(p.drawerBg).
		BorderWidth(0, 0, 0, 1).BorderColor(p.border).
		Shadow(p.drawerShadow())

	if spec.Modal {
		panel.Modal()
		if spec.OnDismiss != nil && panel.OverlayShortcut(0, ui.KeyEscape) {
			spec.OnDismiss()
		}
	}

	panel.Children(build)
}

// dsDrawerHeader renders the standardized drawer header bar with bottom hairline border.
func dsDrawerHeader(c *ui.Context, p palette, left, right func()) {
	ui.Row(c).
		AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(dsSpaceMD).
		Padding(dsDrawerHeaderPadV, dsDrawerPadH, dsDrawerHeaderPadV, dsDrawerPadH).
		BorderWidth(0, 0, 1, 0).BorderColor(p.borderSubtle).
		Children(func() {
			if left != nil {
				left()
			}
			if right != nil {
				right()
			}
		})
}

// dsDrawerBody renders the standardized scrollable drawer content region.
func dsDrawerBody(c *ui.Context, p palette, key string, scroll *ui.ScrollState, children func()) ui.Element {
	sc := ui.Scroll(c.Key(key)).
		Grow(1).Fill().
		Background(p.surface).
		Padding(dsDrawerBodyPadTop, dsDrawerPadH, dsDrawerPadH, dsDrawerPadH).
		Gap(dsDrawerBodyGap)
	if scroll != nil {
		sc.TrackScroll(scroll)
	}
	return sc.Children(children)
}

// dsDrawerFooter renders the standardized sticky drawer footer bar.
func dsDrawerFooter(c *ui.Context, p palette, left, right func()) {
	ui.Row(c).
		AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(dsSpaceMD).
		Padding(dsDrawerFooterPadTop, dsDrawerPadH, dsDrawerFooterPadBot, dsDrawerPadH).
		Background(p.drawerBg).
		BorderWidth(1, 0, 0, 0).BorderColor(p.borderSubtle).
		Children(func() {
			if left != nil {
				left()
			} else {
				ui.Box(c)
			}
			if right != nil {
				right()
			}
		})
}

// dsDrawerErrorBanner renders a consistent inline error alert inside drawers with a copy button.
func dsDrawerErrorBanner(c *ui.Context, p palette, rowKey, copyBtnKey, errText, copyLabel, copyTooltip string, onCopy func()) {
	if errText == "" {
		return
	}
	ui.Box(c).Padding(dsSpaceLG, dsDrawerPadH, 0, dsDrawerPadH).Children(func() {
		ui.Row(c.Key(rowKey)).
			AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(dsSpaceMD).
			PaddingX(dsSpaceLG).PaddingY(dsSpaceMD).Radius(dsRadiusMD).
			Background(p.redBg).Border(1, p.red.Alpha(0.24)).
			Children(func() {
				ui.Text(c, errText).FontSize(dsFontBody).FontWeight(500).TextColor(p.redText).LineHeight(dsLineHeightBody).Grow(1)
				btnCopy := ui.ButtonBase(c.Key(copyBtnKey)).
					Label(copyBtnKey).
					Padding(2, 6, 2, 6).Radius(dsRadiusXS).
					Background(p.card).Border(1, p.borderSubtle).
					Tooltip(copyTooltip).
					Children(func() {
						ui.Text(c, copyLabel).FontSize(dsFontMicro).TextColor(p.textDim)
					})
				if btnCopy.Clicked() && onCopy != nil {
					onCopy()
				}
			})
	})
}

// dsCard renders a primary form or detail card container.
func dsCard(c *ui.Context, p palette, children func()) {
	ui.Column(c).Gap(dsCardGap).Padding(dsCardPad).Radius(dsRadiusLG).
		Background(p.card).Border(1, p.borderSubtle).
		Children(children)
}

// dsInsetBox renders a secondary nested surface inside a card (e.g., policy bar, picker box).
func dsInsetBox(c *ui.Context, p palette, key string, children func()) {
	box := ui.Column(c)
	if key != "" {
		box = ui.Column(c.Key(key))
	}
	box.Gap(dsInsetGap).Padding(dsInsetPad).Radius(dsRadiusMD).
		Background(p.surface).Border(1, p.borderSubtle).
		Children(children)
}

// dsSectionLabel renders a card section heading using the unified typography scale.
func dsSectionLabel(c *ui.Context, p palette, text string) {
	ui.Text(c, text).FontSize(dsFontSectionTitle).FontWeight(600).TextColor(p.text)
}

// dsHintText renders secondary helper or warning text with unified caption line-height.
func dsHintText(c *ui.Context, text string, col ui.Color) {
	ui.Text(c, text).FontSize(dsFontCaption).TextColor(col).LineHeight(dsLineHeightBody)
}

// dsSettingHeaderRow renders a standardized setting row with a title + right-aligned control on row 1
// and an optional full-width description underneath.
func dsSettingHeaderRow(c *ui.Context, p palette, key, title, desc string, control func()) {
	col := ui.Column(c)
	if key != "" {
		col = ui.Column(c.Key(key))
	}
	col.Gap(dsSpaceXS).Children(func() {
		ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(10).Children(func() {
			ui.Text(c, title).FontSize(dsFontSectionTitle).FontWeight(600).TextColor(p.text).Grow(1).MinWidth(0)
			if control != nil {
				ui.Row(c).Shrink(0).Children(control)
			}
		})
		if desc != "" {
			dsHintText(c, desc, p.textMuted)
		}
	})
}

// dsDetailBody renders the standardized scrollable body for read-only detail drawers.
func dsDetailBody(c *ui.Context, p palette, key string, scroll *ui.ScrollState, children func()) ui.Element {
	return dsDrawerBody(c, p, key, scroll, children).
		Padding(dsDetailBodyPadTop, dsDrawerPadH, dsDrawerPadH, dsDrawerPadH).
		Gap(dsDrawerBodyGap)
}

// dsDetailHeaderEyebrow renders the compact eyebrow status line ("Title · Status") in detail drawer headers.
func dsDetailHeaderEyebrow(c *ui.Context, p palette, title, statusText string, statusCol ui.Color) {
	ui.Row(c).AlignItems(ui.Center).Gap(dsSpaceSM).Children(func() {
		ui.Text(c, title).FontSize(dsFontCaption).FontWeight(600).TextColor(p.textDim).NoWrap()
		ui.Text(c, "·").FontSize(dsFontCaption).TextColor(p.textDim)
		ui.Text(c, statusText).FontSize(dsFontCaption).FontWeight(600).TextColor(statusCol).NoWrap()
	})
}

// dsDetailCard renders a light, well-spaced section card inside detail drawers.
func dsDetailCard(c *ui.Context, p palette, children func()) {
	ui.Column(c).Gap(dsDetailCardGap).Padding(dsDetailCardPad).Radius(dsRadiusLG).
		Background(p.card).Border(1, p.borderSubtle).
		Children(children)
}

// dsDetailSectionTitle renders a restrained card group heading in detail drawers.
func dsDetailSectionTitle(c *ui.Context, p palette, text string) {
	ui.Text(c, text).FontSize(dsFontCaption).FontWeight(600).TextColor(p.textDim)
}

// dsDetailSubTitle renders a subordinate sub-group heading inside a detail card.
func dsDetailSubTitle(c *ui.Context, p palette, text string) {
	ui.Text(c, text).FontSize(dsFontCaption).FontWeight(500).TextColor(p.textMuted)
}

// dsDetailKvGroup groups key-value rows inside a detail card with consistent vertical rhythm.
func dsDetailKvGroup(c *ui.Context, children func()) {
	ui.Column(c).Gap(dsDetailGroupGap).Children(children)
}

// dsDetailKvRow renders a two-column key-value metadata row inside detail drawers.
func dsDetailKvRow(c *ui.Context, p palette, label, value string, mono, tabular bool, valColor ui.Color, tip string) {
	ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(dsSpaceLG).Children(func() {
		ui.Text(c, label).FontSize(dsFontBody).TextColor(p.textMuted).NoWrap().Shrink(0)
		v := ui.Text(c, value).FontSize(dsFontBody).TextColor(valColor).TextAlign(ui.End).
			SingleLine().Ellipsis("…").Shrink(1).MinWidth(0)
		if mono {
			v.Font("monospace").FontSize(dsFontCaption)
		} else {
			v.FontWeight(400)
		}
		if tabular {
			v.FontFeatures("tnum")
		}
		if tip != "" {
			v.Tooltip(tip)
		}
	})
}

// dsDetailMetricTile renders a compact telemetry metric cell inside detail drawers.
func dsDetailMetricTile(c *ui.Context, p palette, label, value string, valColor ui.Color, compactVal bool, tip string) {
	tile := ui.Column(c).Gap(dsSpaceXS).Padding(10, 12, 10, 12).Radius(dsRadiusMD).Background(p.surface)
	if tip != "" {
		tile.Tooltip(tip)
	}
	tile.Children(func() {
		ui.Text(c, label).FontSize(dsFontCaption).TextColor(p.textDim).SingleLine().Ellipsis("…")
		size := dsFontCardTitle
		weight := 600
		if compactVal {
			size = dsFontBody
			weight = 500
		}
		ui.Text(c, value).FontSize(size).FontWeight(weight).FontFeatures("tnum").TextColor(valColor).
			SingleLine().Ellipsis("…")
	})
}

// dsDetailInsetBlock renders a subtle code/URI preview inset block inside detail drawers.
func dsDetailInsetBlock(c *ui.Context, p palette, gap float32, children func()) {
	ui.Column(c).Gap(gap).Padding(10, 12, 10, 12).Radius(dsRadiusMD).
		Background(p.codeBg).Border(1, p.borderSubtle).
		Children(children)
}
