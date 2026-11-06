package app

import (
	"fmt"
	"time"

	"github.com/egoist/mygo/ui"
)

const collapsedTileSize float32 = 36

func (a *app) renderSidebar(c *ui.Context, p palette) {
	cat := a.catalog()
	collapsed := a.state.SidebarCollapsed

	var targetWidth float32 = 190
	if collapsed {
		targetWidth = 56
	}

	sidebar := ui.Column(c.Key("sidebar"))
	if collapsed {
		sidebar.AlignItems(ui.Center)
	}
	anim := ui.Animation{Spring: ui.SpringOptions{Duration: 220 * time.Millisecond, Bounce: 0.04}}
	width := sidebar.AnimateTo("width", targetWidth, anim)

	sidebar.
		Width(width).
		Padding(10, 10, 10, 10).Gap(8).
		Clip().
		Background(p.sidebarBg).
		BorderWidth(0, 1, 0, 0).BorderColor(p.borderSubtle).
		Children(func() {
			// Brand header with window control clearance
			a.renderSidebarHeader(c, p, collapsed)

			// Navigation items
			navCol := ui.Column(c).Gap(4)
			if collapsed {
				navCol.AlignItems(ui.Center)
			}
			navCol.Children(func() {
				a.renderNavItem(c, p, TabNodes, iconNavNodes, cat.NavNodes(), "⌘1", collapsed)
				a.renderNavItem(c, p, TabRouting, iconNavRouting, cat.NavRouting(), "⌘2", collapsed)
				a.renderNavItem(c, p, TabInsights, iconNavInsights, cat.NavInsights(), "⌘3", collapsed)
				a.renderNavItem(c, p, TabTailnet, iconNavTailnet, cat.NavTailnet(), "⌘4", collapsed)
				a.renderNavItem(c, p, TabSettings, iconNavSettings, cat.NavSettings(), "⌘,", collapsed)
			})

			// Spacer
			ui.Box(c).Grow(1)

			// Dedicated collapse/expand toggle button at bottom of navigation
			a.renderSidebarToggleButton(c, p, collapsed)
		})
}

func (a *app) renderSidebarHeader(c *ui.Context, p palette, collapsed bool) {
	if collapsed {
		ui.Column(c).AlignItems(ui.Center).Padding(4, 0, 6, 0).Children(func() {
			ui.Row(c).AlignItems(ui.Center).Justify(ui.Center).
				Size(collapsedTileSize, collapsedTileSize).Radius(8).Background(p.accentBg).
				Children(func() {
					ui.Image(c, iconBrandFor(p.dark)).Size(18, 18)
				})
		})
		return
	}

	ui.Row(c).AlignItems(ui.Center).Padding(4, 2, 6, 2).Children(func() {
		ui.Row(c).AlignItems(ui.Center).Gap(10).Children(func() {
			ui.Row(c).AlignItems(ui.Center).Justify(ui.Center).
				Size(collapsedTileSize, collapsedTileSize).Radius(8).Background(p.accentBg).
				Children(func() {
					ui.Image(c, iconBrandFor(p.dark)).Size(18, 18)
				})
			ui.Text(c, "NaiveClient").FontSize(15).FontWeight(700).TextColor(p.text).NoWrap()
		})
	})
}

func (a *app) renderSidebarToggleButton(c *ui.Context, p palette, collapsed bool) {
	cat := a.catalog()

	if collapsed {
		btn := ui.ButtonBase(c.Key("btn-sidebar-toggle-bottom")).
			Label(cat.SidebarExpand()).
			Size(collapsedTileSize, collapsedTileSize).Radius(8).
			Background(ui.Transparent).
			AlignItems(ui.Center).Justify(ui.Center).
			Tooltip(cat.SidebarExpand() + " (⌘B)").
			Children(func() {
				ui.Icon(c, iconSidebarExpand).Size(16, 16).TextColor(p.textDim)
			})
		if btn.Hovered() {
			btn.Background(p.cardHover)
		}
		if btn.Clicked() {
			a.toggleSidebar()
		}
		return
	}

	btn := ui.Row(c.Key("btn-sidebar-toggle-bottom")).
		Label(cat.SidebarCollapse()).
		AlignItems(ui.Center).Justify(ui.SpaceBetween).
		Height(collapsedTileSize).PaddingX(10).Radius(8).
		Background(ui.Transparent).
		Tooltip(cat.SidebarCollapse() + " (⌘B)").
		Children(func() {
			ui.Row(c).AlignItems(ui.Center).Gap(9).Children(func() {
				ui.Icon(c, iconSidebarCollapse).Size(16, 16).TextColor(p.textDim)
				ui.Text(c, cat.SidebarCollapse()).FontSize(12).TextColor(p.textMuted).NoWrap()
			})
			ui.Text(c, "⌘B").FontSize(11).TextColor(p.textDim).NoWrap()
		})
	if btn.Hovered() {
		btn.Background(p.cardHover)
	}
	if btn.Clicked() {
		a.toggleSidebar()
	}
}

func (a *app) renderNavItem(c *ui.Context, p palette, tab TabID, icon *ui.SVG, label, shortcut string, collapsed bool) {
	active := a.activeTab == tab
	bg := ui.Transparent
	fg := p.textMuted
	weight := 400
	if active {
		bg = p.elevated
		fg = p.accentText
		if !p.dark {
			fg = p.accent
		}
		weight = 600
	}

	hasBadge := tab == TabSettings && (a.localVersion == "" || a.hasUpdate)
	isUpcoming := tab == TabTailnet
	if !active && isUpcoming {
		fg = p.textDim
	}
	key := fmt.Sprintf("nav-item-%d", tab)
	if collapsed {
		tip := fmt.Sprintf("%s (%s)", label, shortcut)
		if isUpcoming {
			tip = fmt.Sprintf("%s · %s (%s)", label, a.catalog().BadgeSoon(), shortcut)
		}
		btn := ui.ButtonBase(c.Key(key)).
			Label(label).
			Size(collapsedTileSize, collapsedTileSize).Radius(8).
			Background(bg).
			AlignItems(ui.Center).Justify(ui.Center).
			Tooltip(tip).
			Children(func() {
				if icon != nil {
					ui.Icon(c, icon).Size(16, 16).TextColor(fg)
				}
				if hasBadge {
					ui.Box(c).Absolute().Top(6).Right(6).Size(6, 6).Radius(999).Background(p.amber)
				}
			})
		if !active && btn.Hovered() {
			btn.Background(p.cardHover)
		}
		if btn.Clicked() {
			a.activeTab = tab
		}
		return
	}

	btn := ui.Row(c.Key(key)).
		AlignItems(ui.Center).Justify(ui.SpaceBetween).
		Height(collapsedTileSize).PaddingX(10).Radius(8).
		Background(bg).
		Children(func() {
			ui.Row(c).AlignItems(ui.Center).Gap(9).Children(func() {
				if icon != nil {
					ui.Icon(c, icon).Size(16, 16).TextColor(fg)
				}
				ui.Text(c, label).FontSize(13).FontWeight(weight).TextColor(fg).NoWrap()
				if hasBadge {
					ui.Box(c).Size(6, 6).Radius(999).Background(p.amber)
				}
			})
			if isUpcoming {
				tagPill(c, a.catalog().BadgeSoon(), p.textDim, p.elevated)
			} else {
				ui.Text(c, shortcut).FontSize(11).TextColor(p.textDim).NoWrap()
			}
		})

	if !active && btn.Hovered() {
		btn.Background(p.cardHover)
	}
	if btn.Clicked() {
		a.activeTab = tab
	}
}
