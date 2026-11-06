package app

import (
	"fmt"

	"github.com/egoist/mygo/ui"
)

func (a *app) renderSidebar(c *ui.Context, p palette) {
	cat := a.catalog()
	collapsed := a.state.SidebarCollapsed

	var width float32 = 190
	var paddingH float32 = 10
	if collapsed {
		width = 62
		paddingH = 6
	}

	ui.Column(c.Key("sidebar")).
		Width(width).
		Padding(10, paddingH, 10, paddingH).Gap(8).
		Background(p.sidebarBg).
		BorderWidth(0, 1, 0, 0).BorderColor(p.borderSubtle).
		Children(func() {
			// Brand header with window control clearance
			a.renderSidebarHeader(c, p, collapsed)

			// Navigation items
			ui.Column(c).Gap(4).Children(func() {
				a.renderNavItem(c, p, TabNodes, iconNavNodes, cat.NavNodes(), "⌘1", collapsed)
				a.renderNavItem(c, p, TabRouting, iconNavRouting, cat.NavRouting(), "⌘2", collapsed)
				a.renderNavItem(c, p, TabInsights, iconNavInsights, cat.NavInsights(), "⌘3", collapsed)
				a.renderNavItem(c, p, TabTailnet, iconNavTailnet, cat.NavTailnet(), "⌘4", collapsed)
				a.renderNavItem(c, p, TabSettings, iconNavSettings, cat.NavSettings(), "⌘5", collapsed)
			})

			// Spacer
			ui.Box(c).Grow(1)

			// Dedicated collapse/expand toggle button at bottom of navigation
			a.renderSidebarToggleButton(c, p, collapsed)

			// Bottom core status capsule
			a.renderCoreStatusCapsule(c, p, collapsed)
		})
}

func (a *app) renderSidebarHeader(c *ui.Context, p palette, collapsed bool) {
	if collapsed {
		ui.Column(c).AlignItems(ui.Center).Padding(28, 0, 4, 0).Children(func() {
			ui.Row(c).AlignItems(ui.Center).Justify(ui.Center).
				Size(36, 36).Radius(8).Background(p.accentBg).
				Children(func() {
					ui.Image(c, iconBrandFor(p.dark)).Size(18, 18)
				})
		})
		return
	}

	ui.Row(c).AlignItems(ui.Center).Padding(30, 4, 6, 4).Children(func() {
		ui.Row(c).AlignItems(ui.Center).Gap(9).Children(func() {
			ui.Row(c).AlignItems(ui.Center).Justify(ui.Center).
				Size(30, 30).Radius(8).Background(p.accentBg).
				Children(func() {
					ui.Image(c, iconBrandFor(p.dark)).Size(16, 16)
				})
			ui.Text(c, "NaiveClient").FontSize(15).FontWeight(700).TextColor(p.text)
		})
	})
}

func (a *app) renderSidebarToggleButton(c *ui.Context, p palette, collapsed bool) {
	cat := a.catalog()

	if collapsed {
		btn := ui.ButtonBase(c.Key("btn-sidebar-toggle-bottom")).
			Label(cat.SidebarExpand()).
			Size(44, 34).Radius(8).
			Background(p.surface).Border(1, p.borderSubtle).
			AlignItems(ui.Center).Justify(ui.Center).
			Tooltip(cat.SidebarExpand() + " (⌘B)").
			Children(func() {
				ui.Icon(c, iconSidebarExpand).Size(16, 16).TextColor(p.textMuted)
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
		PaddingX(10).PaddingY(7).Radius(6).
		Background(ui.Transparent).
		Tooltip(cat.SidebarCollapse() + " (⌘B)").
		Children(func() {
			ui.Row(c).AlignItems(ui.Center).Gap(9).Children(func() {
				ui.Icon(c, iconSidebarCollapse).Size(15, 15).TextColor(p.textDim)
				ui.Text(c, cat.SidebarCollapse()).FontSize(12).TextColor(p.textMuted)
			})
			ui.Text(c, "⌘B").FontSize(11).TextColor(p.textDim)
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

	key := fmt.Sprintf("nav-item-%d", tab)
	if collapsed {
		btn := ui.ButtonBase(c.Key(key)).
			Label(label).
			Size(44, 38).Radius(8).
			Background(bg).
			AlignItems(ui.Center).Justify(ui.Center).
			Tooltip(fmt.Sprintf("%s (%s)", label, shortcut)).
			Children(func() {
				if icon != nil {
					ui.Icon(c, icon).Size(18, 18).TextColor(fg)
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
		PaddingX(10).PaddingY(8).Radius(6).
		Background(bg).
		Children(func() {
			ui.Row(c).AlignItems(ui.Center).Gap(9).Children(func() {
				if icon != nil {
					ui.Icon(c, icon).Size(16, 16).TextColor(fg)
				}
				ui.Text(c, label).FontSize(13).FontWeight(weight).TextColor(fg)
			})
			ui.Text(c, shortcut).FontSize(11).TextColor(p.textDim)
		})

	if !active && btn.Hovered() {
		btn.Background(p.cardHover)
	}
	if btn.Clicked() {
		a.activeTab = tab
	}
}

func (a *app) renderCoreStatusCapsule(c *ui.Context, p palette, collapsed bool) {
	cat := a.catalog()

	if collapsed {
		dotColor := p.green
		statusTip := "NaiveProxy: " + cat.CoreLocal() + a.localVersion
		if a.localVersion == "" {
			dotColor = p.amber
			statusTip = "NaiveProxy: " + cat.CoreNotInstalled()
		} else if a.hasUpdate && a.latestRelease != nil {
			dotColor = p.amber
			statusTip = fmt.Sprintf("NaiveProxy: %s (新版本 %s)", a.localVersion, a.latestRelease.TagName)
		}

		btn := ui.ButtonBase(c.Key("btn-core-status-collapsed")).
			Size(44, 36).Radius(8).
			Background(p.surface).Border(1, p.borderSubtle).
			AlignItems(ui.Center).Justify(ui.Center).
			Tooltip(statusTip).
			Children(func() {
				ui.Box(c).Size(10, 10).Radius(999).Background(dotColor)
			})
		if btn.Hovered() {
			btn.Background(p.cardHover)
		}
		if btn.Clicked() {
			a.triggerCheckUpdate(true)
		}
		return
	}

	ui.Column(c).
		Padding(8).Radius(8).Gap(6).
		Background(p.surface).
		BorderWidth(1, 1, 1, 1).BorderColor(p.borderSubtle).
		Children(func() {
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
				ui.Text(c, "NaiveProxy").FontSize(11).FontWeight(600).TextColor(p.textDim)

				checkBtn := ui.ButtonBase(c.Key("btn-check-update")).
					Height(22).PaddingX(6).Radius(4).
					Background(p.elevated).Border(1, p.borderSubtle).
					Disabled(a.checkingUpdate || a.updatingCore)
				if !a.checkingUpdate && !a.updatingCore && checkBtn.Hovered() {
					checkBtn.Background(p.cardHover)
				}
				checkBtn.Children(func() {
					ui.Row(c).AlignItems(ui.Center).Gap(3).TextColor(p.textMuted).Children(func() {
						if iconRefresh != nil {
							ui.Icon(c, iconRefresh).Size(11, 11)
						}
						ui.Text(c, cat.CheckUpdates()).FontSize(10).FontWeight(500)
					})
				})
				if checkBtn.Clicked() {
					a.triggerCheckUpdate(true)
				}
			})

			if a.localVersion == "" {
				statusBadge(c, cat.CoreNotInstalled(), p.amber, p.amberBg)
			} else {
				statusBadge(c, cat.CoreLocal()+a.localVersion, p.green, p.greenBg)
			}

			if a.hasUpdate && a.latestRelease != nil {
				tagPill(c, "新版本 "+a.latestRelease.TagName, p.amber, p.amberBg)
			}

			if a.localVersion == "" || a.hasUpdate || a.updatingCore {
				updLabel := cat.InstallCore()
				if a.updatingCore {
					updLabel = cat.Updating()
				} else if a.latestRelease != nil && a.hasUpdate {
					updLabel = fmt.Sprintf("无感更新至 %s", a.latestRelease.TagName)
				}
				if primaryPillButton(c.Key("btn-seamless-update"), p, iconDownload, updLabel, p.accent, a.updatingCore).Clicked() {
					a.triggerSeamlessUpdate()
				}
			}
		})
}
