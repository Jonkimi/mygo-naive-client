package app

import (
	"fmt"

	"github.com/egoist/mygo/ui"
)

func (a *app) renderSidebar(c *ui.Context, p palette) {
	cat := a.catalog()

	ui.Column(c).
		Width(160).
		Padding(12).Gap(8).
		Background(p.sidebarBg).
		BorderWidth(0, 1, 0, 0).BorderColor(p.borderSubtle).
		Children(func() {
			// Brand header
			ui.Row(c).AlignItems(ui.Center).Gap(10).PaddingX(6).PaddingY(8).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Justify(ui.Center).
					Size(30, 30).Radius(8).Background(p.accentBg).
					Children(func() {
						ui.Image(c, iconBrandFor(p.dark)).Size(16, 16)
					})
				ui.Text(c, "NaiveClient").FontSize(15).FontWeight(700).TextColor(p.text)
			})

			// Navigation items
			ui.Column(c).Gap(4).Children(func() {
				a.renderNavItem(c, p, TabNodes, cat.NavNodes, "⌘1")
				a.renderNavItem(c, p, TabRouting, cat.NavRouting, "⌘2")
				a.renderNavItem(c, p, TabInsights, cat.NavInsights, "⌘3")
				a.renderNavItem(c, p, TabTailnet, cat.NavTailnet, "⌘4")
				a.renderNavItem(c, p, TabSettings, cat.NavSettings, "⌘5")
			})

			// Spacer
			ui.Box(c).Grow(1)

			// Bottom core status capsule
			a.renderCoreStatusCapsule(c, p)
		})
}

func (a *app) renderNavItem(c *ui.Context, p palette, tab TabID, label, shortcut string) {
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

	btn := ui.Row(c.Key(fmt.Sprintf("nav-item-%d", tab))).
		AlignItems(ui.Center).Justify(ui.SpaceBetween).
		PaddingX(10).PaddingY(8).Radius(6).
		Background(bg).
		Children(func() {
			ui.Text(c, label).FontSize(13).FontWeight(weight).TextColor(fg)
			ui.Text(c, shortcut).FontSize(11).TextColor(p.textDim)
		})

	if btn.Clicked() {
		a.activeTab = tab
	}
}

func (a *app) renderCoreStatusCapsule(c *ui.Context, p palette) {
	ui.Column(c).
		Padding(10).Radius(8).Gap(6).
		Background(p.surface).
		BorderWidth(1, 1, 1, 1).BorderColor(p.borderSubtle).
		Children(func() {
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
				ui.Text(c, "NaiveProxy").FontSize(11).FontWeight(600).TextColor(p.textDim)
				if actionChip(c.Key("btn-check-update"), p, iconRefresh, "检查更新", a.checkingUpdate || a.updatingCore).Clicked() {
					a.triggerCheckUpdate(true)
				}
			})

			if a.localVersion == "" {
				statusBadge(c, "未安装 naive 核心", p.amber, p.amberBg)
			} else {
				statusBadge(c, "本地核心 "+a.localVersion, p.green, p.greenBg)
			}

			if a.hasUpdate && a.latestRelease != nil {
				tagPill(c, "新版本 "+a.latestRelease.TagName, p.amber, p.amberBg)
			}

			if a.localVersion == "" || a.hasUpdate || a.updatingCore {
				updLabel := "下载并无感更新"
				if a.localVersion == "" {
					updLabel = "一键下载核心"
				}
				if a.updatingCore {
					updLabel = "更新中..."
				} else if a.latestRelease != nil && a.hasUpdate {
					updLabel = fmt.Sprintf("无感更新至 %s", a.latestRelease.TagName)
				}
				if primaryPillButton(c.Key("btn-seamless-update"), p, iconDownload, updLabel, p.accent, a.updatingCore).Clicked() {
					a.triggerSeamlessUpdate()
				}
			}
		})
}
