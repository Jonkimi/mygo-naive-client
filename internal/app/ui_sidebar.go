package app

import (
	"fmt"
	"strings"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/sagernet/sing-box/constant"

	"naive-client/internal/config"
	"naive-client/internal/tailnet"
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

			// Multi-engine status pill (sing-box + sidecars)
			a.renderSidebarEngineStatusPill(c, p, collapsed)

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

	hasBadge := tab == TabSettings && (a.localVersion == "" || a.hasUpdate || a.hasXrayUpdate)
	key := fmt.Sprintf("nav-item-%d", tab)
	if collapsed {
		tip := fmt.Sprintf("%s (%s)", label, shortcut)
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
			ui.Text(c, shortcut).FontSize(11).TextColor(p.textDim).NoWrap()
		})

	if !active && btn.Hovered() {
		btn.Background(p.cardHover)
	}
	if btn.Clicked() {
		a.activeTab = tab
	}
}

func (a *app) renderSidebarEngineStatusPill(c *ui.Context, p palette, collapsed bool) {
	cat := a.catalog()
	sbVer := "v1.14.4"
	if constant.Version != "" && constant.Version != "unknown" {
		sbVer = constant.Version
	}

	runningSidecars := a.activeRunningCount()
	needsNaive := false
	needsXray := false
	for _, s := range a.state.Services {
		if s.EffectiveEngine() == config.EngineSidecar {
			if s.EffectiveProtocol() == config.ProtoNaive {
				needsNaive = true
			} else {
				needsXray = true
			}
		}
	}
	missingCore := (needsNaive && a.localVersion == "") || (needsXray && a.localXrayVersion == "")
	hasAnyUpdate := a.hasUpdate || a.hasXrayUpdate

	gwPort := a.state.GatewayPort
	if gwPort <= 0 {
		gwPort = 10809
	}
	gwAddr := fmt.Sprintf("127.0.0.1:%d", gwPort)

	// Gateway dot & badge colors
	gwRunning := (a.gateway != nil && a.state.GatewayEnabled) || runningSidecars > 0
	gwDotColor := p.textDim
	if gwRunning {
		gwDotColor = p.green
	}
	if missingCore || hasAnyUpdate {
		gwDotColor = p.amber
	}

	// Tailnet status
	var ts tailnet.Status
	if a.tailnetMgr != nil {
		ts = a.tailnetMgr.Status()
	}
	tsDotColor := p.textDim
	tsBadgeText := cat.TailnetModeOff()
	tsBadgeFg := p.textDim
	tsBadgeBg := p.elevated
	tsDetail := cat.TailnetStatusOffline()

	if a.state.TailnetEnabled && a.state.TailnetMode != string(tailnet.ModeOff) {
		switch ts.BackendState {
		case "Running":
			tsDotColor = p.green
			tsBadgeFg = p.accentText
			tsBadgeBg = p.accentBg
			if ts.ActiveMode == tailnet.ModeHost {
				tsBadgeText = cat.TailnetModeHost()
			} else {
				tsBadgeText = cat.TailnetModeEmbedded()
			}
			if len(ts.Self.IPs) > 0 {
				tsDetail = ts.Self.IPs[0]
			} else {
				tsDetail = cat.TailnetStatusConnected()
			}
		case "NeedsLogin":
			tsDotColor = p.amber
			tsBadgeText = cat.TailnetStatusNeedsLogin()
			tsBadgeFg = p.amber
			tsBadgeBg = p.amberBg
			tsDetail = cat.TailnetStatusNeedsLogin()
		case "Starting":
			tsDotColor = p.amber
			tsBadgeText = cat.TailnetStarting()
			tsBadgeFg = p.textDim
			tsBadgeBg = p.elevated
			tsDetail = cat.TailnetStarting()
		default:
			tsDotColor = p.textDim
			tsBadgeText = cat.TailnetStatusOffline()
			tsBadgeFg = p.textDim
			tsBadgeBg = p.elevated
			tsDetail = cat.TailnetStatusOffline()
		}
	}

	// Mode handling
	activeMode := a.state.TrafficMode
	if activeMode == "" {
		activeMode = "port"
	}
	var activeModeLabel string
	switch activeMode {
	case "sysproxy":
		activeModeLabel = cat.ModeSysProxy()
	case "tun":
		activeModeLabel = cat.ModeTun()
	default:
		activeModeLabel = cat.ModePortOnly()
	}

	// Rich hover tooltip (showing gateway, tailnet, mode, and each core's version/update status)
	var tipLines []string
	tipLines = append(tipLines, fmt.Sprintf("%s: %s", cat.MasterGateway(), gwAddr))
	tipLines = append(tipLines, fmt.Sprintf("%s: %s (%s)", cat.NavTailnet(), tsDetail, tsBadgeText))
	tipLines = append(tipLines, fmt.Sprintf("%s: %s", cat.TailnetModeLabel(), activeModeLabel))
	tipLines = append(tipLines, fmt.Sprintf("sing-box: %s (%s)", sbVer, cat.TagBuiltin()))
	tipLines = append(tipLines, fmt.Sprintf("Naive: %s", a.naiveStatusText()))
	tipLines = append(tipLines, fmt.Sprintf("Xray: %s", a.xrayStatusText()))
	if hasAnyUpdate {
		tipLines = append(tipLines, cat.UpdateAvailableBadge())
	} else if missingCore {
		tipLines = append(tipLines, cat.EngineMissingSidecar())
	}
	fullTip := strings.Join(tipLines, "\n")

	renderSidebarTooltip := func(anchor ui.Element) {
		ui.TooltipBase(c, anchor, func(tip ui.Element) {
			tip.AttachTo(anchor, ui.AnchorRight, ui.AnchorLeft).
				Margin(0, 0, 0, 8).
				Padding(10, 12, 10, 12).Radius(8).
				Background(ui.RGB(15, 23, 42)). // slate-900
				Border(1, ui.RGB(51, 65, 85)).   // slate-700
				Shadow(0, 8, 20, 0, ui.RGBA(0, 0, 0, 0.35)).
				Children(func() {
					ui.Column(c).Gap(6).Width(210).Children(func() {
						// Section 1: Gateway, Tailnet & Mode
						ui.Column(c).Gap(4).Children(func() {
							// Line 1: Gateway
							ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
								ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
									ui.Box(c).Size(6, 6).Radius(999).Background(gwDotColor)
									ui.Text(c, cat.MasterGateway()).FontSize(11).FontWeight(600).TextColor(ui.RGB(248, 250, 252))
								})
								ui.Text(c, gwAddr).FontSize(11).TextColor(ui.RGB(52, 211, 153)) // emerald-400
							})

							// Line 2: Tailnet
							ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
								ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
									ui.Box(c).Size(6, 6).Radius(999).Background(tsDotColor)
									ui.Text(c, cat.NavTailnet()).FontSize(11).TextColor(ui.RGB(203, 213, 225))
								})
								ui.Text(c, tsDetail).FontSize(11).TextColor(ui.RGB(52, 211, 153))
							})

							// Line 3: Working mode
							ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
								ui.Text(c, cat.TailnetModeLabel()).FontSize(11).TextColor(ui.RGB(148, 163, 184))
								ui.Text(c, activeModeLabel).FontSize(11).FontWeight(600).TextColor(ui.RGB(147, 197, 253)) // blue-300
							})
						})

						// Divider
						ui.Box(c).Fill().Height(1).Background(ui.RGB(51, 65, 85))

						// Section 2: Core versions
						ui.Column(c).Gap(3).Children(func() {
							// sing-box
							ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
								ui.Text(c, "sing-box ("+cat.TagBuiltin()+")").FontSize(11).TextColor(ui.RGB(148, 163, 184))
								ui.Text(c, sbVer).FontSize(11).TextColor(ui.RGB(52, 211, 153))
							})

							// Naive
							ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
								ui.Text(c, "NaiveProxy").FontSize(11).TextColor(ui.RGB(148, 163, 184))
								naiveCol := ui.RGB(226, 232, 240)
								if a.localVersion == "" || a.hasUpdate {
									naiveCol = ui.RGB(251, 191, 36) // amber-400
								}
								ui.Text(c, a.naiveStatusText()).FontSize(11).TextColor(naiveCol)
							})

							// Xray
							ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
								ui.Text(c, "Xray-core").FontSize(11).TextColor(ui.RGB(148, 163, 184))
								xrayCol := ui.RGB(226, 232, 240)
								if a.localXrayVersion == "" || a.hasXrayUpdate {
									xrayCol = ui.RGB(251, 191, 36)
								}
								ui.Text(c, a.xrayStatusText()).FontSize(11).TextColor(xrayCol)
							})

							if hasAnyUpdate {
								ui.Row(c).AlignItems(ui.Center).Justify(ui.End).Children(func() {
									ui.Text(c, cat.UpdateAvailableBadge()).FontSize(10).FontWeight(600).TextColor(ui.RGB(251, 191, 36))
								})
							} else if missingCore {
								ui.Row(c).AlignItems(ui.Center).Justify(ui.End).Children(func() {
									ui.Text(c, cat.EngineMissingSidecar()).FontSize(10).FontWeight(500).TextColor(ui.RGB(251, 191, 36))
								})
							}
						})
					})
				})
		})
	}

	if collapsed {
		card := ui.Column(c.Key("sidebar-engine-pill")).
			Label(cat.EngineStatusPillTitle()).
			Width(collapsedTileSize).Padding(4, 4, 4, 4).Gap(4).Radius(8).
			Background(p.card).Border(1, p.borderSubtle).
			AlignItems(ui.Center).
			Tooltip(fullTip).
			Children(func() {
				// Row 1: Gateway status dot
				gwBtn := ui.ButtonBase(c.Key("collapsed-gw-dot")).
					Label(cat.MasterGateway()).
					Size(24, 18).Radius(4).
					Background(ui.Transparent).
					AlignItems(ui.Center).Justify(ui.Center).
					Children(func() {
						ui.Box(c).Size(7, 7).Radius(999).Background(gwDotColor)
					})
				if gwBtn.Hovered() {
					gwBtn.Background(p.cardHover)
				}
				if gwBtn.Clicked() {
					a.activeTab = TabSettings
				}

				// Divider 1
				ui.Box(c).Width(24).Height(1).Background(p.borderSubtle)

				// Row 2: Tailnet status dot
				tsBtn := ui.ButtonBase(c.Key("collapsed-ts-dot")).
					Label(cat.NavTailnet()).
					Size(24, 18).Radius(4).
					Background(ui.Transparent).
					AlignItems(ui.Center).Justify(ui.Center).
					Children(func() {
						ui.Box(c).Size(7, 7).Radius(999).Background(tsDotColor)
					})
				if tsBtn.Hovered() {
					tsBtn.Background(p.cardHover)
				}
				if tsBtn.Clicked() {
					a.activeTab = TabTailnet
				}

				// Divider 2
				ui.Box(c).Width(24).Height(1).Background(p.borderSubtle)

				// Row 3: Positional 3-bar gray lamp (Left: Port, Center: SysProxy, Right: TUN)
				modeBtn := ui.ButtonBase(c.Key("collapsed-mode-lamp")).
					Label(cat.TailnetModeLabel()).
					Size(28, 16).Radius(4).
					Background(ui.Transparent).
					AlignItems(ui.Center).Justify(ui.Center).
					Children(func() {
						ui.Row(c).AlignItems(ui.Center).Gap(2).Children(func() {
							activeBarColor := p.textMuted
							inactiveBarColor := p.borderSubtle

							// Left: Port
							c1 := inactiveBarColor
							if activeMode == "port" {
								c1 = activeBarColor
							}
							ui.Box(c).Width(7).Height(3).Radius(2).Background(c1)

							// Center: SysProxy
							c2 := inactiveBarColor
							if activeMode == "sysproxy" {
								c2 = activeBarColor
							}
							ui.Box(c).Width(7).Height(3).Radius(2).Background(c2)

							// Right: TUN
							c3 := inactiveBarColor
							if activeMode == "tun" {
								c3 = activeBarColor
							}
							ui.Box(c).Width(7).Height(3).Radius(2).Background(c3)
						})
					})
				if modeBtn.Hovered() {
					modeBtn.Background(p.cardHover)
				}
				if modeBtn.Clicked() {
					nextMode := "sysproxy"
					if activeMode == "sysproxy" {
						nextMode = "tun"
					} else if activeMode == "tun" {
						nextMode = "port"
					}
					_ = a.setTrafficMode(nextMode)
				}
			})
		renderSidebarTooltip(card)
		return
	}

	// Expanded state: unified 3-row white card
	card := ui.Column(c.Key("sidebar-engine-pill")).
		Label(cat.EngineStatusPillTitle()).
		Padding(6, 8, 6, 8).Gap(4).Radius(8).
		Background(p.card).Border(1, p.borderSubtle).
		Tooltip(fullTip).
		Children(func() {
			// Row 1: Gateway status + port
			row1 := ui.Row(c.Key("expanded-gw-row")).
				Label(cat.MasterGateway()).
				AlignItems(ui.Center).Justify(ui.SpaceBetween).
				Padding(2, 4, 2, 4).Radius(6).
				Background(ui.Transparent).
				Children(func() {
					ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
						ui.Box(c).Size(7, 7).Radius(999).Background(gwDotColor)
						ui.Text(c, cat.MasterGateway()).FontSize(11).FontWeight(600).TextColor(p.text).NoWrap()
						ui.Text(c, fmt.Sprintf(":%d", gwPort)).FontSize(11).TextColor(p.textMuted).NoWrap()
					})

					if missingCore {
						tagPill(c, cat.EngineMissingSidecar(), p.amber, p.amberBg)
					} else if hasAnyUpdate {
						tagPill(c, cat.UpdateAvailableBadge(), p.amber, p.amberBg)
					} else if runningSidecars > 0 {
						tagPill(c, fmt.Sprintf("%d", runningSidecars), p.green, p.greenBg)
					}
				})
			if row1.Hovered() {
				row1.Background(p.cardHover)
			}
			if row1.Clicked() {
				a.activeTab = TabSettings
			}

			// Divider 1
			ui.Box(c).Fill().Height(1).Background(p.borderSubtle)

			// Row 2: Tailnet (组网) status
			row2 := ui.Row(c.Key("expanded-ts-row")).
				Label(cat.NavTailnet()).
				AlignItems(ui.Center).Justify(ui.SpaceBetween).
				Padding(2, 4, 2, 4).Radius(6).
				Background(ui.Transparent).
				Children(func() {
					ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
						ui.Box(c).Size(7, 7).Radius(999).Background(tsDotColor)
						ui.Text(c, cat.NavTailnet()).FontSize(11).FontWeight(600).TextColor(p.text).NoWrap()
						ui.Text(c, tsDetail).FontSize(11).TextColor(p.textDim).NoWrap()
					})
					tagPill(c, tsBadgeText, tsBadgeFg, tsBadgeBg)
				})
			if row2.Hovered() {
				row2.Background(p.cardHover)
			}
			if row2.Clicked() {
				a.activeTab = TabTailnet
			}

			// Divider 2
			ui.Box(c).Fill().Height(1).Background(p.borderSubtle)

			// Row 3: 3-Way Segmented Working Mode (Left: Port, Center: SysProxy, Right: TUN)
			// White card background, selected option has a neutral gray pill background
			ui.Row(c.Key("expanded-mode-row")).
				AlignItems(ui.Center).Justify(ui.SpaceBetween).
				Padding(2, 0, 2, 0).Gap(3).
				Children(func() {
					renderModeBtn := func(modeID, label string) {
						isSelected := activeMode == modeID
						bg := ui.Transparent
						fg := p.textDim
						weight := 400
						if isSelected {
							bg = p.elevated
							fg = p.text
							weight = 600
						}

						btn := ui.Row(c.Key("btn-mode-" + modeID)).
							Grow(1).Justify(ui.Center).AlignItems(ui.Center).
							Height(22).Radius(4).
							Background(bg).
							Children(func() {
								ui.Text(c, label).FontSize(10).FontWeight(weight).TextColor(fg).NoWrap()
							})
						if !isSelected && btn.Hovered() {
							btn.Background(p.cardHover)
						}
						if btn.Clicked() {
							_ = a.setTrafficMode(modeID)
						}
					}

					renderModeBtn("port", cat.ModePortOnly())
					renderModeBtn("sysproxy", cat.ModeSysProxy())
					renderModeBtn("tun", cat.ModeTun())
				})
		})
	renderSidebarTooltip(card)
}

func (a *app) naiveStatusText() string {
	if a.localVersion != "" {
		return a.localVersion
	}
	return a.catalog().CoreNotInstalled()
}

func (a *app) xrayStatusText() string {
	if a.localXrayVersion != "" {
		return a.localXrayVersion
	}
	return a.catalog().XrayNotInstalled()
}
