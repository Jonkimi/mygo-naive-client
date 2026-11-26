package app

import (
	"fmt"
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
			navCol := ui.Column(c).Fill().Gap(4)
			if collapsed {
				navCol.AlignItems(ui.Center)
			}
			navCol.Children(func() {
				a.renderNavItem(c, p, TabNodes, iconNavNodes, cat.NavNodes(), "⌘1", collapsed)
				a.renderNavItem(c, p, TabRouting, iconNavRouting, cat.NavRouting(), "⌘2", collapsed)
				a.renderNavItem(c, p, TabInsights, iconNavInsights, cat.NavInsights(), "⌘3", collapsed)
				a.renderNavItem(c, p, TabTailnet, iconNavTailnet, cat.NavTailnet(), "⌘4", collapsed)
				a.renderNavItem(c, p, TabCloudflare, iconNavCloudflare, cat.NavCloudflare(), "⌘5", collapsed)
				a.renderNavItem(c, p, TabLogs, iconTerminal, cat.NavLogs(), "⌘6", collapsed)
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
				Size(collapsedTileSize, collapsedTileSize).Radius(dsRadiusMD).Background(p.accentBg).
				Children(func() {
					ui.Image(c, iconBrandFor(p.dark)).Size(18, 18)
				})
		})
		return
	}

	ui.Row(c).AlignItems(ui.Center).Padding(4, 2, 6, 2).Children(func() {
		ui.Row(c).AlignItems(ui.Center).Gap(10).Children(func() {
			ui.Row(c).AlignItems(ui.Center).Justify(ui.Center).
				Size(collapsedTileSize, collapsedTileSize).Radius(dsRadiusMD).Background(p.accentBg).
				Children(func() {
					ui.Image(c, iconBrandFor(p.dark)).Size(18, 18)
				})
			ui.Text(c, "NaiveClient").FontSize(dsFontDrawerTitle).FontWeight(700).TextColor(p.text).NoWrap()
		})
	})
}

func (a *app) renderSidebarToggleButton(c *ui.Context, p palette, collapsed bool) {
	cat := a.catalog()

	if collapsed {
		btn := ui.ButtonBase(c.Key("btn-sidebar-toggle-bottom")).
			Label(cat.SidebarExpand()).
			Size(collapsedTileSize, collapsedTileSize).Radius(dsRadiusMD).
			Background(ui.Transparent).
			AlignItems(ui.Center).Justify(ui.Center).
			Tooltip(cat.SidebarExpand() + " (⌘B)").
			Children(func() {
				ui.Icon(c, iconSidebarExpand).Size(16, 16).TextColor(p.textDim)
			})
		if btn.Pressed() {
			btn.Background(p.elevated)
		} else if btn.Hovered() {
			btn.Background(p.cardHover)
		}
		if btn.Clicked() {
			a.toggleSidebar()
		}
		return
	}

	btn := ui.ButtonBase(c.Key("btn-sidebar-toggle-bottom")).
		Label(cat.SidebarCollapse()).
		FillWidth().
		AlignItems(ui.Center).Justify(ui.SpaceBetween).
		Height(collapsedTileSize).PaddingX(10).Radius(dsRadiusMD).
		Background(ui.Transparent).
		Tooltip(cat.SidebarCollapse() + " (⌘B)").
		Children(func() {
			ui.Row(c).AlignItems(ui.Center).Gap(9).Children(func() {
				ui.Icon(c, iconSidebarCollapse).Size(16, 16).TextColor(p.textDim)
				ui.Text(c, cat.SidebarCollapse()).FontSize(dsFontBody).TextColor(p.textMuted).NoWrap()
			})
			ui.Row(c).Width(24).Justify(ui.Start).AlignItems(ui.Center).Children(func() {
				ui.Text(c, "⌘B").FontSize(dsFontCaption).TextColor(p.textDim).NoWrap()
			})
		})
	if btn.Pressed() {
		btn.Background(p.elevated)
	} else if btn.Hovered() {
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
		fg = p.navActiveColor()
		weight = 600
	}

	hasBadge := tab == TabSettings && (a.localVersion == "" || a.hasUpdate || a.hasXrayUpdate)
	key := fmt.Sprintf("nav-item-%d", tab)
	if collapsed {
		tip := fmt.Sprintf("%s (%s)", label, shortcut)
		btn := ui.ButtonBase(c.Key(key)).
			Label(label).
			Size(collapsedTileSize, collapsedTileSize).Radius(dsRadiusMD).
			Background(bg).
			AlignItems(ui.Center).Justify(ui.Center).
			Tooltip(tip).
			Children(func() {
				if icon != nil {
					ui.Icon(c, icon).Size(16, 16).TextColor(fg)
				}
				if hasBadge {
					ui.Box(c).Absolute().Top(6).Right(6).Size(6, 6).Radius(dsRadiusPill).Background(p.amber)
				}
			})
		if !active {
			if btn.Pressed() {
				btn.Background(p.elevated)
			} else if btn.Hovered() {
				btn.Background(p.cardHover)
			}
		}
		if btn.Clicked() {
			a.activeTab = tab
		}
		return
	}

	btn := ui.ButtonBase(c.Key(key)).
		Label(label).
		FillWidth().
		AlignItems(ui.Center).Justify(ui.SpaceBetween).
		Height(collapsedTileSize).PaddingX(10).Radius(dsRadiusMD).
		Background(bg).
		Children(func() {
			ui.Row(c).AlignItems(ui.Center).Gap(9).Children(func() {
				if icon != nil {
					ui.Icon(c, icon).Size(16, 16).TextColor(fg)
				}
				ui.Text(c, label).FontSize(dsFontSectionTitle).FontWeight(weight).TextColor(fg).NoWrap()
				if hasBadge {
					ui.Box(c).Size(6, 6).Radius(dsRadiusPill).Background(p.amber)
				}
			})
			ui.Row(c).Width(24).Justify(ui.Start).AlignItems(ui.Center).Children(func() {
				ui.Text(c, shortcut).FontSize(dsFontCaption).TextColor(p.textDim).NoWrap()
			})
		})

	if !active {
		if btn.Pressed() {
			btn.Background(p.elevated)
		} else if btn.Hovered() {
			btn.Background(p.cardHover)
		}
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
	gwRunning := a.state.GatewayEnabled && a.getGateway() != nil
	gwErr := a.getLastGatewayErr()
	gwDotColor := p.textDim
	gwBadgeText := ""
	gwBadgeFg := p.textDim
	gwBadgeBg := p.elevated

	if !gwRunning {
		if a.state.GatewayEnabled && gwErr != nil {
			gwDotColor = p.red
			gwBadgeText = cat.StatusError()
			gwBadgeFg = p.redText
			gwBadgeBg = p.redBg
		} else {
			gwBadgeText = cat.TailnetModeOff()
		}
	} else {
		gwDotColor = p.green
	}

	if missingCore {
		gwDotColor = p.amber
		gwBadgeText = cat.EngineMissingSidecar()
		gwBadgeFg = p.amberText
		gwBadgeBg = p.amberBg
	} else if hasAnyUpdate {
		gwDotColor = p.amber
		gwBadgeText = cat.UpdateAvailableBadge()
		gwBadgeFg = p.amberText
		gwBadgeBg = p.amberBg
	}

	tp := darkPalette
	gwDetail := gwAddr
	gwTipColor := tp.greenText
	if !gwRunning {
		gwDetail = cat.TailnetModeOff()
		gwTipColor = tp.textMuted
	} else if missingCore || hasAnyUpdate {
		gwTipColor = tp.amberText
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
	var tsModeName string

	tsIP := ""
	if a.state.TailnetEnabled && a.state.TailnetMode != string(tailnet.ModeOff) && len(ts.Self.IPs) > 0 {
		tsIP = ts.Self.IPs[0]
	}

	if a.state.TailnetEnabled && a.state.TailnetMode != string(tailnet.ModeOff) {
		if ts.ActiveMode == tailnet.ModeHost {
			tsModeName = cat.TailnetModeHost()
		} else {
			tsModeName = cat.TailnetModeEmbedded()
		}
		switch ts.BackendState {
		case "Running":
			tsDotColor = p.green
			if tsIP == "" {
				tsBadgeText = cat.TailnetStatusConnected()
			} else {
				tsBadgeText = ""
			}
			tsBadgeFg = p.accentText
			tsBadgeBg = p.accentBg
		case "NeedsLogin":
			tsDotColor = p.amber
			tsBadgeText = cat.TailnetStatusNeedsLogin()
			tsBadgeFg = p.amberText
			tsBadgeBg = p.amberBg
		case "Starting":
			tsDotColor = p.amber
			tsBadgeText = cat.TailnetStarting()
			tsBadgeFg = p.textDim
			tsBadgeBg = p.elevated
		default:
			tsDotColor = p.textDim
			tsBadgeText = cat.TailnetStatusOffline()
			tsBadgeFg = p.textDim
			tsBadgeBg = p.elevated
		}
	}

	tsDetail := tsBadgeText
	if tsIP != "" {
		tsDetail = tsIP
	} else if ts.BackendState == "Running" {
		tsDetail = cat.TailnetStatusConnected()
	}

	tsTipColor := tp.textMuted
	if a.state.TailnetEnabled && a.state.TailnetMode != string(tailnet.ModeOff) {
		switch ts.BackendState {
		case "Running":
			tsTipColor = tp.greenText
		case "NeedsLogin", "Starting":
			tsTipColor = tp.amberText
		}
	}

	// Mode handling
	activeMode := a.getTrafficMode()
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

	renderSidebarTooltip := func(anchor ui.Element) {
		ui.TooltipBase(c, anchor, func(tip ui.Element) {
			tip.AttachTo(anchor, ui.AnchorRight, ui.AnchorLeft).
				Margin(0, 0, 0, dsSpaceMD).
				Padding(10, 12, 10, 12).Radius(dsRadiusMD).
				Background(tp.card).
				Border(1, tp.border).
				Shadow(tp.popoverShadow()).
				Children(func() {
					ui.Column(c).Gap(dsSpaceSM).Width(210).Children(func() {
						// Section 1: Gateway & Working mode
						ui.Column(c).Gap(dsSpaceXS).Children(func() {
							// Line 1: Gateway
							ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
								ui.Row(c).AlignItems(ui.Center).Gap(dsSpaceSM).Children(func() {
									ui.Box(c).Size(6, 6).Radius(dsRadiusPill).Background(gwDotColor)
									ui.Text(c, cat.MasterGateway()).FontSize(dsFontCaption).FontWeight(600).TextColor(tp.text)
								})
								ui.Text(c, gwDetail).FontSize(dsFontCaption).TextColor(gwTipColor)
							})

							// Line 1b: Working mode (belongs to Gateway)
							ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
								ui.Text(c, cat.TrafficModeLabel()).FontSize(dsFontCaption).TextColor(tp.textMuted)
								ui.Text(c, activeModeLabel).FontSize(dsFontCaption).FontWeight(600).TextColor(tp.accentText)
							})

							// Line 1c: Running nodes count (shown in tooltip)
							if gwRunning {
								ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
									ui.Text(c, cat.RuleDrawerActiveNodes()).FontSize(dsFontCaption).TextColor(tp.textMuted)
									nodeColor := tp.greenText
									if runningSidecars == 0 {
										nodeColor = tp.textMuted
									}
									ui.Text(c, cat.RunningCountBadge(runningSidecars)).FontSize(dsFontCaption).TextColor(nodeColor)
								})
							}
						})

						// Divider 1: separates Gateway from Tailnet
						ui.Box(c).Fill().Height(1).Background(tp.border)

						// Section 2: Tailnet
						ui.Column(c).Gap(dsSpaceXS).Children(func() {
							// Line 2: Tailnet
							ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
								ui.Row(c).AlignItems(ui.Center).Gap(dsSpaceSM).Children(func() {
									ui.Box(c).Size(6, 6).Radius(dsRadiusPill).Background(tsDotColor)
									ui.Text(c, cat.NavTailnet()).FontSize(dsFontCaption).TextColor(tp.text)
								})
								ui.Text(c, tsDetail).FontSize(dsFontCaption).TextColor(tsTipColor)
							})

							// Line 2b: Tailnet connection mode (shown in tooltip when connected)
							if a.state.TailnetEnabled && a.state.TailnetMode != string(tailnet.ModeOff) && ts.BackendState == "Running" && tsModeName != "" {
								ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
									ui.Text(c, cat.TailnetModeLabel()).FontSize(dsFontCaption).TextColor(tp.textMuted)
									ui.Text(c, tsModeName).FontSize(dsFontCaption).TextColor(tp.accentText)
								})
							}
						})

						// Divider 2: separates Tailnet from Core versions
						ui.Box(c).Fill().Height(1).Background(tp.border)

						// Section 2: Core versions
						ui.Column(c).Gap(3).Children(func() {
							// sing-box
							ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
								ui.Text(c, "sing-box ("+cat.TagBuiltin()+")").FontSize(dsFontCaption).TextColor(tp.textMuted)
								ui.Text(c, sbVer).FontSize(dsFontCaption).TextColor(tp.greenText)
							})

							renderCoreVersion := func(name, statusText string, installed, hasUpd bool) {
								ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
									ui.Text(c, name).FontSize(dsFontCaption).TextColor(tp.textMuted)
									col := tp.text
									canUpdate := installed && hasUpd
									if !installed || canUpdate {
										col = tp.amberText
									}
									if canUpdate {
										ui.Row(c).AlignItems(ui.Center).Gap(3).Children(func() {
											ui.Text(c, statusText).FontSize(dsFontCaption).TextColor(col)
											ui.Icon(c, iconArrowUp).Size(11, 11).TextColor(col)
										})
									} else {
										ui.Text(c, statusText).FontSize(dsFontCaption).TextColor(col)
									}
								})
							}

							// NaiveProxy
							renderCoreVersion("NaiveProxy", a.naiveStatusText(), a.localVersion != "", a.hasUpdate)

							// Xray-core
							renderCoreVersion("Xray-core", a.xrayStatusText(), a.localXrayVersion != "", a.hasXrayUpdate)

							if hasAnyUpdate {
								ui.Row(c).AlignItems(ui.Center).Justify(ui.End).Children(func() {
									ui.Text(c, cat.UpdateAvailableBadge()).FontSize(dsFontMicro).FontWeight(600).TextColor(tp.amberText)
								})
							} else if missingCore {
								ui.Row(c).AlignItems(ui.Center).Justify(ui.End).Children(func() {
									ui.Text(c, cat.EngineMissingSidecar()).FontSize(dsFontMicro).FontWeight(500).TextColor(tp.amberText)
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
			Width(collapsedTileSize).Height(91).
			Padding(6, 2, 6, 2).Gap(dsSpaceXS).Radius(dsRadiusMD).
			Background(p.card).Border(1, p.borderSubtle).
			AlignItems(ui.Center).
			Children(func() {
				// Row 1: Positional 3-bar mode capsule (Left: Port, Center: SysProxy, Right: TUN)
				ui.Row(c.Key("collapsed-mode-row")).
					Size(32, 22).Radius(dsRadiusXS).
					Background(ui.Transparent).
					AlignItems(ui.Center).Justify(ui.Center).
					Children(func() {
						// Modes form an escalating ladder (port < sysproxy < tun):
						// bars up to and including the active tier are lit, like signal strength.
						tierOf := func(id string) int {
							switch id {
							case "sysproxy":
								return 2
							case "tun":
								return 3
							}
							return 1
						}
						renderCollapsedModeBtn := func(modeID, label string) {
							tier := tierOf(modeID)
							lit := tier <= tierOf(activeMode)
							barColor := p.borderSubtle
							if p.dark {
								barColor = p.textDim
							}
							if lit {
								barColor = p.navActiveColor()
							}

							btn := ui.ButtonBase(c.Key("collapsed-mode-btn-" + modeID)).
								Column().
								Label(label).
								Grow(1).Height(22).Radius(3).
								Background(ui.Transparent).
								AlignItems(ui.Center).Justify(ui.End).
								Tooltip(label).
								Children(func() {
									ui.Box(c).Width(6).Height(float32(6+tier*4)).Radius(2).Background(barColor)
								})
							if btn.Pressed() {
								btn.Background(p.elevated)
							} else if btn.Hovered() {
								btn.Background(p.cardHover)
							}
							if btn.Clicked() {
								_ = a.setTrafficMode(modeID)
							}
						}

						renderCollapsedModeBtn("port", cat.ModePortOnly())
						renderCollapsedModeBtn("sysproxy", cat.ModeSysProxy())
						renderCollapsedModeBtn("tun", cat.ModeTun())
					})

				// Row 2: Gateway status dot
				gwBtn := ui.ButtonBase(c.Key("collapsed-gw-dot")).
					Label(cat.MasterGateway()).
					Size(28, 22).Radius(dsRadiusXS).
					Background(ui.Transparent).
					AlignItems(ui.Center).Justify(ui.Center).
					Children(func() {
						ui.Box(c).Size(7, 7).Radius(dsRadiusPill).Background(gwDotColor)
					})
				if gwBtn.Pressed() {
					gwBtn.Background(p.elevated)
				} else if gwBtn.Hovered() {
					gwBtn.Background(p.cardHover)
				}
				if gwBtn.Clicked() {
					a.activeTab = TabSettings
					a.settingsSubTab = 1
				}

				// Divider (separates Gateway and Tailnet)
				ui.Box(c).Width(24).Height(1).Background(p.borderSubtle)

				// Row 3: Tailnet status dot
				tsBtn := ui.ButtonBase(c.Key("collapsed-ts-dot")).
					Label(cat.NavTailnet()).
					Size(28, 22).Radius(dsRadiusXS).
					Background(ui.Transparent).
					AlignItems(ui.Center).Justify(ui.Center).
					Children(func() {
						ui.Box(c).Size(7, 7).Radius(dsRadiusPill).Background(tsDotColor)
					})
				if tsBtn.Pressed() {
					tsBtn.Background(p.elevated)
				} else if tsBtn.Hovered() {
					tsBtn.Background(p.cardHover)
				}
				if tsBtn.Clicked() {
					a.activeTab = TabTailnet
				}
			})
		renderSidebarTooltip(card)
		return
	}

	// Expanded state: unified 3-row card
	card := ui.Column(c.Key("sidebar-engine-pill")).
		Label(cat.EngineStatusPillTitle()).
		Height(91).
		Padding(6, 8, 6, 8).Gap(dsSpaceXS).Radius(dsRadiusMD).
		Background(p.card).Border(1, p.borderSubtle).
		Children(func() {
			// Row 1: 3-Way Segmented Working Mode (Left: Port, Center: SysProxy, Right: TUN)
			ui.Row(c.Key("expanded-mode-row")).
				Height(22).
				AlignItems(ui.Center).Justify(ui.SpaceBetween).
				Padding(0, 0, 0, 0).Gap(3).
				Children(func() {
					renderModeBtn := func(modeID, label string) {
						isSelected := activeMode == modeID
						bg := ui.Transparent
						fg := p.textDim
						weight := 400
						if isSelected {
							bg = p.elevated
							fg = p.navActiveColor()
							weight = 600
						}

						btn := ui.ButtonBase(c.Key("btn-mode-" + modeID)).
							Label(label).
							Grow(1).Justify(ui.Center).AlignItems(ui.Center).
							Height(22).Radius(dsRadiusXS).
							Background(bg).
							Children(func() {
								ui.Text(c, label).FontSize(dsFontMicro).FontWeight(weight).TextColor(fg).NoWrap()
							})
						if !isSelected {
							if btn.Pressed() {
								btn.Background(p.borderSubtle)
							} else if btn.Hovered() {
								btn.Background(p.cardHover)
							}
						}
						if btn.Clicked() {
							_ = a.setTrafficMode(modeID)
						}
					}

					renderModeBtn("port", cat.ModePortOnly())
					renderModeBtn("sysproxy", cat.ModeSysProxy())
					renderModeBtn("tun", cat.ModeTun())
				})

			// Row 2: Gateway status + full address (127.0.0.1:10809)
			row1 := ui.ButtonBase(c.Key("expanded-gw-row")).
				Label(cat.MasterGateway()).
				FillWidth().
				Height(22).
				AlignItems(ui.Center).Justify(ui.SpaceBetween).
				Padding(0, 4, 0, 4).Radius(dsRadiusSM).
				Background(ui.Transparent).
				Children(func() {
					ui.Row(c).AlignItems(ui.Center).Gap(dsSpaceSM).Children(func() {
						ui.Box(c).Size(7, 7).Radius(dsRadiusPill).Background(gwDotColor)
						ui.Text(c, cat.MasterGateway()).FontSize(dsFontCaption).FontWeight(600).TextColor(p.text).NoWrap()
					})

					if gwBadgeText != "" {
						tagPill(c, gwBadgeText, gwBadgeFg, gwBadgeBg)
					} else {
						ui.Text(c, gwAddr).FontSize(dsFontCaption).TextColor(p.textMuted).NoWrap()
					}
				})
			if row1.Pressed() {
				row1.Background(p.elevated)
			} else if row1.Hovered() {
				row1.Background(p.cardHover)
			}
			if row1.Clicked() {
				a.activeTab = TabSettings
				a.settingsSubTab = 1
			}

			// Divider: separates Gateway and Tailnet
			ui.Box(c).Fill().Height(1).Background(p.borderSubtle)

			// Row 3: Tailnet status
			row2 := ui.ButtonBase(c.Key("expanded-ts-row")).
				Label(cat.NavTailnet()).
				FillWidth().
				Height(22).
				AlignItems(ui.Center).Justify(ui.SpaceBetween).
				Padding(0, 4, 0, 4).Radius(dsRadiusSM).
				Background(ui.Transparent).
				Children(func() {
					ui.Row(c).AlignItems(ui.Center).Gap(dsSpaceSM).Children(func() {
						ui.Box(c).Size(7, 7).Radius(dsRadiusPill).Background(tsDotColor)
						ui.Text(c, cat.NavTailnet()).FontSize(dsFontCaption).FontWeight(600).TextColor(p.text).NoWrap()
					})
					if tsIP != "" {
						ui.Text(c, tsIP).FontSize(dsFontCaption).TextColor(p.textMuted).NoWrap()
					} else if tsBadgeText != "" {
						tagPill(c, tsBadgeText, tsBadgeFg, tsBadgeBg)
					}
				})
			if row2.Pressed() {
				row2.Background(p.elevated)
			} else if row2.Hovered() {
				row2.Background(p.cardHover)
			}
			if row2.Clicked() {
				a.activeTab = TabTailnet
			}
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
