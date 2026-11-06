package app

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/egoist/mygo/ui"

	"naive-client/internal/blocker"
)

func (a *app) renderInsightsPage(c *ui.Context, p palette) {
	cat := a.catalog()

	ui.Column(c.Key("insights-page")).Grow(1).Fill().MinHeight(0).Children(func() {
		// Header row with title and controls
		ui.Row(c.Key("insights-header")).
			Padding(14, 18, 14, 18).
			AlignItems(ui.Center).
			BorderWidth(0, 0, 1, 0).BorderColor(p.borderSubtle).
			Children(func() {
				ui.Column(c).Gap(2).Children(func() {
					ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
						ui.Text(c, cat.NavInsights()).FontSize(17).FontWeight(700).TextColor(p.text)
						if a.state.BlockerEnabled {
							tagPill(c, "防护运行中", p.green, p.greenBg)
						} else {
							tagPill(c, "防护已暂停", p.textDim, p.card)
						}
					})
					ui.Text(c, "类 Pi-hole 双层 DNS 与网关防护，高频请求内存无损统计").FontSize(11).TextColor(p.textDim)
				})

				ui.Box(c).Grow(1)

				// Header Action Controls
				ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
					// 1. Toggle Protection Button
					blockerBtnBg := p.greenBg
					blockerBtnFg := p.green
					blockerBtnLabel := "防护中"
					if !a.state.BlockerEnabled {
						blockerBtnBg = p.card
						blockerBtnFg = p.textDim
						blockerBtnLabel = "已暂停"
					}
					btnToggle := ui.ButtonBase(c.Key("btn-toggle-blocker")).
						Label("btn-toggle-blocker").
						Padding(6, 12, 6, 12).Radius(6).
						Background(blockerBtnBg).Border(1, p.borderSubtle).
						Tooltip("一键开启/暂停广告与域名防护").
						Children(func() {
							ui.Text(c, blockerBtnLabel).FontSize(12).FontWeight(600).TextColor(blockerBtnFg)
						})
					if btnToggle.Clicked() {
						a.toggleBlockerEnabled()
					}

					// 2. Toggle Ads Button
					adsBg := p.accentBg
					adsFg := p.accentText
					adsLabel := "内置去广告: 开"
					if !a.state.BlockerBlockAds {
						adsBg = p.card
						adsFg = p.textDim
						adsLabel = "内置去广告: 关"
					}
					btnAds := ui.ButtonBase(c.Key("btn-toggle-ads")).
						Label("btn-toggle-ads").
						Padding(6, 12, 6, 12).Radius(6).
						Background(adsBg).Border(1, p.borderSubtle).
						Tooltip("启用或关闭内置 geosite:category-ads-all").
						Children(func() {
							ui.Text(c, adsLabel).FontSize(12).FontWeight(600).TextColor(adsFg)
						})
					if btnAds.Clicked() {
						a.toggleBlockerBlockAds()
					}

					// 3. Manage Rules Drawer Button
					btnRules := ui.ButtonBase(c.Key("btn-manage-rules")).
						Label("btn-manage-rules").
						Padding(6, 12, 6, 12).Radius(6).
						Background(p.elevated).Border(1, p.borderSubtle).
						Tooltip("管理用户黑白名单与外部规则订阅").
						Children(func() {
							ui.Text(c, "黑白名单与订阅").FontSize(12).FontWeight(600).TextColor(p.text)
						})
					if btnRules.Clicked() {
						a.insightsShowManageRules = !a.insightsShowManageRules
					}
				})
			})

		// Scrollable main content
		ui.Scroll(c.Key("insights-scroll")).Grow(1).Fill().Children(func() {
			ui.Column(c).Padding(16, 18, 20, 18).Gap(14).Children(func() {
				// 1. KPI Cards
				a.renderInsightsKPICards(c, p)

				// 2. 24-Hour Activity Trend Chart
				a.renderInsightsTrendChart(c, p)

				// 3. Top-10 Blocked & Allowed Rankings
				a.renderInsightsTopDomains(c, p)

				// 4. Live Query Log
				a.renderInsightsQueryLogs(c, p)
			})
		})
	})

	if a.insightsShowManageRules {
		a.renderInsightsManageRulesDialog(c, p)
	}
}

func (a *app) renderInsightsKPICards(c *ui.Context, p palette) {
	var totalQueries, totalBlocked int64
	activeRules := 0
	if a.blocker != nil {
		totalQueries, totalBlocked = a.blocker.Logger().GetStatsSummary()
		activeRules = a.blocker.RuleCount()
	}

	blockRate := 0.0
	if totalQueries > 0 {
		blockRate = float64(totalBlocked) / float64(totalQueries) * 100.0
	}

	ui.Row(c.Key("insights-kpi-row")).Gap(10).Children(func() {
		a.renderKPICard(c, p, "24h 总查询/连接", fmt.Sprintf("%d", totalQueries), p.text, p.surface)
		a.renderKPICard(c, p, "已拦截威胁与广告", fmt.Sprintf("%d", totalBlocked), p.red, p.redBg)
		a.renderKPICard(c, p, "拦截率", fmt.Sprintf("%.1f%%", blockRate), p.amber, p.amberBg)
		a.renderKPICard(c, p, "生效规则数", fmt.Sprintf("%d", activeRules), p.accentText, p.accentBg)
	})
}

func (a *app) renderKPICard(c *ui.Context, p palette, title, value string, fg, bg ui.Color) {
	ui.Column(c).Grow(1).
		Padding(12, 14, 12, 14).Radius(8).
		Background(p.card).Border(1, p.borderSubtle).
		Children(func() {
			ui.Text(c, title).FontSize(11).TextColor(p.textDim)
			ui.Row(c).AlignItems(ui.Baseline).Gap(6).Children(func() {
				ui.Text(c, value).FontSize(20).FontWeight(700).TextColor(fg)
			})
		})
}

func (a *app) renderInsightsTrendChart(c *ui.Context, p palette) {
	if a.blocker == nil {
		return
	}

	now := time.Now()
	buckets := a.blocker.Logger().Get24HourlyBuckets(now)

	var maxVal int64 = 1
	for _, b := range buckets {
		if b.Total > maxVal {
			maxVal = b.Total
		}
	}

	ui.Column(c.Key("insights-chart-card")).
		Padding(12, 14, 12, 14).Radius(8).
		Background(p.card).Border(1, p.borderSubtle).Gap(8).
		Children(func() {
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
				ui.Text(c, "过去 24 小时活动趋势").FontSize(12).FontWeight(600).TextColor(p.text)
				ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
					ui.Row(c).Gap(4).AlignItems(ui.Center).Children(func() {
						ui.Box(c).Size(8, 8).Radius(2).Background(p.accent)
						ui.Text(c, "总请求").FontSize(10).TextColor(p.textDim)
					})
					ui.Row(c).Gap(4).AlignItems(ui.Center).Children(func() {
						ui.Box(c).Size(8, 8).Radius(2).Background(p.red)
						ui.Text(c, "已拦截").FontSize(10).TextColor(p.textDim)
					})
				})
			})

			// Bar chart container
			ui.Row(c.Key("trend-bars-container")).
				Height(60).AlignItems(ui.End).Gap(3).
				Padding(4, 0, 4, 0).
				Children(func() {
					for idx, b := range buckets {
						bucket := b
						totalHeight := float32(bucket.Total) / float32(maxVal) * 50.0
						if totalHeight < 2 {
							totalHeight = 2
						}
						blockedHeight := float32(bucket.Blocked) / float32(maxVal) * 50.0

						tip := fmt.Sprintf("%s | 总: %d, 拦截: %d", bucket.Hour.Format("15:04"), bucket.Total, bucket.Blocked)

						barCol := ui.Column(c.Key(fmt.Sprintf("bar-%d", idx))).
							Grow(1).Height(totalHeight).Radius(2).
							Background(p.elevated).Clip().
							Tooltip(tip)

						barCol.Children(func() {
							ui.Box(c).Grow(1)
							if blockedHeight > 0 {
								ui.Box(c).Height(blockedHeight).Background(p.red)
							}
						})
					}
				})
		})
}

func (a *app) renderInsightsTopDomains(c *ui.Context, p palette) {
	if a.blocker == nil {
		return
	}

	topBlocked := a.blocker.Logger().GetTopBlocked(10)
	topAllowed := a.blocker.Logger().GetTopAllowed(10)

	ui.Row(c.Key("insights-top-row")).AlignItems(ui.Stretch).Gap(10).Children(func() {
		// Top Blocked Panel
		ui.Column(c.Key("top-blocked-panel")).Grow(1).
			Label("panel-top-blocked").
			Padding(12, 14, 12, 14).Radius(8).
			Background(p.card).Border(1, p.borderSubtle).Gap(6).
			Children(func() {
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
					ui.Text(c, "Top 被拦截域名").FontSize(12).FontWeight(600).TextColor(p.text)
					tagPill(c, fmt.Sprintf("%d", len(topBlocked)), p.red, p.redBg)
				})

				if len(topBlocked) == 0 {
					ui.Column(c).Grow(1).AlignItems(ui.Center).Justify(ui.Center).PaddingY(16).Children(func() {
						ui.Text(c, "暂无拦截记录").FontSize(11).TextColor(p.textDim)
					})
				} else {
					for _, item := range topBlocked {
						dom := item.Domain
						cnt := item.Count
						ui.Row(c.Key("top-block-" + dom)).
							AlignItems(ui.Center).Justify(ui.SpaceBetween).
							PaddingY(3).
							Children(func() {
								ui.Text(c, dom).FontSize(11).TextColor(p.text).NoWrap()
								ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
									ui.Text(c, fmt.Sprintf("%d", cnt)).FontSize(11).FontWeight(600).TextColor(p.red)
									btnAllow := ui.ButtonBase(c.Key("btn-quick-whitelist-"+dom)).
										Label("btn-quick-whitelist-"+dom).
										Padding(2, 6, 2, 6).Radius(4).
										Background(p.surface).Border(1, p.borderSubtle).
										Tooltip("加入白名单，解除拦截").
										Children(func() {
											ui.Text(c, "+ 白名单").FontSize(10).TextColor(p.accentText)
										})
									if btnAllow.Clicked() {
										a.addBlockerAllowlist(dom)
									}
								})
							})
					}
					ui.Box(c).Grow(1)
				}
			})

		// Top Allowed Panel
		ui.Column(c.Key("top-allowed-panel")).Grow(1).
			Label("panel-top-allowed").
			Padding(12, 14, 12, 14).Radius(8).
			Background(p.card).Border(1, p.borderSubtle).Gap(6).
			Children(func() {
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
					ui.Text(c, "Top 放行域名").FontSize(12).FontWeight(600).TextColor(p.text)
					tagPill(c, fmt.Sprintf("%d", len(topAllowed)), p.green, p.greenBg)
				})

				if len(topAllowed) == 0 {
					ui.Column(c).Grow(1).AlignItems(ui.Center).Justify(ui.Center).PaddingY(16).Children(func() {
						ui.Text(c, "暂无放行记录").FontSize(11).TextColor(p.textDim)
					})
				} else {
					for _, item := range topAllowed {
						dom := item.Domain
						cnt := item.Count
						ui.Row(c.Key("top-allow-" + dom)).
							AlignItems(ui.Center).Justify(ui.SpaceBetween).
							PaddingY(3).
							Children(func() {
								ui.Text(c, dom).FontSize(11).TextColor(p.text).NoWrap()
								ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
									ui.Text(c, fmt.Sprintf("%d", cnt)).FontSize(11).FontWeight(600).TextColor(p.green)
									btnDeny := ui.ButtonBase(c.Key("btn-quick-denylist-"+dom)).
										Label("btn-quick-denylist-"+dom).
										Padding(2, 6, 2, 6).Radius(4).
										Background(p.surface).Border(1, p.borderSubtle).
										Tooltip("加入黑名单，禁止连接").
										Children(func() {
											ui.Text(c, "+ 拦截").FontSize(10).TextColor(p.red)
										})
									if btnDeny.Clicked() {
										a.addBlockerDenylist(dom)
									}
								})
							})
					}
					ui.Box(c).Grow(1)
				}
			})
	})
}

func (a *app) renderInsightsQueryLogs(c *ui.Context, p palette) {
	if a.blocker == nil {
		return
	}

	filtered, totalCount := a.blocker.Logger().GetFilteredEntries(a.insightsFilter, a.insightsSearch, 30)

	ui.Column(c.Key("insights-query-log-card")).
		Padding(12, 14, 12, 14).Radius(8).
		Background(p.card).Border(1, p.borderSubtle).Gap(8).
		Children(func() {
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
					ui.Text(c, "实时查询日志").FontSize(12).FontWeight(600).TextColor(p.text)
					tagPill(c, fmt.Sprintf("%d 条", totalCount), p.textDim, p.surface)
				})

				// Segment Filter Tabs
				ui.Row(c).AlignItems(ui.Center).Gap(4).Children(func() {
					btnAll := ui.ButtonBase(c.Key("btn-filter-all")).
						Label("btn-filter-all").
						Padding(3, 8, 3, 8).Radius(4).
						Background(ternaryColor(a.insightsFilter == "", p.elevated, p.surface)).
						Children(func() {
							ui.Text(c, "全部").FontSize(11).TextColor(ternaryColor(a.insightsFilter == "", p.text, p.textDim))
						})
					if btnAll.Clicked() {
						a.insightsFilter = ""
					}

					btnBlocked := ui.ButtonBase(c.Key("btn-filter-blocked")).
						Label("btn-filter-blocked").
						Padding(3, 8, 3, 8).Radius(4).
						Background(ternaryColor(a.insightsFilter == "blocked", p.redBg, p.surface)).
						Children(func() {
							ui.Text(c, "仅拦截").FontSize(11).TextColor(ternaryColor(a.insightsFilter == "blocked", p.red, p.textDim))
						})
					if btnBlocked.Clicked() {
						a.insightsFilter = "blocked"
					}

					btnAllowed := ui.ButtonBase(c.Key("btn-filter-allowed")).
						Label("btn-filter-allowed").
						Padding(3, 8, 3, 8).Radius(4).
						Background(ternaryColor(a.insightsFilter == "allowed", p.greenBg, p.surface)).
						Children(func() {
							ui.Text(c, "仅放行").FontSize(11).TextColor(ternaryColor(a.insightsFilter == "allowed", p.green, p.textDim))
						})
					if btnAllowed.Clicked() {
						a.insightsFilter = "allowed"
					}
				})
			})

			// Search input
			ui.TextInput(c.Key("input-search-query-logs"), &a.insightsSearch).
				Placeholder("按域名过滤最近请求...").
				FontSize(11).
				Padding(4, 8, 4, 8).Radius(5).
				Background(p.surface).Border(1, p.borderSubtle)

			// Table header
			ui.Row(c).Padding(4, 6, 4, 6).Background(p.surface).Radius(4).Children(func() {
				ui.Text(c, "时间").FontSize(10).FontWeight(600).TextColor(p.textDim).Width(65)
				ui.Text(c, "来源").FontSize(10).FontWeight(600).TextColor(p.textDim).Width(60)
				ui.Text(c, "裁决").FontSize(10).FontWeight(600).TextColor(p.textDim).Width(85)
				ui.Text(c, "域名").FontSize(10).FontWeight(600).TextColor(p.textDim).Grow(1)
				ui.Text(c, "匹配规则").FontSize(10).FontWeight(600).TextColor(p.textDim).Width(120)
				ui.Text(c, "操作").FontSize(10).FontWeight(600).TextColor(p.textDim).Width(65)
			})

			if len(filtered) == 0 {
				ui.Text(c, "暂无匹配的查询记录").FontSize(11).TextColor(p.textDim).Padding(10, 6, 10, 6)
			} else {
				for _, entry := range filtered {
					e := entry
					dom := e.Domain
					idStr := strconv.FormatInt(e.ID, 10)
					timeStr := e.Timestamp.Format("15:04:05")

					verdictBg := p.greenBg
					verdictFg := p.green
					if e.Verdict == blocker.VerdictBlocked {
						verdictBg = p.redBg
						verdictFg = p.red
					} else if e.Verdict == blocker.VerdictWhitelisted {
						verdictBg = p.accentBg
						verdictFg = p.accentText
					}

					ui.Row(c.Key("log-row-" + idStr)).
						AlignItems(ui.Center).Padding(4, 6, 4, 6).
						BorderWidth(0, 0, 1, 0).BorderColor(p.borderSubtle.Alpha(0.4)).
						Children(func() {
							ui.Text(c, timeStr).FontSize(10).TextColor(p.textDim).Width(65)
							tagPill(c, string(e.Source), p.textDim, p.surface)
							ui.Box(c).Width(8)
							tagPill(c, string(e.Verdict), verdictFg, verdictBg)
							ui.Box(c).Width(12)
							ui.Text(c, dom).FontSize(11).TextColor(p.text).Grow(1).NoWrap()
							ruleText := e.Rule
							if ruleText == "" {
								ruleText = "-"
							}
							ui.Text(c, ruleText).FontSize(10).TextColor(p.textDim).Width(120).NoWrap()

							// Quick action
							if e.Verdict == blocker.VerdictBlocked {
								btnW := ui.ButtonBase(c.Key("btn-log-whitelist-" + idStr)).
									Label("btn-log-whitelist-" + dom).
									Padding(2, 6, 2, 6).Radius(4).
									Background(p.surface).Border(1, p.borderSubtle).
									Children(func() {
										ui.Text(c, "+ 白名单").FontSize(10).TextColor(p.accentText)
									})
								if btnW.Clicked() {
									a.addBlockerAllowlist(dom)
								}
							} else {
								btnB := ui.ButtonBase(c.Key("btn-log-block-" + idStr)).
									Label("btn-log-block-" + dom).
									Padding(2, 6, 2, 6).Radius(4).
									Background(p.surface).Border(1, p.borderSubtle).
									Children(func() {
										ui.Text(c, "+ 拦截").FontSize(10).TextColor(p.red)
									})
								if btnB.Clicked() {
									a.addBlockerDenylist(dom)
								}
							}
						})
				}
			}
		})
}

func (a *app) renderInsightsManageRulesDialog(c *ui.Context, p palette) {
	white := ui.RGB(255, 255, 255)
	ui.DialogBase(c.Key("manage-rules-dialog"), &a.insightsShowManageRules, func(backdrop, panel ui.Element) {
		backdrop.Background(ui.RGBA(0, 0, 0, 0.5))
		panel.Column().
			Width(520).
			Padding(18).Gap(14).
			Radius(14).Background(p.card).Border(1, p.border).
			Shadow(0, 12, 36, 0, ui.RGBA(0, 0, 0, 0.3)).
			Children(func() {
				ui.Column(c.Key("manage-rules-modal")).Gap(14).Children(func() {
					// Title & Close
					ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
						ui.Text(c, "黑白名单与规则订阅").FontSize(15).FontWeight(700).TextColor(p.text)
						btnClose := ui.ButtonBase(c.Key("btn-close-rules")).
							Label("btn-close-rules").
							Padding(4, 8, 4, 8).Radius(4).
							Background(p.surface).Border(1, p.borderSubtle).
							Children(func() {
								ui.Text(c, "关闭").FontSize(11).TextColor(p.textDim)
							})
						if btnClose.Clicked() {
							a.insightsShowManageRules = false
						}
					})

					// 1. User Allowlist
					ui.Column(c).Gap(6).Children(func() {
						ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
							ui.Text(c, "用户自定义白名单 (Allowlist)").FontSize(12).FontWeight(600).TextColor(p.text)
							tagPill(c, fmt.Sprintf("%d", len(a.state.BlockerAllowlist)), p.accentText, p.accentBg)
						})
						ui.Text(c, "白名单域名及其子域名将永久放行，具有最高豁免优先级").FontSize(10).TextColor(p.textDim)

						ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
							ui.TextInput(c.Key("input-add-allowlist"), &a.blockerAllowlistInput).
								Placeholder("输入域名 (如 example.com)").
								FontSize(11).Grow(1).
								Padding(5, 8, 5, 8).Radius(5).
								Background(p.surface).Border(1, p.borderSubtle)

							btnAdd := ui.ButtonBase(c.Key("btn-add-allowlist")).
								Label("btn-add-allowlist").
								Padding(5, 12, 5, 12).Radius(5).
								Background(p.accent).
								Children(func() {
									ui.Text(c, "+ 添加").FontSize(11).FontWeight(600).TextColor(white)
								})
							if btnAdd.Clicked() {
								if d := strings.TrimSpace(a.blockerAllowlistInput); d != "" {
									a.addBlockerAllowlist(d)
									a.blockerAllowlistInput = ""
								}
							}
						})

						// Chips
						ui.Row(c).Wrap().Gap(4).Children(func() {
							for _, dom := range a.state.BlockerAllowlist {
								d := dom
								ui.Row(c.Key("chip-allow-"+d)).
									AlignItems(ui.Center).Gap(4).
									Padding(2, 6, 2, 6).Radius(4).
									Background(p.surface).Border(1, p.borderSubtle).
									Children(func() {
										ui.Text(c, d).FontSize(10).TextColor(p.text)
										btnDel := ui.ButtonBase(c.Key("btn-del-allowlist-" + d)).
											Label("btn-del-allowlist-" + d).
											Radius(999).PaddingX(2).
											Background(ui.Transparent).
											Children(func() {
												ui.Text(c, "×").FontSize(10).FontWeight(700).TextColor(p.textDim)
											})
										if btnDel.Clicked() {
											a.removeBlockerAllowlist(d)
										}
									})
							}
						})
					})

					// 2. User Denylist
					ui.Column(c).Gap(6).Children(func() {
						ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
							ui.Text(c, "用户自定义黑名单 (Denylist)").FontSize(12).FontWeight(600).TextColor(p.text)
							tagPill(c, fmt.Sprintf("%d", len(a.state.BlockerDenylist)), p.red, p.redBg)
						})
						ui.Text(c, "黑名单域名及其子域名将直接阻断，无需消耗远端代理流量").FontSize(10).TextColor(p.textDim)

						ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
							ui.TextInput(c.Key("input-add-denylist"), &a.blockerDenylistInput).
								Placeholder("输入域名 (如 bad-tracker.com)").
								FontSize(11).Grow(1).
								Padding(5, 8, 5, 8).Radius(5).
								Background(p.surface).Border(1, p.borderSubtle)

							btnAdd := ui.ButtonBase(c.Key("btn-add-denylist")).
								Label("btn-add-denylist").
								Padding(5, 12, 5, 12).Radius(5).
								Background(p.red).
								Children(func() {
									ui.Text(c, "+ 拦截").FontSize(11).FontWeight(600).TextColor(white)
								})
							if btnAdd.Clicked() {
								if d := strings.TrimSpace(a.blockerDenylistInput); d != "" {
									a.addBlockerDenylist(d)
									a.blockerDenylistInput = ""
								}
							}
						})

						// Chips
						ui.Row(c).Wrap().Gap(4).Children(func() {
							for _, dom := range a.state.BlockerDenylist {
								d := dom
								ui.Row(c.Key("chip-deny-"+d)).
									AlignItems(ui.Center).Gap(4).
									Padding(2, 6, 2, 6).Radius(4).
									Background(p.surface).Border(1, p.borderSubtle).
									Children(func() {
										ui.Text(c, d).FontSize(10).TextColor(p.text)
										btnDel := ui.ButtonBase(c.Key("btn-del-denylist-" + d)).
											Label("btn-del-denylist-" + d).
											Radius(999).PaddingX(2).
											Background(ui.Transparent).
											Children(func() {
												ui.Text(c, "×").FontSize(10).FontWeight(700).TextColor(p.textDim)
											})
										if btnDel.Clicked() {
											a.removeBlockerDenylist(d)
										}
									})
							}
						})
					})

					// 3. External Rule Subscriptions
					ui.Column(c).Gap(6).Children(func() {
						ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
							ui.Text(c, "外部规则订阅 (URL)").FontSize(12).FontWeight(600).TextColor(p.text)
							tagPill(c, fmt.Sprintf("%d", len(a.state.BlockerSubscriptions)), p.textDim, p.surface)
						})
						ui.Text(c, "支持 hosts 格式、纯域名列表与 AdGuard/EasyList 基础语法").FontSize(10).TextColor(p.textDim)

						ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
							ui.TextInput(c.Key("input-add-sub"), &a.blockerSubscriptionInput).
								Placeholder("输入规则订阅 URL (https://...)").
								FontSize(11).Grow(1).
								Padding(5, 8, 5, 8).Radius(5).
								Background(p.surface).Border(1, p.borderSubtle)

							btnAdd := ui.ButtonBase(c.Key("btn-add-sub")).
								Label("btn-add-sub").
								Padding(5, 12, 5, 12).Radius(5).
								Background(p.accent).
								Children(func() {
									ui.Text(c, "+ 订阅").FontSize(11).FontWeight(600).TextColor(white)
								})
							if btnAdd.Clicked() {
								if s := strings.TrimSpace(a.blockerSubscriptionInput); s != "" {
									a.addBlockerSubscription(s)
									a.blockerSubscriptionInput = ""
								}
							}
						})

						// Subscriptions list
						for _, subURL := range a.state.BlockerSubscriptions {
							s := subURL
							ui.Row(c.Key("sub-item-"+s)).
								AlignItems(ui.Center).Justify(ui.SpaceBetween).
								Padding(4, 6, 4, 6).Radius(4).
								Background(p.surface).Border(1, p.borderSubtle).
								Children(func() {
									ui.Text(c, s).FontSize(10).TextColor(p.text).NoWrap().Grow(1)
									btnDel := ui.ButtonBase(c.Key("btn-del-sub-"+s)).
										Label("btn-del-sub-"+s).
										Padding(2, 6, 2, 6).Radius(4).
										Background(ui.Transparent).
										Children(func() {
											ui.Text(c, "删除").FontSize(10).TextColor(p.red)
										})
									if btnDel.Clicked() {
										a.removeBlockerSubscription(s)
									}
								})
						}
					})
				})
			})
	})
}

func ternaryColor(cond bool, a, b ui.Color) ui.Color {
	if cond {
		return a
	}
	return b
}
