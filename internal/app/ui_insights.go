package app

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/egoist/mygo/ui"

	"naive-client/internal/blocker"
	"naive-client/internal/routing"
	"naive-client/locales"
)

func (a *app) renderInsightsPage(c *ui.Context, p palette) {
	cat := a.catalog()
	activeRules := 0
	if a.blocker != nil {
		activeRules = a.blocker.RuleCount()
	}

	ui.Column(c.Key("insights-page")).Grow(1).Fill().MinHeight(0).Children(func() {
		// Header row: Title + quiet status dot summary | Protection & Ads Switches + Manage Rules button
		ui.Row(c.Key("insights-header")).
			Padding(14, 18, 14, 18).
			AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).
			Background(p.surface).
			BorderWidth(0, 0, 1, 0).BorderColor(p.borderSubtle).
			Children(func() {
				ui.Row(c).AlignItems(ui.Center).Gap(10).MinWidth(0).Shrink(1).Children(func() {
					ui.Text(c, cat.NavInsights()).FontSize(17).FontWeight(700).TextColor(p.text).NoWrap()

					ui.Row(c).AlignItems(ui.Center).Gap(6).MinWidth(0).Shrink(1).Children(func() {
						statusLabel := cat.InsightsProtectionPaused()
						if a.state.BlockerEnabled {
							statusDot(c, p.green)
							statusLabel = cat.InsightsProtectionActive()
						} else {
							hollowStatusDot(c, p.textDim.Alpha(0.5))
						}
						ui.Text(c, statusLabel).FontSize(12).TextColor(p.textMuted).NoWrap()
						ui.Text(c, "·").FontSize(12).TextColor(p.textDim).NoWrap()
						ui.Text(c, cat.InsightsRulesCountShort(activeRules)).
							FontSize(12).FontFeatures("tnum").TextColor(p.textMuted).SingleLine().Ellipsis("…")
					})
				})

				// Header Action Controls
				ui.Row(c).AlignItems(ui.Center).Gap(10).Shrink(0).Children(func() {
					ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
						ui.Text(c, cat.InsightsProtectionShort()).FontSize(12).TextColor(p.textMuted).NoWrap()
						blockerOn := a.state.BlockerEnabled
						if ui.Switch(c.Key("btn-toggle-blocker"), &blockerOn).
							Label("btn-toggle-blocker").
							Tooltip(cat.InsightsToggleProtectionTooltip()).
							Changed() {
							a.toggleBlockerEnabled()
						}
					})

					ui.Box(c).Size(1, 16).Background(p.borderSubtle).Shrink(0)

					ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
						ui.Text(c, cat.InsightsBuiltinAdsShort()).FontSize(12).TextColor(p.textMuted).NoWrap()
						adsOn := a.state.BlockerBlockAds
						if ui.Switch(c.Key("btn-toggle-ads"), &adsOn).
							Label("btn-toggle-ads").
							Tooltip(cat.InsightsToggleAdsTooltip()).
							Changed() {
							a.toggleBlockerBlockAds()
						}
					})

					btnRules := actionChip(c.Key("btn-manage-rules"), p, iconList, cat.InsightsRulesAndSubscriptions(), false).
						Label("btn-manage-rules").
						Tooltip(cat.InsightsManageRulesTooltip())
					if btnRules.Clicked() {
						a.insightsShowManageRules = !a.insightsShowManageRules
					}
				})
			})

		// Scrollable main content
		ui.Scroll(c.Key("insights-scroll")).Grow(1).Fill().MinHeight(0).Children(func() {
			ui.Column(c).Padding(16, 18, 22, 18).Gap(14).Children(func() {
				// 1. KPI Cards
				a.renderInsightsKPICards(c, p)

				// 2. 24-Hour Activity Trend Chart
				a.renderInsightsTrendChart(c, p)

				// 3. Top-10 Blocked & Allowed Rankings
				a.renderInsightsTopDomains(c, p)

				// 4. Failed Requests (FailureMonitor)
				a.renderInsightsFailures(c, p)

				// 5. Live Query Log
				a.renderInsightsQueryLogs(c, p)
			})
		})
	})
}

func (a *app) renderInsightsKPICards(c *ui.Context, p palette) {
	cat := a.catalog()
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
		a.renderKPICard(c, p, cat.InsightsKpi24hQueries(), fmt.Sprintf("%d", totalQueries), nil)
		a.renderKPICard(c, p, cat.InsightsKpiBlocked(), fmt.Sprintf("%d", totalBlocked), &p.red)
		a.renderKPICard(c, p, cat.InsightsKpiBlockRate(), fmt.Sprintf("%.1f%%", blockRate), &p.amber)
		a.renderKPICard(c, p, cat.InsightsKpiActiveRules(), fmt.Sprintf("%d", activeRules), &p.accent)
	})
}

func (a *app) renderKPICard(c *ui.Context, p palette, title, value string, dotCol *ui.Color) {
	ui.Column(c).Grow(1).MinWidth(0).
		Padding(12, 14, 12, 14).Radius(10).Gap(4).
		Background(p.card).Border(1, p.borderSubtle).
		Children(func() {
			ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
				if dotCol != nil {
					statusDot(c, *dotCol)
				}
				ui.Text(c, title).FontSize(11).TextColor(p.textDim).SingleLine().Ellipsis("…")
			})
			ui.Text(c, value).FontSize(19).FontWeight(700).FontFeatures("tnum").TextColor(p.text).SingleLine().Ellipsis("…")
		})
}

func (a *app) renderInsightsTrendChart(c *ui.Context, p palette) {
	if a.blocker == nil {
		return
	}
	cat := a.catalog()
	isEn := locales.ResolveLocale(a.state.Language) == locales.LangEn

	now := time.Now()
	buckets := a.blocker.Logger().Get24HourlyBuckets(now)

	var maxVal int64 = 1
	var total24h int64 = 0
	for _, b := range buckets {
		if b.Total > maxVal {
			maxVal = b.Total
		}
		total24h += b.Total
	}

	ui.Column(c.Key("insights-chart-card")).
		Padding(12, 14, 12, 14).Radius(10).
		Background(p.card).Border(1, p.borderSubtle).Gap(8).
		Children(func() {
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
					ui.Text(c, cat.InsightsTrendTitle()).FontSize(12).FontWeight(600).TextColor(p.text)
					if total24h > 0 {
						peakText := fmt.Sprintf("峰值: %d/时", maxVal)
						if isEn {
							peakText = fmt.Sprintf("Peak: %d/h", maxVal)
						}
						ui.Text(c, peakText).FontSize(11).FontFeatures("tnum").TextColor(p.textMuted)
					}
				})
				ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
					ui.Row(c).Gap(4).AlignItems(ui.Center).Children(func() {
						ui.Box(c).Size(8, 8).Radius(2).Background(p.accent)
						ui.Text(c, cat.InsightsTrendTotal()).FontSize(10).TextColor(p.textDim)
					})
					ui.Row(c).Gap(4).AlignItems(ui.Center).Children(func() {
						ui.Box(c).Size(8, 8).Radius(2).Background(p.red)
						ui.Text(c, cat.InsightsTrendBlocked()).FontSize(10).TextColor(p.textDim)
					})
				})
			})

			// Bar chart container
			const chartHeight float32 = 64
			const maxBarHeight float32 = 56

			ui.Row(c.Key("trend-bars-container")).
				Height(chartHeight).AlignItems(ui.End).Gap(2).
				Padding(4, 0, 0, 0).
				Children(func() {
					for idx, b := range buckets {
						bucket := b
						tip := cat.InsightsTrendTooltip(bucket.Hour.Format("15:04"), int(bucket.Total), int(bucket.Blocked))

						barCol := ui.Column(c.Key(fmt.Sprintf("bar-%d", idx))).
							Grow(1).Height(chartHeight).AlignItems(ui.Center).Justify(ui.End).
							Radius(3).Padding(2, 1, 2, 1).Clip().
							Tooltip(tip)

						if barCol.Hovered() {
							barCol.Background(p.elevated)
						}

						barCol.Children(func() {
							if bucket.Total == 0 {
								ui.Box(c).Fill().Height(2).Radius(1).Background(p.borderSubtle)
								return
							}

							totalHeight := float32(bucket.Total) / float32(maxVal) * maxBarHeight
							if totalHeight < 3 {
								totalHeight = 3
							}

							blockedHeight := float32(bucket.Blocked) / float32(maxVal) * maxBarHeight
							if bucket.Blocked > 0 && blockedHeight < 2 {
								blockedHeight = 2
							}
							if blockedHeight > totalHeight {
								blockedHeight = totalHeight
							}

							allowedHeight := totalHeight - blockedHeight
							if bucket.Total > bucket.Blocked && allowedHeight < 2 {
								allowedHeight = 2
								totalHeight = allowedHeight + blockedHeight
							}

							ui.Column(c).Fill().Height(totalHeight).Radius(2).Clip().Children(func() {
								if allowedHeight > 0 {
									ui.Box(c).Fill().Height(allowedHeight).Background(p.accent)
								}
								if blockedHeight > 0 {
									ui.Box(c).Fill().Height(blockedHeight).Background(p.red)
								}
							})
						})
					}
				})

			// X-Axis Time Labels
			nowLabel := "现在"
			if isEn {
				nowLabel = "Now"
			}
			ui.Row(c.Key("trend-x-axis")).Justify(ui.SpaceBetween).Padding(2, 2, 0, 2).Children(func() {
				ui.Text(c, buckets[0].Hour.Format("15:04")).FontSize(10).TextColor(p.textDim)
				ui.Text(c, buckets[6].Hour.Format("15:04")).FontSize(10).TextColor(p.textDim)
				ui.Text(c, buckets[12].Hour.Format("15:04")).FontSize(10).TextColor(p.textDim)
				ui.Text(c, buckets[18].Hour.Format("15:04")).FontSize(10).TextColor(p.textDim)
				ui.Text(c, nowLabel).FontSize(10).TextColor(p.textDim)
			})
		})
}

func (a *app) renderInsightsTopDomains(c *ui.Context, p palette) {
	if a.blocker == nil {
		return
	}
	cat := a.catalog()

	topBlocked := a.blocker.Logger().GetTopBlocked(10)
	topAllowed := a.blocker.Logger().GetTopAllowed(10)

	ui.Row(c.Key("insights-top-row")).AlignItems(ui.Stretch).Gap(10).Children(func() {
		// Top Blocked Panel
		ui.Column(c.Key("top-blocked-panel")).Grow(1).
			Label("panel-top-blocked").
			Padding(12, 14, 12, 14).Radius(10).
			Background(p.card).Border(1, p.borderSubtle).Gap(6).
			Children(func() {
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
					ui.Text(c, cat.InsightsTopBlockedTitle()).FontSize(12).FontWeight(600).TextColor(p.text)
					ui.Text(c, fmt.Sprintf("%d", len(topBlocked))).FontSize(11).FontFeatures("tnum").TextColor(p.textDim)
				})

				if len(topBlocked) == 0 {
					ui.Column(c).Grow(1).AlignItems(ui.Center).Justify(ui.Center).PaddingY(16).Children(func() {
						ui.Text(c, cat.InsightsTopBlockedEmpty()).FontSize(11).TextColor(p.textDim)
					})
				} else {
					for _, item := range topBlocked {
						dom := item.Domain
						cnt := item.Count
						ui.Row(c.Key("top-block-" + dom)).
							AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(8).
							PaddingY(3).
							Children(func() {
								ui.Text(c, dom).Font("monospace").FontSize(11).TextColor(p.text).Grow(1).SingleLine().Ellipsis("…").Tooltip(dom)
								ui.Row(c).AlignItems(ui.Center).Gap(8).Shrink(0).Children(func() {
									ui.Text(c, fmt.Sprintf("%d", cnt)).FontSize(11).FontWeight(600).FontFeatures("tnum").TextColor(p.red)
									btnAllow := ui.ButtonBase(c.Key("btn-quick-whitelist-"+dom)).
										Label("btn-quick-whitelist-"+dom).
										Padding(2, 6, 2, 6).Radius(4).
										Background(ui.Transparent).
										Tooltip(cat.InsightsActionWhitelistTooltip())
									if btnAllow.Hovered() {
										btnAllow.Background(p.elevated)
									}
									btnAllow.Children(func() {
										ui.Text(c, cat.InsightsActionWhitelist()).FontSize(11).FontWeight(500).TextColor(p.accentText)
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
			Padding(12, 14, 12, 14).Radius(10).
			Background(p.card).Border(1, p.borderSubtle).Gap(6).
			Children(func() {
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
					ui.Text(c, cat.InsightsTopAllowedTitle()).FontSize(12).FontWeight(600).TextColor(p.text)
					ui.Text(c, fmt.Sprintf("%d", len(topAllowed))).FontSize(11).FontFeatures("tnum").TextColor(p.textDim)
				})

				if len(topAllowed) == 0 {
					ui.Column(c).Grow(1).AlignItems(ui.Center).Justify(ui.Center).PaddingY(16).Children(func() {
						ui.Text(c, cat.InsightsTopAllowedEmpty()).FontSize(11).TextColor(p.textDim)
					})
				} else {
					for _, item := range topAllowed {
						dom := item.Domain
						cnt := item.Count
						ui.Row(c.Key("top-allow-" + dom)).
							AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(8).
							PaddingY(3).
							Children(func() {
								ui.Text(c, dom).Font("monospace").FontSize(11).TextColor(p.text).Grow(1).SingleLine().Ellipsis("…").Tooltip(dom)
								ui.Row(c).AlignItems(ui.Center).Gap(8).Shrink(0).Children(func() {
									ui.Text(c, fmt.Sprintf("%d", cnt)).FontSize(11).FontWeight(600).FontFeatures("tnum").TextColor(p.green)
									btnDeny := ui.ButtonBase(c.Key("btn-quick-denylist-"+dom)).
										Label("btn-quick-denylist-"+dom).
										Padding(2, 6, 2, 6).Radius(4).
										Background(ui.Transparent).
										Tooltip(cat.InsightsActionDenylistTooltip())
									if btnDeny.Hovered() {
										btnDeny.Background(p.redBg)
									}
									btnDeny.Children(func() {
										ui.Text(c, cat.InsightsActionDenylist()).FontSize(11).FontWeight(500).TextColor(p.red)
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
	cat := a.catalog()

	filtered, totalCount := a.blocker.Logger().GetFoldedEntries(a.insightsFilter, a.insightsSearch, 30)

	ui.Column(c.Key("insights-query-log-card")).
		Padding(12, 14, 12, 14).Radius(10).
		Background(p.card).Border(1, p.borderSubtle).Gap(8).
		Children(func() {
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(8).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Gap(8).MinWidth(0).Shrink(1).Children(func() {
					ui.Text(c, cat.InsightsQueryLogTitle()).FontSize(12).FontWeight(600).TextColor(p.text).NoWrap()
					ui.Text(c, cat.InsightsLogCount(totalCount)).FontSize(11).FontFeatures("tnum").TextColor(p.textDim).NoWrap()
				})

				ui.Row(c).AlignItems(ui.Center).Gap(8).Shrink(0).Children(func() {
					ui.SearchField(c.Key("input-search-query-logs"), &a.insightsSearch).
						Placeholder(cat.InsightsSearchPlaceholder()).
						Label(cat.InsightsSearchPlaceholder()).
						Width(176).Height(28).Radius(6).FontSize(11).
						Background(p.surface)

					// Segmented-track Filter Tabs (L2)
					filterKeys := []string{"", "blocked", "allowed"}
					filterIdx := 0
					for i, k := range filterKeys {
						if a.insightsFilter == k {
							filterIdx = i
							break
						}
					}
					filterOpts := []segmentedOption{
						{Label: cat.InsightsFilterAll(), A11yLabel: "btn-filter-all", ActiveColor: p.text},
						{Label: cat.InsightsFilterBlocked(), A11yLabel: "btn-filter-blocked", ActiveColor: p.red},
						{Label: cat.InsightsFilterAllowed(), A11yLabel: "btn-filter-allowed", ActiveColor: p.green},
					}
					if compactSegmentedOptions(c.Key("insights-log-filter-ctrl"), p, &filterIdx, filterOpts) {
						a.insightsFilter = filterKeys[filterIdx]
					}
				})
			})

			// Table header
			ui.Row(c).Padding(4, 6, 4, 6).Background(p.surface).Radius(6).AlignItems(ui.Center).Gap(8).Children(func() {
				ui.Text(c, cat.InsightsColTime()).FontSize(10).FontWeight(600).TextColor(p.textDim).Width(55)
				ui.Text(c, cat.InsightsColSource()).FontSize(10).FontWeight(600).TextColor(p.textDim).Width(84)
				ui.Text(c, cat.InsightsColVerdict()).FontSize(10).FontWeight(600).TextColor(p.textDim).Width(84)
				ui.Text(c, cat.InsightsColDuration()).FontSize(10).FontWeight(600).TextColor(p.textDim).Width(55)
				ui.Text(c, cat.InsightsColDomain()).FontSize(10).FontWeight(600).TextColor(p.textDim).Width(175)
				ui.Text(c, cat.InsightsColRule()).FontSize(10).FontWeight(600).TextColor(p.textDim).Grow(1).Shrink(1).MinWidth(0)
				ui.Text(c, cat.InsightsColAction()).FontSize(10).FontWeight(600).TextColor(p.textDim).Width(50).TextAlign(ui.End)
			})

			if len(filtered) == 0 {
				ui.Text(c, cat.InsightsQueryLogEmpty()).FontSize(11).TextColor(p.textDim).Padding(10, 6, 10, 6)
			} else {
				for _, entry := range filtered {
					e := entry.QueryLogEntry
					foldCount := entry.Count
					foldFirst := entry.First
					dom := e.Domain
					idStr := strconv.FormatInt(e.ID, 10)
					timeStr := e.Timestamp.Format("15:04:05")

					verdictFg := p.green
					if e.Verdict == blocker.VerdictBlocked {
						verdictFg = p.red
					} else if e.Verdict == blocker.VerdictWhitelisted {
						verdictFg = p.accentText
					}

					ui.Row(c.Key("log-row-" + idStr)).
						AlignItems(ui.Center).Padding(5, 6, 5, 6).
						BorderWidth(0, 0, 1, 0).BorderColor(p.borderSubtle.Alpha(0.5)).
						Gap(8).
						Children(func() {
							// Col 1: Time
							ui.Text(c, timeStr).FontSize(10).FontFeatures("tnum").TextColor(p.textDim).Width(55)

							// Col 2: Source / Application
							srcLabel := e.SourceDisplay()
							srcTip := e.SourceTooltip()
							srcColor := p.textMuted
							if e.Process != "" && srcLabel == e.Process {
								srcColor = p.text
							}
							ui.Row(c).Width(84).AlignItems(ui.Center).Tooltip(srcTip).Children(func() {
								ui.Text(c, srcLabel).FontSize(10).FontWeight(500).TextColor(srcColor).SingleLine().Ellipsis("…").Shrink(1).MinWidth(0)
							})

							// Col 3: Verdict (7px dot + label, no pill)
							ui.Row(c).Width(84).AlignItems(ui.Center).Gap(6).Children(func() {
								statusDot(c, verdictFg)
								ui.Text(c, string(e.Verdict)).FontSize(10).FontWeight(600).TextColor(verdictFg).SingleLine().Ellipsis("…")
							})

							// Col 4: Duration
							durStr := formatQueryDuration(e.Duration)
							if e.Duration <= 0 && e.Network == "udp" {
								durStr = "UDP"
							}
							durColor := queryDurationColor(e.Duration, p)
							ui.Text(c, durStr).FontSize(10).FontWeight(600).FontFeatures("tnum").TextColor(durColor).Width(55).NoWrap()

							// Col 5: Domain
							domTip := dom
							if foldCount > 1 {
								domTip = fmt.Sprintf("%s ×%d (%s – %s)", dom, foldCount, foldFirst.Format("15:04:05"), timeStr)
							}
							ui.Row(c).Width(175).AlignItems(ui.Center).Gap(4).Tooltip(domTip).Children(func() {
								ui.Text(c, dom).Font("monospace").FontSize(11).TextColor(p.text).SingleLine().Ellipsis("…").Shrink(1).MinWidth(0)
								if foldCount > 1 {
									ui.Text(c, fmt.Sprintf("×%d", foldCount)).FontSize(10).FontWeight(600).FontFeatures("tnum").TextColor(p.red).Shrink(0)
								}
							})

							// Col 6: Chain
							chainText := e.Chain
							if chainText == "" {
								chainText = e.Rule
							}
							if chainText == "" {
								chainText = "-"
							}
							errText := e.Error
							if errText == "" && !strings.Contains(chainText, "WARP") {
								if idx := strings.LastIndex(chainText, " ("); idx > 0 && strings.HasSuffix(chainText, ")") {
									errText = strings.TrimSuffix(chainText[idx+2:], ")")
									chainText = chainText[:idx]
								}
							}
							fullChain := chainText
							if errText != "" {
								fullChain = chainText + " (" + errText + ")"
							}
							ui.Row(c).Grow(1).Shrink(1).MinWidth(0).AlignItems(ui.Center).Gap(4).Tooltip(fullChain).Children(func() {
								if idx := strings.LastIndex(chainText, " -> "); idx >= 0 {
									prefix := chainText[:idx+4]
									target := chainText[idx+4:]
									ui.Text(c, prefix).FontSize(10).TextColor(p.textDim).SingleLine().Ellipsis("…").Shrink(1).MinWidth(0)
									isWarp := strings.Contains(target, "WARP") || strings.Contains(target, "Cloudflare")
									targetColor := p.textDim
									targetWeight := 400
									if isWarp {
										targetColor = p.amber
										targetWeight = 600
									}
									ui.Text(c, target).FontSize(10).FontWeight(targetWeight).TextColor(targetColor).SingleLine().Ellipsis("…").Shrink(0)
								} else if strings.Contains(chainText, "WARP") || strings.Contains(chainText, "Cloudflare") {
									ui.Text(c, chainText).FontSize(10).FontWeight(600).TextColor(p.amber).SingleLine().Ellipsis("…").Shrink(1).MinWidth(0)
								} else {
									ui.Text(c, chainText).FontSize(10).TextColor(p.textDim).SingleLine().Ellipsis("…").Shrink(1).MinWidth(0)
								}
								if errText != "" {
									ui.Text(c, "("+errText+")").FontSize(10).TextColor(p.red).SingleLine().Shrink(0)
								}
							})

							// Col 7: Quiet row action
							ui.Row(c).Width(50).AlignItems(ui.Center).Justify(ui.End).Children(func() {
								if e.Verdict == blocker.VerdictBlocked {
									btnW := ui.ButtonBase(c.Key("btn-log-whitelist-" + idStr)).
										Label("btn-log-whitelist-" + dom).
										Padding(2, 6, 2, 6).Radius(4).
										Background(ui.Transparent)
									if btnW.Hovered() {
										btnW.Background(p.elevated)
									}
									btnW.Children(func() {
										ui.Text(c, cat.InsightsActionWhitelist()).FontSize(11).FontWeight(500).TextColor(p.accentText)
									})
									if btnW.Clicked() {
										a.addBlockerAllowlist(dom)
									}
								} else {
									btnB := ui.ButtonBase(c.Key("btn-log-block-" + idStr)).
										Label("btn-log-block-" + dom).
										Padding(2, 6, 2, 6).Radius(4).
										Background(ui.Transparent)
									if btnB.Hovered() {
										btnB.Background(p.redBg)
									}
									btnB.Children(func() {
										ui.Text(c, cat.InsightsActionDenylist()).FontSize(11).FontWeight(500).TextColor(p.red)
									})
									if btnB.Clicked() {
										a.addBlockerDenylist(dom)
									}
								}
							})
						})
				}
			}
		})
}

func (a *app) renderInsightsManageRulesDrawer(c *ui.Context, p palette) {
	cat := a.catalog()
	ui.Overlay(c, func() {
		if !a.insightsShowManageRules {
			return
		}

		// Backdrop (fades in and out, click to dismiss)
		backdrop := ui.Box(c.Key("insights-rules-backdrop")).
			Absolute().Top(0).Left(0).Right(0).Bottom(0).
			Background(ui.RGBA(0, 0, 0, 0.35)).
			Transition(ui.ElementTransition{
				Enter: &ui.Motion{Opacity: 0},
				Exit:  &ui.Motion{Opacity: 0},
			})
		if backdrop.Clicked() {
			a.insightsShowManageRules = false
		}

		// Slide-over drawer panel anchored to right edge (460px unified width)
		panel := ui.Column(c.Key("insights-rules-panel")).
			Absolute().Top(0).Right(0).Bottom(0).Width(460).MaxWidthPercent(100).
			Modal().
			Transition(ui.ElementTransition{
				Enter: &ui.Motion{X: 460},
				Exit:  &ui.Motion{X: 460},
			}).
			Background(p.drawerBg).
			BorderWidth(0, 0, 0, 1).BorderColor(p.border).
			Shadow(0, 8, 36, 0, ui.RGBA(0, 0, 0, 0.4))

		if panel.OverlayShortcut(0, ui.KeyEscape) {
			a.insightsShowManageRules = false
		}

		panel.Children(func() {
			// Header
			ui.Row(c).
				AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(8).
				Padding(14, 20, 14, 20).
				BorderWidth(0, 0, 1, 0).BorderColor(p.borderSubtle).
				Children(func() {
					ui.Column(c).Grow(1).Shrink(1).MinWidth(0).Gap(2).Children(func() {
						ui.Text(c, cat.InsightsDrawerEyebrow()).FontSize(11).FontWeight(600).TextColor(p.textDim).NoWrap()
						ui.Text(c, cat.InsightsModalTitle()).FontSize(15).FontWeight(700).TextColor(p.text).
							SingleLine().Ellipsis("…")
					})

					closeBtn := quietRowIconButton(c.Key("btn-close-rules"), p, iconClose, "btn-close-rules", false, false).
						Tooltip(cat.InsightsModalClose())
					if closeBtn.Clicked() {
						a.insightsShowManageRules = false
					}
				})

			// Scrollable drawer body
			ui.Scroll(c.Key("insights-rules-scroll")).
				TrackScroll(&a.insightsRulesScroll).
				Grow(1).Fill().
				Background(p.surface).
				Padding(16, 20, 20, 20).
				Gap(12).
				Children(func() {
					// 1. User Allowlist
					editorSectionCard(c, p, func() {
						ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
							ui.Text(c, cat.InsightsAllowlistTitle()).FontSize(12).FontWeight(600).TextColor(p.text)
							ui.Text(c, fmt.Sprintf("%d", len(a.state.BlockerAllowlist))).FontSize(11).FontFeatures("tnum").TextColor(p.textDim)
						})
						ui.Text(c, cat.InsightsAllowlistDesc()).FontSize(11).TextColor(p.textMuted)

						ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
							ui.TextInput(c.Key("input-add-allowlist"), &a.blockerAllowlistInput).
								Placeholder(cat.InsightsAllowlistPlaceholder()).
								FontSize(12).Grow(1)

							if primaryPillButton(c.Key("btn-add-allowlist"), p, nil, cat.InsightsActionAdd(), p.accent, false).
								Label("btn-add-allowlist").Height(30).Clicked() {
								if d := strings.TrimSpace(a.blockerAllowlistInput); d != "" {
									a.addBlockerAllowlist(d)
									a.blockerAllowlistInput = ""
								}
							}
						})

						if len(a.state.BlockerAllowlist) > 0 {
							ui.Row(c).Wrap().Gap(6).Children(func() {
								for _, dom := range a.state.BlockerAllowlist {
									d := dom
									ui.Row(c.Key("chip-allow-"+d)).
										AlignItems(ui.Center).Gap(4).
										Padding(3, 8, 3, 8).Radius(6).
										Background(p.elevated).
										Children(func() {
											ui.Text(c, d).Font("monospace").FontSize(11).TextColor(p.text)
											btnDel := ui.ButtonBase(c.Key("btn-del-allowlist-" + d)).
												Label("btn-del-allowlist-" + d).
												Radius(999).PaddingX(2).
												Background(ui.Transparent).
												Children(func() {
													ui.Text(c, "×").FontSize(11).FontWeight(700).TextColor(p.textDim)
												})
											if btnDel.Clicked() {
												a.removeBlockerAllowlist(d)
											}
										})
								}
							})
						}
					})

					// 2. User Denylist
					editorSectionCard(c, p, func() {
						ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
							ui.Text(c, cat.InsightsDenylistTitle()).FontSize(12).FontWeight(600).TextColor(p.text)
							ui.Text(c, fmt.Sprintf("%d", len(a.state.BlockerDenylist))).FontSize(11).FontFeatures("tnum").TextColor(p.red)
						})
						ui.Text(c, cat.InsightsDenylistDesc()).FontSize(11).TextColor(p.textMuted)

						ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
							ui.TextInput(c.Key("input-add-denylist"), &a.blockerDenylistInput).
								Placeholder(cat.InsightsDenylistPlaceholder()).
								FontSize(12).Grow(1)

							if primaryPillButton(c.Key("btn-add-denylist"), p, nil, cat.InsightsActionDenylist(), p.red, false).
								Label("btn-add-denylist").Height(30).Clicked() {
								if d := strings.TrimSpace(a.blockerDenylistInput); d != "" {
									a.addBlockerDenylist(d)
									a.blockerDenylistInput = ""
								}
							}
						})

						if len(a.state.BlockerDenylist) > 0 {
							ui.Row(c).Wrap().Gap(6).Children(func() {
								for _, dom := range a.state.BlockerDenylist {
									d := dom
									ui.Row(c.Key("chip-deny-"+d)).
										AlignItems(ui.Center).Gap(4).
										Padding(3, 8, 3, 8).Radius(6).
										Background(p.elevated).
										Children(func() {
											ui.Text(c, d).Font("monospace").FontSize(11).TextColor(p.text)
											btnDel := ui.ButtonBase(c.Key("btn-del-denylist-" + d)).
												Label("btn-del-denylist-" + d).
												Radius(999).PaddingX(2).
												Background(ui.Transparent).
												Children(func() {
													ui.Text(c, "×").FontSize(11).FontWeight(700).TextColor(p.textDim)
												})
											if btnDel.Clicked() {
												a.removeBlockerDenylist(d)
											}
										})
								}
							})
						}
					})

					// 3. External Rule Subscriptions
					editorSectionCard(c, p, func() {
						ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
							ui.Text(c, cat.InsightsSubscriptionsTitle()).FontSize(12).FontWeight(600).TextColor(p.text)
							ui.Text(c, fmt.Sprintf("%d", len(a.state.BlockerSubscriptions))).FontSize(11).FontFeatures("tnum").TextColor(p.textDim)
						})
						ui.Text(c, cat.InsightsSubscriptionsDesc()).FontSize(11).TextColor(p.textMuted)

						ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
							ui.TextInput(c.Key("input-add-sub"), &a.blockerSubscriptionInput).
								Placeholder(cat.InsightsSubscriptionsPlaceholder()).
								FontSize(12).Grow(1)

							if primaryPillButton(c.Key("btn-add-sub"), p, nil, cat.InsightsActionSubscribe(), p.accent, false).
								Label("btn-add-sub").Height(30).Clicked() {
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
								AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(8).
								Padding(6, 10, 6, 10).Radius(8).
								Background(p.surface).Border(1, p.borderSubtle).
								Children(func() {
									ui.Text(c, s).Font("monospace").FontSize(11).TextColor(p.text).SingleLine().Ellipsis("…").Grow(1).Shrink(1).MinWidth(0)
									btnDel := ui.ButtonBase(c.Key("btn-del-sub-"+s)).
										Label("btn-del-sub-"+s).
										Padding(2, 6, 2, 6).Radius(4).
										Background(ui.Transparent)
									if btnDel.Hovered() {
										btnDel.Background(p.redBg)
									}
									btnDel.Children(func() {
										ui.Text(c, cat.InsightsActionDelete()).FontSize(11).TextColor(p.red)
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

func (a *app) openCreateRuleDialogWithTarget(target string, recommendedAction string) {
	actionIdx := 0 // Proxy by default
	if recommendedAction == "DIRECT" {
		actionIdx = 1
	} else if recommendedAction == "BLOCK" {
		actionIdx = 2
	}
	a.activeTab = TabRouting
	a.ruleEditor = ruleEditorForm{
		open:           true,
		isNew:          true,
		ruleID:         fmt.Sprintf("rule-%d", len(a.state.RoutingRules)+1),
		name:           "分流修复: " + target,
		actionIndex:     actionIdx,
		dispatchPolicy:  routing.DispatchSmart,
		strictIsolation: true,
		domainsInput:    target,
		tab:            1, // Custom domains tab
	}
	if a.win != nil {
		a.win.Invalidate()
	}
}

const maxInsightsFailures = 5

func (a *app) renderInsightsFailures(c *ui.Context, p palette) {
	if a.failureMonitor == nil {
		return
	}
	failures := a.failureMonitor.ListUnresolved()
	totalCount := len(failures)
	if totalCount == 0 {
		return
	}
	white := ui.RGB(255, 255, 255)

	displayList := failures
	if len(displayList) > maxInsightsFailures {
		displayList = displayList[:maxInsightsFailures]
	}

	ui.Column(c.Key("insights-failures-card")).
		Padding(12, 14, 12, 14).Radius(10).
		Background(p.card).Border(1, p.borderSubtle).Gap(8).
		Children(func() {
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
					statusDot(c, p.red)
					ui.Text(c, "异常连接与分流诊断").FontSize(12).FontWeight(600).TextColor(p.text)
					ui.Text(c, fmt.Sprintf("共 %d 项异常", totalCount)).FontSize(11).FontFeatures("tnum").TextColor(p.red)
				})

				btnResolveAll := ui.ButtonBase(c.Key("btn-resolve-all-failures")).
					Label("btn-resolve-all-failures").
					Padding(3, 8, 3, 8).Radius(5).
					Background(ui.Transparent)
				if btnResolveAll.Hovered() {
					btnResolveAll.Background(p.elevated)
				}
				btnResolveAll.Children(func() {
					ui.Text(c, "全部忽略").FontSize(11).TextColor(p.textMuted)
				})
				if btnResolveAll.Clicked() {
					a.failureMonitor.ResolveAll()
					if a.win != nil {
						a.win.Invalidate()
					}
				}
			})

			for idx, f := range displayList {
				item := f
				itemKey := fmt.Sprintf("%s-%d", item.Target, idx)
				ui.Row(c.Key("failure-item-" + itemKey)).
					AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(8).
					Padding(8, 10, 8, 10).Radius(8).
					Background(p.surface).Border(1, p.borderSubtle).
					Children(func() {
						ui.Column(c).Gap(2).Grow(1).MinWidth(0).Children(func() {
							ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
								ui.Text(c, item.Target).Font("monospace").FontSize(11).FontWeight(600).TextColor(p.text)
								drawerInlineNeutralChip(c, p, string(item.Category))
								ui.Text(c, fmt.Sprintf("失败 %d 次", item.FailCount)).FontSize(10).FontFeatures("tnum").TextColor(p.textDim)
							})
							if item.LastError != "" {
								ui.Text(c, item.LastError).FontSize(10).TextColor(p.textDim).SingleLine().Ellipsis("…")
							}
						})

						ui.Row(c).AlignItems(ui.Center).Gap(4).Shrink(0).Children(func() {
							btnFix := ui.ButtonBase(c.Key("btn-fix-" + itemKey)).
								Label("btn-fix-" + item.Target).
								Padding(4, 8, 4, 8).Radius(5).
								Background(p.accent)
							if btnFix.Hovered() {
								btnFix.Background(p.accent.Alpha(0.88))
							}
							btnFix.Children(func() {
								ui.Text(c, "快速分流").FontSize(11).FontWeight(600).TextColor(white)
							})
							if btnFix.Clicked() {
								a.openCreateRuleDialogWithTarget(item.Target, item.RecommendedAction)
							}

							btnResolve := ui.ButtonBase(c.Key("btn-resolve-" + itemKey)).
								Label("btn-resolve-" + item.Target).
								Padding(4, 8, 4, 8).Radius(5).
								Background(ui.Transparent)
							if btnResolve.Hovered() {
								btnResolve.Background(p.elevated)
							}
							btnResolve.Children(func() {
								ui.Text(c, "忽略").FontSize(11).TextColor(p.textMuted)
							})
							if btnResolve.Clicked() {
								a.failureMonitor.Resolve(item.Target)
								if a.win != nil {
									a.win.Invalidate()
								}
							}
						})
					})
			}

			if totalCount > len(displayList) {
				ui.Row(c).Justify(ui.Center).PaddingY(2).Children(func() {
					ui.Text(c, fmt.Sprintf("已显示前 %d 项，还有 %d 项异常", len(displayList), totalCount-len(displayList))).
						FontSize(10).FontFeatures("tnum").TextColor(p.textDim)
				})
			}
		})
}

func formatQueryDuration(d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	if d < time.Millisecond {
		return fmt.Sprintf("%dµs", d.Microseconds())
	}
	if d < 100*time.Millisecond {
		ms := float64(d.Microseconds()) / 1000.0
		return fmt.Sprintf("%.1fms", ms)
	}
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}

func queryDurationColor(d time.Duration, p palette) ui.Color {
	if d <= 0 {
		return p.textDim
	}
	if d < 200*time.Millisecond {
		return p.green
	}
	if d < 800*time.Millisecond {
		return p.amber
	}
	return p.red
}
