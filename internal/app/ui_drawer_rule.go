package app

import (
	"fmt"
	"strings"

	"github.com/egoist/mygo/ui"

	"naive-client/internal/routing"
)

func (a *app) renderRuleDrawer(c *ui.Context, p palette) {
	if a.activeRuleDrawerID == "" {
		return
	}

	cat := a.catalog()
	hasGeo := a.hasGeoData()
	var runningIDs map[string]bool
	if a.mgr != nil {
		runningIDs = a.mgr.RunningServiceIDs()
	}

	var targetRule routing.Rule
	ruleIndex := -1
	isFinal := false

	if a.activeRuleDrawerID == "final" {
		isFinal = true
		targetRule = routing.Rule{
			ID:          "final",
			Name:        cat.RoutingFinalFallback(),
			Description: cat.RoutingFinalDesc(),
			Enabled:     true,
			Action:      a.state.RoutingFinal,
		}
	} else {
		for i, r := range a.state.RoutingRules {
			if r.ID == a.activeRuleDrawerID {
				targetRule = r
				ruleIndex = i
				break
			}
		}
		if ruleIndex == -1 {
			a.activeRuleDrawerID = ""
			return
		}
	}

	dsDrawerShell(c, p, dsDrawerSpec{
		BackdropKey: "rule-drawer-backdrop",
		PanelKey:    "rule-drawer-panel",
		OnDismiss:   func() { a.activeRuleDrawerID = "" },
	}, func() {
			// Header aligned with ui_drawer_node.go
			statusText := cat.StatusStopped()
			statusCol := p.textDim
			if isFinal {
				statusText = "FINAL"
				statusCol = p.accentText
			} else if targetRule.Enabled {
				statusText = cat.StatusRunning()
				statusCol = p.green
			}

			ui.Row(c).
				AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(10).
				Padding(14, 20, 14, 20).
				BorderWidth(0, 0, 1, 0).BorderColor(p.borderSubtle).
				Children(func() {
					// Left: eyebrow + dot & rule name
					ui.Column(c).Grow(1).Shrink(1).MinWidth(0).Gap(4).Children(func() {
						dsDetailHeaderEyebrow(c, p, cat.RuleDrawerTitle(), statusText, statusCol)
						ui.Row(c).AlignItems(ui.Center).Gap(8).MinWidth(0).Children(func() {
							if targetRule.Enabled || isFinal {
								statusDot(c, p.green)
							} else {
								hollowStatusDot(c, p.textDim.Alpha(0.5))
							}
							ui.Text(c, a.localizedRuleName(targetRule)).FontSize(15).FontWeight(700).TextColor(p.text).
								SingleLine().Ellipsis("…").Shrink(1).MinWidth(0)
						})
					})

					// Right: Edit | Quick Switch (non-final) + Close
					ui.Row(c).AlignItems(ui.Center).Gap(4).Shrink(0).Children(func() {
						editBtn := subtleActionChip(c.Key("btn-drawer-edit-rule"), p, iconEdit, cat.ActionEdit(), false).
							Label(cat.RuleDrawerEdit()).
							Tooltip(cat.RuleDrawerEdit())
						if editBtn.Clicked() {
							if isFinal {
								a.openEditFinalRuleFromDrawer()
							} else {
								a.openEditRuleFromDrawer(targetRule)
							}
						}

						if !isFinal {
							ui.Box(c).Size(1, 16).Background(p.borderSubtle).Margin(0, 4, 0, 4).Shrink(0)
							enabled := targetRule.Enabled
							if ui.Switch(c.Key("drawer-toggle-rule"), &enabled).Label("drawer-toggle-rule").Changed() {
								if isCategoryAdsBlockRule(targetRule) {
									a.setBlockerBlockAds(enabled)
									if enabled {
										a.toast("已启用内置广告拦截")
									} else {
										a.toast("已关闭内置广告拦截")
									}
								} else {
									a.state.RoutingRules[ruleIndex].Enabled = enabled
									a.saveState()
								}
							}
						}

						closeBtn := quietRowIconButton(c.Key("btn-drawer-close-rule"), p, iconClose, cat.RuleDrawerClose(), false, false).
							Tooltip(cat.RuleDrawerClose())
						if closeBtn.Clicked() {
							a.activeRuleDrawerID = ""
						}
					})
				})

			// Body: Scrollable section cards
			dsDetailBody(c, p, "rule-drawer-scroll", nil, func() {
				// 1. Basic Info Section
				dsDetailCard(c, p, func() {
					dsDetailSectionTitle(c, p, cat.RuleDrawerBasic())
					if desc := a.localizedRuleDescription(targetRule); desc != "" {
						ui.Text(c, desc).FontSize(12).TextColor(p.textMuted).LineHeight(1.45)
					}
					dsDetailKvGroup(c, func() {
						if !isFinal {
							dsDetailKvRow(c, p, cat.RuleDrawerRuleID(), targetRule.ID, true, false, p.text, "")
						} else {
							dsDetailKvRow(c, p, cat.RuleDrawerRuleID(), "FINAL", true, false, p.accentText, "")
						}
					})
				})

				// 2. Outbound Action & Scheduling Section
				dsDetailCard(c, p, func() {
					dsDetailSectionTitle(c, p, cat.RuleDrawerAction())

					switch targetRule.Action.Type {
					case routing.ActionBlock:
						dsDetailKvGroup(c, func() {
							dsDetailKvRow(c, p, cat.RuleActionLabel(), cat.RoutingBlock(), false, false, p.red, "")
						})
						ui.Text(c, cat.RuleDrawerDescBlock()).FontSize(11).TextColor(p.textMuted).LineHeight(1.4)

					case routing.ActionDirect:
						dsDetailKvGroup(c, func() {
							dsDetailKvRow(c, p, cat.RuleActionLabel(), cat.RoutingDirect(), false, false, p.text, "")
							dsDetailKvRow(c, p, "DNS", cat.DnsDomesticBadge(), false, false, p.textMuted, "")
						})
						ui.Text(c, cat.RuleDrawerDescDirect()).FontSize(11).TextColor(p.textMuted).LineHeight(1.4)

					default:
						targets := targetRule.Action.NormalizedTargets()
						res := a.resolveActionTargets(targetRule.Action, runningIDs)
						isDirectWarp := !isFinal && isSingleWarpTarget(targetRule.Action) && isRuleDomesticDNS(targetRule)

						dsDetailKvGroup(c, func() {
							actionLabel := cat.RoutingProxy()
							if isDirectWarp {
								actionLabel = cat.RoutingWarp()
							}
							dsDetailKvRow(c, p, cat.RuleActionLabel(), actionLabel, false, false, p.text, "")

							dnsLabel := cat.DnsRemoteBadge()
							if !isFinal && isRuleDomesticDNS(targetRule) {
								dnsLabel = cat.DnsDomesticBadge()
							}
							dsDetailKvRow(c, p, "DNS", dnsLabel, false, false, p.textMuted, "")

							if len(targets) == 0 {
								dsDetailKvRow(c, p, cat.RuleDrawerTargetsTitle(), cat.RoutingProxyPool(), false, false, p.text, "")
								activeCount := res.OnlineCount
								if activeCount == 0 && !a.isBuiltinWarpNeeded() {
									activeCount = a.activeRunningCount()
								}
								if activeCount > 0 {
									dsDetailKvRow(c, p, cat.RuleDrawerActiveNodes(), cat.RuleDrawerNodesOnline(fmt.Sprint(activeCount)), false, true, p.green, "")
								} else {
									dsDetailKvRow(c, p, cat.RuleDrawerActiveNodes(), cat.RuleDrawerNoNodesOnline(), false, true, p.amber, "")
								}
							} else {
								isOrder := targetRule.Action.EffectiveDispatchPolicy() == routing.DispatchOrder
								var targetParts []string
								for _, t := range targets {
									if t.Kind == routing.TargetNode {
										if svc, ok := a.serviceOrBuiltinWarp(t.Value); ok {
											part := svc.Name
											if svc.EnableWARP {
												part += " +WARP"
											}
											targetParts = append(targetParts, part)
										} else {
											targetParts = append(targetParts, t.Value+" ("+cat.RuleTargetMissingNode()+")")
										}
									} else {
										targetParts = append(targetParts, "#"+t.Value)
									}
								}
								sep := ", "
								if isOrder && len(targets) > 1 {
									sep = " → "
								}
								targetSummary := strings.Join(targetParts, sep)
								targetCol := p.text
								if len(res.MissingNodeIDs) > 0 {
									targetCol = p.amber
								}
								dsDetailKvRow(c, p, cat.RuleDrawerTargetsTitle(), targetSummary, false, false, targetCol, targetSummary)

								dispatchLabel := cat.RuleDispatchSmart()
								if isOrder {
									dispatchLabel = cat.RuleDispatchOrder()
								}
								if targetRule.Action.FallbackToPool {
									dispatchLabel += " · " + cat.RuleTargetFallbackBadge()
								} else {
									dispatchLabel += " · " + cat.RuleTargetStrictBadge()
								}
								dsDetailKvRow(c, p, cat.RuleDrawerDispatchTitle(), dispatchLabel, false, false, p.textMuted, "")

								if res.OnlineCount > 0 {
									dsDetailKvRow(c, p, cat.RuleDrawerActiveNodes(), cat.RuleDrawerNodesOnline(fmt.Sprint(res.OnlineCount)), false, true, p.green, "")
								} else {
									dsDetailKvRow(c, p, cat.RuleDrawerActiveNodes(), cat.RuleDrawerNoNodesOnline(), false, true, p.amber, "")
								}
							}
						})

						if len(targets) == 0 {
							activeCount := res.OnlineCount
							if activeCount == 0 && !a.isBuiltinWarpNeeded() {
								activeCount = a.activeRunningCount()
							}
							if activeCount > 0 {
								ui.Text(c, cat.RuleDrawerDescProxyPool()).FontSize(11).TextColor(p.textMuted).LineHeight(1.4)
							} else {
								ui.Text(c, cat.RuleDrawerDescProxyPoolEmpty()).FontSize(11).TextColor(p.amber).LineHeight(1.4)
							}
						} else if isDirectWarp {
							ui.Text(c, cat.RuleDrawerDescWarp()).FontSize(11).TextColor(p.textMuted).LineHeight(1.4)
						}

						if len(res.OnlineNodes) > 0 {
							ui.Column(c).Gap(6).Padding(8, 0, 0, 0).BorderWidth(1, 0, 0, 0).BorderColor(p.borderSubtle).Children(func() {
								ui.Text(c, cat.RuleDrawerCandidatesTitle()).FontSize(11).FontWeight(500).TextColor(p.textDim)
								ui.Row(c).AlignItems(ui.Center).Gap(6).Wrap().Children(func() {
									for _, svc := range res.OnlineNodes {
										renderRuleCriteriaChip(c, p, svc.Name, true)
									}
								})
							})
						}
					}
				})

				// 3. Routing Criteria Section
				dsDetailCard(c, p, func() {
					hasGeoCriteria := len(targetRule.GeoSite) > 0 || len(targetRule.GeoIP) > 0
					ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
						dsDetailSectionTitle(c, p, cat.RuleDrawerCriteria())
						if hasGeoCriteria {
							if hasGeo {
								ui.Text(c, cat.GeodataStatusReady()).FontSize(11).FontWeight(500).TextColor(p.green)
							} else {
								ui.Text(c, cat.RulePendingGeoData()).FontSize(11).FontWeight(500).TextColor(p.amber)
							}
						}
					})

					hasAnyCriteria := false
					ui.Column(c).Gap(10).Children(func() {
						renderCriteriaGroup := func(title string, items []string, prefix, suffix string) {
							if len(items) == 0 {
								return
							}
							hasAnyCriteria = true
							ui.Column(c).Gap(6).Children(func() {
								ui.Text(c, fmt.Sprintf("%s (%d)", title, len(items))).
									FontSize(11).FontWeight(500).FontFeatures("tnum").TextColor(p.textMuted)
								ui.Row(c).AlignItems(ui.Center).Gap(6).Wrap().Children(func() {
									for _, item := range items {
										renderRuleCriteriaChip(c, p, prefix+item+suffix, true)
									}
								})
							})
						}

						if len(targetRule.GeoSite) > 0 {
							hasAnyCriteria = true
							ui.Column(c).Gap(6).Children(func() {
								dsDetailSubTitle(c, p, cat.RuleDrawerGeoSiteTitle())
								ui.Row(c).AlignItems(ui.Center).Gap(6).Wrap().Children(func() {
									for _, gs := range targetRule.GeoSite {
										renderRuleCriteriaChip(c, p, "geosite:"+gs, true)
									}
								})
							})
						}
						if len(targetRule.GeoIP) > 0 {
							hasAnyCriteria = true
							ui.Column(c).Gap(6).Children(func() {
								dsDetailSubTitle(c, p, cat.RuleDrawerGeoIPTitle())
								ui.Row(c).AlignItems(ui.Center).Gap(6).Wrap().Children(func() {
									for _, gi := range targetRule.GeoIP {
										renderRuleCriteriaChip(c, p, "geoip:"+gi, true)
									}
								})
							})
						}
						renderCriteriaGroup(cat.RuleDrawerDomainFullTitle(), targetRule.DomainFull, "", "")
						renderCriteriaGroup(cat.RuleDrawerDomainSuffixTitle(), targetRule.DomainSuffix, "", "")
						renderCriteriaGroup(cat.RuleDrawerIPCidrTitle(), targetRule.IPCidr, "", "")
						renderCriteriaGroup(cat.RuleDrawerKeywordTitle(), targetRule.DomainKeyword, "*", "*")

						if !hasAnyCriteria {
							ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
								renderRuleCriteriaChip(c, p, "MATCH: *", true)
								ui.Text(c, cat.RuleDrawerNoCriteria()).FontSize(11).TextColor(p.textMuted).Grow(1).Shrink(1).MinWidth(0)
							})
						}
					})
				})
			})
		})
}

func renderRuleCriteriaChip(c *ui.Context, p palette, text string, mono bool) {
	ui.Row(c).AlignItems(ui.Center).PaddingX(8).PaddingY(3).Radius(6).
		Background(p.elevated).
		Children(func() {
			t := ui.Text(c, text).FontSize(11).TextColor(p.text)
			if mono {
				t.Font("monospace")
			}
		})
}
