package app

import (
	"fmt"
	"strings"

	"github.com/egoist/mygo/ui"

	"naive-client/internal/routing"
	"naive-client/internal/runner"
)

func (a *app) renderRuleDrawer(c *ui.Context, p palette) {
	if a.activeRuleDrawerID == "" {
		return
	}

	cat := a.catalog()
	hasGeo := a.hasGeoData()

	var targetRule routing.Rule
	var ruleIndex int = -1
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

	// Backdrop (fades in and out, click to dismiss)
	backdrop := ui.Box(c.Key("rule-drawer-backdrop")).
		Absolute().Top(0).Left(0).Right(0).Bottom(0).
		Background(ui.RGBA(0, 0, 0, 0.3)).
		Transition(ui.ElementTransition{
			Enter: &ui.Motion{Opacity: 0},
			Exit:  &ui.Motion{Opacity: 0},
		})
	if backdrop.Clicked() {
		a.activeRuleDrawerID = ""
	}

	// Slide-over drawer panel anchored to right edge
	ui.Column(c.Key("rule-drawer-panel")).
		Absolute().Top(0).Right(0).Bottom(0).Width(460).
		Transition(ui.ElementTransition{
			Enter: &ui.Motion{X: 460},
			Exit:  &ui.Motion{X: 460},
		}).
		Padding(20).Gap(16).
		Background(p.drawerBg).
		BorderWidth(0, 0, 0, 1).BorderColor(p.border).
		Shadow(0, 8, 36, 0, ui.RGBA(0, 0, 0, 0.4)).
		Children(func() {
			// Header
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
					ui.Text(c, cat.RuleDrawerTitle()).FontSize(15).FontWeight(700).TextColor(p.text)
					if isFinal {
						tagPill(c, "FINAL", p.accentText, p.accentBg)
					} else if targetRule.Enabled {
						tagPill(c, cat.StatusRunning(), p.green, p.greenBg)
					} else {
						tagPill(c, cat.StatusStopped(), p.textMuted, p.elevated)
					}
				})

				ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
					if subtleActionChip(c.Key("btn-drawer-edit-rule"), p, iconEdit, cat.RuleDrawerEdit(), false).Clicked() {
						targetID := a.activeRuleDrawerID
						a.activeRuleDrawerID = ""
						if targetID == "final" {
							a.openEditFinalRuleDialog()
						} else {
							a.openEditRuleDialog(targetRule)
						}
					}
					if subtleActionChip(c.Key("btn-drawer-close-rule"), p, iconClose, cat.RuleDrawerClose(), false).Clicked() {
						a.activeRuleDrawerID = ""
					}
				})
			})

			// Body: Scrollable content
			ui.Scroll(c.Key("rule-drawer-scroll")).Grow(1).Fill().Children(func() {
				ui.Column(c).Gap(16).Children(func() {
					// 1. Basic Info Section
					ui.Column(c).Gap(8).Padding(14).Radius(10).
						Background(p.card).Border(1, p.borderSubtle).
						Children(func() {
							ui.Text(c, cat.RuleDrawerBasic()).FontSize(12).FontWeight(700).TextColor(p.textDim)
							ui.Text(c, a.localizedRuleName(targetRule)).FontSize(16).FontWeight(700).TextColor(p.text)
							if desc := a.localizedRuleDescription(targetRule); desc != "" {
								ui.Text(c, desc).FontSize(12).TextColor(p.textMuted).LineHeight(1.4)
							}
							if !isFinal {
								ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
									ui.Text(c, cat.RuleDrawerRuleID()+":").FontSize(11).TextColor(p.textDim)
									ui.Text(c, targetRule.ID).FontSize(11).TextColor(p.textMuted)
								})
							}
						})

					// 2. Outbound Action Section
					ui.Column(c).Gap(8).Padding(14).Radius(10).
						Background(p.card).Border(1, p.borderSubtle).
						Children(func() {
							ui.Text(c, cat.RuleDrawerAction()).FontSize(12).FontWeight(700).TextColor(p.textDim)

							switch targetRule.Action.Type {
							case routing.ActionBlock:
								statusBadge(c, cat.RoutingBlock(), p.red, p.redBg)
								ui.Text(c, cat.RuleDrawerDescBlock()).FontSize(11).TextColor(p.textMuted)

							case routing.ActionDirect:
								statusBadge(c, cat.RoutingDirect(), p.textDim, p.elevated)
								ui.Text(c, cat.RuleDrawerDescDirect()).FontSize(11).TextColor(p.textMuted)

							case routing.ActionProxyTag:
								tags := targetRule.Action.GetTags()
								activeNodes := a.activeNodesForTags(tags)
								var tagLabels []string
								for _, t := range tags {
									tagLabels = append(tagLabels, "#"+t)
								}
								tagDisplay := strings.Join(tagLabels, ", ")
								if tagDisplay == "" {
									tagDisplay = "#Proxy"
								}

								if activeNodes > 0 {
									statusBadge(c, fmt.Sprintf("%s (%d 在线)", tagDisplay, activeNodes), p.accentText, p.accentBg)
								} else {
									statusBadge(c, fmt.Sprintf("%s (0 在线)", tagDisplay), p.amber, p.amberBg)
								}

								// Matched tags & online nodes
								ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
									ui.Text(c, cat.RuleDrawerActionTags()+":").FontSize(12).FontWeight(600).TextColor(p.text)
									for _, t := range tags {
										tagPill(c, "#"+t, p.accentText, p.accentBg)
									}
								})

								if activeNodes > 0 {
									ui.Text(c, cat.RuleDrawerNodesOnline(fmt.Sprint(activeNodes))).FontSize(11).TextColor(p.accentText)
									var matchedNames []string
									for _, svc := range a.state.Services {
										if a.mgr != nil && a.mgr.StatusOf(svc.ID).State == runner.StateRunning {
											for _, st := range svc.Tags {
												matched := false
												for _, tg := range tags {
													if strings.EqualFold(strings.TrimSpace(st), strings.TrimSpace(tg)) {
														matchedNames = append(matchedNames, svc.Name)
														matched = true
														break
													}
												}
												if matched {
													break
												}
											}
										}
									}
									if len(matchedNames) > 0 {
										ui.Row(c).AlignItems(ui.Center).Gap(6).Wrap().Children(func() {
											ui.Text(c, cat.RuleDrawerActiveNodes()+":").FontSize(11).TextColor(p.textDim)
											for _, name := range matchedNames {
												tagPill(c, name, p.text, p.surface)
											}
										})
									}
								} else {
									ui.Text(c, cat.RuleDrawerNoNodesOnline()).FontSize(11).TextColor(p.amber)
								}

							default:
								activeCount := a.activeRunningCount()
								label := fmt.Sprintf("%s (%d 在线)", cat.RoutingProxyPool(), activeCount)
								if activeCount > 0 {
									statusBadge(c, label, p.green, p.greenBg)
									ui.Text(c, cat.RuleDrawerDescProxyPool()).FontSize(11).TextColor(p.textMuted)
								} else {
									statusBadge(c, label, p.amber, p.amberBg)
									ui.Text(c, cat.RuleDrawerDescProxyPoolEmpty()).FontSize(11).TextColor(p.amber)
								}
							}
						})

					// 3. Routing Criteria Section
					ui.Column(c).Gap(10).Padding(14).Radius(10).
						Background(p.card).Border(1, p.borderSubtle).
						Children(func() {
							ui.Text(c, cat.RuleDrawerCriteria()).FontSize(12).FontWeight(700).TextColor(p.textDim)

							hasAnyCriteria := false

							// GeoSite
							if len(targetRule.GeoSite) > 0 {
								hasAnyCriteria = true
								ui.Column(c).Gap(4).Children(func() {
									ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
										ui.Text(c, cat.RuleDrawerGeoSiteTitle()).FontSize(12).FontWeight(600).TextColor(p.text)
										if hasGeo {
											tagPill(c, cat.GeodataStatusReady(), p.green, p.greenBg)
										} else {
											tagPill(c, cat.RulePendingGeoData(), p.amber, p.amberBg)
										}
									})
									ui.Row(c).AlignItems(ui.Center).Gap(6).Wrap().Children(func() {
										for _, gs := range targetRule.GeoSite {
											tagPill(c, "geosite:"+gs, p.accentText, p.accentBg)
										}
									})
								})
							}

							// GeoIP
							if len(targetRule.GeoIP) > 0 {
								hasAnyCriteria = true
								ui.Column(c).Gap(4).Children(func() {
									ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
										ui.Text(c, cat.RuleDrawerGeoIPTitle()).FontSize(12).FontWeight(600).TextColor(p.text)
										if hasGeo {
											tagPill(c, cat.GeodataStatusReady(), p.green, p.greenBg)
										} else {
											tagPill(c, cat.RulePendingGeoData(), p.amber, p.amberBg)
										}
									})
									ui.Row(c).AlignItems(ui.Center).Gap(6).Wrap().Children(func() {
										for _, gi := range targetRule.GeoIP {
											tagPill(c, "geoip:"+gi, p.accentText, p.accentBg)
										}
									})
								})
							}

							// Domain Suffix
							if len(targetRule.DomainSuffix) > 0 {
								hasAnyCriteria = true
								ui.Column(c).Gap(4).Children(func() {
									ui.Text(c, fmt.Sprintf("%s (%d)", cat.RuleDrawerDomainSuffixTitle(), len(targetRule.DomainSuffix))).
										FontSize(12).FontWeight(600).TextColor(p.text)
									ui.Row(c).AlignItems(ui.Center).Gap(6).Wrap().Children(func() {
										for _, d := range targetRule.DomainSuffix {
											tagPill(c, d, p.textMuted, p.surface)
										}
									})
								})
							}

							// IP CIDR
							if len(targetRule.IPCidr) > 0 {
								hasAnyCriteria = true
								ui.Column(c).Gap(4).Children(func() {
									ui.Text(c, fmt.Sprintf("%s (%d)", cat.RuleDrawerIPCidrTitle(), len(targetRule.IPCidr))).
										FontSize(12).FontWeight(600).TextColor(p.text)
									ui.Row(c).AlignItems(ui.Center).Gap(6).Wrap().Children(func() {
										for _, cidr := range targetRule.IPCidr {
											tagPill(c, cidr, p.textMuted, p.surface)
										}
									})
								})
							}

							// Domain Keywords
							if len(targetRule.DomainKeyword) > 0 {
								hasAnyCriteria = true
								ui.Column(c).Gap(4).Children(func() {
									ui.Text(c, fmt.Sprintf("%s (%d)", cat.RuleDrawerKeywordTitle(), len(targetRule.DomainKeyword))).
										FontSize(12).FontWeight(600).TextColor(p.text)
									ui.Row(c).AlignItems(ui.Center).Gap(6).Wrap().Children(func() {
										for _, kw := range targetRule.DomainKeyword {
											tagPill(c, "*"+kw+"*", p.textMuted, p.surface)
										}
									})
								})
							}

							if !hasAnyCriteria {
								ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
									tagPill(c, "MATCH: *", p.accentText, p.accentBg)
									ui.Text(c, cat.RuleDrawerNoCriteria()).FontSize(11).TextColor(p.textMuted)
								})
							}
						})
				})
			})
		})
}
