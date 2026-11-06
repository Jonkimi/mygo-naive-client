package app

import (
	"fmt"
	"strings"

	"github.com/egoist/mygo/ui"

	"naive-client/internal/routing"
	"naive-client/internal/runner"
)

func (a *app) activeNodesForTag(tag string) int {
	count := 0
	if a.mgr == nil {
		return 0
	}
	for _, svc := range a.state.Services {
		if a.mgr.StatusOf(svc.ID).State == runner.StateRunning {
			for _, t := range svc.Tags {
				if strings.EqualFold(strings.TrimSpace(t), strings.TrimSpace(tag)) {
					count++
					break
				}
			}
		}
	}
	return count
}

func (a *app) renderRoutingPage(c *ui.Context, p palette) {
	cat := a.catalog()

	ui.Scroll(c.Key("routing-page-scroll")).
		TrackScroll(&a.routingPageScroll).
		Grow(1).Fill().
		Padding(20, 24, 30, 24).Gap(16).
		Children(func() {
			// Page Title & Subtitle
			ui.Column(c).Gap(4).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
					ui.Text(c, cat.RoutingTitle()).FontSize(18).FontWeight(700).TextColor(p.text)
					// Fallback policy pill
					tagPill(c, cat.RoutingFinalFallback()+": "+cat.RoutingProxyPool(), p.textMuted, p.elevated)
				})
				ui.Text(c, cat.RoutingSubtitle()).FontSize(12).TextColor(p.textMuted)
			})

			// Presets Section Header
			ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
				ui.Text(c, cat.RoutingPresetsSection()).FontSize(14).FontWeight(600).TextColor(p.text)
				tagPill(c, fmt.Sprintf("%d", len(a.state.RoutingRules)), p.accentText, p.accentBg)
			})

			// List of Rules
			for idx := range a.state.RoutingRules {
				ruleIndex := idx
				rule := &a.state.RoutingRules[ruleIndex]

				ui.Column(c.Key(fmt.Sprintf("rule-card-%s", rule.ID))).
					Padding(14).Radius(8).Gap(8).
					Background(p.card).
					Border(1, p.borderSubtle).
					Children(func() {
						// Header row: Name + Action Badge + Switch
						ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
							ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
								ui.Text(c, rule.Name).FontSize(13).FontWeight(600).TextColor(p.text)

								switch rule.Action.Type {
								case routing.ActionBlock:
									statusBadge(c, cat.RoutingBlock(), p.red, p.redBg)
								case routing.ActionDirect:
									statusBadge(c, cat.RoutingDirect(), p.textDim, p.elevated)
								case routing.ActionProxyTag:
									activeNodes := a.activeNodesForTag(rule.Action.Tag)
									label := fmt.Sprintf("#%s (%d 在线)", rule.Action.Tag, activeNodes)
									if activeNodes > 0 {
										statusBadge(c, label, p.accentText, p.accentBg)
									} else {
										statusBadge(c, fmt.Sprintf("#%s (降级池)", rule.Action.Tag), p.amber, p.amberBg)
									}
								default:
									statusBadge(c, cat.RoutingProxyPool(), p.green, p.greenBg)
								}
							})

							enabled := rule.Enabled
							toggleKey := fmt.Sprintf("toggle-rule-%s", rule.ID)
							if ui.Switch(c.Key(toggleKey), &enabled).Label(toggleKey).Changed() {
								rule.Enabled = enabled
								a.saveState()
							}
						})

						// Description
						if rule.Description != "" {
							ui.Text(c, rule.Description).FontSize(11).TextColor(p.textMuted)
						}

						// Domain suffixes / criteria pills
						ui.Row(c).AlignItems(ui.Center).Gap(6).Wrap().Children(func() {
							for _, d := range rule.DomainSuffix {
								tagPill(c, d, p.textMuted, p.surface)
							}
							for _, cidr := range rule.IPCidr {
								tagPill(c, cidr, p.textMuted, p.surface)
							}
							for _, kw := range rule.DomainKeyword {
								tagPill(c, "*"+kw+"*", p.textMuted, p.surface)
							}
						})
					})
			}
		})
}
