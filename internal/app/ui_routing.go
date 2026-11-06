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

func (a *app) preferredNodeForRule(rule routing.Rule) string {
	if a.tracker == nil || a.mgr == nil {
		return ""
	}
	var candidates []string
	switch rule.Action.Type {
	case routing.ActionProxyTag:
		for _, s := range a.state.Services {
			if a.mgr.StatusOf(s.ID).State == runner.StateRunning {
				for _, t := range s.Tags {
					if strings.EqualFold(strings.TrimSpace(t), strings.TrimSpace(rule.Action.Tag)) {
						candidates = append(candidates, s.ID)
						break
					}
				}
			}
		}
	case routing.ActionProxyPool:
		for _, s := range a.state.Services {
			if a.mgr.StatusOf(s.ID).State == runner.StateRunning {
				candidates = append(candidates, s.ID)
			}
		}
	}
	if len(candidates) == 0 {
		return ""
	}
	targetHost := "example.com"
	if len(rule.DomainSuffix) > 0 {
		targetHost = rule.DomainSuffix[0]
	}
	bestID, ok := a.tracker.SelectBest(candidates, targetHost)
	if !ok {
		return ""
	}
	for _, s := range a.state.Services {
		if s.ID == bestID {
			sc := a.tracker.GetScore(bestID)
			if sc.EWMA > 0 {
				return fmt.Sprintf("驻留: %s (%dms)", s.Name, max(1, sc.EWMA.Milliseconds()))
			}
			return fmt.Sprintf("驻留: %s", s.Name)
		}
	}
	return ""
}

func (a *app) openCreateRuleDialog() {
	a.ruleEditor = ruleEditorForm{
		open:        true,
		isNew:       true,
		ruleID:      fmt.Sprintf("rule-%d", len(a.state.RoutingRules)+1),
		name:        fmt.Sprintf("分流规则 %d", len(a.state.RoutingRules)+1),
		actionIndex: 0,
		tag:         "AI",
	}
	if a.win != nil {
		a.win.Invalidate()
	}
}

func (a *app) openEditRuleDialog(rule routing.Rule) {
	actionIdx := 0
	switch rule.Action.Type {
	case routing.ActionProxyTag:
		actionIdx = 0
	case routing.ActionProxyPool:
		actionIdx = 1
	case routing.ActionDirect:
		actionIdx = 2
	case routing.ActionBlock:
		actionIdx = 3
	}

	a.ruleEditor = ruleEditorForm{
		open:          true,
		isNew:         false,
		ruleID:        rule.ID,
		name:          rule.Name,
		desc:          rule.Description,
		actionIndex:   actionIdx,
		tag:           rule.Action.Tag,
		domainsInput:  strings.Join(rule.DomainSuffix, "\n"),
		cidrsInput:    strings.Join(rule.IPCidr, "\n"),
		keywordsInput: strings.Join(rule.DomainKeyword, ", "),
		geositeInput:  strings.Join(rule.GeoSite, ", "),
		geoipInput:    strings.Join(rule.GeoIP, ", "),
	}
	if a.win != nil {
		a.win.Invalidate()
	}
}

func (a *app) deleteRule(id string) {
	var remaining []routing.Rule
	for _, r := range a.state.RoutingRules {
		if r.ID != id {
			remaining = append(remaining, r)
		}
	}
	a.state.RoutingRules = remaining
	a.saveState()
	a.toast("已删除分流规则")
	if a.win != nil {
		a.win.Invalidate()
	}
}

func (a *app) resetRoutingPresets() {
	a.state.RoutingRules = routing.DefaultPresets()
	a.state.RoutingFinal = routing.RouteAction{Type: routing.ActionProxyPool}
	a.saveState()
	a.toast("已恢复为默认分流预设")
	if a.win != nil {
		a.win.Invalidate()
	}
}

func (a *app) cycleFinalAction() {
	switch a.state.RoutingFinal.Type {
	case routing.ActionProxyPool:
		a.state.RoutingFinal = routing.RouteAction{Type: routing.ActionDirect}
	case routing.ActionDirect:
		a.state.RoutingFinal = routing.RouteAction{Type: routing.ActionProxyTag, Tag: "AI"}
	default:
		a.state.RoutingFinal = routing.RouteAction{Type: routing.ActionProxyPool}
	}
	a.saveState()
	if a.win != nil {
		a.win.Invalidate()
	}
}

func parseLines(text string) []string {
	var out []string
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func parseCommaOrLines(text string) []string {
	var out []string
	repl := strings.ReplaceAll(text, "\n", ",")
	parts := strings.Split(repl, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (a *app) saveRuleEditor() {
	name := strings.TrimSpace(a.ruleEditor.name)
	if name == "" {
		a.ruleEditor.errText = "规则名称不能为空"
		return
	}

	domains := parseLines(a.ruleEditor.domainsInput)
	cidrs := parseLines(a.ruleEditor.cidrsInput)
	keywords := parseCommaOrLines(a.ruleEditor.keywordsInput)
	geosites := parseCommaOrLines(a.ruleEditor.geositeInput)
	geoips := parseCommaOrLines(a.ruleEditor.geoipInput)

	if len(domains) == 0 && len(cidrs) == 0 && len(keywords) == 0 && len(geosites) == 0 && len(geoips) == 0 {
		a.ruleEditor.errText = "请至少填写一个匹配条件（域名后缀、IP-CIDR、关键字、GeoSite 或 GeoIP）"
		return
	}

	var act routing.RouteAction
	switch a.ruleEditor.actionIndex {
	case 0:
		tag := strings.TrimSpace(a.ruleEditor.tag)
		if tag == "" {
			tag = "AI"
		}
		act = routing.RouteAction{Type: routing.ActionProxyTag, Tag: tag}
	case 1:
		act = routing.RouteAction{Type: routing.ActionProxyPool}
	case 2:
		act = routing.RouteAction{Type: routing.ActionDirect}
	case 3:
		act = routing.RouteAction{Type: routing.ActionBlock}
	}

	if a.ruleEditor.isNew {
		newRule := routing.Rule{
			ID:            a.ruleEditor.ruleID,
			Name:          name,
			Description:   strings.TrimSpace(a.ruleEditor.desc),
			Enabled:       true,
			DomainSuffix:  domains,
			IPCidr:        cidrs,
			DomainKeyword: keywords,
			GeoSite:       geosites,
			GeoIP:         geoips,
			Action:        act,
		}
		a.state.RoutingRules = append(a.state.RoutingRules, newRule)
	} else {
		for i := range a.state.RoutingRules {
			if a.state.RoutingRules[i].ID == a.ruleEditor.ruleID {
				a.state.RoutingRules[i].Name = name
				a.state.RoutingRules[i].Description = strings.TrimSpace(a.ruleEditor.desc)
				a.state.RoutingRules[i].DomainSuffix = domains
				a.state.RoutingRules[i].IPCidr = cidrs
				a.state.RoutingRules[i].DomainKeyword = keywords
				a.state.RoutingRules[i].GeoSite = geosites
				a.state.RoutingRules[i].GeoIP = geoips
				a.state.RoutingRules[i].Action = act
				break
			}
		}
	}

	a.saveState()
	a.ruleEditor.open = false
	a.ruleEditor.errText = ""
	a.toast("分流规则已更新")
	if a.win != nil {
		a.win.Invalidate()
	}
}

func (a *app) renderRoutingPage(c *ui.Context, p palette) {
	cat := a.catalog()

	ui.Scroll(c.Key("routing-page-scroll")).
		TrackScroll(&a.routingPageScroll).
		Grow(1).Fill().
		Padding(20, 24, 30, 24).Gap(16).
		Children(func() {
			// Page Title & Header Actions
			ui.Column(c).Gap(6).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
					ui.Text(c, cat.RoutingTitle()).FontSize(18).FontWeight(700).TextColor(p.text)

					ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
						if actionChip(c.Key("btn-update-geodata"), p, iconDownload, cat.UpdateGeoData(), a.updatingGeoData).Clicked() {
							a.triggerUpdateGeoData()
						}
						if actionChip(c.Key("btn-reset-presets"), p, iconRefresh, cat.ResetPresets(), false).Clicked() {
							a.resetRoutingPresets()
						}
						if primaryPillButton(c.Key("btn-new-rule"), p, iconPlus, cat.NewRule(), p.accent, false).Clicked() {
							a.openCreateRuleDialog()
						}
					})
				})
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
					ui.Text(c, cat.RoutingSubtitle()).FontSize(12).TextColor(p.textMuted)

					// Clickable fallback policy button
					finalLabel := string(a.state.RoutingFinal.Type)
					if a.state.RoutingFinal.Type == routing.ActionProxyTag {
						finalLabel = "#" + a.state.RoutingFinal.Tag
					}
					fallbackBtn := ui.ButtonBase(c.Key("btn-cycle-fallback")).
						Radius(6).PaddingX(8).PaddingY(3).
						Background(p.elevated).
						Children(func() {
							ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
								ui.Text(c, cat.RoutingFinalFallback()+":").FontSize(11).TextColor(p.textMuted)
								ui.Text(c, finalLabel).FontSize(11).FontWeight(600).TextColor(p.accentText)
							})
						})
					if fallbackBtn.Clicked() {
						a.cycleFinalAction()
					}
				})
			})

			// Presets Section Header
			ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
				ui.Text(c, cat.RoutingPresetsSection()).FontSize(14).FontWeight(600).TextColor(p.text)
				tagPill(c, fmt.Sprintf("%d", len(a.state.RoutingRules)), p.accentText, p.accentBg)
			})

			// List of Rules
			for idx := range a.state.RoutingRules {
				ruleIndex := idx
				rule := a.state.RoutingRules[ruleIndex]

				ui.Column(c.Key(fmt.Sprintf("rule-card-%s", rule.ID))).
					Padding(14).Radius(8).Gap(10).
					Background(p.card).
					Border(1, p.borderSubtle).
					Children(func() {
						// Header row: Name + Action Badge + Edit/Delete + Switch
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

								if pref := a.preferredNodeForRule(rule); pref != "" {
									tagPill(c, pref, p.accentText, p.accentBg)
								}
							})

							ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
								if subtleActionChip(c.Key("btn-edit-rule-"+rule.ID), p, iconEdit, cat.ActionEdit(), false).Clicked() {
									a.openEditRuleDialog(rule)
								}
								if dangerActionChip(c.Key("btn-delete-rule-"+rule.ID), p, iconTrash, cat.ActionDelete(), false).Clicked() {
									a.deleteRule(rule.ID)
								}

								enabled := rule.Enabled
								toggleKey := fmt.Sprintf("toggle-rule-%s", rule.ID)
								if ui.Switch(c.Key(toggleKey), &enabled).Label(toggleKey).Changed() {
									a.state.RoutingRules[ruleIndex].Enabled = enabled
									a.saveState()
								}
							})
						})

						// Description
						if rule.Description != "" {
							ui.Text(c, rule.Description).FontSize(11).TextColor(p.textMuted)
						}

						// Domain suffixes / criteria pills
						ui.Row(c).AlignItems(ui.Center).Gap(6).Wrap().Children(func() {
							for _, gs := range rule.GeoSite {
								tagPill(c, "geosite:"+gs, p.accentText, p.accentBg)
							}
							for _, gi := range rule.GeoIP {
								tagPill(c, "geoip:"+gi, p.accentText, p.accentBg)
							}
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

func (a *app) renderRuleEditorDialog(c *ui.Context, p palette) {
	cat := a.catalog()

	ui.DialogBase(c.Key("rule-editor-dialog"), &a.ruleEditor.open, func(backdrop, panel ui.Element) {
		backdrop.Background(ui.RGBA(0, 0, 0, 0.5))
		panel.Column().
			Width(540).
			Padding(20).Gap(14).
			Radius(14).Background(p.card).Border(1, p.border).
			Shadow(0, 12, 36, 0, ui.RGBA(0, 0, 0, 0.3)).
			Children(func() {
				// Dialog Title
				title := cat.EditRule()
				if a.ruleEditor.isNew {
					title = cat.NewRule()
				}
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
					ui.Text(c, title).FontSize(16).FontWeight(700).TextColor(p.text)
					if subtleActionChip(c.Key("btn-close-rule-editor"), p, iconClose, "", false).Clicked() {
						a.ruleEditor.open = false
					}
				})

				// Action selector
				ui.Column(c).Gap(4).Children(func() {
					ui.Text(c, cat.RuleActionLabel()).FontSize(12).FontWeight(500).TextColor(p.text)
					actions := []string{cat.RoutingTagPool(), cat.RoutingProxyPool(), cat.RoutingDirect(), cat.RoutingBlock()}
					segmentedControl(c.Key("rule-set-action"), p, &a.ruleEditor.actionIndex, actions)
				})

				// Tag input (if PROXY_TAG)
				if a.ruleEditor.actionIndex == 0 {
					labeledInput(c, p, "rule-set-tag", cat.RuleTagLabel(), &a.ruleEditor.tag, cat.RuleTagHint())
				}

				// Name input
				labeledInput(c, p, "rule-set-name", cat.RuleNameLabel(), &a.ruleEditor.name, "规则名称")

				// Description input
				labeledInput(c, p, "rule-set-desc", cat.RuleDescLabel(), &a.ruleEditor.desc, "可选说明")

				// Domain suffixes
				labeledTextArea(c, p, "rule-set-domains", cat.RuleDomainsLabel(), &a.ruleEditor.domainsInput, cat.RuleDomainsHint(), 3, 6)

				// IP-CIDRs
				labeledTextArea(c, p, "rule-set-cidrs", cat.RuleCIDRsLabel(), &a.ruleEditor.cidrsInput, cat.RuleCIDRsHint(), 2, 4)

				// Keywords
				labeledInput(c, p, "rule-set-keywords", cat.RuleKeywordsLabel(), &a.ruleEditor.keywordsInput, cat.RuleKeywordsHint())

				// GeoSite tags
				labeledInput(c, p, "rule-set-geosite", cat.RuleGeoSiteLabel(), &a.ruleEditor.geositeInput, cat.RuleGeoSiteHint())

				// GeoIP tags
				labeledInput(c, p, "rule-set-geoip", cat.RuleGeoIPLabel(), &a.ruleEditor.geoipInput, cat.RuleGeoIPHint())

				// Error display
				if a.ruleEditor.errText != "" {
					ui.Text(c, a.ruleEditor.errText).FontSize(12).TextColor(p.red)
				}

				// Action buttons
				ui.Row(c).AlignItems(ui.Center).Justify(ui.End).Gap(8).Children(func() {
					cancelBtn := ui.ButtonBase(c.Key("btn-cancel-rule-editor")).
						PaddingX(14).PaddingY(6).Radius(6).
						Background(p.card).
						Children(func() {
							ui.Text(c, cat.Cancel()).FontSize(12).TextColor(p.text)
						})
					if cancelBtn.Clicked() {
						a.ruleEditor.open = false
					}

					saveBtn := primaryPillButton(c.Key("btn-save-rule-editor"), p, nil, cat.Confirm(), p.accent, false)
					if saveBtn.Clicked() {
						a.saveRuleEditor()
					}
				})
			})
	})
}
