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

	initTab := 0
	if (len(rule.GeoSite) > 0 || len(rule.GeoIP) > 0) && len(rule.DomainSuffix) == 0 && len(rule.IPCidr) == 0 {
		initTab = 1
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
		geosites:      append([]string(nil), rule.GeoSite...),
		geoips:        append([]string(nil), rule.GeoIP...),
		tab:           initTab,
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

func addTag(tags *[]string, tag string) {
	tag = strings.TrimSpace(strings.ToLower(tag))
	tag = strings.TrimPrefix(tag, "#")
	if tag == "" {
		return
	}
	for _, t := range *tags {
		if strings.EqualFold(t, tag) {
			return
		}
	}
	*tags = append(*tags, tag)
}

func filterSuggestedTags(allTags []string, currentTags []string, query string, maxSuggestions int) []string {
	existingMap := make(map[string]bool)
	for _, t := range currentTags {
		existingMap[strings.ToLower(strings.TrimSpace(t))] = true
	}

	query = strings.ToLower(strings.TrimSpace(query))
	var matches []string

	if query != "" {
		for _, t := range allTags {
			if existingMap[t] {
				continue
			}
			if strings.HasPrefix(t, query) || strings.Contains(t, query) {
				matches = append(matches, t)
				if len(matches) >= maxSuggestions {
					break
				}
			}
		}
	}

	if len(matches) < maxSuggestions {
		for _, t := range allTags {
			if existingMap[t] {
				continue
			}
			found := false
			for _, m := range matches {
				if m == t {
					found = true
					break
				}
			}
			if !found {
				matches = append(matches, t)
				if len(matches) >= maxSuggestions {
					break
				}
			}
		}
	}

	return matches
}

func (a *app) renderChipsTagInput(
	c *ui.Context,
	p palette,
	key string,
	label string,
	tags *[]string,
	query *string,
	placeholder string,
	allKnownTags []string,
) {
	cat := a.catalog()
	ui.Column(c).Gap(6).Children(func() {
		// Label row with count
		ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
			ui.Text(c, label).FontSize(12).FontWeight(500).TextColor(p.text)
			if len(*tags) > 0 {
				tagPill(c, fmt.Sprintf("%d", len(*tags)), p.accentText, p.accentBg)
			}
		})

		// Container box mimicking a chip-input field
		ui.Row(c.Key(key+"-container")).
			AlignItems(ui.Center).Gap(6).Wrap().
			Padding(6, 8, 6, 8).Radius(6).
			Background(p.surface).Border(1, p.borderSubtle).
			Children(func() {
				// Render existing tags as chips
				for idx, t := range *tags {
					tagIdx := idx
					tagVal := t
					ui.Row(c.Key(fmt.Sprintf("%s-pill-%s", key, tagVal))).
						AlignItems(ui.Center).Gap(4).
						PaddingX(6).PaddingY(2).Radius(4).
						Background(p.elevated).Border(1, p.borderSubtle).
						Children(func() {
							ui.Text(c, tagVal).FontSize(11).FontWeight(500).TextColor(p.text)
							closeBtn := ui.ButtonBase(c.Key(fmt.Sprintf("%s-del-%s", key, tagVal))).
								Label("del-tag-" + tagVal).
								Radius(999).PaddingX(2).
								Background(ui.Transparent).
								Children(func() {
									ui.Text(c, "×").FontSize(11).FontWeight(700).TextColor(p.textDim)
								})
							if closeBtn.Clicked() {
								var newTags []string
								for i, elem := range *tags {
									if i != tagIdx {
										newTags = append(newTags, elem)
									}
								}
								*tags = newTags
							}
						})
				}

				// Inline text input to type and add new tag
				ui.TextInput(c.Key(key+"-input"), query).
					Label(label).
					Placeholder(placeholder).
					Height(24).Radius(4).
					FontSize(11).
					Background(ui.Transparent).Border(0, ui.Transparent)

				q := *query
				if strings.Contains(q, ",") || strings.Contains(q, "\n") {
					parts := parseCommaOrLines(q)
					for _, pt := range parts {
						addTag(tags, pt)
					}
					*query = ""
				}
			})

		// Suggestions or download guidance
		if len(allKnownTags) == 0 {
			guideText := cat.GeodataDownloadGuide()
			if a.updatingGeoData {
				guideText = cat.GeodataDownloading()
			}
			btn := ui.ButtonBase(c.Key(key + "-guide-download")).
				Radius(4).PaddingX(8).PaddingY(3).
				Background(p.elevated).Border(1, p.amber.Alpha(0.3)).
				Children(func() {
					ui.Row(c).AlignItems(ui.Center).Gap(4).Children(func() {
						ui.Icon(c, iconDownload).Size(11, 11).TextColor(p.amber)
						ui.Text(c, guideText).FontSize(11).TextColor(p.amber)
					})
				})
			if btn.Clicked() && !a.updatingGeoData {
				a.triggerUpdateGeoData()
			}
		} else {
			suggestions := filterSuggestedTags(allKnownTags, *tags, *query, 7)
			if len(suggestions) > 0 {
				ui.Row(c).AlignItems(ui.Center).Gap(6).Wrap().Children(func() {
					for _, sug := range suggestions {
						sugTag := sug
						btn := ui.ButtonBase(c.Key(fmt.Sprintf("%s-sug-%s", key, sugTag))).
							Radius(4).PaddingX(6).PaddingY(2).
							Background(p.elevated).
							Children(func() {
								ui.Text(c, "+ "+sugTag).FontSize(11).TextColor(p.accentText)
							})
						if btn.Clicked() {
							addTag(tags, sugTag)
							*query = ""
						}
					}
				})
			}
		}
	})
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

	geosites := append([]string(nil), a.ruleEditor.geosites...)
	if q := strings.TrimSpace(a.ruleEditor.geositeQuery); q != "" {
		for _, pt := range parseCommaOrLines(q) {
			addTag(&geosites, pt)
		}
	}

	geoips := append([]string(nil), a.ruleEditor.geoips...)
	if q := strings.TrimSpace(a.ruleEditor.geoipQuery); q != "" {
		for _, pt := range parseCommaOrLines(q) {
			addTag(&geoips, pt)
		}
	}

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
	hasGeo := a.hasGeoData()

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
						if !hasGeo {
							btnText := cat.UpdateGeoData()
							if a.updatingGeoData {
								btnText = cat.Updating()
							}
							if primaryPillButton(c.Key("btn-update-geodata"), p, iconDownload, btnText, p.amber, a.updatingGeoData).Clicked() {
								a.triggerUpdateGeoData()
							}
						} else {
							if actionChip(c.Key("btn-update-geodata"), p, iconDownload, cat.UpdateGeoData(), a.updatingGeoData).Clicked() {
								a.triggerUpdateGeoData()
							}
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

			// Missing GeoData Callout Banner
			if !hasGeo {
				ui.Row(c.Key("banner-geodata-missing")).
					AlignItems(ui.Center).Justify(ui.SpaceBetween).
					Padding(10, 14, 10, 14).Radius(8).
					Background(p.amberBg).Border(1, p.amber.Alpha(0.3)).
					Children(func() {
						ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
							ui.Icon(c, iconAlert).Size(14, 14).TextColor(p.amber)
							ui.Text(c, cat.RoutingGeodataBanner()).FontSize(12).FontWeight(500).TextColor(p.amber)
						})
						btnText := cat.UpdateGeoData()
						if a.updatingGeoData {
							btnText = cat.Updating()
						}
						if primaryPillButton(c.Key("btn-banner-download-geodata"), p, iconDownload, btnText, p.amber, a.updatingGeoData).Clicked() {
							a.triggerUpdateGeoData()
						}
					})
			}

			// Presets Section Header
			ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
				ui.Text(c, cat.RoutingPresetsSection()).FontSize(14).FontWeight(600).TextColor(p.text)
				tagPill(c, fmt.Sprintf("%d", len(a.state.RoutingRules)), p.accentText, p.accentBg)
			})

			// List of Rules
			for idx := range a.state.RoutingRules {
				ruleIndex := idx
				rule := a.state.RoutingRules[ruleIndex]
				hasGeoCriteria := len(rule.GeoSite) > 0 || len(rule.GeoIP) > 0
				hasOtherCriteria := len(rule.DomainSuffix) > 0 || len(rule.IPCidr) > 0 || len(rule.DomainKeyword) > 0

				cardBorder := p.borderSubtle
				cardBg := p.card
				if rule.Enabled && hasGeoCriteria && !hasGeo && !hasOtherCriteria {
					cardBorder = p.amber.Alpha(0.3)
				}

				ui.Column(c.Key(fmt.Sprintf("rule-card-%s", rule.ID))).
					Padding(14).Radius(8).Gap(10).
					Background(cardBg).
					Border(1, cardBorder).
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

								// If GeoData is missing and rule has Geo criteria, show status badge
								if rule.Enabled && hasGeoCriteria && !hasGeo {
									if !hasOtherCriteria {
										statusBadge(c, cat.RulePendingGeoData(), p.amber, p.amberBg)
									} else {
										tagPill(c, cat.RulePartialGeoPending(), p.amber, p.amberBg)
									}
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
								if hasGeo {
									tagPill(c, "geosite:"+gs, p.accentText, p.accentBg)
								} else {
									tagPill(c, "geosite:"+gs+" (待规则库)", p.amber, p.amberBg)
								}
							}
							for _, gi := range rule.GeoIP {
								if hasGeo {
									tagPill(c, "geoip:"+gi, p.accentText, p.accentBg)
								} else {
									tagPill(c, "geoip:"+gi+" (待规则库)", p.amber, p.amberBg)
								}
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

				// Action selector & Tag
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(10).Children(func() {
					ui.Column(c).Grow(1).Gap(4).Children(func() {
						ui.Text(c, cat.RuleActionLabel()).FontSize(12).FontWeight(500).TextColor(p.text)
						actions := []string{cat.RoutingTagPool(), cat.RoutingProxyPool(), cat.RoutingDirect(), cat.RoutingBlock()}
						segmentedControl(c.Key("rule-set-action"), p, &a.ruleEditor.actionIndex, actions)
					})
					if a.ruleEditor.actionIndex == 0 {
						ui.Column(c).Width(140).Children(func() {
							labeledInput(c, p, "rule-set-tag", cat.RuleTagLabel(), &a.ruleEditor.tag, cat.RuleTagHint())
						})
					}
				})

				// Name & Description row
				ui.Row(c).AlignItems(ui.Center).Gap(10).Children(func() {
					ui.Column(c).Grow(1).Children(func() {
						labeledInput(c, p, "rule-set-name", cat.RuleNameLabel(), &a.ruleEditor.name, "规则名称")
					})
					ui.Column(c).Grow(1).Children(func() {
						labeledInput(c, p, "rule-set-desc", cat.RuleDescLabel(), &a.ruleEditor.desc, "可选说明")
					})
				})

				// Criteria Tabs (Domains & IPs vs GeoData)
				segmentedControl(c.Key("rule-criteria-tabs"), p, &a.ruleEditor.tab, []string{
					cat.RuleTabCriteria(),
					cat.RuleTabGeoData(),
				})

				if a.ruleEditor.tab == 0 {
					// Domain suffixes
					labeledTextArea(c, p, "rule-set-domains", cat.RuleDomainsLabel(), &a.ruleEditor.domainsInput, cat.RuleDomainsHint(), 2, 4)

					// IP-CIDRs
					labeledTextArea(c, p, "rule-set-cidrs", cat.RuleCIDRsLabel(), &a.ruleEditor.cidrsInput, cat.RuleCIDRsHint(), 2, 3)

					// Keywords
					labeledInput(c, p, "rule-set-keywords", cat.RuleKeywordsLabel(), &a.ruleEditor.keywordsInput, cat.RuleKeywordsHint())
				} else {
					// GeoSite tags chip-input
					a.renderChipsTagInput(c, p, "rule-set-geosite", cat.RuleGeoSiteLabel(), &a.ruleEditor.geosites, &a.ruleEditor.geositeQuery, cat.RuleGeoSiteHint(), a.availableGeoSiteTags())

					// GeoIP tags chip-input
					a.renderChipsTagInput(c, p, "rule-set-geoip", cat.RuleGeoIPLabel(), &a.ruleEditor.geoips, &a.ruleEditor.geoipQuery, cat.RuleGeoIPHint(), a.availableGeoIPTags())
				}

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
