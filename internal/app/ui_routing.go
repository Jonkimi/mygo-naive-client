package app

import (
	"fmt"
	"strings"

	"github.com/egoist/mygo/ui"

	"naive-client/internal/routing"
)

func (a *app) activeNodesForTags(tags []string, precomputedRunning ...map[string]bool) int {
	if a.mgr == nil || len(tags) == 0 {
		return 0
	}
	var running map[string]bool
	if len(precomputedRunning) > 0 && precomputedRunning[0] != nil {
		running = precomputedRunning[0]
	} else {
		running = a.mgr.RunningServiceIDs()
	}
	if len(running) == 0 {
		return 0
	}
	count := 0
	for _, svc := range a.state.Services {
		if running[svc.ID] {
			for _, t := range svc.Tags {
				matched := false
				for _, targetTag := range tags {
					if strings.EqualFold(strings.TrimSpace(t), strings.TrimSpace(targetTag)) {
						count++
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
	return count
}

func (a *app) allKnownServiceTags() []string {
	seen := make(map[string]bool)
	var list []string
	for _, s := range a.state.Services {
		for _, t := range s.Tags {
			t = strings.TrimSpace(t)
			if t != "" && !seen[strings.ToLower(t)] {
				seen[strings.ToLower(t)] = true
				list = append(list, t)
			}
		}
	}
	return list
}

func (a *app) preferredNodeForAction(act routing.RouteAction, targetHost string, precomputedRunning ...map[string]bool) string {
	if a.tracker == nil || a.mgr == nil {
		return ""
	}
	if act.Type != routing.ActionProxyTag && act.Type != routing.ActionProxyPool {
		return ""
	}
	var running map[string]bool
	if len(precomputedRunning) > 0 && precomputedRunning[0] != nil {
		running = precomputedRunning[0]
	} else {
		running = a.mgr.RunningServiceIDs()
	}
	if len(running) == 0 {
		return ""
	}
	var candidates []string
	switch act.Type {
	case routing.ActionProxyTag:
		tags := act.GetTags()
		for _, s := range a.state.Services {
			if running[s.ID] {
				for _, t := range s.Tags {
					matched := false
					for _, targetTag := range tags {
						if strings.EqualFold(strings.TrimSpace(t), strings.TrimSpace(targetTag)) {
							candidates = append(candidates, s.ID)
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
	case routing.ActionProxyPool:
		for _, s := range a.state.Services {
			if running[s.ID] {
				candidates = append(candidates, s.ID)
			}
		}
	}
	if len(candidates) == 0 {
		return ""
	}
	if targetHost == "" {
		targetHost = "example.com"
	}
	bestID, sc, ok := a.tracker.PeekBest(candidates, targetHost)
	if !ok {
		return ""
	}
	for _, s := range a.state.Services {
		if s.ID == bestID {
			if sc.EWMA > 0 {
				return fmt.Sprintf("驻留: %s (%dms)", s.Name, max(1, sc.EWMA.Milliseconds()))
			}
			return fmt.Sprintf("驻留: %s", s.Name)
		}
	}
	return ""
}

func (a *app) preferredNodeForRule(rule routing.Rule, precomputedRunning ...map[string]bool) string {
	if rule.Action.Type != routing.ActionProxyTag && rule.Action.Type != routing.ActionProxyPool {
		return ""
	}
	targetHost := "example.com"
	if len(rule.DomainSuffix) > 0 {
		targetHost = rule.DomainSuffix[0]
	}
	return a.preferredNodeForAction(rule.Action, targetHost, precomputedRunning...)
}

func (a *app) openCreateRuleDialog() {
	a.ruleEditor = ruleEditorForm{
		open:        true,
		isNew:       true,
		ruleID:      fmt.Sprintf("rule-%d", len(a.state.RoutingRules)+1),
		name:        fmt.Sprintf("分流规则 %d", len(a.state.RoutingRules)+1),
		actionIndex: 0,
		tags:        []string{"AI"},
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
	if len(rule.GeoSite) == 0 && len(rule.GeoIP) == 0 && (len(rule.DomainSuffix) > 0 || len(rule.IPCidr) > 0 || len(rule.DomainKeyword) > 0) {
		initTab = 1
	}

	tags := rule.Action.GetTags()
	if len(tags) == 0 && rule.Action.Type == routing.ActionProxyTag {
		tags = []string{"AI"}
	}

	a.ruleEditor = ruleEditorForm{
		open:          true,
		isNew:         false,
		ruleID:        rule.ID,
		name:          a.localizedRuleName(rule),
		desc:          a.localizedRuleDescription(rule),
		actionIndex:   actionIdx,
		tags:          tags,
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

func (a *app) openEditFinalRuleDialog() {
	cat := a.catalog()
	actionIdx := 1
	switch a.state.RoutingFinal.Type {
	case routing.ActionProxyTag:
		actionIdx = 0
	case routing.ActionProxyPool:
		actionIdx = 1
	case routing.ActionDirect:
		actionIdx = 2
	case routing.ActionBlock:
		actionIdx = 3
	}

	tags := a.state.RoutingFinal.GetTags()
	if len(tags) == 0 && a.state.RoutingFinal.Type == routing.ActionProxyTag {
		tags = []string{"AI"}
	}

	a.ruleEditor = ruleEditorForm{
		open:        true,
		isNew:       false,
		isFinal:     true,
		ruleID:      "final-fallback",
		name:        cat.RoutingFinalFallback(),
		desc:        cat.RoutingFinalDesc(),
		actionIndex: actionIdx,
		tags:        tags,
	}
	if a.win != nil {
		a.win.Invalidate()
	}
}

func (a *app) deleteRule(id string) {
	if strings.HasPrefix(id, "preset-") {
		return
	}
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
	a.state.BlockerBlockAds = true
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
		a.state.RoutingFinal = routing.RouteAction{Type: routing.ActionProxyTag, Tag: "AI", Tags: []string{"AI"}}
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
	tag = strings.TrimSpace(tag)
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
		var prefixMatches []string
		var containsMatches []string
		for _, t := range allTags {
			cleanTag := strings.TrimSpace(t)
			if cleanTag == "" || existingMap[strings.ToLower(cleanTag)] {
				continue
			}
			tLower := strings.ToLower(cleanTag)
			if strings.HasPrefix(tLower, query) {
				prefixMatches = append(prefixMatches, cleanTag)
			} else if strings.Contains(tLower, query) {
				containsMatches = append(containsMatches, cleanTag)
			}
		}
		matches = append(prefixMatches, containsMatches...)
		if len(matches) > maxSuggestions {
			matches = matches[:maxSuggestions]
		}
		return matches
	}

	for _, t := range allTags {
		cleanTag := strings.TrimSpace(t)
		if cleanTag == "" || existingMap[strings.ToLower(cleanTag)] {
			continue
		}
		matches = append(matches, cleanTag)
		if len(matches) >= maxSuggestions {
			break
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
	isGeoData bool,
) {
	cat := a.catalog()
	isDisabled := isGeoData && len(allKnownTags) == 0

	ui.Column(c).Gap(6).Children(func() {
		// Label row with count
		ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
			ui.Text(c, label).FontSize(12).FontWeight(500).TextColor(p.text)
			if len(*tags) > 0 {
				tagPill(c, fmt.Sprintf("%d", len(*tags)), p.accentText, p.accentBg)
			}
		})

		// Container box mimicking a chip-input field
		contBg := p.surface
		contBorder := p.borderSubtle
		var contOpacity float32 = 1.0
		if isDisabled {
			contBg = p.elevated.Alpha(0.4)
			contBorder = p.borderSubtle.Alpha(0.4)
			contOpacity = 0.65
		}

		ui.Row(c.Key(key+"-container")).
			AlignItems(ui.Center).Gap(6).Wrap().
			Padding(6, 8, 6, 8).Radius(6).
			Background(contBg).Border(1, contBorder).Opacity(contOpacity).
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
							if !isDisabled {
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
							}
						})
				}

				// Inline text input to type and add new tag
				inpPlaceholder := placeholder
				if isDisabled {
					inpPlaceholder = cat.GeodataStatusMissing()
				}
				ui.TextInput(c.Key(key+"-input"), query).
					Label(label).
					Placeholder(inpPlaceholder).
					Height(24).Radius(4).
					FontSize(11).
					Disabled(isDisabled).
					ReadOnly(isDisabled).
					Background(ui.Transparent).Border(0, ui.Transparent)

				if !isDisabled {
					q := *query
					if strings.Contains(q, ",") || strings.Contains(q, "\n") {
						parts := parseCommaOrLines(q)
						for _, pt := range parts {
							addTag(tags, pt)
						}
						*query = ""
					}
				}
			})

		// Suggestions or download guidance
		if isGeoData && len(allKnownTags) == 0 {
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
	var act routing.RouteAction
	switch a.ruleEditor.actionIndex {
	case 0:
		tags := append([]string(nil), a.ruleEditor.tags...)
		if q := strings.TrimSpace(a.ruleEditor.tagQuery); q != "" {
			for _, pt := range parseCommaOrLines(q) {
				addTag(&tags, pt)
			}
		}
		if len(tags) == 0 {
			tags = []string{"AI"}
		}
		act = routing.RouteAction{Type: routing.ActionProxyTag, Tag: tags[0], Tags: tags}
	case 1:
		act = routing.RouteAction{Type: routing.ActionProxyPool}
	case 2:
		act = routing.RouteAction{Type: routing.ActionDirect}
	case 3:
		act = routing.RouteAction{Type: routing.ActionBlock}
	}

	if a.ruleEditor.isFinal {
		a.state.RoutingFinal = act
		a.saveState()
		a.ruleEditor.open = false
		a.ruleEditor.errText = ""
		a.toast("兜底出站策略已更新")
		if a.win != nil {
			a.win.Invalidate()
		}
		return
	}

	name := strings.TrimSpace(a.ruleEditor.name)
	if name == "" {
		a.ruleEditor.errText = a.catalog().RuleNameRequired()
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
		a.ruleEditor.errText = a.catalog().RuleCriteriaRequired()
		return
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

func (a *app) renderRuleCard(c *ui.Context, p palette, ruleIndex int, rule routing.Rule, hasGeo bool, runningIDs map[string]bool) {
	cat := a.catalog()
	hasGeoCriteria := len(rule.GeoSite) > 0 || len(rule.GeoIP) > 0
	hasOtherCriteria := len(rule.DomainSuffix) > 0 || len(rule.IPCidr) > 0 || len(rule.DomainKeyword) > 0

	cardBorder := p.borderSubtle
	cardBg := p.card
	if rule.Enabled && hasGeoCriteria && !hasGeo && !hasOtherCriteria {
		cardBorder = p.amber.Alpha(0.3)
	}

	ui.Column(c.Key(fmt.Sprintf("rule-card-%s", rule.ID))).
		Grow(1).
		Padding(14).Radius(8).Gap(8).
		Background(cardBg).
		Border(1, cardBorder).
		Children(func() {
			// Line 1: Rule Name on left, Actions (Icon-only) + Switch on right
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
					nameBtn := ui.Box(c.Key("btn-name-rule-" + rule.ID)).Children(func() {
						ui.Text(c, a.localizedRuleName(rule)).FontSize(13).FontWeight(600).TextColor(p.text)
					})
					if nameBtn.Clicked() {
						a.activeRuleDrawerID = rule.ID
					}
				})

				ui.Row(c).AlignItems(ui.Center).Gap(4).Children(func() {
					if subtleActionChip(c.Key("btn-detail-rule-"+rule.ID), p, iconList, "", false).
						Label(cat.RuleDrawerTitle()).
						Tooltip(cat.RuleDrawerTitle()).
						Clicked() {
						a.activeRuleDrawerID = rule.ID
					}
					if subtleActionChip(c.Key("btn-edit-rule-"+rule.ID), p, iconEdit, "", false).
						Label(cat.ActionEdit()).
						Tooltip(cat.ActionEdit()).
						Clicked() {
						a.openEditRuleDialog(rule)
					}
					if !strings.HasPrefix(rule.ID, "preset-") {
						if dangerActionChip(c.Key("btn-delete-rule-"+rule.ID), p, iconTrash, "", false).
							Label(cat.ActionDelete()).
							Tooltip(cat.ActionDelete()).
							Clicked() {
							a.deleteRule(rule.ID)
						}
					}

					enabled := rule.Enabled
					toggleKey := fmt.Sprintf("toggle-rule-%s", rule.ID)
					if ui.Switch(c.Key(toggleKey), &enabled).Label(toggleKey).Changed() {
						if isCategoryAdsBlockRule(rule) {
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
				})
			})

			// Line 2: Description
			if desc := a.localizedRuleDescription(rule); desc != "" {
				ui.Text(c, desc).FontSize(11).TextColor(p.textMuted)
			}

			// Line 3: Outbound Action Badge + Criteria Tags
			ui.Row(c).AlignItems(ui.Center).Gap(6).Wrap().Children(func() {
				// Outbound Action Badge
				switch rule.Action.Type {
				case routing.ActionBlock:
					statusBadge(c, cat.RoutingBlock(), p.red, p.redBg)
				case routing.ActionDirect:
					statusBadge(c, cat.RoutingDirect(), p.textDim, p.elevated)
				case routing.ActionProxyTag:
					tags := rule.Action.GetTags()
					activeNodes := a.activeNodesForTags(tags, runningIDs)
					var tagLabels []string
					for _, t := range tags {
						tagLabels = append(tagLabels, "#"+t)
					}
					tagDisplay := strings.Join(tagLabels, ", ")
					if tagDisplay == "" {
						tagDisplay = "#AI"
					}
					label := fmt.Sprintf("%s (%d 在线)", tagDisplay, activeNodes)
					if activeNodes > 0 {
						statusBadge(c, label, p.accentText, p.accentBg)
					} else {
						statusBadge(c, fmt.Sprintf("%s (0 在线)", tagDisplay), p.amber, p.amberBg)
					}
				default:
					activeCount := a.activeRunningCount()
					label := fmt.Sprintf("%s (%d 在线)", cat.RoutingProxyPool(), activeCount)
					if activeCount > 0 {
						statusBadge(c, label, p.green, p.greenBg)
					} else {
						statusBadge(c, label, p.amber, p.amberBg)
					}
				}

				// If GeoData is missing and rule has Geo criteria, show status badge
				if rule.Enabled && hasGeoCriteria && !hasGeo {
					if !hasOtherCriteria {
						statusBadge(c, cat.RulePendingGeoData(), p.amber, p.amberBg)
					} else {
						tagPill(c, cat.RulePartialGeoPending(), p.amber, p.amberBg)
					}
				}

				if pref := a.preferredNodeForRule(rule, runningIDs); pref != "" {
					tagPill(c, pref, p.accentText, p.accentBg)
				}
			})
		})
}

func (a *app) renderRoutingPage(c *ui.Context, p palette) {
	cat := a.catalog()
	hasGeo := a.hasGeoData()
	var runningIDs map[string]bool
	if a.mgr != nil {
		runningIDs = a.mgr.RunningServiceIDs()
	}

	ui.Scroll(c.Key("routing-page-scroll")).
		Grow(1).Fill().MinHeight(0).
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

			// Separate Custom Rules and Preset Rules
			var customRules []routing.Rule
			var customIndices []int
			var presetRules []routing.Rule
			var presetIndices []int

			for idx, rule := range a.state.RoutingRules {
				if strings.HasPrefix(rule.ID, "preset-") {
					presetRules = append(presetRules, rule)
					presetIndices = append(presetIndices, idx)
				} else {
					customRules = append(customRules, rule)
					customIndices = append(customIndices, idx)
				}
			}

			// Section 1: Custom Rules (Top Priority)
			ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
				ui.Text(c, cat.RoutingCustomSection()).FontSize(14).FontWeight(600).TextColor(p.text)
				tagPill(c, fmt.Sprintf("%d", len(customRules)), p.accentText, p.accentBg)
			})

			if len(customRules) > 0 {
				ui.Grid(c.Key("custom-rules-grid")).Columns(2).Gap(12).Children(func() {
					for i := range customRules {
						a.renderRuleCard(c, p, customIndices[i], customRules[i], hasGeo, runningIDs)
					}
				})
			} else {
				ui.Column(c.Key("custom-rules-empty")).
					Padding(14).Radius(8).
					Background(p.card).Border(1, p.borderSubtle).
					Children(func() {
						ui.Text(c, cat.RoutingCustomEmpty()).FontSize(12).TextColor(p.textMuted)
					})
			}

			// Section 2: Preset Rule Groups (5 Presets + Final Fallback = 6 cards)
			ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
				ui.Text(c, cat.RoutingPresetsSection()).FontSize(14).FontWeight(600).TextColor(p.text)
				tagPill(c, fmt.Sprintf("%d", len(presetRules)+1), p.accentText, p.accentBg)
			})

			ui.Grid(c.Key("preset-rules-grid")).Columns(2).Gap(12).Children(func() {
				for i := range presetRules {
					a.renderRuleCard(c, p, presetIndices[i], presetRules[i], hasGeo, runningIDs)
				}
				a.renderFinalFallbackCard(c, p, runningIDs)
			})
		})
}

func (a *app) renderFinalFallbackCard(c *ui.Context, p palette, runningIDs map[string]bool) {
	cat := a.catalog()

	// Final Fallback Rule Card (Undeletable, Always Active)
	ui.Column(c.Key("rule-card-final-fallback")).
		Grow(1).
		Padding(14).Radius(8).Gap(8).
		Background(p.card).
		Border(1, p.borderSubtle).
		Children(func() {
			// Line 1: Name + FINAL pill + Always Active pill on left, Edit on right
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
					ui.Text(c, cat.RoutingFinalFallback()).FontSize(13).FontWeight(600).TextColor(p.text)
					tagPill(c, "FINAL", p.textDim, p.elevated)
					tagPill(c, cat.RoutingFinalAlwaysActive(), p.accentText, p.accentBg)
				})

				ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
					if subtleActionChip(c.Key("btn-detail-final-rule"), p, iconList, "", false).
						Label(cat.RuleDrawerTitle()).
						Tooltip(cat.RuleDrawerTitle()).
						Clicked() {
						a.activeRuleDrawerID = "final"
					}
					if subtleActionChip(c.Key("btn-edit-final-rule"), p, iconEdit, "", false).
						Label(cat.ActionEdit()).
						Tooltip(cat.ActionEdit()).
						Clicked() {
						a.openEditFinalRuleDialog()
					}
				})
			})

			// Line 2: Description
			ui.Text(c, cat.RoutingFinalDesc()).FontSize(11).TextColor(p.textMuted)

			// Line 3: Outbound Action Badge
			ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
				switch a.state.RoutingFinal.Type {
				case routing.ActionBlock:
					statusBadge(c, cat.RoutingBlock(), p.red, p.redBg)
				case routing.ActionDirect:
					statusBadge(c, cat.RoutingDirect(), p.textDim, p.elevated)
				case routing.ActionProxyTag:
					tags := a.state.RoutingFinal.GetTags()
					activeNodes := a.activeNodesForTags(tags, runningIDs)
					var tagLabels []string
					for _, t := range tags {
						tagLabels = append(tagLabels, "#"+t)
					}
					tagDisplay := strings.Join(tagLabels, ", ")
					if tagDisplay == "" {
						tagDisplay = "#AI"
					}
					label := fmt.Sprintf("%s (%d 在线)", tagDisplay, activeNodes)
					if activeNodes > 0 {
						statusBadge(c, label, p.accentText, p.accentBg)
					} else {
						statusBadge(c, fmt.Sprintf("%s (0 在线)", tagDisplay), p.amber, p.amberBg)
					}
				default:
					activeCount := a.activeRunningCount()
					label := fmt.Sprintf("%s (%d 在线)", cat.RoutingProxyPool(), activeCount)
					if activeCount > 0 {
						statusBadge(c, label, p.green, p.greenBg)
					} else {
						statusBadge(c, label, p.amber, p.amberBg)
					}
				}

				if pref := a.preferredNodeForAction(a.state.RoutingFinal, "", runningIDs); pref != "" {
					tagPill(c, pref, p.accentText, p.accentBg)
				}
			})
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
				if a.ruleEditor.isFinal {
					title = cat.EditFinalRule()
				} else if a.ruleEditor.isNew {
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

				if a.ruleEditor.actionIndex == 0 {
					a.renderChipsTagInput(c, p, "rule-set-tag", cat.RuleTagLabel(), &a.ruleEditor.tags, &a.ruleEditor.tagQuery, cat.RuleTagHint(), a.allKnownServiceTags(), false)
				}

				if a.ruleEditor.isFinal {
					ui.Text(c, cat.RoutingFinalDesc()).FontSize(11).TextColor(p.textMuted)
				} else {
					// Name & Description row
					ui.Row(c).AlignItems(ui.Center).Gap(10).Children(func() {
						ui.Column(c).Grow(1).Children(func() {
							labeledInput(c, p, "rule-set-name", cat.RuleNameLabel(), &a.ruleEditor.name, "规则名称")
						})
						ui.Column(c).Grow(1).Children(func() {
							labeledInput(c, p, "rule-set-desc", cat.RuleDescLabel(), &a.ruleEditor.desc, "可选说明")
						})
					})

					// Criteria Tabs (GeoData vs Domains & IPs)
					segmentedControl(c.Key("rule-criteria-tabs"), p, &a.ruleEditor.tab, []string{
						cat.RuleTabGeoData(),
						cat.RuleTabCriteria(),
					})

					if a.ruleEditor.tab == 0 {
						// GeoSite tags chip-input
						a.renderChipsTagInput(c, p, "rule-set-geosite", cat.RuleGeoSiteLabel(), &a.ruleEditor.geosites, &a.ruleEditor.geositeQuery, cat.RuleGeoSiteHint(), a.availableGeoSiteTags(), true)

						// GeoIP tags chip-input
						a.renderChipsTagInput(c, p, "rule-set-geoip", cat.RuleGeoIPLabel(), &a.ruleEditor.geoips, &a.ruleEditor.geoipQuery, cat.RuleGeoIPHint(), a.availableGeoIPTags(), true)
					} else {
						// Domain suffixes
						labeledTextArea(c, p, "rule-set-domains", cat.RuleDomainsLabel(), &a.ruleEditor.domainsInput, cat.RuleDomainsHint(), 2, 4)

						// IP-CIDRs
						labeledTextArea(c, p, "rule-set-cidrs", cat.RuleCIDRsLabel(), &a.ruleEditor.cidrsInput, cat.RuleCIDRsHint(), 2, 3)

						// Keywords
						labeledInput(c, p, "rule-set-keywords", cat.RuleKeywordsLabel(), &a.ruleEditor.keywordsInput, cat.RuleKeywordsHint())
					}
				}

				// Error display
				if a.ruleEditor.errText != "" {
					ui.Row(c.Key("rule-editor-error-row")).
						AlignItems(ui.Center).Justify(ui.SpaceBetween).
						Padding(6, 10, 6, 10).Radius(6).
						Background(p.redBg).
						Children(func() {
							ui.Text(c, a.ruleEditor.errText).FontSize(12).TextColor(p.red).Grow(1)
							btnCopy := ui.ButtonBase(c.Key("btn-copy-rule-error")).
								Label("btn-copy-rule-error").
								Padding(2, 6, 2, 6).Radius(4).
								Background(p.card).Border(1, p.borderSubtle).
								Tooltip(cat.ActionCopyError()).
								Children(func() {
									ui.Text(c, cat.BtnCopy()).FontSize(10).TextColor(p.textDim)
								})
							if btnCopy.Clicked() {
								a.writeClipboard(a.ruleEditor.errText, cat.ToastErrorCopied())
							}
						})
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
