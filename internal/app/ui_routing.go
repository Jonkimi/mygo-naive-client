package app

import (
	"fmt"
	"strings"

	"github.com/egoist/mygo/ui"

	"naive-client/internal/config"
	"naive-client/internal/routing"
)

type resolvedTargetNode struct {
	Service config.Service
	Online  bool
	Missing bool
	MissingID string
}

type targetResolution struct {
	CandidateIDs    []string
	OnlineNodes     []config.Service
	OnlineCount     int
	MissingNodeIDs  []string
	FallbackOnline  int
}

func (a *app) serviceOrBuiltinWarp(id string) (config.Service, bool) {
	for _, s := range a.state.Services {
		if s.ID == id {
			return s, true
		}
	}
	if id == config.BuiltinWarpServiceID {
		cat := a.catalog()
		name := cat.BuiltinWarpNodeName()
		if name == "" {
			name = "Cloudflare WARP"
		}
		return config.Service{
			ID:       config.BuiltinWarpServiceID,
			Name:     name,
			Protocol: config.ProtoWARP,
			Engine:   config.EngineSingBox,
		}, true
	}
	return config.Service{}, false
}

func (a *app) allSelectableNodes() []config.Service {
	var list []config.Service
	var builtin *config.Service
	for _, s := range a.state.Services {
		if s.IsBuiltinWarp() {
			cp := s
			builtin = &cp
			continue
		}
		list = append(list, s)
	}
	if builtin != nil {
		list = append(list, *builtin)
	} else {
		if bw, ok := a.serviceOrBuiltinWarp(config.BuiltinWarpServiceID); ok {
			list = append(list, bw)
		}
	}
	return list
}

func (a *app) resolveActionTargets(act routing.RouteAction, precomputedRunning ...map[string]bool) targetResolution {
	var running map[string]bool
	if len(precomputedRunning) > 0 && precomputedRunning[0] != nil {
		running = precomputedRunning[0]
	} else if a.mgr != nil {
		running = a.mgr.RunningServiceIDs()
	}

	var res targetResolution
	if !act.IsProxyAction() {
		return res
	}

	targets := act.NormalizedTargets()
	seenCand := make(map[string]bool)
	addOnlineSvc := func(s config.Service) {
		if seenCand[s.ID] {
			return
		}
		if running[s.ID] {
			seenCand[s.ID] = true
			res.CandidateIDs = append(res.CandidateIDs, s.ID)
			res.OnlineNodes = append(res.OnlineNodes, s)
			res.OnlineCount++
		}
	}

	if len(targets) == 0 {
		for _, s := range a.state.Services {
			if s.IsBuiltinWarp() {
				continue
			}
			addOnlineSvc(s)
		}
		return res
	}

	seenMissing := make(map[string]bool)
	for _, t := range targets {
		switch t.Kind {
		case routing.TargetNode:
			svc, ok := a.serviceOrBuiltinWarp(t.Value)
			if !ok {
				if !seenMissing[t.Value] {
					seenMissing[t.Value] = true
					res.MissingNodeIDs = append(res.MissingNodeIDs, t.Value)
				}
				continue
			}
			addOnlineSvc(svc)
		case routing.TargetTag:
			for _, s := range a.state.Services {
				for _, st := range s.Tags {
					if strings.EqualFold(strings.TrimSpace(st), strings.TrimSpace(t.Value)) {
						addOnlineSvc(s)
						break
					}
				}
			}
		}
	}

	if act.FallbackToPool {
		for _, s := range a.state.Services {
			if s.IsBuiltinWarp() || seenCand[s.ID] {
				continue
			}
			if running[s.ID] {
				seenCand[s.ID] = true
				res.CandidateIDs = append(res.CandidateIDs, s.ID)
				res.OnlineNodes = append(res.OnlineNodes, s)
				res.FallbackOnline++
			}
		}
	}
	return res
}

func (a *app) activeNodesForTags(tags []string, precomputedRunning ...map[string]bool) int {
	if a.mgr == nil || len(tags) == 0 {
		return 0
	}
	var refs []routing.TargetRef
	for _, t := range tags {
		refs = append(refs, routing.TargetRef{Kind: routing.TargetTag, Value: t})
	}
	return a.resolveActionTargets(routing.NewProxyAction(refs, routing.DispatchSmart, false), precomputedRunning...).OnlineCount
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
	if a.tracker == nil || a.mgr == nil || !act.IsProxyAction() {
		return ""
	}
	res := a.resolveActionTargets(act, precomputedRunning...)
	if len(res.CandidateIDs) == 0 {
		return ""
	}
	if targetHost == "" {
		targetHost = "example.com"
	}
	bestID, sc, ok := a.tracker.PeekBest(res.CandidateIDs, targetHost)
	if !ok {
		return ""
	}
	if s, found := a.serviceOrBuiltinWarp(bestID); found {
		if sc.EWMA > 0 {
			return fmt.Sprintf("驻留: %s (%dms)", s.Name, max(1, sc.EWMA.Milliseconds()))
		}
		return fmt.Sprintf("驻留: %s", s.Name)
	}
	return ""
}

func (a *app) preferredNodeForRule(rule routing.Rule, precomputedRunning ...map[string]bool) string {
	if !rule.Action.IsProxyAction() {
		return ""
	}
	targetHost := "example.com"
	if len(rule.DomainSuffix) > 0 {
		targetHost = rule.DomainSuffix[0]
	}
	return a.preferredNodeForAction(rule.Action, targetHost, precomputedRunning...)
}

func isRuleDomesticDNS(rule routing.Rule) bool {
	if rule.ID == "preset-lan-direct" || rule.ID == "preset-cn-direct" {
		return true
	}
	if rule.Action.Type == routing.ActionDirect {
		return true
	}
	if rule.Action.TargetsNode(config.BuiltinWarpServiceID) {
		for _, gs := range rule.GeoSite {
			clean := strings.ToLower(strings.TrimSpace(gs))
			if clean == "cn" || clean == "geolocation-cn" || clean == "tld-cn" {
				return true
			}
		}
		for _, gi := range rule.GeoIP {
			if strings.EqualFold(strings.TrimSpace(gi), "cn") {
				return true
			}
		}
	}
	return false
}

func isSingleWarpTarget(act routing.RouteAction) bool {
	targets := act.NormalizedTargets()
	return len(targets) == 1 &&
		targets[0].Kind == routing.TargetNode &&
		targets[0].Value == config.BuiltinWarpServiceID &&
		!act.FallbackToPool
}

func isDirectWarpRule(rule routing.Rule) bool {
	return isSingleWarpTarget(rule.Action) && isRuleDomesticDNS(rule)
}

func topActionIndexForRouteAction(act routing.RouteAction) int {
	switch act.Type {
	case routing.ActionDirect:
		return 1
	case routing.ActionBlock:
		return 2
	default:
		return 0
	}
}

func (a *app) openEditRuleFromDrawer(rule routing.Rule) {
	a.activeRuleDrawerID = ""
	a.openEditRuleDialog(rule)
	a.ruleEditor.returnToDrawer = true
}

func (a *app) openEditFinalRuleFromDrawer() {
	a.activeRuleDrawerID = ""
	a.openEditFinalRuleDialog()
	a.ruleEditor.returnToDrawer = true
}

func (a *app) dismissRuleEditorDrawer(reopenDetails bool) {
	wasReturn := a.ruleEditor.returnToDrawer && !a.ruleEditor.isNew
	targetID := a.ruleEditor.ruleID
	if a.ruleEditor.isFinal {
		targetID = "final"
	}
	a.ruleEditor.open = false
	a.ruleEditor.errText = ""
	a.ruleEditor.returnToDrawer = false
	if reopenDetails && wasReturn && targetID != "" {
		a.activeRuleDrawerID = targetID
	}
}

func (a *app) openCreateRuleDialog() {
	a.ruleEditor = ruleEditorForm{
		open:           true,
		isNew:          true,
		ruleID:         fmt.Sprintf("rule-%d", len(a.state.RoutingRules)+1),
		name:           fmt.Sprintf("分流规则 %d", len(a.state.RoutingRules)+1),
		actionIndex:     0,
		directWarp:      false,
		targets:         nil,
		dispatchPolicy:  routing.DispatchSmart,
		strictIsolation: true,
	}
	if a.win != nil {
		a.win.Invalidate()
	}
}

func (a *app) openEditRuleDialog(rule routing.Rule) {
	initTab := 0
	if len(rule.GeoSite) == 0 && len(rule.GeoIP) == 0 && (len(rule.DomainSuffix) > 0 || len(rule.IPCidr) > 0 || len(rule.DomainKeyword) > 0 || len(rule.DomainFull) > 0) {
		initTab = 1
	}

	actionIdx := topActionIndexForRouteAction(rule.Action)
	directWarp := false
	targets := rule.Action.NormalizedTargets()
	if isDirectWarpRule(rule) {
		actionIdx = 1
		directWarp = true
		targets = nil
	}

	a.ruleEditor = ruleEditorForm{
		open:             true,
		isNew:            false,
		ruleID:           rule.ID,
		name:             a.localizedRuleName(rule),
		desc:             a.localizedRuleDescription(rule),
		actionIndex:      actionIdx,
		directWarp:       directWarp,
		targets:          targets,
		dispatchPolicy:   rule.Action.EffectiveDispatchPolicy(),
		strictIsolation:  !rule.Action.FallbackToPool,
		domainsInput:     strings.Join(rule.DomainSuffix, "\n"),
		fullDomainsInput: strings.Join(rule.DomainFull, "\n"),
		cidrsInput:       strings.Join(rule.IPCidr, "\n"),
		keywordsInput:    strings.Join(rule.DomainKeyword, ", "),
		geosites:         append([]string(nil), rule.GeoSite...),
		geoips:           append([]string(nil), rule.GeoIP...),
		tab:              initTab,
	}
	if a.win != nil {
		a.win.Invalidate()
	}
}

func (a *app) openEditFinalRuleDialog() {
	cat := a.catalog()
	a.ruleEditor = ruleEditorForm{
		open:           true,
		isNew:          false,
		isFinal:        true,
		ruleID:         "final-fallback",
		name:           cat.RoutingFinalFallback(),
		desc:           cat.RoutingFinalDesc(),
		actionIndex:    topActionIndexForRouteAction(a.state.RoutingFinal),
		targets:         a.state.RoutingFinal.NormalizedTargets(),
		dispatchPolicy:  a.state.RoutingFinal.EffectiveDispatchPolicy(),
		strictIsolation: !a.state.RoutingFinal.FallbackToPool,
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
	if a.state.RoutingFinal.Type == routing.ActionProxyPool && len(a.state.RoutingFinal.NormalizedTargets()) == 0 {
		a.state.RoutingFinal = routing.RouteAction{Type: routing.ActionDirect}
	} else if a.state.RoutingFinal.Type == routing.ActionDirect {
		a.state.RoutingFinal = routing.NewWarpTargetAction()
	} else if a.state.RoutingFinal.TargetsNode(config.BuiltinWarpServiceID) {
		a.state.RoutingFinal = routing.NewProxyAction([]routing.TargetRef{{Kind: routing.TargetTag, Value: "AI"}}, routing.DispatchSmart, false)
	} else {
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
						ui.Icon(c, iconDownload).Size(11, 11).TextColor(p.amberText)
						ui.Text(c, guideText).FontSize(11).TextColor(p.amberText)
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

func (a *app) hasTargetRef(kind routing.TargetKind, value string) bool {
	for _, t := range a.ruleEditor.targets {
		if t.Kind != kind {
			continue
		}
		if kind == routing.TargetTag && strings.EqualFold(t.Value, value) {
			return true
		}
		if kind == routing.TargetNode && t.Value == value {
			return true
		}
	}
	return false
}

func (a *app) toggleTargetRef(kind routing.TargetKind, value string) {
	value = strings.TrimSpace(value)
	if kind == routing.TargetTag {
		value = strings.TrimSpace(strings.TrimPrefix(value, "#"))
	}
	if value == "" {
		return
	}
	for i, t := range a.ruleEditor.targets {
		if t.Kind != kind {
			continue
		}
		match := (kind == routing.TargetNode && t.Value == value) || (kind == routing.TargetTag && strings.EqualFold(t.Value, value))
		if match {
			a.ruleEditor.targets = append(a.ruleEditor.targets[:i], a.ruleEditor.targets[i+1:]...)
			return
		}
	}
	a.ruleEditor.targets = append(a.ruleEditor.targets, routing.TargetRef{Kind: kind, Value: value})
}

func (a *app) addTargetFromQuery(raw string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return
	}
	if strings.HasPrefix(raw, "#") {
		tag := strings.TrimSpace(strings.TrimPrefix(raw, "#"))
		if tag != "" && !a.hasTargetRef(routing.TargetTag, tag) {
			a.ruleEditor.targets = append(a.ruleEditor.targets, routing.TargetRef{Kind: routing.TargetTag, Value: tag})
		}
		return
	}
	clean := strings.TrimSpace(strings.TrimPrefix(raw, "@"))
	for _, svc := range a.allSelectableNodes() {
		if strings.EqualFold(svc.Name, clean) || svc.ID == clean {
			if !a.hasTargetRef(routing.TargetNode, svc.ID) {
				a.ruleEditor.targets = append(a.ruleEditor.targets, routing.TargetRef{Kind: routing.TargetNode, Value: svc.ID})
			}
			return
		}
	}
	if !a.hasTargetRef(routing.TargetTag, clean) {
		a.ruleEditor.targets = append(a.ruleEditor.targets, routing.TargetRef{Kind: routing.TargetTag, Value: clean})
	}
}

func (a *app) moveTargetRef(idx int, delta int) {
	next := idx + delta
	if idx < 0 || idx >= len(a.ruleEditor.targets) || next < 0 || next >= len(a.ruleEditor.targets) {
		return
	}
	a.ruleEditor.targets[idx], a.ruleEditor.targets[next] = a.ruleEditor.targets[next], a.ruleEditor.targets[idx]
}

func (a *app) renderProxyTargetPicker(c *ui.Context, p palette, runningIDs map[string]bool) {
	cat := a.catalog()
	isOrder := a.ruleEditor.dispatchPolicy == routing.DispatchOrder

	ui.Column(c.Key("rule-proxy-target-picker")).Gap(6).Children(func() {
		// Header row: Label + Mode Pill + Clear button
		ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(8).Children(func() {
			ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
				ui.Text(c, cat.RuleTargetLabel()).FontSize(12).FontWeight(600).TextColor(p.text)
				if len(a.ruleEditor.targets) == 0 {
					tagPill(c, cat.RoutingProxyPool(), p.accentText, p.accentBg)
				} else {
					tagPill(c, fmt.Sprintf("%d", len(a.ruleEditor.targets)), p.accentText, p.accentBg)
				}
			})
			if len(a.ruleEditor.targets) > 0 {
				clearBtn := ui.ButtonBase(c.Key("btn-clear-rule-targets")).
					Label(cat.RuleTargetClearAll()).
					Radius(4).PaddingX(8).PaddingY(2).
					Background(p.elevated).Border(1, p.borderSubtle).
					Children(func() {
						ui.Text(c, cat.RuleTargetClearAll()).FontSize(11).TextColor(p.textMuted)
					})
				if clearBtn.Clicked() {
					a.ruleEditor.targets = nil
					a.ruleEditor.targetQuery = ""
				}
			}
		})

		// Unified Chip Box + Quick-Pick Palette
		dsInsetBox(c, p, "rule-target-picker-box", func() {
				// Selected Chips + Inline Query Input
				ui.Row(c.Key("rule-target-chips-row")).
					AlignItems(ui.Center).Gap(6).Wrap().
					Children(func() {
						for idx, t := range a.ruleEditor.targets {
							chipIdx := idx
							ref := t
							chipKey := fmt.Sprintf("rule-target-chip-%d-%s-%s", chipIdx, ref.Kind, ref.Value)
							isNode := ref.Kind == routing.TargetNode

							var labelText string
							var svc config.Service
							var foundSvc bool
							var missing bool
							var online bool
							if isNode {
								svc, foundSvc = a.serviceOrBuiltinWarp(ref.Value)
								if !foundSvc {
									missing = true
									labelText = ref.Value
								} else {
									labelText = svc.Name
									online = runningIDs[svc.ID]
								}
							} else {
								labelText = "#" + ref.Value
							}

							chipBg := p.accentBg
							chipBorder := p.accent.Alpha(0.35)
							chipText := p.accentText
							if isNode && missing {
								chipBg = p.amberBg
								chipBorder = p.amber.Alpha(0.5)
								chipText = p.amberText
							} else if isNode {
								chipBg = p.elevated
								chipBorder = p.borderSubtle
								chipText = p.text
							}

							ui.Row(c.Key(chipKey)).
								AlignItems(ui.Center).Gap(4).
								PaddingX(7).PaddingY(3).Radius(5).
								Background(chipBg).Border(1, chipBorder).
								Children(func() {
									if isOrder && len(a.ruleEditor.targets) > 1 {
										ui.Text(c, fmt.Sprintf("%d.", chipIdx+1)).FontSize(10).FontWeight(700).TextColor(p.textDim)
									}
									if isNode {
										dotCol := p.textDim.Alpha(0.45)
										if missing {
											dotCol = p.amber
										} else if online {
											dotCol = p.green
										}
										ui.Box(c).Size(6, 6).Radius(3).Background(dotCol)
									}
									ui.Text(c, labelText).FontSize(11).FontWeight(500).TextColor(chipText)
									if isNode && foundSvc && svc.EnableWARP {
										tagPill(c, "+WARP", p.greenText, p.greenBg)
									}
									if isNode && missing {
										tagPill(c, cat.RuleTargetMissingNode(), p.amberText, p.amberBg)
									}
									if isOrder && len(a.ruleEditor.targets) > 1 {
										if chipIdx > 0 {
											leftBtn := ui.ButtonBase(c.Key(chipKey + "-left")).
												Label("move-left-" + ref.Value).
												Radius(3).PaddingX(3).Background(ui.Transparent).
												Children(func() {
													ui.Text(c, "‹").FontSize(11).FontWeight(700).TextColor(p.textDim)
												})
											if leftBtn.Clicked() {
												a.moveTargetRef(chipIdx, -1)
											}
										}
										if chipIdx < len(a.ruleEditor.targets)-1 {
											rightBtn := ui.ButtonBase(c.Key(chipKey + "-right")).
												Label("move-right-" + ref.Value).
												Radius(3).PaddingX(3).Background(ui.Transparent).
												Children(func() {
													ui.Text(c, "›").FontSize(11).FontWeight(700).TextColor(p.textDim)
												})
											if rightBtn.Clicked() {
												a.moveTargetRef(chipIdx, 1)
											}
										}
									}
									delBtn := ui.ButtonBase(c.Key(fmt.Sprintf("rule-target-del-%s-%s", ref.Kind, ref.Value))).
										Label("del-target-" + ref.Value).
										Radius(999).PaddingX(2).Background(ui.Transparent).
										Children(func() {
											ui.Text(c, "×").FontSize(11).FontWeight(700).TextColor(p.textDim)
										})
									if delBtn.Clicked() {
										a.toggleTargetRef(ref.Kind, ref.Value)
									}
								})
						}

						placeholder := cat.RuleTargetHintEmpty()
						if len(a.ruleEditor.targets) > 0 {
							placeholder = cat.RuleTargetHintMore()
						}
						inp := ui.TextInput(c.Key("rule-set-target-input"), &a.ruleEditor.targetQuery).
							Label(cat.RuleTargetLabel()).
							Placeholder(placeholder).
							Height(24).Radius(4).FontSize(11).Grow(1).MinWidth(160).
							Background(ui.Transparent).Border(0, ui.Transparent)

						if strings.Contains(a.ruleEditor.targetQuery, ",") || strings.Contains(a.ruleEditor.targetQuery, "\n") {
							for _, pt := range parseCommaOrLines(a.ruleEditor.targetQuery) {
								a.addTargetFromQuery(pt)
							}
							a.ruleEditor.targetQuery = ""
						} else if inp.Submitted() && strings.TrimSpace(a.ruleEditor.targetQuery) != "" {
							a.addTargetFromQuery(a.ruleEditor.targetQuery)
							a.ruleEditor.targetQuery = ""
						}
					})

				ui.Box(c).Fill().Height(1).Background(p.borderSubtle)

				// Group A: Direct Node Suggestions
				q := strings.ToLower(strings.TrimSpace(a.ruleEditor.targetQuery))
				nodeQuery := q
				if strings.HasPrefix(nodeQuery, "@") {
					nodeQuery = strings.TrimSpace(strings.TrimPrefix(nodeQuery, "@"))
				}
				nodes := a.allSelectableNodes()
				var visibleNodes []config.Service
				for _, svc := range nodes {
					if strings.HasPrefix(q, "#") {
						continue
					}
					if nodeQuery != "" {
						protoStr := strings.ToLower(string(svc.EffectiveProtocol()))
						if !strings.Contains(strings.ToLower(svc.Name), nodeQuery) &&
							!strings.Contains(strings.ToLower(svc.ID), nodeQuery) &&
							!strings.Contains(protoStr, nodeQuery) {
							continue
						}
					}
					visibleNodes = append(visibleNodes, svc)
				}

				ui.Column(c.Key("rule-pick-nodes-group")).Gap(5).Children(func() {
					ui.Text(c, cat.RuleTargetNodesGroup()).FontSize(11).FontWeight(500).TextColor(p.textMuted)
					ui.Row(c).AlignItems(ui.Center).Gap(6).Wrap().Children(func() {
						for _, svc := range visibleNodes {
							s := svc
							selected := a.hasTargetRef(routing.TargetNode, s.ID)
							online := runningIDs[s.ID]
							bg := p.elevated
							bd := p.borderSubtle
							if selected {
								bg = p.accentBg
								bd = p.accent.Alpha(0.5)
							}
							btn := ui.ButtonBase(c.Key("rule-pick-node-" + s.ID)).
								Label("pick-node-" + s.ID).
								Radius(5).PaddingX(8).PaddingY(4).
								Background(bg).Border(1, bd).
								Children(func() {
									ui.Row(c).AlignItems(ui.Center).Gap(5).Children(func() {
										dotCol := p.textDim.Alpha(0.45)
										if online {
											dotCol = p.green
										}
										ui.Box(c).Size(6, 6).Radius(3).Background(dotCol)
										ui.Text(c, s.Name).FontSize(11).FontWeight(500).TextColor(p.text)
										protoLabel := strings.ToUpper(string(s.EffectiveProtocol()))
										ui.Text(c, protoLabel).FontSize(dsFontMicro).TextColor(p.textDim)
										if s.IsBuiltinWarp() {
											tagPill(c, cat.TagBuiltin(), p.greenText, p.greenBg)
										} else if s.EnableWARP {
											tagPill(c, "+WARP", p.greenText, p.greenBg)
										}
									})
								})
							if btn.Clicked() {
								a.toggleTargetRef(routing.TargetNode, s.ID)
								a.ruleEditor.targetQuery = ""
							}
						}
					})
				})

				// Group B: Tag Pool Suggestions
				allTags := a.allKnownServiceTags()
				tagFilter := strings.TrimSpace(strings.TrimPrefix(q, "#"))
				var visibleTags []string
				for _, t := range allTags {
					if tagFilter == "" || strings.Contains(strings.ToLower(t), tagFilter) {
						visibleTags = append(visibleTags, t)
					}
				}
				if len(visibleTags) > 0 {
					ui.Column(c.Key("rule-pick-tags-group")).Gap(5).Children(func() {
						ui.Text(c, cat.RuleTargetTagsGroup()).FontSize(11).FontWeight(500).TextColor(p.textMuted)
						ui.Row(c).AlignItems(ui.Center).Gap(6).Wrap().Children(func() {
							for _, t := range visibleTags {
								tagVal := t
								selected := a.hasTargetRef(routing.TargetTag, tagVal)
								bg := p.elevated
								bd := p.borderSubtle
								txt := p.accentText
								if selected {
									bg = p.accentBg
									bd = p.accent.Alpha(0.5)
								}
								btn := ui.ButtonBase(c.Key("rule-pick-tag-" + tagVal)).
									Label("pick-tag-" + tagVal).
									Radius(5).PaddingX(8).PaddingY(3).
									Background(bg).Border(1, bd).
									Children(func() {
										ui.Text(c, "#"+tagVal).FontSize(11).FontWeight(500).TextColor(txt)
									})
								if btn.Clicked() {
									a.toggleTargetRef(routing.TargetTag, tagVal)
									a.ruleEditor.targetQuery = ""
								}
							}
						})
					})
				}
			})

		// Dispatch Policy & Isolation Bar (Dispatch mode always visible under Proxy; Isolation shown when specific targets are selected)
		dsInsetBox(c, p, "rule-policy-bar", func() {
			polIdx := 0
			if a.ruleEditor.dispatchPolicy == routing.DispatchOrder {
				polIdx = 1
			}
			desc := cat.RuleDispatchSmartDesc()
			if polIdx == 1 {
				desc = cat.RuleDispatchOrderDesc()
			}
			dsSettingHeaderRow(c, p, "", cat.RuleDispatchPolicyLabel(), desc, func() {
				if segmentedControl(c.Key("rule-dispatch-policy"), p, &polIdx, []string{cat.RuleDispatchSmart(), cat.RuleDispatchOrder()}) {
					if polIdx == 1 {
						a.ruleEditor.dispatchPolicy = routing.DispatchOrder
					} else {
						a.ruleEditor.dispatchPolicy = routing.DispatchSmart
					}
				}
			})

			if len(a.ruleEditor.targets) > 0 {
				ui.Box(c).Fill().Height(1).Background(p.borderSubtle)

				isoDesc := cat.RuleFallbackStrictDesc()
				if !a.ruleEditor.strictIsolation {
					isoDesc = cat.RuleFallbackOpenDesc()
				}
				dsSettingHeaderRow(c, p, "rule-isolation-row", cat.RuleStrictIsolationLabel(), isoDesc, func() {
					ui.Switch(c.Key("toggle-rule-strict-isolation"), &a.ruleEditor.strictIsolation).
						Label("toggle-rule-strict-isolation")
				})
			}
		})
	})
}

func (a *app) saveRuleEditor() {
	var act routing.RouteAction
	switch a.ruleEditor.actionIndex {
	case 0:
		targets := append([]routing.TargetRef(nil), a.ruleEditor.targets...)
		if q := strings.TrimSpace(a.ruleEditor.targetQuery); q != "" {
			for _, pt := range parseCommaOrLines(q) {
				a.addTargetFromQuery(pt)
			}
			targets = append([]routing.TargetRef(nil), a.ruleEditor.targets...)
		}
		act = routing.NewProxyAction(targets, a.ruleEditor.dispatchPolicy, !a.ruleEditor.strictIsolation)
	case 1:
		if a.ruleEditor.directWarp && a.ruleEditor.ruleID != "preset-lan-direct" {
			act = routing.NewWarpTargetAction()
		} else {
			act = routing.RouteAction{Type: routing.ActionDirect}
		}
	case 2:
		act = routing.RouteAction{Type: routing.ActionBlock}
	}

	if a.ruleEditor.isFinal {
		a.state.RoutingFinal = act
		a.saveState()
		returnToDetails := a.ruleEditor.returnToDrawer
		a.ruleEditor.open = false
		a.ruleEditor.errText = ""
		a.ruleEditor.returnToDrawer = false
		if returnToDetails {
			a.activeRuleDrawerID = "final"
		}
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
	fullDomains := parseLines(a.ruleEditor.fullDomainsInput)
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

	if len(domains) == 0 && len(fullDomains) == 0 && len(cidrs) == 0 && len(keywords) == 0 && len(geosites) == 0 && len(geoips) == 0 {
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
			DomainFull:    fullDomains,
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
				a.state.RoutingRules[i].DomainFull = fullDomains
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
	returnToDetails := a.ruleEditor.returnToDrawer && !a.ruleEditor.isNew
	savedID := a.ruleEditor.ruleID
	a.ruleEditor.open = false
	a.ruleEditor.errText = ""
	a.ruleEditor.returnToDrawer = false
	if returnToDetails && savedID != "" {
		a.activeRuleDrawerID = savedID
	}
	a.toast("分流规则已更新")
	if a.win != nil {
		a.win.Invalidate()
	}
}

func (a *app) ruleMatchesSearch(rule routing.Rule, lowerQuery string) bool {
	if lowerQuery == "" {
		return true
	}
	if strings.Contains(strings.ToLower(a.localizedRuleName(rule)), lowerQuery) ||
		strings.Contains(strings.ToLower(a.localizedRuleDescription(rule)), lowerQuery) ||
		strings.Contains(strings.ToLower(rule.ID), lowerQuery) {
		return true
	}
	for _, list := range [][]string{
		rule.DomainSuffix,
		rule.DomainFull,
		rule.IPCidr,
		rule.DomainKeyword,
		rule.GeoSite,
		rule.GeoIP,
	} {
		for _, item := range list {
			if strings.Contains(strings.ToLower(item), lowerQuery) {
				return true
			}
		}
	}
	return false
}

func (a *app) finalRuleMatchesSearch(lowerQuery string) bool {
	if lowerQuery == "" {
		return true
	}
	cat := a.catalog()
	return strings.Contains(strings.ToLower(cat.RoutingFinalFallback()), lowerQuery) ||
		strings.Contains(strings.ToLower(cat.RoutingFinalDesc()), lowerQuery) ||
		strings.Contains("final", lowerQuery)
}

func (a *app) preferredNodeNameForRule(act routing.RouteAction, targetHost string, precomputedRunning ...map[string]bool) string {
	if a.tracker == nil || a.mgr == nil || !act.IsProxyAction() {
		return ""
	}
	res := a.resolveActionTargets(act, precomputedRunning...)
	if len(res.CandidateIDs) == 0 {
		return ""
	}
	if targetHost == "" {
		targetHost = "example.com"
	}
	bestID, sc, ok := a.tracker.PeekBest(res.CandidateIDs, targetHost)
	if !ok {
		return ""
	}
	if s, found := a.serviceOrBuiltinWarp(bestID); found {
		if sc.EWMA > 0 {
			return fmt.Sprintf("%s (%dms)", s.Name, max(1, sc.EWMA.Milliseconds()))
		}
		return s.Name
	}
	return ""
}

func (a *app) renderRuleRouteSummary(c *ui.Context, p palette, rule routing.Rule, isFinal, hasGeo bool, runningIDs map[string]bool) {
	cat := a.catalog()
	act := rule.Action
	hasGeoCriteria := len(rule.GeoSite) > 0 || len(rule.GeoIP) > 0
	hasOtherCriteria := len(rule.DomainSuffix) > 0 || len(rule.IPCidr) > 0 || len(rule.DomainKeyword) > 0 || len(rule.DomainFull) > 0

	var routeText string
	var routeColor ui.Color
	dnsText := ""

	switch act.Type {
	case routing.ActionBlock:
		routeText = "➔ " + cat.RoutingBlock()
		routeColor = p.redText
	case routing.ActionDirect:
		routeText = "➔ " + cat.RoutingDirect()
		routeColor = p.textMuted
		dnsText = cat.DnsDomesticBadge()
	default:
		targets := act.NormalizedTargets()
		res := a.resolveActionTargets(act, runningIDs)
		targetHost := ""
		if len(rule.DomainSuffix) > 0 {
			targetHost = rule.DomainSuffix[0]
		}
		pref := a.preferredNodeNameForRule(act, targetHost, runningIDs)

		if len(targets) == 0 {
			activeCount := res.OnlineCount
			if activeCount == 0 && !a.isBuiltinWarpNeeded() {
				activeCount = a.activeRunningCount()
			}
			routeText = fmt.Sprintf("➔ %s (%s)", cat.RoutingProxyPool(), cat.RoutingOnlineCount(fmt.Sprint(activeCount)))
			if pref != "" {
				routeText += " · " + pref
			}
			if activeCount > 0 {
				routeColor = p.text
			} else {
				routeColor = p.amberText
			}
		} else {
			allTags := true
			var tagLabels []string
			for _, t := range targets {
				if t.Kind != routing.TargetTag {
					allTags = false
					break
				}
				tagLabels = append(tagLabels, "#"+t.Value)
			}
			isOrder := act.EffectiveDispatchPolicy() == routing.DispatchOrder && len(targets) > 1
			if !isFinal && isSingleWarpTarget(act) && isRuleDomesticDNS(rule) {
				routeText = "➔ " + cat.RoutingWarp()
				if res.OnlineCount > 0 {
					routeColor = p.greenText
				} else {
					routeColor = p.amberText
				}
			} else if allTags && !isOrder {
				tagDisplay := strings.Join(tagLabels, ", ")
				routeText = fmt.Sprintf("➔ %s (%s)", tagDisplay, cat.RoutingOnlineCount(fmt.Sprint(res.OnlineCount)))
				if act.FallbackToPool {
					routeText += " · " + cat.RuleTargetFallbackBadge()
				}
				if pref != "" {
					routeText += " · " + pref
				}
				if res.OnlineCount > 0 {
					routeColor = p.text
				} else {
					routeColor = p.amberText
				}
			} else {
				var parts []string
				for _, t := range targets {
					if t.Kind == routing.TargetNode {
						if svc, ok := a.serviceOrBuiltinWarp(t.Value); ok {
							part := svc.Name
							if svc.EnableWARP {
								part += " +WARP"
							}
							parts = append(parts, part)
						} else {
							parts = append(parts, t.Value+" ("+cat.RuleTargetMissingNode()+")")
						}
					} else {
						parts = append(parts, "#"+t.Value)
					}
				}
				sep := ", "
				if isOrder {
					sep = " → "
				}
				routeText = fmt.Sprintf("➔ %s (%s)", strings.Join(parts, sep), cat.RoutingOnlineCount(fmt.Sprint(res.OnlineCount)))
				if act.FallbackToPool {
					routeText += " · " + cat.RuleTargetFallbackBadge()
				}
				if pref != "" {
					routeText += " · " + pref
				}
				if len(res.MissingNodeIDs) > 0 || res.OnlineCount == 0 {
					routeColor = p.amberText
				} else {
					routeColor = p.text
				}
			}
		}

		if !isFinal && isRuleDomesticDNS(rule) {
			dnsText = cat.DnsDomesticBadge()
		} else {
			dnsText = cat.DnsRemoteBadge()
		}
	}

	ui.Row(c).
		AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(8).
		Padding(8, 0, 0, 15).
		BorderWidth(1, 0, 0, 0).BorderColor(p.borderSubtle).
		Children(func() {
			ui.Text(c, routeText).FontSize(11).FontWeight(500).FontFeatures("tnum").TextColor(routeColor).
				SingleLine().Ellipsis("…").Shrink(1).MinWidth(0)

			ui.Row(c).AlignItems(ui.Center).Gap(6).Shrink(0).Children(func() {
				if !isFinal && rule.Enabled && hasGeoCriteria && !hasGeo {
					warnLabel := cat.RulePartialGeoPending()
					if !hasOtherCriteria {
						warnLabel = cat.RulePendingGeoData()
					}
					ui.Text(c, warnLabel).FontSize(10).FontWeight(600).TextColor(p.amberText).NoWrap()
				}
				if dnsText != "" {
					ui.Text(c, dnsText).FontSize(11).TextColor(p.textDim).NoWrap()
				}
			})
		})
}

func (a *app) renderRuleCard(c *ui.Context, p palette, ruleIndex int, rule routing.Rule, hasGeo bool, runningIDs map[string]bool) {
	cat := a.catalog()
	hasGeoCriteria := len(rule.GeoSite) > 0 || len(rule.GeoIP) > 0
	hasOtherCriteria := len(rule.DomainSuffix) > 0 || len(rule.IPCidr) > 0 || len(rule.DomainKeyword) > 0 || len(rule.DomainFull) > 0

	cardBorder := p.borderSubtle
	cardBg := p.card
	if rule.Enabled && hasGeoCriteria && !hasGeo && !hasOtherCriteria {
		cardBorder = p.amber.Alpha(0.35)
	}

	card := ui.Column(c.Key(fmt.Sprintf("rule-card-%s", rule.ID))).
		Grow(1).
		Padding(14).Radius(10).Gap(6).
		Background(cardBg).
		Border(1, cardBorder)
	if card.Hovered() {
		card.Background(p.cardHover).Border(1, p.border)
	}

	card.Children(func() {
		// Line 1: Status dot + Rule Name on left, Quiet icon actions + Switch on right
		ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(8).Children(func() {
			ui.Row(c).AlignItems(ui.Center).Gap(8).Grow(1).Shrink(1).MinWidth(0).Children(func() {
				switch {
				case !rule.Enabled:
					hollowStatusDot(c, p.textDim.Alpha(0.5))
				case hasGeoCriteria && !hasGeo && !hasOtherCriteria:
					statusDot(c, p.amber)
				default:
					statusDot(c, p.green)
				}

				titleCol := p.text
				if !rule.Enabled {
					titleCol = p.textMuted
				}
				nameBtn := ui.Box(c.Key("btn-name-rule-" + rule.ID)).MinWidth(0).Shrink(1).Children(func() {
					ui.Text(c, a.localizedRuleName(rule)).FontSize(13).FontWeight(600).TextColor(titleCol).
						SingleLine().Ellipsis("…")
				})
				if nameBtn.Clicked() {
					a.activeRuleDrawerID = rule.ID
				}
			})

			ui.Row(c).AlignItems(ui.Center).Gap(2).Shrink(0).Children(func() {
				if quietRowIconButton(c.Key("btn-detail-rule-"+rule.ID), p, iconList, cat.RuleDrawerTitle(), false, false).
					Tooltip(cat.RuleDrawerTitle()).
					Clicked() {
					a.activeRuleDrawerID = rule.ID
				}
				if quietRowIconButton(c.Key("btn-edit-rule-"+rule.ID), p, iconEdit, cat.ActionEdit(), false, false).
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

				ui.Box(c).Size(1, 14).Background(p.borderSubtle).Margin(0, 4, 0, 4).Shrink(0)

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

		// Line 2: Description (always render one line so cards stay uniform in height)
		desc := strings.TrimSpace(a.localizedRuleDescription(rule))
		descColor := p.textMuted
		if desc == "" {
			desc = cat.RuleCardDefaultDesc()
			descColor = p.textDim
		}
		ui.Box(c).Padding(0, 0, 0, 15).Children(func() {
			ui.Text(c, desc).FontSize(11).TextColor(descColor).SingleLine().Ellipsis("…")
		})

		// Line 3: Single-line outbound route summary + right-aligned DNS/Geo status
		a.renderRuleRouteSummary(c, p, rule, false, hasGeo, runningIDs)
	})

	if card.Clicked() {
		a.activeRuleDrawerID = rule.ID
	}
}

func (a *app) renderRoutingPage(c *ui.Context, p palette) {
	cat := a.catalog()
	hasGeo := a.hasGeoData()
	var runningIDs map[string]bool
	if a.mgr != nil {
		runningIDs = a.mgr.RunningServiceIDs()
	}

	enabledCount := 1 // Final fallback is always active
	for _, r := range a.state.RoutingRules {
		if r.Enabled {
			enabledCount++
		}
	}
	totalCount := len(a.state.RoutingRules) + 1

	ui.Column(c.Key("routing-page")).Grow(1).Fill().MinHeight(0).Children(func() {
		// Fixed Page Header (Nodes pattern)
		dsPageHeader(c, p, "routing-header", false, func() {
			// Left: Title + tabular summary + GeoData dot
			ui.Row(c).AlignItems(ui.Center).Gap(10).MinWidth(0).Shrink(1).Children(func() {
				dsPageTitle(c, p, cat.RoutingTitle())

				ui.Row(c).AlignItems(ui.Center).Gap(dsSpaceSM).MinWidth(0).Shrink(1).Children(func() {
					ui.Text(c, cat.RoutingEnabledSummary(enabledCount, totalCount)).
						FontSize(dsFontBody).FontFeatures("tnum").TextColor(p.textMuted).NoWrap()
					ui.Text(c, "·").FontSize(dsFontBody).TextColor(p.textDim).NoWrap()
					if hasGeo {
						statusDot(c, p.green)
						geoLabel := cat.GeodataStatusReady()
						if a.localGeodataVersion != "" {
							geoLabel = fmt.Sprintf("%s (%s)", cat.GeodataStatusReady(), a.localGeodataVersion)
						}
						ui.Text(c, geoLabel).FontSize(dsFontBody).FontFeatures("tnum").TextColor(p.textMuted).SingleLine().Ellipsis("…")
					} else {
						statusDot(c, p.amber)
						ui.Text(c, cat.GeodataStatusMissing()).FontSize(dsFontBody).TextColor(p.amberText).SingleLine().Ellipsis("…")
					}
				})
			})
		}, func() {
			// Right: Search + Strategy Help Popover + More Menu + New Rule CTA
			ui.Row(c).AlignItems(ui.Center).Gap(dsSpaceSM).Shrink(0).Children(func() {
				ui.SearchField(c.Key("input-routing-search"), &a.routingSearch).
					Placeholder(cat.RoutingSearchPlaceholder()).
					Label(cat.RoutingSearchPlaceholder()).
					Width(156).Height(dsHeightControl).Radius(dsRadiusMD).FontSize(dsFontBody).
					Background(p.card)

				helpBtn := quietToolbarButton(c.Key("btn-routing-strategy-help"), p, iconInfo, cat.RoutingStrategyHelpBtn(), false).
					Tooltip(cat.RoutingStrategyHelpTooltip())
				if helpBtn.Clicked() {
					a.openRoutingMoreMenu = false
					a.showRoutingStrategyHelp = !a.showRoutingStrategyHelp
				}
				dsHelpPopover(c, p, helpBtn, &a.showRoutingStrategyHelp, 380, ui.AnchorBottomEnd, ui.AnchorTopEnd, func() {
					ui.Column(c).Gap(dsSpaceXS).Children(func() {
						ui.Text(c, cat.RoutingMatchOrderTitle()).FontSize(dsFontBody).FontWeight(600).TextColor(p.text)
						ui.Text(c, cat.RoutingMatchOrderDesc()).FontSize(dsFontCaption).TextColor(p.textMuted).LineHeight(1.4)
					})
					ui.Box(c).FillWidth().Height(1).Background(p.borderSubtle)
					ui.Column(c).Gap(dsSpaceXS).Children(func() {
						ui.Text(c, cat.RoutingDnsAlignmentTitle()).FontSize(dsFontBody).FontWeight(600).TextColor(p.text)
						ui.Text(c, cat.RoutingDnsAlignmentDesc()).FontSize(dsFontCaption).TextColor(p.textMuted).LineHeight(1.4)
						ui.Text(c, cat.RoutingDnsDescDirect()).FontSize(dsFontCaption).TextColor(p.textDim).LineHeight(1.4)
						ui.Text(c, cat.RoutingDnsDescProxyPort()).FontSize(dsFontCaption).TextColor(p.textDim).LineHeight(1.4)
						ui.Text(c, cat.RoutingDnsDescTun()).FontSize(dsFontCaption).TextColor(p.textDim).LineHeight(1.4)
					})
					ui.Box(c).FillWidth().Height(1).Background(p.borderSubtle)
					ui.Column(c).Gap(dsSpaceXS).Children(func() {
						ui.Text(c, cat.RoutingSmartPoolTitle()).FontSize(dsFontBody).FontWeight(600).TextColor(p.text)
						ui.Text(c, cat.RoutingSmartPoolDesc()).FontSize(dsFontCaption).TextColor(p.textMuted).LineHeight(1.4)
						ui.Text(c, cat.RoutingSmartPoolDetailEWMA()).FontSize(dsFontCaption).TextColor(p.textDim).LineHeight(1.4)
						ui.Text(c, cat.RoutingSmartPoolDetailCircuit()).FontSize(dsFontCaption).TextColor(p.textDim).LineHeight(1.4)
						ui.Text(c, cat.RoutingSmartPoolDetailAffinity()).FontSize(dsFontCaption).TextColor(p.textDim).LineHeight(1.4)
					})
				})

				moreBtn := quietToolbarIconButton(c.Key("btn-routing-more"), p, iconMore, cat.RoutingMoreActions(), a.openRoutingMoreMenu).
					Tooltip(cat.RoutingMoreActions())
				if moreBtn.Clicked() {
					a.showRoutingStrategyHelp = false
					a.openRoutingMoreMenu = !a.openRoutingMoreMenu
				}
				ui.PopoverBase(c, moreBtn, &a.openRoutingMoreMenu, func(panel ui.Element) {
					styleMenuPopoverPanel(panel, moreBtn, p, 176)
					panel.Children(func() {
						geoLabel := cat.UpdateGeoData()
						if a.updatingGeoData {
							geoLabel = cat.Updating()
						}
						if popoverMenuItem(c.Key("btn-update-geodata"), p, geoLabel, p.text, a.updatingGeoData, false).
							Disabled(a.updatingGeoData).DimDisabled(false).Clicked() {
							a.openRoutingMoreMenu = false
							a.triggerUpdateGeoData()
						}
						if popoverMenuItem(c.Key("btn-reset-presets"), p, cat.ResetPresets(), p.text, false, false).Clicked() {
							a.openRoutingMoreMenu = false
							a.resetRoutingPresets()
						}
					})
				})

				if primaryPillButton(c.Key("btn-new-rule"), p, iconPlus, cat.NewRule(), p.accent, false).Clicked() {
					a.openRoutingMoreMenu = false
					a.showRoutingStrategyHelp = false
					a.openCreateRuleDialog()
				}
			})
		})

		ui.Scroll(c.Key("routing-page-scroll")).
			Grow(1).Fill().MinHeight(0).
			Padding(16, 18, 24, 18).Gap(14).
			Children(func() {
				// Missing GeoData Callout Banner (only shown when GeoData is absent)
				if !hasGeo {
					ui.Row(c.Key("banner-geodata-missing")).
						AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(10).
						Padding(10, 14, 10, 14).Radius(8).
						Background(p.amberBg).Border(1, p.amber.Alpha(0.3)).
						Children(func() {
							ui.Row(c).AlignItems(ui.Center).Gap(8).Grow(1).MinWidth(0).Children(func() {
								ui.Icon(c, iconAlert).Size(14, 14).TextColor(p.amberText).Shrink(0)
								ui.Text(c, cat.RoutingGeodataBanner()).FontSize(12).FontWeight(500).TextColor(p.amberText).
									SingleLine().Ellipsis("…")
							})
							btnText := cat.UpdateGeoData()
							if a.updatingGeoData {
								btnText = cat.Updating()
							}
							if amberOutlineButton(c.Key("btn-banner-download-geodata"), p, iconDownload, btnText, a.updatingGeoData).Shrink(0).Clicked() {
								a.triggerUpdateGeoData()
							}
						})
				}

				lowerQuery := strings.ToLower(strings.TrimSpace(a.routingSearch))
				var customRules []routing.Rule
				var customIndices []int
				var presetRules []routing.Rule
				var presetIndices []int

				for idx, rule := range a.state.RoutingRules {
					if !a.ruleMatchesSearch(rule, lowerQuery) {
						continue
					}
					if strings.HasPrefix(rule.ID, "preset-") {
						presetRules = append(presetRules, rule)
						presetIndices = append(presetIndices, idx)
					} else {
						customRules = append(customRules, rule)
						customIndices = append(customIndices, idx)
					}
				}
				finalMatches := a.finalRuleMatchesSearch(lowerQuery)

				if lowerQuery != "" && len(customRules) == 0 && len(presetRules) == 0 && !finalMatches {
					ui.Column(c.Key("routing-search-empty")).
						AlignItems(ui.Center).Justify(ui.Center).
						Padding(28, 20, 28, 20).Radius(10).Gap(10).
						Background(p.card).Border(1, p.borderSubtle).
						Children(func() {
							ui.Text(c, cat.RoutingEmptySearch()).FontSize(13).TextColor(p.textMuted)
							if compactStripButton(c.Key("btn-routing-reset-search"), p, cat.ResetFilters(), cat.ResetFilters(), p.accentText).Clicked() {
								a.routingSearch = ""
							}
						})
					return
				}

				// Section 1: Custom Rules (Top Priority)
				ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
					ui.Text(c, cat.RoutingCustomSection()).FontSize(13).FontWeight(700).TextColor(p.text)
					ui.Text(c, fmt.Sprintf("%d", len(customRules))).FontSize(11).FontFeatures("tnum").TextColor(p.textDim)
					ui.Text(c, "·").FontSize(11).TextColor(p.textDim)
					ui.Text(c, cat.RoutingCustomPriorityHint()).FontSize(11).TextColor(p.textDim)
				})

				if len(customRules) > 0 {
					ui.Grid(c.Key("custom-rules-grid")).Columns(2).Gap(12).Children(func() {
						for i := range customRules {
							a.renderRuleCard(c, p, customIndices[i], customRules[i], hasGeo, runningIDs)
						}
					})
				} else if lowerQuery == "" {
					ui.Column(c.Key("custom-rules-empty")).
						Padding(14).Radius(10).
						Background(p.card).Border(1, p.borderSubtle).
						Children(func() {
							ui.Text(c, cat.RoutingCustomEmpty()).FontSize(12).TextColor(p.textMuted)
						})
				}

				// Section 2: Preset Rule Groups (Presets + Final Fallback)
				presetTotal := len(presetRules)
				if finalMatches {
					presetTotal++
				}
				if presetTotal > 0 {
					ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
						ui.Text(c, cat.RoutingPresetsSection()).FontSize(13).FontWeight(700).TextColor(p.text)
						ui.Text(c, fmt.Sprintf("%d", presetTotal)).FontSize(11).FontFeatures("tnum").TextColor(p.textDim)
						ui.Text(c, "·").FontSize(11).TextColor(p.textDim)
						ui.Text(c, cat.RoutingPresetsFallbackHint()).FontSize(11).TextColor(p.textDim)
					})

					ui.Grid(c.Key("preset-rules-grid")).Columns(2).Gap(12).Children(func() {
						for i := range presetRules {
							a.renderRuleCard(c, p, presetIndices[i], presetRules[i], hasGeo, runningIDs)
						}
						if finalMatches {
							a.renderFinalFallbackCard(c, p, hasGeo, runningIDs)
						}
					})
				}
			})
	})
}

func (a *app) renderFinalFallbackCard(c *ui.Context, p palette, hasGeo bool, runningIDs map[string]bool) {
	cat := a.catalog()

	// Final Fallback Rule Card (Undeletable, Always Active)
	card := ui.Column(c.Key("rule-card-final-fallback")).
		Grow(1).
		Padding(14).Radius(10).Gap(6).
		Background(p.card).
		Border(1, p.borderSubtle)
	if card.Hovered() {
		card.Background(p.cardHover).Border(1, p.border)
	}

	card.Children(func() {
		// Line 1: Status dot + Name + FINAL chip on left, Actions + Always Active text on right
		ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(8).Children(func() {
			ui.Row(c).AlignItems(ui.Center).Gap(8).Grow(1).Shrink(1).MinWidth(0).Children(func() {
				statusDot(c, p.green)
				ui.Text(c, cat.RoutingFinalFallback()).FontSize(13).FontWeight(600).TextColor(p.text).
					SingleLine().Ellipsis("…")
				drawerInlineNeutralChip(c, p, "FINAL")
			})

			ui.Row(c).AlignItems(ui.Center).Gap(2).Shrink(0).Children(func() {
				if quietRowIconButton(c.Key("btn-detail-final-rule"), p, iconList, cat.RuleDrawerTitle(), false, false).
					Tooltip(cat.RuleDrawerTitle()).
					Clicked() {
					a.activeRuleDrawerID = "final"
				}
				if quietRowIconButton(c.Key("btn-edit-final-rule"), p, iconEdit, cat.ActionEdit(), false, false).
					Tooltip(cat.ActionEdit()).
					Clicked() {
					a.openEditFinalRuleDialog()
				}
				ui.Box(c).Size(1, 14).Background(p.borderSubtle).Margin(0, 4, 0, 4).Shrink(0)
				ui.Text(c, cat.RoutingFinalAlwaysActive()).FontSize(10).FontWeight(500).TextColor(p.textDim).NoWrap()
			})
		})

		// Line 2: Description
		ui.Box(c).Padding(0, 0, 0, 15).Children(func() {
			ui.Text(c, cat.RoutingFinalDesc()).FontSize(11).TextColor(p.textMuted).SingleLine().Ellipsis("…")
		})

		// Line 3: Single-line Outbound Route Summary
		finalRule := routing.Rule{ID: "final", Action: a.state.RoutingFinal}
		a.renderRuleRouteSummary(c, p, finalRule, true, hasGeo, runningIDs)
	})

	if card.Clicked() {
		a.activeRuleDrawerID = "final"
	}
}

func (a *app) renderRuleEditorDrawer(c *ui.Context, p palette) {
	cat := a.catalog()
	var runningIDs map[string]bool
	if a.mgr != nil {
		runningIDs = a.mgr.RunningServiceIDs()
	}

	ui.Overlay(c, func() {
		if !a.ruleEditor.open {
			return
		}

		dsDrawerShell(c, p, dsDrawerSpec{
			BackdropKey: "rule-editor-backdrop",
			PanelKey:    "rule-editor-panel",
			Modal:       true,
			OnDismiss:   func() { a.dismissRuleEditorDrawer(false) },
		}, func() {
			dsDrawerHeader(c, p, func() {
				ui.Row(c).AlignItems(ui.Center).Gap(dsSpaceSM).MinWidth(0).Shrink(1).Children(func() {
					if a.ruleEditor.returnToDrawer && !a.ruleEditor.isNew {
						if quietRowIconButton(c.Key("rule-editor-back-header"), p, iconArrowLeft, cat.EditorBackToDetails(), false, false).
							Tooltip(cat.EditorBackToDetails()).
							Clicked() {
							a.dismissRuleEditorDrawer(true)
						}
					}
					title := cat.EditRule()
					if a.ruleEditor.isFinal {
						title = cat.EditFinalRule()
					} else if a.ruleEditor.isNew {
						title = cat.NewRule()
					}
					ui.Text(c, title).FontSize(dsFontDrawerTitle).FontWeight(700).TextColor(p.text).
						SingleLine().Ellipsis("…").MinWidth(0).Shrink(1)
				})
			}, func() {
				ui.Row(c).AlignItems(ui.Center).Gap(dsSpaceSM).Shrink(0).Children(func() {
					if !a.ruleEditor.isFinal {
						segmentedControl(c.Key("rule-criteria-tabs"), p, &a.ruleEditor.tab, []string{
							cat.RuleTabGeoData(),
							cat.RuleTabCriteria(),
						})
					}
					if quietRowIconButton(c.Key("btn-close-rule-editor"), p, iconClose, cat.RuleDrawerClose(), false, false).
						Label("btn-close-rule-editor").
						Tooltip(cat.RuleDrawerClose()).
						Clicked() {
						a.dismissRuleEditorDrawer(false)
					}
				})
			})

			dsDrawerErrorBanner(
				c, p,
				"rule-editor-error-row", "btn-copy-rule-error",
				a.ruleEditor.errText, cat.BtnCopy(), cat.ActionCopyError(),
				func() { a.writeClipboard(a.ruleEditor.errText, cat.ToastErrorCopied()) },
			)

			dsDrawerBody(c, p, "rule-editor-scroll", &a.ruleEditor.scroll, func() {
				// Card 1: Rule Identity
				dsCard(c, p, func() {
					if !a.ruleEditor.isFinal {
						ui.Grid(c.Key("rule-editor-identity-grid")).Columns(2).Gap(10).Children(func() {
							labeledInput(c, p, "rule-set-name", cat.RuleNameLabel(), &a.ruleEditor.name, "规则名称")
							labeledInput(c, p, "rule-set-desc", cat.RuleDescLabel(), &a.ruleEditor.desc, "可选说明")
						})
					} else {
						ui.Text(c, cat.RoutingFinalDesc()).FontSize(dsFontBody).TextColor(p.textMuted).LineHeight(dsLineHeightBody)
					}
				})

				// Card 2: Outbound Action & Scheduling
				dsCard(c, p, func() {
					ui.Column(c).Gap(dsSpaceSM).Children(func() {
						dsSectionLabel(c, p, cat.RuleActionLabel())
						actionOpts := []segmentedOption{
							{Label: cat.RoutingProxy(), ActiveColor: p.accentText},
							{Label: cat.RoutingDirect(), ActiveColor: p.text},
							{Label: cat.RoutingBlock(), ActiveColor: p.redText},
						}
						fullWidthSegmentedOptions(c.Key("rule-set-action"), p, &a.ruleEditor.actionIndex, actionOpts)
						switch a.ruleEditor.actionIndex {
						case 0: // Proxy
							dsHintText(c, cat.RuleActionProxyHint(), p.textDim)
						case 1: // Direct
							if a.ruleEditor.ruleID == "preset-lan-direct" {
								dsHintText(c, cat.RuleActionDirectHint(), p.textDim)
							}
						case 2: // Block
							dsHintText(c, cat.RuleDrawerDescBlock(), p.redText)
						}
					})

					if a.ruleEditor.actionIndex == 0 {
						a.renderProxyTargetPicker(c, p, runningIDs)
					} else if a.ruleEditor.actionIndex == 1 && a.ruleEditor.ruleID != "preset-lan-direct" {
						dsInsetBox(c, p, "rule-direct-warp-box", func() {
							ui.Column(c).Gap(dsSpaceXS).Children(func() {
								ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(dsSpaceMD).Children(func() {
									ui.Row(c).AlignItems(ui.Center).Gap(dsSpaceSM).Grow(1).Children(func() {
										dsSectionLabel(c, p, cat.RuleDirectWarpTitle())
										if a.ruleEditor.directWarp {
											tagPill(c, cat.RoutingWarp(), p.greenText, p.greenBg)
										}
									})
									ui.Switch(c.Key("toggle-rule-direct-warp"), &a.ruleEditor.directWarp).Label("toggle-rule-direct-warp")
								})
								dsHintText(c, cat.RuleDirectWarpDesc(), p.textMuted)
							})
							ui.Box(c).Fill().Height(1).Background(p.borderSubtle)
							if a.ruleEditor.directWarp {
								dsHintText(c, cat.RuleActionWarpHint(), p.greenText)
							} else {
								dsHintText(c, cat.RuleActionDirectHint(), p.textDim)
							}
						})
					}
				})

				// Card 3: Matching Criteria
				if !a.ruleEditor.isFinal {
					dsCard(c, p, func() {
						if a.ruleEditor.tab == 0 {
							a.renderChipsTagInput(c, p, "rule-set-geosite", cat.RuleGeoSiteLabel(), &a.ruleEditor.geosites, &a.ruleEditor.geositeQuery, cat.RuleGeoSiteHint(), a.availableGeoSiteTags(), true)
							a.renderChipsTagInput(c, p, "rule-set-geoip", cat.RuleGeoIPLabel(), &a.ruleEditor.geoips, &a.ruleEditor.geoipQuery, cat.RuleGeoIPHint(), a.availableGeoIPTags(), true)
						} else {
							labeledTextArea(c, p, "rule-set-domains", cat.RuleDomainsLabel(), &a.ruleEditor.domainsInput, cat.RuleDomainsHint(), 2, 4)
							labeledTextArea(c, p, "rule-set-full-domains", cat.RuleFullDomainsLabel(), &a.ruleEditor.fullDomainsInput, cat.RuleFullDomainsHint(), 2, 3)
							labeledTextArea(c, p, "rule-set-cidrs", cat.RuleCIDRsLabel(), &a.ruleEditor.cidrsInput, cat.RuleCIDRsHint(), 2, 3)
							labeledInput(c, p, "rule-set-keywords", cat.RuleKeywordsLabel(), &a.ruleEditor.keywordsInput, cat.RuleKeywordsHint())
						}
					})
				}
			})

			var footerLeft func()
			if a.ruleEditor.returnToDrawer && !a.ruleEditor.isNew {
				footerLeft = func() {
					if subtleActionChip(c.Key("rule-editor-back-to-details"), p, iconArrowLeft, cat.EditorBackToDetails(), false).Clicked() {
						a.dismissRuleEditorDrawer(true)
					}
				}
			}
			dsDrawerFooter(c, p, footerLeft, func() {
				ui.Row(c).AlignItems(ui.Center).Gap(dsSpaceMD).Shrink(0).Children(func() {
					if ui.Button(c.Key("btn-cancel-rule-editor"), cat.Cancel()).Clicked() {
						a.dismissRuleEditorDrawer(false)
					}
					if primaryPillButton(c.Key("btn-save-rule-editor"), p, nil, cat.Confirm(), p.accent, false).Clicked() {
						a.saveRuleEditor()
					}
				})
			})
		})
	})
}
