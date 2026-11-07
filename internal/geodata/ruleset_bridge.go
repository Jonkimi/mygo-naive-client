package geodata

import (
	"sort"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// BuildRuleSets converts requested GeoSite and GeoIP tags into sing-box native inline RuleSets.
func BuildRuleSets(siteDB *GeoSiteDB, ipDB *GeoIPDB, siteTags []string, ipTags []string) []option.RuleSet {
	var ruleSets []option.RuleSet

	// Process GeoSite tags
	seenSite := make(map[string]bool)
	for _, rawTag := range siteTags {
		clean := strings.ToUpper(strings.TrimSpace(rawTag))
		if clean == "" || seenSite[clean] {
			continue
		}
		seenSite[clean] = true
		tagKey := "geosite-" + strings.ToLower(clean)

		var exactList, suffixList, keywordList []string
		if siteDB != nil {
			if idx, ok := siteDB.indices[clean]; ok && idx != nil {
				for k := range idx.exact {
					exactList = append(exactList, k)
				}
				sort.Strings(exactList)

				for k := range idx.suffix {
					suffixList = append(suffixList, k)
				}
				sort.Strings(suffixList)

				if len(idx.keywords) > 0 {
					keywordList = append(keywordList, idx.keywords...)
					sort.Strings(keywordList)
				}
			}
		}

		var headlessRules []option.HeadlessRule
		if len(exactList) > 0 || len(suffixList) > 0 || len(keywordList) > 0 {
			headlessRules = append(headlessRules, option.HeadlessRule{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultHeadlessRule{
					Domain:        badoption.Listable[string](exactList),
					DomainSuffix:  badoption.Listable[string](suffixList),
					DomainKeyword: badoption.Listable[string](keywordList),
				},
			})
		} else {
			// sing-box requires rule_set to have at least 1 rule; use reserved .invalid placeholder
			headlessRules = append(headlessRules, option.HeadlessRule{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultHeadlessRule{
					Domain: badoption.Listable[string]{"placeholder.empty.invalid"},
				},
			})
		}

		ruleSets = append(ruleSets, option.RuleSet{
			Type: C.RuleSetTypeInline,
			Tag:  badoption.Listable[string]{tagKey},
			InlineOptions: option.PlainRuleSet{
				Rules: headlessRules,
			},
		})
	}

	// Process GeoIP tags
	seenIP := make(map[string]bool)
	for _, rawTag := range ipTags {
		clean := strings.ToUpper(strings.TrimSpace(rawTag))
		if clean == "" || seenIP[clean] {
			continue
		}
		seenIP[clean] = true
		tagKey := "geoip-" + strings.ToLower(clean)

		var cidrList []string
		if ipDB != nil {
			if nets, ok := ipDB.tags[clean]; ok && len(nets) > 0 {
				for _, n := range nets {
					cidrList = append(cidrList, n.String())
				}
				sort.Strings(cidrList)
			}
		}

		var headlessRules []option.HeadlessRule
		if len(cidrList) > 0 {
			headlessRules = append(headlessRules, option.HeadlessRule{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultHeadlessRule{
					IPCIDR: badoption.Listable[string](cidrList),
				},
			})
		} else {
			headlessRules = append(headlessRules, option.HeadlessRule{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultHeadlessRule{
					IPCIDR: badoption.Listable[string]{"192.0.2.254/32"},
				},
			})
		}

		ruleSets = append(ruleSets, option.RuleSet{
			Type: C.RuleSetTypeInline,
			Tag:  badoption.Listable[string]{tagKey},
			InlineOptions: option.PlainRuleSet{
				Rules: headlessRules,
			},
		})
	}

	return ruleSets
}
