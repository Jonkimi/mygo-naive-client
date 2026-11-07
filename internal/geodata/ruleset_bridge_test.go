package geodata

import (
	"bytes"
	"net"
	"testing"

	C "github.com/sagernet/sing-box/constant"
)

// Tests that GeoSite and GeoIP tags are converted into sing-box PlainRuleSet and inline RuleSet.
func TestBuildRuleSets(t *testing.T) {
	// Construct mock GeoIP data for "CN"
	var cidrMsg []byte
	cidrMsg = append(cidrMsg, encodeBytesField(1, net.ParseIP("192.168.1.0").To4())...)
	cidrMsg = append(cidrMsg, encodeVarintField(2, 24)...)

	var entryCN []byte
	entryCN = append(entryCN, encodeBytesField(1, []byte("CN"))...)
	entryCN = append(entryCN, encodeBytesField(2, cidrMsg)...)

	var geoIPList []byte
	geoIPList = append(geoIPList, encodeBytesField(1, entryCN)...)

	ipDB, err := LoadGeoIP(bytes.NewReader(geoIPList), []string{"CN"})
	if err != nil {
		t.Fatalf("LoadGeoIP failed: %v", err)
	}

	// Construct mock GeoSite data for "OPENAI"
	// domain: suffix "openai.com", exact "chat.openai.com", keyword "chatgpt"
	var siteEntry []byte
	siteEntry = append(siteEntry, encodeBytesField(1, []byte("OPENAI"))...)

	var d1, d2, d3 []byte
	d1 = append(d1, encodeVarintField(1, 2)...) // RootDomain / suffix
	d1 = append(d1, encodeBytesField(2, []byte("openai.com"))...)
	siteEntry = append(siteEntry, encodeBytesField(2, d1)...)

	d2 = append(d2, encodeVarintField(1, 3)...) // Full / exact
	d2 = append(d2, encodeBytesField(2, []byte("chat.openai.com"))...)
	siteEntry = append(siteEntry, encodeBytesField(2, d2)...)

	d3 = append(d3, encodeVarintField(1, 0)...) // Plain / keyword
	d3 = append(d3, encodeBytesField(2, []byte("chatgpt"))...)
	siteEntry = append(siteEntry, encodeBytesField(2, d3)...)

	var geoSiteList []byte
	geoSiteList = append(geoSiteList, encodeBytesField(1, siteEntry)...)

	siteDB, err := LoadGeoSite(bytes.NewReader(geoSiteList), []string{"OPENAI"})
	if err != nil {
		t.Fatalf("LoadGeoSite failed: %v", err)
	}

	ruleSets := BuildRuleSets(siteDB, ipDB, []string{"OPENAI"}, []string{"CN"})
	if len(ruleSets) != 2 {
		t.Fatalf("expected 2 ruleSets, got %d", len(ruleSets))
	}

	// Verify geosite rule set
	var siteFound, ipFound bool
	for _, rs := range ruleSets {
		if rs.Type != C.RuleSetTypeInline && rs.Type != "inline" {
			t.Errorf("expected inline ruleset, got %s", rs.Type)
		}
		tags := []string(rs.Tag)
		if len(tags) == 0 {
			t.Fatalf("empty tag for ruleset")
		}
		if tags[0] == "geosite-openai" {
			siteFound = true
			if len(rs.InlineOptions.Rules) != 1 {
				t.Fatalf("expected 1 headless rule, got %d", len(rs.InlineOptions.Rules))
			}
			hr := rs.InlineOptions.Rules[0]
			opts := hr.DefaultOptions
			if len(opts.DomainSuffix) != 1 || opts.DomainSuffix[0] != "openai.com" {
				t.Errorf("expected suffix openai.com, got %v", opts.DomainSuffix)
			}
			if len(opts.Domain) != 1 || opts.Domain[0] != "chat.openai.com" {
				t.Errorf("expected domain chat.openai.com, got %v", opts.Domain)
			}
			if len(opts.DomainKeyword) != 1 || opts.DomainKeyword[0] != "chatgpt" {
				t.Errorf("expected keyword chatgpt, got %v", opts.DomainKeyword)
			}
		} else if tags[0] == "geoip-cn" {
			ipFound = true
			if len(rs.InlineOptions.Rules) != 1 {
				t.Fatalf("expected 1 headless rule, got %d", len(rs.InlineOptions.Rules))
			}
			hr := rs.InlineOptions.Rules[0]
			opts := hr.DefaultOptions
			if len(opts.IPCIDR) != 1 || opts.IPCIDR[0] != "192.168.1.0/24" {
				t.Errorf("expected ip_cidr 192.168.1.0/24, got %v", opts.IPCIDR)
			}
		}
	}

	if !siteFound {
		t.Errorf("geosite-openai ruleset not found")
	}
	if !ipFound {
		t.Errorf("geoip-cn ruleset not found")
	}
}

func TestBuildRuleSets_EdgeCases(t *testing.T) {
	// Nil databases should still produce placeholder rulesets for requested tags so sing-box doesn't error
	sets := BuildRuleSets(nil, nil, []string{"openai"}, []string{"cn"})
	if len(sets) != 2 {
		t.Errorf("expected 2 placeholder rulesets for nil dbs, got %d", len(sets))
	}

	// Empty tags should return 0
	siteDB := &GeoSiteDB{indices: make(map[string]*siteTagIndex)}
	ipDB := &GeoIPDB{tags: make(map[string][]net.IPNet)}
	sets = BuildRuleSets(siteDB, ipDB, []string{"", "   "}, []string{})
	if len(sets) != 0 {
		t.Errorf("expected 0 rulesets for empty tags, got %d", len(sets))
	}
}

