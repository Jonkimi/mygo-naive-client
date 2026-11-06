package routing

import (
	"bytes"
	"net"
	"testing"

	"naive-client/internal/geodata"
)

// Tests that Router matches GeoSite and GeoIP categories when geodata databases are loaded.
func TestRouter_GeoSiteAndGeoIPMatching(t *testing.T) {
	// Construct mock GeoSite with CN (baidu.com) and GeoIP with CN (1.2.3.0/24)
	siteDB, err := geodata.LoadGeoSite(bytes.NewReader(mockGeoSiteData()), []string{"CN"})
	if err != nil {
		t.Fatalf("LoadGeoSite: %v", err)
	}
	ipDB, err := geodata.LoadGeoIP(bytes.NewReader(mockGeoIPData()), []string{"CN"})
	if err != nil {
		t.Fatalf("LoadGeoIP: %v", err)
	}

	rules := []Rule{
		{
			Name:    "China Direct",
			Enabled: true,
			GeoSite: []string{"CN"},
			GeoIP:   []string{"CN"},
			Action:  RouteAction{Type: ActionDirect},
		},
	}

	r := NewRouter(rules, RouteAction{Type: ActionProxyPool})
	r.SetGeoData(ipDB, siteDB)

	// "www.baidu.com" should match GeoSite:CN -> ActionDirect
	act1, rule1 := r.Match("www.baidu.com:443")
	if act1.Type != ActionDirect || rule1 != "China Direct" {
		t.Fatalf("expected GeoSite CN match, got %+v (%s)", act1, rule1)
	}

	// 1.2.3.4 should match GeoIP:CN -> ActionDirect
	act2, rule2 := r.Match("1.2.3.4:80")
	if act2.Type != ActionDirect || rule2 != "China Direct" {
		t.Fatalf("expected GeoIP CN match, got %+v (%s)", act2, rule2)
	}

	// 8.8.8.8 should NOT match and fall back to FinalAction
	act3, rule3 := r.Match("8.8.8.8:53")
	if act3.Type != ActionProxyPool || rule3 != "Final" {
		t.Fatalf("expected fallback for 8.8.8.8, got %+v (%s)", act3, rule3)
	}
}

func mockGeoIPData() []byte {
	// 1.2.3.0/24 -> CN
	cidrMsg := append([]byte{0x0a, 0x04}, net.ParseIP("1.2.3.0").To4()...)
	cidrMsg = append(cidrMsg, 0x10, 24)
	entryCN := append([]byte{0x0a, 0x02, 'C', 'N', 0x12, byte(len(cidrMsg))}, cidrMsg...)
	return append([]byte{0x0a, byte(len(entryCN))}, entryCN...)
}

func mockGeoSiteData() []byte {
	// baidu.com -> CN
	domMsg := []byte{0x08, 0x02, 0x12, 0x09, 'b', 'a', 'i', 'd', 'u', '.', 'c', 'o', 'm'}
	entryCN := append([]byte{0x0a, 0x02, 'C', 'N', 0x12, byte(len(domMsg))}, domMsg...)
	return append([]byte{0x0a, byte(len(entryCN))}, entryCN...)
}
