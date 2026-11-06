package geodata

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// Helper to encode varint field (tag << 3 | wireType)
func encodeTag(fieldNum int, wireType int) []byte {
	val := uint64((fieldNum << 3) | wireType)
	buf := make([]byte, 10)
	n := binary.PutUvarint(buf, val)
	return buf[:n]
}

// Helper to encode string or bytes field (wire type 2)
func encodeBytesField(fieldNum int, data []byte) []byte {
	out := encodeTag(fieldNum, 2)
	lenBuf := make([]byte, 10)
	n := binary.PutUvarint(lenBuf, uint64(len(data)))
	out = append(out, lenBuf[:n]...)
	out = append(out, data...)
	return out
}

func encodeVarintField(fieldNum int, val uint64) []byte {
	out := encodeTag(fieldNum, 0)
	valBuf := make([]byte, 10)
	n := binary.PutUvarint(valBuf, val)
	out = append(out, valBuf[:n]...)
	return out
}

// Tests that GeoIP decoder parses requested country codes and checks IP containment.
func TestGeoIP_DecodeAndMatch(t *testing.T) {
	// Build mock GeoIP Protobuf payload:
	// Entry 1: country_code = "CN", cidr = 1.2.3.0/24
	var cidrMsg []byte
	cidrMsg = append(cidrMsg, encodeBytesField(1, net.ParseIP("1.2.3.0").To4())...)
	cidrMsg = append(cidrMsg, encodeVarintField(2, 24)...)

	var entryCN []byte
	entryCN = append(entryCN, encodeBytesField(1, []byte("CN"))...)
	entryCN = append(entryCN, encodeBytesField(2, cidrMsg)...)

	// Entry 2: country_code = "US", cidr = 8.8.8.0/24 (unrequested)
	var cidrUS []byte
	cidrUS = append(cidrUS, encodeBytesField(1, net.ParseIP("8.8.8.0").To4())...)
	cidrUS = append(cidrUS, encodeVarintField(2, 24)...)

	var entryUS []byte
	entryUS = append(entryUS, encodeBytesField(1, []byte("US"))...)
	entryUS = append(entryUS, encodeBytesField(2, cidrUS)...)

	// Top level GeoIPList message
	var geoIPList []byte
	geoIPList = append(geoIPList, encodeBytesField(1, entryCN)...)
	geoIPList = append(geoIPList, encodeBytesField(1, entryUS)...)

	db, err := LoadGeoIP(bytes.NewReader(geoIPList), []string{"CN"})
	if err != nil {
		t.Fatalf("LoadGeoIP: %v", err)
	}

	// 1.2.3.4 should match CN
	if !db.MatchIP("CN", net.ParseIP("1.2.3.4")) {
		t.Fatalf("expected 1.2.3.4 to match CN")
	}

	// 8.8.8.8 should NOT match CN
	if db.MatchIP("CN", net.ParseIP("8.8.8.8")) {
		t.Fatalf("expected 8.8.8.8 not to match CN")
	}

	// US was unrequested, should not be loaded
	if db.MatchIP("US", net.ParseIP("8.8.8.8")) {
		t.Fatalf("expected US not loaded")
	}
}

// Tests that GeoSite decoder parses requested site codes and checks domain suffix matching.
func TestGeoSite_DecodeAndMatch(t *testing.T) {
	// Build mock GeoSite Protobuf payload:
	// Domain: type = 2 (Domain/Root domain), value = "openai.com"
	var domMsg []byte
	domMsg = append(domMsg, encodeVarintField(1, 2)...)
	domMsg = append(domMsg, encodeBytesField(2, []byte("openai.com"))...)

	var entryOpenAI []byte
	entryOpenAI = append(entryOpenAI, encodeBytesField(1, []byte("OPENAI"))...)
	entryOpenAI = append(entryOpenAI, encodeBytesField(2, domMsg)...)

	var geoSiteList []byte
	geoSiteList = append(geoSiteList, encodeBytesField(1, entryOpenAI)...)

	db, err := LoadGeoSite(bytes.NewReader(geoSiteList), []string{"OPENAI"})
	if err != nil {
		t.Fatalf("LoadGeoSite: %v", err)
	}

	// "api.openai.com" should match OPENAI
	if !db.MatchDomain("OPENAI", "api.openai.com") {
		t.Fatalf("expected api.openai.com to match OPENAI")
	}

	// "google.com" should NOT match OPENAI
	if db.MatchDomain("OPENAI", "google.com") {
		t.Fatalf("expected google.com not to match OPENAI")
	}
}

// Tests that ListGeoTags extracts all category tags from protobuf streams without parsing payloads.
func TestListGeoTags(t *testing.T) {
	var payload []byte

	// Entry 1: tag "CN" with large payload
	var entry1 []byte
	entry1 = append(entry1, encodeBytesField(1, []byte("CN"))...)
	entry1 = append(entry1, encodeBytesField(2, []byte("dummy-large-payload-1"))...)
	payload = append(payload, encodeBytesField(1, entry1)...)

	// Entry 2: tag "apple"
	var entry2 []byte
	entry2 = append(entry2, encodeBytesField(1, []byte("apple"))...)
	entry2 = append(entry2, encodeBytesField(2, []byte("dummy-large-payload-2"))...)
	payload = append(payload, encodeBytesField(1, entry2)...)

	// Entry 3: tag "CATEGORY-ADS-ALL"
	var entry3 []byte
	entry3 = append(entry3, encodeBytesField(1, []byte("CATEGORY-ADS-ALL"))...)
	payload = append(payload, encodeBytesField(1, entry3)...)

	tags, err := ListGeoTags(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("ListGeoTags: %v", err)
	}

	expected := []string{"cn", "apple", "category-ads-all"}
	if len(tags) != len(expected) {
		t.Fatalf("expected %d tags, got %v", len(expected), tags)
	}
	for i, exp := range expected {
		if tags[i] != exp {
			t.Errorf("tag[%d]: expected %q, got %q", i, exp, tags[i])
		}
	}
}

// Tests that passing an empty requestedTags list loads zero entries instead of loading the entire database.
func TestLoadGeoData_EmptyRequestedTagsLoadsNothing(t *testing.T) {
	var cidrMsg []byte
	cidrMsg = append(cidrMsg, encodeBytesField(1, net.ParseIP("1.2.3.0").To4())...)
	cidrMsg = append(cidrMsg, encodeVarintField(2, 24)...)
	var entryCN []byte
	entryCN = append(entryCN, encodeBytesField(1, []byte("CN"))...)
	entryCN = append(entryCN, encodeBytesField(2, cidrMsg)...)
	geoIPList := encodeBytesField(1, entryCN)

	ipDB, err := LoadGeoIP(bytes.NewReader(geoIPList), nil)
	if err != nil {
		t.Fatalf("LoadGeoIP: %v", err)
	}
	if ipDB.MatchIP("CN", net.ParseIP("1.2.3.4")) {
		t.Fatalf("expected empty requestedTags to load no GeoIP entries")
	}

	var domMsg []byte
	domMsg = append(domMsg, encodeVarintField(1, 2)...)
	domMsg = append(domMsg, encodeBytesField(2, []byte("openai.com"))...)
	var entryOpenAI []byte
	entryOpenAI = append(entryOpenAI, encodeBytesField(1, []byte("OPENAI"))...)
	entryOpenAI = append(entryOpenAI, encodeBytesField(2, domMsg)...)
	geoSiteList := encodeBytesField(1, entryOpenAI)

	siteDB, err := LoadGeoSite(bytes.NewReader(geoSiteList), nil)
	if err != nil {
		t.Fatalf("LoadGeoSite: %v", err)
	}
	if siteDB.MatchDomain("OPENAI", "api.openai.com") {
		t.Fatalf("expected empty requestedTags to load no GeoSite entries")
	}
}
