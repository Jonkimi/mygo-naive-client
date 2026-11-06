package geodata

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
)

type GeoIPDB struct {
	tags    map[string][]*net.IPNet
	allTags []string
}

func (db *GeoIPDB) AllTags() []string {
	if db == nil {
		return nil
	}
	return db.allTags
}

func (db *GeoIPDB) MatchIP(tag string, ip net.IP) bool {
	if db == nil || ip == nil {
		return false
	}
	nets, ok := db.tags[strings.ToUpper(strings.TrimSpace(tag))]
	if !ok {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

type siteTagIndex struct {
	exact    map[string]struct{}
	suffix   map[string]struct{}
	keywords []string
}

type GeoSiteDB struct {
	indices map[string]*siteTagIndex
	allTags []string
}

func (db *GeoSiteDB) AllTags() []string {
	if db == nil {
		return nil
	}
	return db.allTags
}

func (db *GeoSiteDB) HasTag(tag string) bool {
	if db == nil {
		return false
	}
	_, ok := db.indices[strings.ToUpper(strings.TrimSpace(tag))]
	return ok
}

func (db *GeoSiteDB) TagRuleCount(tag string) int {
	if db == nil {
		return 0
	}
	idx, ok := db.indices[strings.ToUpper(strings.TrimSpace(tag))]
	if !ok {
		return 0
	}
	return len(idx.exact) + len(idx.suffix) + len(idx.keywords)
}

// DomainTagEntry represents a domain entry extracted from GeoSite database.
type DomainTagEntry struct {
	Value  string
	IsFull bool
}

// ForEachTagEntry iterates over all domain entries for the specified tag/category without slice allocation.
func (db *GeoSiteDB) ForEachTagEntry(tag string, fn func(val string, isFull bool)) {
	if db == nil || fn == nil {
		return
	}
	idx, ok := db.indices[strings.ToUpper(strings.TrimSpace(tag))]
	if !ok {
		return
	}
	for d := range idx.exact {
		fn(d, true)
	}
	for d := range idx.suffix {
		fn(d, false)
	}
	for _, kw := range idx.keywords {
		fn(kw, false)
	}
}

// TagEntries returns all domain entries for the specified tag/category.
func (db *GeoSiteDB) TagEntries(tag string) []DomainTagEntry {
	if db == nil {
		return nil
	}
	idx, ok := db.indices[strings.ToUpper(strings.TrimSpace(tag))]
	if !ok {
		return nil
	}
	res := make([]DomainTagEntry, 0, len(idx.exact)+len(idx.suffix)+len(idx.keywords))
	for d := range idx.exact {
		res = append(res, DomainTagEntry{Value: d, IsFull: true})
	}
	for d := range idx.suffix {
		res = append(res, DomainTagEntry{Value: d, IsFull: false})
	}
	for _, kw := range idx.keywords {
		res = append(res, DomainTagEntry{Value: kw, IsFull: false})
	}
	return res
}

func (db *GeoSiteDB) MatchDomain(tag string, domain string) bool {
	if db == nil || domain == "" {
		return false
	}
	domain = strings.Trim(strings.ToLower(strings.TrimSpace(domain)), ".")
	tagKey := strings.ToUpper(strings.TrimSpace(tag))
	idx, ok := db.indices[tagKey]
	if !ok {
		return false
	}

	// 1. Full / Exact match
	if _, ok := idx.exact[domain]; ok {
		return true
	}

	// 2. Suffix match (including root domain)
	if _, ok := idx.suffix[domain]; ok {
		return true
	}
	for i := len(domain) - 1; i >= 0; i-- {
		if domain[i] == '.' {
			sub := domain[i+1:]
			if _, ok := idx.suffix[sub]; ok {
				return true
			}
		}
	}

	// 3. Keyword match
	for _, kw := range idx.keywords {
		if strings.Contains(domain, kw) {
			return true
		}
	}

	return false
}

// Wire format helpers for Protobuf
func readVarint(b []byte, offset *int) (uint64, error) {
	val, n := binary.Uvarint(b[*offset:])
	if n <= 0 {
		return 0, errors.New("invalid varint")
	}
	*offset += n
	return val, nil
}

func readBytes(b []byte, offset *int) ([]byte, error) {
	lenVal, err := readVarint(b, offset)
	if err != nil {
		return nil, err
	}
	length := int(lenVal)
	if length < 0 || *offset+length > len(b) {
		return nil, io.ErrUnexpectedEOF
	}
	data := b[*offset : *offset+length]
	*offset += length
	return data, nil
}

func skipField(b []byte, wireType int, offset *int) error {
	switch wireType {
	case 0: // Varint
		_, err := readVarint(b, offset)
		return err
	case 1: // 64-bit
		if *offset+8 > len(b) {
			return io.ErrUnexpectedEOF
		}
		*offset += 8
		return nil
	case 2: // Length-delimited
		_, err := readBytes(b, offset)
		return err
	case 5: // 32-bit
		if *offset+4 > len(b) {
			return io.ErrUnexpectedEOF
		}
		*offset += 4
		return nil
	default:
		return errors.New("unsupported wire type")
	}
}

func skipStreamField(br *bufio.Reader, wireType int) error {
	switch wireType {
	case 0: // Varint
		_, err := binary.ReadUvarint(br)
		return err
	case 1: // 64-bit
		_, err := io.CopyN(io.Discard, br, 8)
		return err
	case 2: // Length-delimited
		lenVal, err := binary.ReadUvarint(br)
		if err != nil {
			return err
		}
		_, err = io.CopyN(io.Discard, br, int64(lenVal))
		return err
	case 5: // 32-bit
		_, err := io.CopyN(io.Discard, br, 4)
		return err
	default:
		return errors.New("unsupported wire type")
	}
}

// streamTopLevelEntries streams length-delimited field 1 entries from r using a single reusable scratch buffer,
// avoiding multi-megabyte io.ReadAll allocations.
func streamTopLevelEntries(r io.Reader, fn func(entryBytes []byte)) error {
	br := bufio.NewReaderSize(r, 32*1024)
	var scratch []byte

	for {
		header, err := binary.ReadUvarint(br)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return nil
		}
		fieldNum := int(header >> 3)
		wireType := int(header & 0x07)

		if fieldNum != 1 || wireType != 2 {
			if err := skipStreamField(br, wireType); err != nil {
				return err
			}
			continue
		}

		lenVal, err := binary.ReadUvarint(br)
		if err != nil {
			return io.ErrUnexpectedEOF
		}
		length := int(lenVal)
		if length < 0 {
			return io.ErrUnexpectedEOF
		}
		if cap(scratch) < length {
			scratch = make([]byte, length)
		} else {
			scratch = scratch[:length]
		}
		if _, err := io.ReadFull(br, scratch); err != nil {
			return io.ErrUnexpectedEOF
		}
		fn(scratch)
	}
}

// LoadGeoIP loads and unmarshals only the requested tags from a Loyalsoldier geoip.dat protobuf stream.
func LoadGeoIP(r io.Reader, requestedTags []string) (*GeoIPDB, error) {
	tagFilter := make(map[string]bool, len(requestedTags))
	for _, t := range requestedTags {
		clean := strings.ToUpper(strings.TrimSpace(t))
		if clean != "" {
			tagFilter[clean] = true
		}
	}

	db := &GeoIPDB{tags: make(map[string][]*net.IPNet)}
	if len(tagFilter) == 0 {
		return db, nil
	}
	seenTags := make(map[string]bool)

	err := streamTopLevelEntries(r, func(entryBytes []byte) {
		parseGeoIPEntry(entryBytes, tagFilter, seenTags, db)
	})
	if err != nil {
		return nil, err
	}

	return db, nil
}

func parseGeoIPEntry(b []byte, filter map[string]bool, seenTags map[string]bool, db *GeoIPDB) {
	var countryCode string
	var cidrs []*net.IPNet

	offset := 0
	for offset < len(b) {
		header, err := readVarint(b, &offset)
		if err != nil {
			break
		}
		fieldNum := int(header >> 3)
		wireType := int(header & 0x07)

		switch fieldNum {
		case 1: // country_code string
			codeBytes, err := readBytes(b, &offset)
			if err != nil {
				return
			}
			rawTag := strings.TrimSpace(string(codeBytes))
			lowerTag := strings.ToLower(rawTag)
			if lowerTag != "" && !seenTags[lowerTag] {
				seenTags[lowerTag] = true
				db.allTags = append(db.allTags, lowerTag)
			}
			countryCode = strings.ToUpper(rawTag)
			if len(filter) > 0 && !filter[countryCode] {
				return // Skip parsing the rest of this unrequested entry
			}
		case 2: // cidr message
			cidrBytes, err := readBytes(b, &offset)
			if err != nil {
				return
			}
			if ipNet := parseCIDRMessage(cidrBytes); ipNet != nil {
				cidrs = append(cidrs, ipNet)
			}
		default:
			if err := skipField(b, wireType, &offset); err != nil {
				return
			}
		}
	}

	if countryCode != "" && len(cidrs) > 0 {
		db.tags[countryCode] = append(db.tags[countryCode], cidrs...)
	}
}

func parseCIDRMessage(b []byte) *net.IPNet {
	var ip net.IP
	prefix := 32

	offset := 0
	for offset < len(b) {
		header, err := readVarint(b, &offset)
		if err != nil {
			break
		}
		fieldNum := int(header >> 3)
		wireType := int(header & 0x07)

		switch fieldNum {
		case 1: // ip bytes
			ipBytes, err := readBytes(b, &offset)
			if err != nil {
				return nil
			}
			ip = append(net.IP(nil), ipBytes...)
		case 2: // prefix uint32
			p, err := readVarint(b, &offset)
			if err != nil {
				return nil
			}
			prefix = int(p)
		default:
			if err := skipField(b, wireType, &offset); err != nil {
				return nil
			}
		}
	}

	if ip == nil {
		return nil
	}
	var mask net.IPMask
	if ip.To4() != nil {
		mask = net.CIDRMask(prefix, 32)
	} else {
		mask = net.CIDRMask(prefix, 128)
	}
	return &net.IPNet{IP: ip, Mask: mask}
}

// ListGeoTags scans a Loyalsoldier geoip.dat or geosite.dat protobuf stream and extracts
// all tag and category names without parsing payload CIDRs or domain lists.
func ListGeoTags(r io.Reader) ([]string, error) {
	var tags []string
	seen := make(map[string]bool)

	err := streamTopLevelEntries(r, func(entryBytes []byte) {
		// Field 1 of entryBytes is string country_code (the tag/category name)
		tagOffset := 0
		if tagOffset < len(entryBytes) {
			tagHeader, err := readVarint(entryBytes, &tagOffset)
			if err == nil && (tagHeader>>3) == 1 && (tagHeader&0x07) == 2 {
				tagBytes, err := readBytes(entryBytes, &tagOffset)
				if err == nil {
					tag := strings.ToLower(strings.TrimSpace(string(tagBytes)))
					if tag != "" && !seen[tag] {
						seen[tag] = true
						tags = append(tags, tag)
					}
				}
			}
		}
	})
	if err != nil {
		return nil, err
	}

	return tags, nil
}

func LoadGeoSite(r io.Reader, requestedTags []string) (*GeoSiteDB, error) {
	tagFilter := make(map[string]bool, len(requestedTags))
	for _, t := range requestedTags {
		clean := strings.ToUpper(strings.TrimSpace(t))
		if clean != "" {
			tagFilter[clean] = true
		}
	}

	db := &GeoSiteDB{
		indices: make(map[string]*siteTagIndex),
	}
	if len(tagFilter) == 0 {
		return db, nil
	}
	seenTags := make(map[string]bool)

	err := streamTopLevelEntries(r, func(entryBytes []byte) {
		parseGeoSiteEntry(entryBytes, tagFilter, seenTags, db)
	})
	if err != nil {
		return nil, err
	}

	return db, nil
}

func parseGeoSiteEntry(b []byte, filter map[string]bool, seenTags map[string]bool, db *GeoSiteDB) {
	var countryCode string
	var idx *siteTagIndex

	offset := 0
	for offset < len(b) {
		header, err := readVarint(b, &offset)
		if err != nil {
			break
		}
		fieldNum := int(header >> 3)
		wireType := int(header & 0x07)

		switch fieldNum {
		case 1: // country_code string
			codeBytes, err := readBytes(b, &offset)
			if err != nil {
				return
			}
			rawTag := strings.TrimSpace(string(codeBytes))
			lowerTag := strings.ToLower(rawTag)
			if lowerTag != "" && !seenTags[lowerTag] {
				seenTags[lowerTag] = true
				db.allTags = append(db.allTags, lowerTag)
			}
			countryCode = strings.ToUpper(rawTag)
			if len(filter) > 0 && !filter[countryCode] {
				return // Skip parsing the rest of this unrequested entry
			}
			idx = db.indices[countryCode]
			if idx == nil {
				idx = &siteTagIndex{
					exact:  make(map[string]struct{}),
					suffix: make(map[string]struct{}),
				}
				db.indices[countryCode] = idx
			}
		case 2: // domain message
			domBytes, err := readBytes(b, &offset)
			if err != nil {
				return
			}
			if idx == nil {
				idx = &siteTagIndex{
					exact:  make(map[string]struct{}),
					suffix: make(map[string]struct{}),
				}
			}
			parseDomainMessageInto(domBytes, idx)
		default:
			if err := skipField(b, wireType, &offset); err != nil {
				return
			}
		}
	}

	if countryCode != "" && idx != nil && (len(idx.exact) > 0 || len(idx.suffix) > 0 || len(idx.keywords) > 0) {
		db.indices[countryCode] = idx
	} else if countryCode != "" {
		delete(db.indices, countryCode)
	}
}

func parseDomainMessageInto(b []byte, idx *siteTagIndex) {
	typ := 2 // default domain suffix
	var val string

	offset := 0
	for offset < len(b) {
		header, err := readVarint(b, &offset)
		if err != nil {
			break
		}
		fieldNum := int(header >> 3)
		wireType := int(header & 0x07)

		switch fieldNum {
		case 1: // type enum
			t, err := readVarint(b, &offset)
			if err != nil {
				return
			}
			typ = int(t)
		case 2: // value string
			valBytes, err := readBytes(b, &offset)
			if err != nil {
				return
			}
			val = strings.ToLower(strings.TrimSpace(string(valBytes)))
		default:
			if err := skipField(b, wireType, &offset); err != nil {
				return
			}
		}
	}

	if val == "" {
		return
	}
	switch typ {
	case 3:
		idx.exact[val] = struct{}{}
	case 0:
		idx.keywords = append(idx.keywords, val)
	default:
		idx.suffix[val] = struct{}{}
	}
}
