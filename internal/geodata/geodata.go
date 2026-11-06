package geodata

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
)

type GeoIPDB struct {
	tags map[string][]*net.IPNet
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

type domainEntry struct {
	typ   int // 0: plain/keyword, 1: regex, 2: domain suffix, 3: full
	value string
}

type GeoSiteDB struct {
	tags map[string][]domainEntry
}

func (db *GeoSiteDB) MatchDomain(tag string, domain string) bool {
	if db == nil || domain == "" {
		return false
	}
	domain = strings.TrimSpace(strings.ToLower(domain))
	entries, ok := db.tags[strings.ToUpper(strings.TrimSpace(tag))]
	if !ok {
		return false
	}
	for _, d := range entries {
		switch d.typ {
		case 3: // Full
			if domain == d.value {
				return true
			}
		case 0: // Plain keyword
			if strings.Contains(domain, d.value) {
				return true
			}
		default: // 2 (Domain/Root domain)
			if domain == d.value || strings.HasSuffix(domain, "."+d.value) {
				return true
			}
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
	if *offset+length > len(b) {
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

// LoadGeoIP loads and unmarshals only the requested tags from a Loyalsoldier geoip.dat protobuf stream.
func LoadGeoIP(r io.Reader, requestedTags []string) (*GeoIPDB, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	tagFilter := make(map[string]bool)
	for _, t := range requestedTags {
		tagFilter[strings.ToUpper(strings.TrimSpace(t))] = true
	}

	db := &GeoIPDB{tags: make(map[string][]*net.IPNet)}

	offset := 0
	for offset < len(data) {
		header, err := readVarint(data, &offset)
		if err != nil {
			break
		}
		fieldNum := int(header >> 3)
		wireType := int(header & 0x07)

		if fieldNum != 1 || wireType != 2 {
			if err := skipField(data, wireType, &offset); err != nil {
				return nil, err
			}
			continue
		}

		entryBytes, err := readBytes(data, &offset)
		if err != nil {
			return nil, err
		}

		// Parse GeoIP entry message
		parseGeoIPEntry(entryBytes, tagFilter, db)
	}

	return db, nil
}

func parseGeoIPEntry(b []byte, filter map[string]bool, db *GeoIPDB) {
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
			countryCode = strings.ToUpper(strings.TrimSpace(string(codeBytes)))
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
			ip = net.IP(ipBytes)
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
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var tags []string
	seen := make(map[string]bool)

	offset := 0
	for offset < len(data) {
		header, err := readVarint(data, &offset)
		if err != nil {
			break
		}
		fieldNum := int(header >> 3)
		wireType := int(header & 0x07)

		if fieldNum != 1 || wireType != 2 {
			if err := skipField(data, wireType, &offset); err != nil {
				return nil, err
			}
			continue
		}

		entryBytes, err := readBytes(data, &offset)
		if err != nil {
			return nil, err
		}

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
	}

	return tags, nil
}
func LoadGeoSite(r io.Reader, requestedTags []string) (*GeoSiteDB, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	tagFilter := make(map[string]bool)
	for _, t := range requestedTags {
		tagFilter[strings.ToUpper(strings.TrimSpace(t))] = true
	}

	db := &GeoSiteDB{tags: make(map[string][]domainEntry)}

	offset := 0
	for offset < len(data) {
		header, err := readVarint(data, &offset)
		if err != nil {
			break
		}
		fieldNum := int(header >> 3)
		wireType := int(header & 0x07)

		if fieldNum != 1 || wireType != 2 {
			if err := skipField(data, wireType, &offset); err != nil {
				return nil, err
			}
			continue
		}

		entryBytes, err := readBytes(data, &offset)
		if err != nil {
			return nil, err
		}

		parseGeoSiteEntry(entryBytes, tagFilter, db)
	}

	return db, nil
}

func parseGeoSiteEntry(b []byte, filter map[string]bool, db *GeoSiteDB) {
	var countryCode string
	var domains []domainEntry

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
			countryCode = strings.ToUpper(strings.TrimSpace(string(codeBytes)))
			if len(filter) > 0 && !filter[countryCode] {
				return // Skip parsing the rest of this unrequested entry
			}
		case 2: // domain message
			domBytes, err := readBytes(b, &offset)
			if err != nil {
				return
			}
			if entry := parseDomainMessage(domBytes); entry != nil {
				domains = append(domains, *entry)
			}
		default:
			if err := skipField(b, wireType, &offset); err != nil {
				return
			}
		}
	}

	if countryCode != "" && len(domains) > 0 {
		db.tags[countryCode] = append(db.tags[countryCode], domains...)
	}
}

func parseDomainMessage(b []byte) *domainEntry {
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
				return nil
			}
			typ = int(t)
		case 2: // value string
			valBytes, err := readBytes(b, &offset)
			if err != nil {
				return nil
			}
			val = strings.ToLower(strings.TrimSpace(string(valBytes)))
		default:
			if err := skipField(b, wireType, &offset); err != nil {
				return nil
			}
		}
	}

	if val == "" {
		return nil
	}
	return &domainEntry{typ: typ, value: val}
}
