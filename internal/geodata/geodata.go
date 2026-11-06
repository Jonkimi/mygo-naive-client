package geodata

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
)

var (
	ipv4Masks [33]net.IPMask
	ipv6Masks [129]net.IPMask
)

func init() {
	for i := 0; i <= 32; i++ {
		ipv4Masks[i] = net.CIDRMask(i, 32)
	}
	for i := 0; i <= 128; i++ {
		ipv6Masks[i] = net.CIDRMask(i, 128)
	}
}

type GeoIPDB struct {
	tags    map[string][]net.IPNet
	allTags []string
}

func (db *GeoIPDB) AllTags() []string {
	if db == nil {
		return nil
	}
	return db.allTags
}

func (db *GeoIPDB) HasTag(tag string) bool {
	if db == nil {
		return false
	}
	_, ok := db.tags[strings.ToUpper(strings.TrimSpace(tag))]
	return ok
}

func (db *GeoIPDB) MissingTags(requestedTags []string) []string {
	var missing []string
	seen := make(map[string]bool, len(requestedTags))
	for _, t := range requestedTags {
		clean := strings.ToUpper(strings.TrimSpace(t))
		if clean == "" || seen[clean] {
			continue
		}
		seen[clean] = true
		if !db.HasTag(clean) {
			missing = append(missing, clean)
		}
	}
	return missing
}

func (db *GeoIPDB) WithTags(requestedTags []string, extra *GeoIPDB) *GeoIPDB {
	out := &GeoIPDB{
		tags: make(map[string][]net.IPNet, len(requestedTags)),
	}
	if db != nil && len(db.allTags) > 0 {
		out.allTags = db.allTags
	} else if extra != nil && len(extra.allTags) > 0 {
		out.allTags = extra.allTags
	}
	for _, t := range requestedTags {
		clean := strings.ToUpper(strings.TrimSpace(t))
		if clean == "" {
			continue
		}
		if extra != nil {
			if nets, ok := extra.tags[clean]; ok {
				out.tags[clean] = nets
				continue
			}
		}
		if db != nil {
			if nets, ok := db.tags[clean]; ok {
				out.tags[clean] = nets
			}
		}
	}
	return out
}

func (db *GeoIPDB) MatchIP(tag string, ip net.IP) bool {
	if db == nil || ip == nil {
		return false
	}
	nets, ok := db.tags[strings.ToUpper(strings.TrimSpace(tag))]
	if !ok {
		return false
	}
	for i := range nets {
		if nets[i].Contains(ip) {
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

func (db *GeoSiteDB) MissingTags(requestedTags []string) []string {
	var missing []string
	seen := make(map[string]bool, len(requestedTags))
	for _, t := range requestedTags {
		clean := strings.ToUpper(strings.TrimSpace(t))
		if clean == "" || seen[clean] {
			continue
		}
		seen[clean] = true
		if !db.HasTag(clean) {
			missing = append(missing, clean)
		}
	}
	return missing
}

func (db *GeoSiteDB) WithTags(requestedTags []string, extra *GeoSiteDB) *GeoSiteDB {
	out := &GeoSiteDB{
		indices: make(map[string]*siteTagIndex, len(requestedTags)),
	}
	if db != nil && len(db.allTags) > 0 {
		out.allTags = db.allTags
	} else if extra != nil && len(extra.allTags) > 0 {
		out.allTags = extra.allTags
	}
	for _, t := range requestedTags {
		clean := strings.ToUpper(strings.TrimSpace(t))
		if clean == "" {
			continue
		}
		if extra != nil {
			if idx, ok := extra.indices[clean]; ok {
				out.indices[clean] = idx
				continue
			}
		}
		if db != nil {
			if idx, ok := db.indices[clean]; ok {
				out.indices[clean] = idx
			}
		}
	}
	return out
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

// streamFilteredEntries streams top-level field 1 entries from r, reading only the leading tag name first
// and discarding unrequested entries directly from the stream without allocating multi-megabyte buffers.
func streamFilteredEntries(r io.Reader, tagFilter map[string]bool, fn func(countryCode string, payload []byte)) error {
	br := bufio.NewReaderSize(r, 32*1024)
	var scratch []byte
	var codeBuf [256]byte

	for {
		header, err := binary.ReadUvarint(br)
		if err != nil {
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
		entryLen := int(lenVal)
		if entryLen <= 0 {
			continue
		}

		// Peek at the first byte of the entry: in GeoIP/GeoSite protobuf, field 1 (country_code, wireType 2) has tag 0x0a.
		firstByte, err := br.ReadByte()
		if err != nil {
			return io.ErrUnexpectedEOF
		}
		remaining := entryLen - 1

		if firstByte == 0x0a && remaining > 0 {
			codeLen, nVarint, err := readStreamUvarint(br, remaining)
			if err != nil {
				return err
			}
			remaining -= nVarint
			if codeLen >= 0 && codeLen <= len(codeBuf) && codeLen <= remaining {
				if _, err := io.ReadFull(br, codeBuf[:codeLen]); err != nil {
					return io.ErrUnexpectedEOF
				}
				remaining -= codeLen
				countryCode := cleanUpperASCII(codeBuf[:codeLen])
				if len(tagFilter) > 0 && !tagFilter[countryCode] {
					if remaining > 0 {
						if _, err := io.CopyN(io.Discard, br, int64(remaining)); err != nil {
							return io.ErrUnexpectedEOF
						}
					}
					continue
				}
				if cap(scratch) < remaining {
					scratch = make([]byte, remaining)
				} else {
					scratch = scratch[:remaining]
				}
				if remaining > 0 {
					if _, err := io.ReadFull(br, scratch); err != nil {
						return io.ErrUnexpectedEOF
					}
				}
				fn(countryCode, scratch)
				continue
			}
			// Fallback if codeLen exceeds codeBuf: unread is not possible after ReadUvarint, so reconstruct into scratch
			if cap(scratch) < entryLen {
				scratch = make([]byte, entryLen)
			} else {
				scratch = scratch[:entryLen]
			}
			scratch[0] = firstByte
			n := binary.PutUvarint(scratch[1:], uint64(codeLen))
			if _, err := io.ReadFull(br, scratch[1+n:]); err != nil {
				return io.ErrUnexpectedEOF
			}
			fn("", scratch)
			continue
		}

		// Fallback when field 1 is not the very first field in the entry
		if cap(scratch) < entryLen {
			scratch = make([]byte, entryLen)
		} else {
			scratch = scratch[:entryLen]
		}
		scratch[0] = firstByte
		if remaining > 0 {
			if _, err := io.ReadFull(br, scratch[1:]); err != nil {
				return io.ErrUnexpectedEOF
			}
		}
		fn("", scratch)
	}
}

func readStreamUvarint(br *bufio.Reader, maxBytes int) (int, int, error) {
	var x uint64
	var s uint
	for i := 0; i < maxBytes && i < binary.MaxVarintLen64; i++ {
		b, err := br.ReadByte()
		if err != nil {
			return 0, i, io.ErrUnexpectedEOF
		}
		if b < 0x80 {
			if i == binary.MaxVarintLen64-1 && b > 1 {
				return 0, i + 1, errors.New("varint overflow")
			}
			return int(x | uint64(b)<<s), i + 1, nil
		}
		x |= uint64(b&0x7f) << s
		s += 7
	}
	return 0, 0, errors.New("invalid varint")
}

func cleanUpperASCII(b []byte) string {
	start := 0
	for start < len(b) && (b[start] == ' ' || b[start] == '\t' || b[start] == '\n' || b[start] == '\r') {
		start++
	}
	end := len(b)
	for end > start && (b[end-1] == ' ' || b[end-1] == '\t' || b[end-1] == '\n' || b[end-1] == '\r') {
		end--
	}
	b = b[start:end]
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 'a' - 'A'
		}
	}
	return string(b)
}

func trimLowerASCIIBytes(b []byte) []byte {
	start := 0
	for start < len(b) && (b[start] == ' ' || b[start] == '\t' || b[start] == '\n' || b[start] == '\r') {
		start++
	}
	end := len(b)
	for end > start && (b[end-1] == ' ' || b[end-1] == '\t' || b[end-1] == '\n' || b[end-1] == '\r') {
		end--
	}
	b = b[start:end]
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return b
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

	db := &GeoIPDB{tags: make(map[string][]net.IPNet, len(tagFilter))}
	if len(tagFilter) == 0 {
		return db, nil
	}

	err := streamFilteredEntries(r, tagFilter, func(countryCode string, payload []byte) {
		parseGeoIPEntry(countryCode, payload, tagFilter, db)
	})
	if err != nil {
		return nil, err
	}

	return db, nil
}

func measureCIDRIPBytes(b []byte) int {
	offset := 0
	for offset < len(b) {
		header, err := readVarint(b, &offset)
		if err != nil {
			break
		}
		fieldNum := int(header >> 3)
		wireType := int(header & 0x07)
		if fieldNum == 1 && wireType == 2 {
			ipBytes, err := readBytes(b, &offset)
			if err != nil {
				return 0
			}
			return len(ipBytes)
		}
		if err := skipField(b, wireType, &offset); err != nil {
			return 0
		}
	}
	return 0
}

func parseGeoIPEntry(countryCode string, b []byte, filter map[string]bool, db *GeoIPDB) {
	// Pass 1: resolve countryCode (if not already extracted) and count CIDRs + IP bytes for single-slab allocation
	cidrCount := 0
	totalIPBytes := 0
	offset := 0
	for offset < len(b) {
		header, err := readVarint(b, &offset)
		if err != nil {
			break
		}
		fieldNum := int(header >> 3)
		wireType := int(header & 0x07)

		switch fieldNum {
		case 1:
			codeBytes, err := readBytes(b, &offset)
			if err != nil {
				return
			}
			countryCode = cleanUpperASCII(codeBytes)
			if len(filter) > 0 && !filter[countryCode] {
				return
			}
		case 2:
			cidrBytes, err := readBytes(b, &offset)
			if err != nil {
				return
			}
			if ipLen := measureCIDRIPBytes(cidrBytes); ipLen > 0 {
				cidrCount++
				totalIPBytes += ipLen
			}
		default:
			if err := skipField(b, wireType, &offset); err != nil {
				return
			}
		}
	}

	if countryCode == "" || (len(filter) > 0 && !filter[countryCode]) || cidrCount == 0 {
		return
	}

	cidrs := make([]net.IPNet, 0, cidrCount)
	ipArena := make([]byte, 0, totalIPBytes)

	// Pass 2: populate cidrs using the preallocated ipArena and static masks
	offset = 0
	for offset < len(b) {
		header, err := readVarint(b, &offset)
		if err != nil {
			break
		}
		fieldNum := int(header >> 3)
		wireType := int(header & 0x07)

		switch fieldNum {
		case 1:
			_, _ = readBytes(b, &offset)
		case 2:
			cidrBytes, err := readBytes(b, &offset)
			if err != nil {
				return
			}
			var ok bool
			var ipNet net.IPNet
			ipNet, ipArena, ok = parseCIDRMessageInto(cidrBytes, ipArena)
			if ok {
				cidrs = append(cidrs, ipNet)
			}
		default:
			if err := skipField(b, wireType, &offset); err != nil {
				return
			}
		}
	}

	if len(cidrs) > 0 {
		db.tags[countryCode] = append(db.tags[countryCode], cidrs...)
	}
}

func parseCIDRMessageInto(b []byte, ipArena []byte) (net.IPNet, []byte, bool) {
	var rawIP []byte
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
				return net.IPNet{}, ipArena, false
			}
			rawIP = ipBytes
		case 2: // prefix uint32
			p, err := readVarint(b, &offset)
			if err != nil {
				return net.IPNet{}, ipArena, false
			}
			prefix = int(p)
		default:
			if err := skipField(b, wireType, &offset); err != nil {
				return net.IPNet{}, ipArena, false
			}
		}
	}

	if len(rawIP) == 0 {
		return net.IPNet{}, ipArena, false
	}
	start := len(ipArena)
	ipArena = append(ipArena, rawIP...)
	ip := net.IP(ipArena[start : start+len(rawIP)])

	var mask net.IPMask
	if ip.To4() != nil {
		if prefix < 0 {
			prefix = 0
		} else if prefix > 32 {
			prefix = 32
		}
		mask = ipv4Masks[prefix]
	} else {
		if prefix < 0 {
			prefix = 0
		} else if prefix > 128 {
			prefix = 128
		}
		mask = ipv6Masks[prefix]
	}
	return net.IPNet{IP: ip, Mask: mask}, ipArena, true
}

// ListGeoTags scans a Loyalsoldier geoip.dat or geosite.dat protobuf stream and extracts
// all tag and category names without parsing payload CIDRs or domain lists.
func ListGeoTags(r io.Reader) ([]string, error) {
	br := bufio.NewReaderSize(r, 32*1024)
	var tags []string
	seen := make(map[string]bool)
	var codeBuf [256]byte

	for {
		header, err := binary.ReadUvarint(br)
		if err != nil {
			return tags, nil
		}
		fieldNum := int(header >> 3)
		wireType := int(header & 0x07)

		if fieldNum != 1 || wireType != 2 {
			if err := skipStreamField(br, wireType); err != nil {
				return nil, err
			}
			continue
		}

		lenVal, err := binary.ReadUvarint(br)
		if err != nil {
			return nil, io.ErrUnexpectedEOF
		}
		entryLen := int(lenVal)
		if entryLen <= 0 {
			continue
		}

		firstByte, err := br.ReadByte()
		if err != nil {
			return nil, io.ErrUnexpectedEOF
		}
		remaining := entryLen - 1

		if firstByte == 0x0a && remaining > 0 {
			codeLen, nVarint, err := readStreamUvarint(br, remaining)
			if err != nil {
				return nil, err
			}
			remaining -= nVarint
			if codeLen >= 0 && codeLen <= len(codeBuf) && codeLen <= remaining {
				if _, err := io.ReadFull(br, codeBuf[:codeLen]); err != nil {
					return nil, io.ErrUnexpectedEOF
				}
				remaining -= codeLen
				tag := string(trimLowerASCIIBytes(codeBuf[:codeLen]))
				if tag != "" && !seen[tag] {
					seen[tag] = true
					tags = append(tags, tag)
				}
			}
		}
		if remaining > 0 {
			if _, err := io.CopyN(io.Discard, br, int64(remaining)); err != nil {
				return nil, io.ErrUnexpectedEOF
			}
		}
	}
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
		indices: make(map[string]*siteTagIndex, len(tagFilter)),
	}
	if len(tagFilter) == 0 {
		return db, nil
	}

	err := streamFilteredEntries(r, tagFilter, func(countryCode string, payload []byte) {
		parseGeoSiteEntry(countryCode, payload, tagFilter, db)
	})
	if err != nil {
		return nil, err
	}

	return db, nil
}

func inspectDomainMessage(b []byte) (typ int, val []byte) {
	typ = 2 // default domain suffix
	offset := 0
	for offset < len(b) {
		header, err := readVarint(b, &offset)
		if err != nil {
			break
		}
		fieldNum := int(header >> 3)
		wireType := int(header & 0x07)

		switch fieldNum {
		case 1:
			t, err := readVarint(b, &offset)
			if err != nil {
				return typ, nil
			}
			typ = int(t)
		case 2:
			valBytes, err := readBytes(b, &offset)
			if err != nil {
				return typ, nil
			}
			val = trimLowerASCIIBytes(valBytes)
		default:
			if err := skipField(b, wireType, &offset); err != nil {
				return typ, nil
			}
		}
	}
	return typ, val
}

func parseGeoSiteEntry(countryCode string, b []byte, filter map[string]bool, db *GeoSiteDB) {
	// Pass 1: count domain types and total string bytes for single-slab string arena + exact-sized maps
	var exactCount, suffixCount, kwCount, totalStrBytes int
	offset := 0
	for offset < len(b) {
		header, err := readVarint(b, &offset)
		if err != nil {
			break
		}
		fieldNum := int(header >> 3)
		wireType := int(header & 0x07)

		switch fieldNum {
		case 1:
			codeBytes, err := readBytes(b, &offset)
			if err != nil {
				return
			}
			countryCode = cleanUpperASCII(codeBytes)
			if len(filter) > 0 && !filter[countryCode] {
				return
			}
		case 2:
			domBytes, err := readBytes(b, &offset)
			if err != nil {
				return
			}
			typ, val := inspectDomainMessage(domBytes)
			if len(val) > 0 {
				totalStrBytes += len(val)
				switch typ {
				case 3:
					exactCount++
				case 0:
					kwCount++
				default:
					suffixCount++
				}
			}
		default:
			if err := skipField(b, wireType, &offset); err != nil {
				return
			}
		}
	}

	if countryCode == "" || (len(filter) > 0 && !filter[countryCode]) || (exactCount+suffixCount+kwCount) == 0 {
		return
	}

	// Build a single contiguous string backing slab for all domains in this tag
	var sb strings.Builder
	sb.Grow(totalStrBytes)
	offset = 0
	for offset < len(b) {
		header, err := readVarint(b, &offset)
		if err != nil {
			break
		}
		fieldNum := int(header >> 3)
		wireType := int(header & 0x07)
		if fieldNum == 2 && wireType == 2 {
			domBytes, err := readBytes(b, &offset)
			if err != nil {
				return
			}
			_, val := inspectDomainMessage(domBytes)
			if len(val) > 0 {
				_, _ = sb.Write(val)
			}
		} else {
			if err := skipField(b, wireType, &offset); err != nil {
				return
			}
		}
	}
	bigStr := sb.String()

	idx := db.indices[countryCode]
	if idx == nil {
		idx = &siteTagIndex{
			exact:    make(map[string]struct{}, exactCount),
			suffix:   make(map[string]struct{}, suffixCount),
			keywords: make([]string, 0, kwCount),
		}
	}

	// Pass 2: slice substrings out of bigStr into pre-sized maps (0 small-object heap allocations, 0 map hashGrow)
	strPos := 0
	offset = 0
	for offset < len(b) {
		header, err := readVarint(b, &offset)
		if err != nil {
			break
		}
		fieldNum := int(header >> 3)
		wireType := int(header & 0x07)
		if fieldNum == 2 && wireType == 2 {
			domBytes, err := readBytes(b, &offset)
			if err != nil {
				break
			}
			typ, val := inspectDomainMessage(domBytes)
			if len(val) > 0 {
				dom := bigStr[strPos : strPos+len(val)]
				strPos += len(val)
				switch typ {
				case 3:
					idx.exact[dom] = struct{}{}
				case 0:
					idx.keywords = append(idx.keywords, dom)
				default:
					idx.suffix[dom] = struct{}{}
				}
			}
		} else {
			if err := skipField(b, wireType, &offset); err != nil {
				break
			}
		}
	}

	db.indices[countryCode] = idx
}
