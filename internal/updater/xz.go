package updater

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
)

// Pure-Go XZ / LZMA2 stream decompressor supporting standard .tar.xz archives
// produced by xz-utils (such as klzgrad/naiveproxy release tarballs).

var xzHeaderMagic = []byte{0xFD, '7', 'z', 'X', 'Z', 0x00}
var xzFooterMagic = []byte{'Y', 'Z'}

const (
	filterIDLZMA2 = 0x21
	filterIDBCJ86 = 0x04
	filterIDARM64 = 0x0A
)

// NewXZReader returns an io.Reader that decompresses an XZ stream from r.
func NewXZReader(r io.Reader) (io.Reader, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	out, err := decodeXZ(data)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(out), nil
}

func decodeXZ(src []byte) ([]byte, error) {
	if len(src) < 12 || !bytes.Equal(src[:6], xzHeaderMagic) {
		return nil, errors.New("xz: invalid stream header")
	}
	checkType := src[7] & 0x0F
	pos := 12 // after 6-byte magic + 2-byte flags + 4-byte CRC32

	var out bytes.Buffer
	for pos < len(src) {
		if src[pos] == 0x00 {
			// Index indicator reached; verify footer exists at end of stream.
			break
		}
		headerSize := (int(src[pos]) + 1) * 4
		if pos+headerSize > len(src) {
			return nil, errors.New("xz: truncated block header")
		}
		hdr := src[pos : pos+headerSize]
		if crc32.ChecksumIEEE(hdr[:headerSize-4]) != binary.LittleEndian.Uint32(hdr[headerSize-4:]) {
			return nil, errors.New("xz: block header CRC mismatch")
		}

		flags := hdr[1]
		numFilters := int(flags&0x03) + 1
		hpos := 2
		if flags&0x40 != 0 { // compressed size present
			_, n, err := readVLI(hdr[hpos:])
			if err != nil {
				return nil, err
			}
			hpos += n
		}
		if flags&0x80 != 0 { // uncompressed size present
			_, n, err := readVLI(hdr[hpos:])
			if err != nil {
				return nil, err
			}
			hpos += n
		}

		type filterSpec struct {
			id    uint64
			props []byte
		}
		filters := make([]filterSpec, numFilters)
		for i := 0; i < numFilters; i++ {
			id, n, err := readVLI(hdr[hpos:])
			if err != nil {
				return nil, err
			}
			hpos += n
			propLen, n, err := readVLI(hdr[hpos:])
			if err != nil {
				return nil, err
			}
			hpos += n
			if hpos+int(propLen) > len(hdr)-4 {
				return nil, errors.New("xz: invalid filter properties")
			}
			filters[i] = filterSpec{id: id, props: hdr[hpos : hpos+int(propLen)]}
			hpos += int(propLen)
		}

		// Last filter must be LZMA2
		lastFilter := filters[len(filters)-1]
		if lastFilter.id != filterIDLZMA2 || len(lastFilter.props) != 1 {
			return nil, fmt.Errorf("xz: unsupported filter chain (last=0x%x)", lastFilter.id)
		}
		dictProp := lastFilter.props[0]
		var dictSize uint32
		if dictProp > 40 {
			return nil, errors.New("xz: invalid LZMA2 dictionary property")
		} else if dictProp == 40 {
			dictSize = 0xFFFFFFFF
		} else {
			base := uint32(2 | (dictProp & 1))
			dictSize = base << (dictProp/2 + 11)
		}

		pos += headerSize
		blockOut, consumed, err := decodeLZMA2(src[pos:], dictSize)
		if err != nil {
			return nil, err
		}
		pos += consumed

		// Block padding to 4-byte boundary
		for pos%4 != 0 {
			if pos >= len(src) || src[pos] != 0x00 {
				return nil, errors.New("xz: non-zero block padding")
			}
			pos++
		}

		// Skip block check field
		checkSize := xzCheckSize(checkType)
		if pos+checkSize > len(src) {
			return nil, errors.New("xz: truncated block check")
		}
		pos += checkSize

		// Apply optional pre-filters (e.g. x86 BCJ or ARM64 BCJ) in reverse order
		for i := len(filters) - 2; i >= 0; i-- {
			var startOffset uint32
			if len(filters[i].props) == 4 {
				startOffset = binary.LittleEndian.Uint32(filters[i].props)
			}
			switch filters[i].id {
			case filterIDBCJ86:
				decodeBCJX86(blockOut, startOffset)
			case filterIDARM64:
				decodeBCJARM64(blockOut, startOffset)
			default:
				return nil, fmt.Errorf("xz: unsupported BCJ filter 0x%x", filters[i].id)
			}
		}

		out.Write(blockOut)
	}
	return out.Bytes(), nil
}

func xzCheckSize(checkType byte) int {
	switch checkType {
	case 0x00:
		return 0
	case 0x01, 0x02, 0x03:
		return 4
	case 0x04, 0x05, 0x06:
		return 8
	case 0x07, 0x08, 0x09:
		return 16
	case 0x0A, 0x0B, 0x0C:
		return 32
	case 0x0D, 0x0E, 0x0F:
		return 64
	default:
		return 4
	}
}

func readVLI(b []byte) (uint64, int, error) {
	var val uint64
	for i := 0; i < len(b) && i < 9; i++ {
		val |= uint64(b[i]&0x7F) << (i * 7)
		if b[i]&0x80 == 0 {
			return val, i + 1, nil
		}
	}
	return 0, 0, errors.New("xz: invalid VLI")
}

// decodeLZMA2 decodes an LZMA2 chunk stream and returns the uncompressed bytes and bytes consumed.
func decodeLZMA2(src []byte, dictCap uint32) ([]byte, int, error) {
	if dictCap == 0 {
		dictCap = 1 << 16
	}
	dec := newLZMADecoder(dictCap)
	pos := 0
	for {
		if pos >= len(src) {
			return nil, 0, errors.New("lzma2: unexpected EOF")
		}
		ctrl := src[pos]
		pos++
		if ctrl == 0x00 {
			// End of LZMA2 stream
			break
		}
		if ctrl == 0x01 || ctrl == 0x02 {
			// Uncompressed chunk
			if pos+2 > len(src) {
				return nil, 0, errors.New("lzma2: truncated uncompressed chunk header")
			}
			uSize := int(binary.BigEndian.Uint16(src[pos:pos+2])) + 1
			pos += 2
			if pos+uSize > len(src) {
				return nil, 0, errors.New("lzma2: truncated uncompressed chunk data")
			}
			if ctrl == 0x01 {
				dec.resetDict()
			}
			dec.writeUncompressed(src[pos : pos+uSize])
			pos += uSize
			continue
		}
		if ctrl < 0x80 {
			return nil, 0, fmt.Errorf("lzma2: invalid control byte 0x%02x", ctrl)
		}

		// LZMA compressed chunk
		if pos+4 > len(src) {
			return nil, 0, errors.New("lzma2: truncated compressed chunk header")
		}
		uSize := (int(ctrl&0x1F) << 16) + int(binary.BigEndian.Uint16(src[pos:pos+2])) + 1
		cSize := int(binary.BigEndian.Uint16(src[pos+2:pos+4])) + 1
		pos += 4

		mode := (ctrl >> 5) & 0x03
		if mode >= 2 {
			if pos >= len(src) {
				return nil, 0, errors.New("lzma2: missing properties byte")
			}
			prop := src[pos]
			pos++
			if err := dec.setProps(prop); err != nil {
				return nil, 0, err
			}
			if mode == 3 {
				dec.resetDict()
			}
			dec.resetStateAndProbs()
		} else if mode == 1 {
			dec.resetState()
		}

		if pos+cSize > len(src) {
			return nil, 0, errors.New("lzma2: truncated compressed chunk data")
		}
		if err := dec.decodeChunk(src[pos:pos+cSize], uSize); err != nil {
			return nil, 0, err
		}
		pos += cSize
	}
	return dec.out, pos, nil
}

type lzmaDecoder struct {
	out []byte

	lc uint32
	lp uint32
	pb uint32

	state uint32
	reps  [4]uint32

	isMatch    [12][16]uint16
	isRep      [12]uint16
	isRepG0    [12]uint16
	isRepG1    [12]uint16
	isRepG2    [12]uint16
	isRep0Long [12][16]uint16
	posSlot    [4][64]uint16
	posDec     [115]uint16
	align      [16]uint16
	litProbs   []uint16

	matchLen lenCoder
	repLen   lenCoder
}

type lenCoder struct {
	choice  uint16
	choice2 uint16
	low     [16][8]uint16
	mid     [16][8]uint16
	high    [256]uint16
}

func (lc *lenCoder) reset() {
	lc.choice = 1024
	lc.choice2 = 1024
	for i := range lc.low {
		for j := range lc.low[i] {
			lc.low[i][j] = 1024
			lc.mid[i][j] = 1024
		}
	}
	for i := range lc.high {
		lc.high[i] = 1024
	}
}

func newLZMADecoder(_ uint32) *lzmaDecoder {
	d := &lzmaDecoder{}
	d.resetStateAndProbs()
	return d
}

func (d *lzmaDecoder) resetDict() {
	// Output slice acts as sliding window reference; resetting dictionary only resets state.
	d.resetState()
}

func (d *lzmaDecoder) resetState() {
	d.state = 0
	d.reps = [4]uint32{0, 0, 0, 0}
}

func (d *lzmaDecoder) setProps(prop byte) error {
	if prop >= 9*5*5 {
		return errors.New("lzma2: invalid properties byte")
	}
	d.lc = uint32(prop % 9)
	prop /= 9
	d.lp = uint32(prop % 5)
	d.pb = uint32(prop / 5)
	numLit := 0x300 << (d.lc + d.lp)
	if len(d.litProbs) != numLit {
		d.litProbs = make([]uint16, numLit)
	}
	return nil
}

func (d *lzmaDecoder) resetStateAndProbs() {
	d.resetState()
	for i := range d.isMatch {
		for j := range d.isMatch[i] {
			d.isMatch[i][j] = 1024
			d.isRep0Long[i][j] = 1024
		}
		d.isRep[i] = 1024
		d.isRepG0[i] = 1024
		d.isRepG1[i] = 1024
		d.isRepG2[i] = 1024
	}
	for i := range d.posSlot {
		for j := range d.posSlot[i] {
			d.posSlot[i][j] = 1024
		}
	}
	for i := range d.posDec {
		d.posDec[i] = 1024
	}
	for i := range d.align {
		d.align[i] = 1024
	}
	for i := range d.litProbs {
		d.litProbs[i] = 1024
	}
	d.matchLen.reset()
	d.repLen.reset()
}

func (d *lzmaDecoder) writeUncompressed(b []byte) {
	d.out = append(d.out, b...)
}

type rangeDecoder struct {
	buf   []byte
	pos   int
	rng   uint32
	code  uint32
	corrupt bool
}

func newRangeDecoder(b []byte) (*rangeDecoder, error) {
	if len(b) < 5 || b[0] != 0x00 {
		return nil, errors.New("lzma2: invalid range coder init")
	}
	return &rangeDecoder{
		buf:  b,
		pos:  5,
		rng:  0xFFFFFFFF,
		code: binary.BigEndian.Uint32(b[1:5]),
	}, nil
}

func (rc *rangeDecoder) normalize() {
	if rc.rng < 0x01000000 {
		rc.rng <<= 8
		var b byte
		if rc.pos < len(rc.buf) {
			b = rc.buf[rc.pos]
			rc.pos++
		}
		rc.code = (rc.code << 8) | uint32(b)
	}
}

func (rc *rangeDecoder) decodeBit(prob *uint16) uint32 {
	rc.normalize()
	p := uint32(*prob)
	bound := (rc.rng >> 11) * p
	if rc.code < bound {
		rc.rng = bound
		*prob = uint16(p + ((2048 - p) >> 5))
		return 0
	}
	rc.rng -= bound
	rc.code -= bound
	*prob = uint16(p - (p >> 5))
	return 1
}

func (rc *rangeDecoder) decodeDirectBits(numBits uint32) uint32 {
	var res uint32
	for i := uint32(0); i < numBits; i++ {
		rc.normalize()
		rc.rng >>= 1
		rc.code -= rc.rng
		t := 0 - (rc.code >> 31)
		rc.code += rc.rng & t
		res = (res << 1) | (1 - (t & 1))
	}
	return res
}

func (rc *rangeDecoder) decodeBitTree(probs []uint16, numBits uint32) uint32 {
	m := uint32(1)
	for i := uint32(0); i < numBits; i++ {
		m = (m << 1) | rc.decodeBit(&probs[m])
	}
	return m - (1 << numBits)
}

func (rc *rangeDecoder) decodeReverseBitTree(probs []uint16, numBits uint32) uint32 {
	m := uint32(1)
	var sym uint32
	for i := uint32(0); i < numBits; i++ {
		bit := rc.decodeBit(&probs[m])
		m = (m << 1) | bit
		sym |= bit << i
	}
	return sym
}

func (lc *lenCoder) decode(rc *rangeDecoder, posState uint32) uint32 {
	if rc.decodeBit(&lc.choice) == 0 {
		return rc.decodeBitTree(lc.low[posState][:], 3)
	}
	if rc.decodeBit(&lc.choice2) == 0 {
		return 8 + rc.decodeBitTree(lc.mid[posState][:], 3)
	}
	return 16 + rc.decodeBitTree(lc.high[:], 8)
}

func (d *lzmaDecoder) decodeChunk(chunk []byte, uSize int) error {
	rc, err := newRangeDecoder(chunk)
	if err != nil {
		return err
	}
	targetLen := len(d.out) + uSize
	posStateMask := (uint32(1) << d.pb) - 1
	litPosMask := (uint32(1) << d.lp) - 1

	for len(d.out) < targetLen {
		posState := uint32(len(d.out)) & posStateMask
		if rc.decodeBit(&d.isMatch[d.state][posState]) == 0 {
			// Literal
			var prevByte byte
			if len(d.out) > 0 {
				prevByte = d.out[len(d.out)-1]
			}
			litState := ((uint32(len(d.out)) & litPosMask) << d.lc) | (uint32(prevByte) >> (8 - d.lc))
			probs := d.litProbs[0x300*litState : 0x300*(litState+1)]
			sym := uint32(1)
			if d.state >= 7 {
				matchPos := len(d.out) - int(d.reps[0]) - 1
				var matchByte byte
				if matchPos >= 0 && matchPos < len(d.out) {
					matchByte = d.out[matchPos]
				}
				for sym < 0x100 {
					matchBit := uint32(matchByte>>7) & 1
					matchByte <<= 1
					bit := rc.decodeBit(&probs[((1+matchBit)<<8)+sym])
					sym = (sym << 1) | bit
					if matchBit != bit {
						break
					}
				}
			}
			for sym < 0x100 {
				sym = (sym << 1) | rc.decodeBit(&probs[sym])
			}
			d.out = append(d.out, byte(sym))
			if d.state < 4 {
				d.state = 0
			} else if d.state < 10 {
				d.state -= 3
			} else {
				d.state -= 6
			}
			continue
		}

		var length uint32
		if rc.decodeBit(&d.isRep[d.state]) == 1 {
			if rc.decodeBit(&d.isRepG0[d.state]) == 0 {
				if rc.decodeBit(&d.isRep0Long[d.state][posState]) == 0 {
					if d.state < 7 {
						d.state = 9
					} else {
						d.state = 11
					}
					idx := len(d.out) - int(d.reps[0]) - 1
					if idx < 0 || idx >= len(d.out) {
						return errors.New("lzma2: invalid short rep distance")
					}
					d.out = append(d.out, d.out[idx])
					continue
				}
			} else {
				var dist uint32
				if rc.decodeBit(&d.isRepG1[d.state]) == 0 {
					dist = d.reps[1]
				} else {
					if rc.decodeBit(&d.isRepG2[d.state]) == 0 {
						dist = d.reps[2]
					} else {
						dist = d.reps[3]
						d.reps[3] = d.reps[2]
					}
					d.reps[2] = d.reps[1]
				}
				d.reps[1] = d.reps[0]
				d.reps[0] = dist
			}
			length = d.repLen.decode(rc, posState) + 2
			if d.state < 7 {
				d.state = 8
			} else {
				d.state = 11
			}
		} else {
			d.reps[3] = d.reps[2]
			d.reps[2] = d.reps[1]
			d.reps[1] = d.reps[0]
			length = d.matchLen.decode(rc, posState) + 2
			if d.state < 7 {
				d.state = 7
			} else {
				d.state = 10
			}
			lenState := length - 2
			if lenState > 3 {
				lenState = 3
			}
			posSlot := rc.decodeBitTree(d.posSlot[lenState][:], 6)
			if posSlot < 4 {
				d.reps[0] = posSlot
			} else {
				numDirectBits := (posSlot >> 1) - 1
				dist := (2 | (posSlot & 1)) << numDirectBits
				if posSlot < 14 {
					base := dist - posSlot
					dist += rc.decodeReverseBitTree(d.posDec[base:], numDirectBits)
				} else {
					dist += rc.decodeDirectBits(numDirectBits-4) << 4
					dist += rc.decodeReverseBitTree(d.align[:], 4)
				}
				d.reps[0] = dist
			}
		}

		dist := int(d.reps[0]) + 1
		if dist <= 0 || dist > len(d.out) {
			return errors.New("lzma2: match distance out of range")
		}
		for i := uint32(0); i < length && len(d.out) < targetLen; i++ {
			d.out = append(d.out, d.out[len(d.out)-dist])
		}
	}
	return nil
}

// decodeBCJX86 reverses the XZ x86 BCJ (CALL/JMP relative-to-absolute) filter in-place.
func decodeBCJX86(buf []byte, startOffset uint32) {
	if len(buf) < 5 {
		return
	}
	var prevMask uint32
	prevPos := -5
	limit := len(buf) - 4
	for i := 0; i < limit; i++ {
		b := buf[i]
		if b != 0xE8 && b != 0xE9 {
			continue
		}
		offset := i - prevPos
		prevPos = i
		if offset > 5 {
			prevMask = 0
		} else {
			for offset > 0 {
				prevMask &= 0x77
				prevMask <<= 1
				offset--
			}
		}
		b4 := buf[i+4]
		if (b4 == 0x00 || b4 == 0xFF) && (prevMask>>1) != 0x01 && (prevMask>>1) != 0x03 {
			src := uint32(buf[i+1]) | (uint32(buf[i+2]) << 8) | (uint32(buf[i+3]) << 16) | (uint32(b4) << 24)
			var dest uint32
			for {
				dest = src - (startOffset + uint32(i) + 5)
				if prevMask == 0 {
					break
				}
				idx := uint8(prevMask >> 1)
				var shift uint
				switch idx {
				case 1:
					shift = 24 - 8
				case 2:
					shift = 24 - 16
				case 4:
					shift = 24 - 24
				default:
					shift = 32
				}
				if shift == 32 {
					break
				}
				checkByte := byte(dest >> shift)
				if checkByte != 0x00 && checkByte != 0xFF {
					break
				}
				src = dest ^ ((uint32(1) << (32 - shift)) - 1)
			}
			dest &= 0x01FFFFFF
			if dest&0x01000000 != 0 {
				dest |= 0xFF000000
			}
			buf[i+1] = byte(dest)
			buf[i+2] = byte(dest >> 8)
			buf[i+3] = byte(dest >> 16)
			buf[i+4] = byte(dest >> 24)
			i += 4
		} else {
			prevMask = (prevMask << 1) | 1
		}
	}
}

// decodeBCJARM64 reverses the XZ ARM64 BCJ filter in-place.
func decodeBCJARM64(buf []byte, startOffset uint32) {
	limit := len(buf) &^ 3
	for i := 0; i < limit; i += 4 {
		pc := startOffset + uint32(i)
		instr := binary.LittleEndian.Uint32(buf[i : i+4])
		if (instr >> 26) == 0x25 {
			// BL instruction
			src := instr & 0x03FFFFFF
			dest := (src - (pc >> 2)) & 0x03FFFFFF
			binary.LittleEndian.PutUint32(buf[i:i+4], (0x25<<26)|dest)
		} else if (instr & 0x9F000000) == 0x90000000 {
			// ADRP instruction
			src := ((instr >> 29) & 3) | ((instr >> 3) & 0x001FFFFC)
			if (src & 0x00020000) != 0 {
				// Only 18-bit range is filtered by xz ARM64 filter
				continue
			}
			dest := src - (pc >> 12)
			out := uint32(0x90000000) | (instr & 0x1F)
			out |= (dest & 3) << 29
			out |= (dest & 0x0003FFFC) << 3
			if (dest & 0x00020000) != 0 {
				out |= 0x00E00000
			}
			binary.LittleEndian.PutUint32(buf[i:i+4], out)
		}
	}
}
