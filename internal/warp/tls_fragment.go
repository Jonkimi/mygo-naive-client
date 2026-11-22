package warp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	tlsRecordHeaderLen    = 5
	tlsContentHandshake   = 22
	tlsHandshakeClientHel = 1
	tlsExtServerName      = 0x0000
	tlsSNIHostNameType    = 0x00

	defaultFragMinChunk = 3
	defaultFragMaxChunk = 8
	defaultFragMinDelay = 2 * time.Millisecond
	defaultFragMaxDelay = 5 * time.Millisecond
)

type tlsFragmentConfig struct {
	minChunk int
	maxChunk int
	minDelay time.Duration
	maxDelay time.Duration
}

func defaultTLSFragmentConfig() tlsFragmentConfig {
	return tlsFragmentConfig{
		minChunk: defaultFragMinChunk,
		maxChunk: defaultFragMaxChunk,
		minDelay: defaultFragMinDelay,
		maxDelay: defaultFragMaxDelay,
	}
}

// tlsFragmentConn wraps a TCP net.Conn and splits the initial TLS ClientHello
// handshake into multiple TLS records written as separate TCP segments with
// brief randomized pauses, breaking plaintext SNI matching in DPI middleboxes.
type tlsFragmentConn struct {
	net.Conn
	ctx       context.Context
	cfg       tlsFragmentConfig
	mu        sync.Mutex
	firstDone atomic.Bool
}

func newTLSFragmentConn(ctx context.Context, conn net.Conn) net.Conn {
	return newTLSFragmentConnWithConfig(ctx, conn, defaultTLSFragmentConfig())
}

func newTLSFragmentConnWithConfig(ctx context.Context, conn net.Conn, cfg tlsFragmentConfig) net.Conn {
	if conn == nil {
		return nil
	}
	if cfg.minChunk <= 0 {
		cfg.minChunk = defaultFragMinChunk
	}
	if cfg.maxChunk < cfg.minChunk {
		cfg.maxChunk = cfg.minChunk
	}
	return &tlsFragmentConn{
		Conn: conn,
		ctx:  ctx,
		cfg:  cfg,
	}
}

func (c *tlsFragmentConn) Write(b []byte) (int, error) {
	if c.firstDone.Load() {
		return c.Conn.Write(b)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.firstDone.Load() {
		return c.Conn.Write(b)
	}
	c.firstDone.Store(true)

	if len(b) < tlsRecordHeaderLen+1 || b[0] != tlsContentHandshake {
		return c.Conn.Write(b)
	}
	recordLen := int(binary.BigEndian.Uint16(b[3:5]))
	if recordLen <= 0 || len(b) < tlsRecordHeaderLen+recordLen {
		return c.Conn.Write(b)
	}
	handshake := b[tlsRecordHeaderLen : tlsRecordHeaderLen+recordLen]
	if handshake[0] != tlsHandshakeClientHel {
		return c.Conn.Write(b)
	}

	sniStart, sniEnd, hasSNI := findClientHelloSNI(handshake)
	ranges := computeFragmentRanges(recordLen, sniStart, sniEnd, hasSNI, c.cfg)
	if len(ranges) <= 1 {
		return c.Conn.Write(b)
	}

	if tc, ok := c.Conn.(interface{ SetNoDelay(bool) error }); ok {
		_ = tc.SetNoDelay(true)
	}

	for i, r := range ranges {
		frag := handshake[r.start:r.end]
		rec := make([]byte, tlsRecordHeaderLen+len(frag))
		rec[0] = b[0]
		rec[1] = b[1]
		rec[2] = b[2]
		binary.BigEndian.PutUint16(rec[3:5], uint16(len(frag)))
		copy(rec[tlsRecordHeaderLen:], frag)

		if err := writeAll(c.Conn, rec); err != nil {
			return 0, err
		}
		if i < len(ranges)-1 {
			if err := sleepWithContext(c.ctx, randomDurationBetween(c.cfg.minDelay, c.cfg.maxDelay)); err != nil {
				return 0, err
			}
		}
	}

	if len(b) > tlsRecordHeaderLen+recordLen {
		if err := writeAll(c.Conn, b[tlsRecordHeaderLen+recordLen:]); err != nil {
			return 0, err
		}
	}
	return len(b), nil
}

type byteRange struct {
	start int
	end   int
}

// findClientHelloSNI returns the byte range [start, end) of the SNI hostname
// inside a TLS ClientHello handshake payload (excluding the 5-byte TLS record header).
func findClientHelloSNI(handshake []byte) (int, int, bool) {
	// Type (1) + Length (3) + LegacyVersion (2) + Random (32) + SessionIDLen (1) = 39
	if len(handshake) < 39 || handshake[0] != tlsHandshakeClientHel {
		return 0, 0, false
	}
	hsLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if 4+hsLen != len(handshake) {
		return 0, 0, false
	}

	pos := 38
	sessionIDLen := int(handshake[pos])
	pos += 1 + sessionIDLen
	if pos+2 > len(handshake) {
		return 0, 0, false
	}

	cipherSuitesLen := int(binary.BigEndian.Uint16(handshake[pos : pos+2]))
	pos += 2 + cipherSuitesLen
	if pos+1 > len(handshake) {
		return 0, 0, false
	}

	compMethodsLen := int(handshake[pos])
	pos += 1 + compMethodsLen
	if pos+2 > len(handshake) {
		return 0, 0, false
	}

	extTotalLen := int(binary.BigEndian.Uint16(handshake[pos : pos+2]))
	pos += 2
	extEnd := min(pos+extTotalLen, len(handshake))

	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(handshake[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(handshake[pos+2 : pos+4]))
		pos += 4
		if pos+extLen > extEnd {
			break
		}
		if extType == tlsExtServerName && extLen >= 5 {
			if handshake[pos+2] == tlsSNIHostNameType {
				nameLen := int(binary.BigEndian.Uint16(handshake[pos+3 : pos+5]))
				nameStart := pos + 5
				nameEnd := nameStart + nameLen
				if nameLen > 0 && nameEnd <= pos+extLen {
					return nameStart, nameEnd, true
				}
			}
		}
		pos += extLen
	}
	return 0, 0, false
}

func computeFragmentRanges(payloadLen, sniStart, sniEnd int, hasSNI bool, cfg tlsFragmentConfig) []byteRange {
	if payloadLen <= 1 {
		return []byteRange{{start: 0, end: payloadLen}}
	}

	var splits []int
	if hasSNI && sniEnd-sniStart >= 4 && sniStart >= 0 && sniEnd <= payloadLen {
		// Cut inside the SNI hostname itself so no single TLS record or TCP packet
		// contains the complete domain name.
		pos := sniStart + randomIntRange(1, min(cfg.minChunk, sniEnd-sniStart-1))
		for pos < sniEnd {
			splits = append(splits, pos)
			step := randomIntRange(cfg.minChunk, cfg.maxChunk)
			pos += step
		}
	} else if payloadLen > 32 {
		// Fallback when ClientHello has no SNI: split handshake into a few chunks.
		pos := randomIntRange(16, min(32, payloadLen-1))
		for i := 0; i < 3 && pos < payloadLen; i++ {
			splits = append(splits, pos)
			pos += randomIntRange(16, 32)
		}
	}

	if len(splits) == 0 {
		return []byteRange{{start: 0, end: payloadLen}}
	}

	ranges := make([]byteRange, 0, len(splits)+1)
	prev := 0
	for _, s := range splits {
		if s > prev && s < payloadLen {
			ranges = append(ranges, byteRange{start: prev, end: s})
			prev = s
		}
	}
	if prev < payloadLen {
		ranges = append(ranges, byteRange{start: prev, end: payloadLen})
	}
	return ranges
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	if ctx == nil {
		time.Sleep(d)
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func randomIntRange(minVal, maxVal int) int {
	if maxVal <= minVal {
		return minVal
	}
	span := maxVal - minVal + 1
	n, err := rand.Int(rand.Reader, big.NewInt(int64(span)))
	if err != nil {
		return minVal
	}
	return minVal + int(n.Int64())
}

func randomDurationBetween(minD, maxD time.Duration) time.Duration {
	if maxD <= minD {
		return minD
	}
	span := int64(maxD - minD + 1)
	n, err := rand.Int(rand.Reader, big.NewInt(span))
	if err != nil {
		return minD
	}
	return minD + time.Duration(n.Int64())
}
