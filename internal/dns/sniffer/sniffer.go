package sniffer

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"strings"
)

var (
	ErrNotTLS     = errors.New("not tls handshake")
	ErrNotHTTP    = errors.New("not http request")
	ErrNoSNIFound = errors.New("no sni found in client hello")
	ErrNoHost     = errors.New("no host header found")
	ErrShortData  = errors.New("data too short")
)

var httpMethods = [][]byte{
	[]byte("GET "),
	[]byte("POST "),
	[]byte("HEAD "),
	[]byte("PUT "),
	[]byte("DELETE "),
	[]byte("OPTIONS "),
	[]byte("CONNECT "),
	[]byte("PATCH "),
	[]byte("TRACE "),
}

// Sniff peeks at the beginning of the stream through bufio.Reader without consuming any bytes,
// detecting TLS ClientHello SNI or HTTP Host.
func Sniff(br *bufio.Reader) (string, string, error) {
	// Peek 5 bytes first to inspect protocol header
	header, err := br.Peek(5)
	if err != nil && len(header) == 0 {
		return "", "", err
	}

	// 1. TLS Handshake Record
	if len(header) >= 5 && header[0] == 0x16 && header[1] == 0x03 {
		recordLen := int(binary.BigEndian.Uint16(header[3:5]))
		need := 5 + recordLen
		// Don't peek more than buffer limit
		if need > 4096 {
			need = 4096
		}
		data, _ := br.Peek(need)
		if len(data) == 0 {
			data = header
		}
		if sni, err := SniffTLS(data); err == nil && sni != "" {
			return sni, "tls", nil
		}
	}

	// 2. HTTP Request
	for _, m := range httpMethods {
		if bytes.HasPrefix(header, m) {
			avail := br.Buffered()
			if avail < 128 {
				avail = 128
			}
			if avail > 4096 {
				avail = 4096
			}
			data, _ := br.Peek(avail)
			if len(data) == 0 {
				data = header
			}
			if host, err := SniffHTTP(data); err == nil && host != "" {
				return host, "http", nil
			}
			break
		}
	}

	return "", "", ErrShortData
}

// SniffTLS extracts the SNI hostname from raw TLS ClientHello bytes.
func SniffTLS(data []byte) (string, error) {
	if len(data) < 5 {
		return "", ErrShortData
	}

	// Check TLS Handshake Record (0x16) and Version (0x03 0x01..0x04)
	if data[0] != 0x16 {
		return "", ErrNotTLS
	}
	if data[1] != 0x03 {
		return "", ErrNotTLS
	}

	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	payload := data[5:]
	if len(payload) > recordLen {
		payload = payload[:recordLen]
	}

	if len(payload) < 4 {
		return "", ErrShortData
	}

	// Handshake type: 0x01 (ClientHello)
	if payload[0] != 0x01 {
		return "", ErrNotTLS
	}

	// Handshake length (3 bytes)
	hsLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if len(payload)-4 < hsLen {
		// Even if incomplete record in buffer, parse as much as available
		hsLen = len(payload) - 4
	}
	body := payload[4 : 4+hsLen]

	// Version (2 bytes) + Random (32 bytes) = 34 bytes
	if len(body) < 34 {
		return "", ErrShortData
	}
	pos := 34

	// Session ID length (1 byte)
	if pos >= len(body) {
		return "", ErrShortData
	}
	sessIDLen := int(body[pos])
	pos += 1 + sessIDLen

	// Cipher Suites length (2 bytes)
	if pos+2 > len(body) {
		return "", ErrShortData
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2 + cipherSuitesLen

	// Compression Methods length (1 byte)
	if pos >= len(body) {
		return "", ErrShortData
	}
	compMethodsLen := int(body[pos])
	pos += 1 + compMethodsLen

	// Extensions total length (2 bytes)
	if pos+2 > len(body) {
		return "", ErrNoSNIFound
	}
	extTotalLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2

	extensions := body[pos:]
	if len(extensions) > extTotalLen {
		extensions = extensions[:extTotalLen]
	}

	// Parse extensions
	offset := 0
	for offset+4 <= len(extensions) {
		extType := binary.BigEndian.Uint16(extensions[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(extensions[offset+2 : offset+4]))
		offset += 4

		if offset+extLen > len(extensions) {
			break
		}
		extData := extensions[offset : offset+extLen]
		offset += extLen

		// Server Name extension type is 0x0000
		if extType == 0 {
			if len(extData) < 2 {
				continue
			}
			serverNameListLen := int(binary.BigEndian.Uint16(extData[0:2]))
			sniList := extData[2:]
			if len(sniList) > serverNameListLen {
				sniList = sniList[:serverNameListLen]
			}

			sniOffset := 0
			for sniOffset+3 <= len(sniList) {
				nameType := sniList[sniOffset]
				nameLen := int(binary.BigEndian.Uint16(sniList[sniOffset+1 : sniOffset+3]))
				sniOffset += 3

				if sniOffset+nameLen > len(sniList) {
					break
				}
				if nameType == 0 { // host_name
					return strings.ToLower(string(sniList[sniOffset : sniOffset+nameLen])), nil
				}
				sniOffset += nameLen
			}
		}
	}

	return "", ErrNoSNIFound
}

// SniffHTTP extracts the Host header value from raw HTTP request bytes.
func SniffHTTP(data []byte) (string, error) {
	if len(data) < 4 {
		return "", ErrShortData
	}

	// Check if starting with an HTTP method
	isHTTP := false
	for _, m := range httpMethods {
		if bytes.HasPrefix(data, m) {
			isHTTP = true
			break
		}
	}
	if !isHTTP {
		return "", ErrNotHTTP
	}

	// Scan lines until header block ends
	r := bufio.NewReader(bytes.NewReader(data))
	// First line is Request-Line
	_, err := r.ReadString('\n')
	if err != nil {
		return "", ErrNoHost
	}

	for {
		line, err := r.ReadString('\n')
		if err != nil && len(line) == 0 {
			break
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "" {
			break // End of HTTP headers
		}

		colon := strings.IndexByte(trimmed, ':')
		if colon > 0 {
			headerName := strings.TrimSpace(trimmed[:colon])
			if strings.EqualFold(headerName, "Host") {
				rawHost := strings.TrimSpace(trimmed[colon+1:])
				host, _, err := net.SplitHostPort(rawHost)
				if err != nil {
					host = rawHost
				}
				host = strings.Trim(host, "[]")
				return strings.ToLower(host), nil
			}
		}
	}

	return "", ErrNoHost
}
