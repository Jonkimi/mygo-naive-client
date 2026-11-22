package warp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func hasTLSExtension(clientHelloPayload []byte, targetExt uint16) bool {
	if len(clientHelloPayload) < 39 || clientHelloPayload[0] != tlsHandshakeClientHel {
		return false
	}
	pos := 38
	sessionIDLen := int(clientHelloPayload[pos])
	pos += 1 + sessionIDLen
	if pos+2 > len(clientHelloPayload) {
		return false
	}
	csLen := int(binary.BigEndian.Uint16(clientHelloPayload[pos : pos+2]))
	pos += 2 + csLen
	if pos+1 > len(clientHelloPayload) {
		return false
	}
	compLen := int(clientHelloPayload[pos])
	pos += 1 + compLen
	if pos+2 > len(clientHelloPayload) {
		return false
	}
	extTotalLen := int(binary.BigEndian.Uint16(clientHelloPayload[pos : pos+2]))
	pos += 2
	extEnd := min(pos+extTotalLen, len(clientHelloPayload))
	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(clientHelloPayload[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(clientHelloPayload[pos+2 : pos+4]))
		pos += 4
		if pos+extLen > extEnd {
			break
		}
		if extType == targetExt {
			return true
		}
		pos += extLen
	}
	return false
}

func TestNewWarpTLSConn_UTLS_Padding_Fragment_And_MTLS(t *testing.T) {
	srvCert := generateTestServerCert(t)
	priv, _, certPEM, err := GenerateMASQUEKeypair()
	if err != nil {
		t.Fatalf("GenerateMASQUEKeypair: %v", err)
	}
	clientCert, err := ParseMASQUETLSCertificate(certPEM, priv)
	if err != nil {
		t.Fatalf("ParseMASQUETLSCertificate: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var serverSeenSNI string
	srvErrCh := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			srvErrCh <- err
			return
		}
		defer raw.Close()

		tSrv := tls.Server(raw, &tls.Config{
			Certificates: []tls.Certificate{srvCert},
			ClientAuth:   tls.RequireAnyClientCert,
			NextProtos:   []string{"h2"},
			GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
				serverSeenSNI = chi.ServerName
				return nil, nil
			},
		})
		if err := tSrv.Handshake(); err != nil {
			srvErrCh <- err
			return
		}
		buf := make([]byte, 16)
		n, err := tSrv.Read(buf)
		if err != nil {
			srvErrCh <- err
			return
		}
		if string(buf[:n]) != "hello-utls" {
			srvErrCh <- errors.New("unexpected payload")
			return
		}
		_, err = tSrv.Write([]byte("ack-utls"))
		srvErrCh <- err
	}()

	rawConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rawConn.Close()

	rec := &writeRecorderConn{Conn: rawConn}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	tlsClient := newWarpTLSConn(ctx, rec, &tls.Config{
		ServerName:         DefaultMASQUESNI,
		Certificates:       []tls.Certificate{clientCert},
		NextProtos:         []string{"h2"},
		InsecureSkipVerify: true,
	}, tlsDialOptions{
		TLSFragment:  true,
		UTLS:         true,
		TLSPadding:   true,
		MixedCaseSNI: true,
	})
	if err := tlsClient.HandshakeContext(ctx); err != nil {
		t.Fatalf("uTLS fragmented handshake failed: %v", err)
	}
	if state := tlsClient.ConnectionState(); state.NegotiatedProtocol != "h2" {
		t.Fatalf("expected negotiated ALPN h2, got %q", state.NegotiatedProtocol)
	}
	if _, err := tlsClient.Write([]byte("hello-utls")); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	resp := make([]byte, 16)
	n, err := tlsClient.Read(resp)
	if err != nil || string(resp[:n]) != "ack-utls" {
		t.Fatalf("unexpected read result: %q err=%v", string(resp[:n]), err)
	}
	if sErr := <-srvErrCh; sErr != nil {
		t.Fatalf("server error: %v", sErr)
	}

	if !strings.EqualFold(serverSeenSNI, DefaultMASQUESNI) {
		t.Fatalf("expected SNI matching %q, got %q", DefaultMASQUESNI, serverSeenSNI)
	}
	if serverSeenSNI == DefaultMASQUESNI {
		t.Fatalf("expected MixedCaseSNI=true to randomize SNI casing, got exact lowercase %q", serverSeenSNI)
	}

	writes := rec.snapshotWrites()
	if len(writes) < 4 {
		t.Fatalf("expected fragmented uTLS ClientHello writes, got %d", len(writes))
	}
	var reassembled []byte
	for _, w := range writes {
		if bytes.Contains(bytes.ToLower(w), []byte(DefaultMASQUESNI)) || bytes.Contains(bytes.ToLower(w), []byte("cloudflareclient.com")) {
			t.Fatalf("single wire write must not contain complete SNI: %q", w)
		}
		if len(w) >= tlsRecordHeaderLen && w[0] == tlsContentHandshake {
			recLen := int(binary.BigEndian.Uint16(w[3:5]))
			if len(w) == tlsRecordHeaderLen+recLen {
				if len(reassembled) == 0 || w[5] != tlsHandshakeClientHel {
					reassembled = append(reassembled, w[tlsRecordHeaderLen:]...)
				}
			}
		}
	}
	if !hasTLSExtension(reassembled, 0x0015) {
		t.Fatalf("expected uTLS ClientHello to include RFC 7685 Padding extension (0x0015)")
	}
}
