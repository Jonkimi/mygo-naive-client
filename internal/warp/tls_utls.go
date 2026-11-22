package warp

import (
	"context"
	"crypto/tls"
	"net"
	"slices"
	"strings"
	"unicode"

	utls "github.com/metacubex/utls"
)

type tlsDialOptions struct {
	TLSFragment  bool
	UTLS         bool
	TLSPadding   bool
	MixedCaseSNI bool
}

type handshakeTLSConn interface {
	net.Conn
	HandshakeContext(ctx context.Context) error
	ConnectionState() tls.ConnectionState
}

func newWarpTLSConn(ctx context.Context, rawConn net.Conn, baseTLS *tls.Config, opts tlsDialOptions) handshakeTLSConn {
	underlying := rawConn
	if opts.TLSFragment {
		underlying = newTLSFragmentConn(ctx, rawConn)
	}

	if !opts.UTLS {
		tlsCfg := baseTLS.Clone()
		if opts.MixedCaseSNI && tlsCfg.ServerName != "" {
			tlsCfg.ServerName = randomizeHostCase(tlsCfg.ServerName)
		}
		return tls.Client(underlying, tlsCfg)
	}

	uCfg := toUTLSConfig(baseTLS)
	uConn := utls.UClient(underlying, uCfg, utls.HelloChrome_Auto)
	return &utlsConnWrapper{
		UConn:        uConn,
		nextProtos:   append([]string(nil), baseTLS.NextProtos...),
		randomPad:    opts.TLSPadding,
		mixedCaseSNI: opts.MixedCaseSNI,
	}
}

func toUTLSConfig(cfg *tls.Config) *utls.Config {
	if cfg == nil {
		return &utls.Config{}
	}
	uCfg := &utls.Config{
		RootCAs:                cfg.RootCAs,
		NextProtos:             append([]string(nil), cfg.NextProtos...),
		ServerName:             cfg.ServerName,
		InsecureSkipVerify:     cfg.InsecureSkipVerify,
		MinVersion:             cfg.MinVersion,
		MaxVersion:             cfg.MaxVersion,
		SessionTicketsDisabled: cfg.SessionTicketsDisabled,
	}
	if len(cfg.Certificates) > 0 {
		uCfg.Certificates = make([]utls.Certificate, len(cfg.Certificates))
		for i, c := range cfg.Certificates {
			uCfg.Certificates[i] = utls.Certificate{
				Certificate:                  c.Certificate,
				PrivateKey:                   c.PrivateKey,
				OCSPStaple:                   c.OCSPStaple,
				SignedCertificateTimestamps:  c.SignedCertificateTimestamps,
				Leaf:                         c.Leaf,
			}
		}
	}
	if cfg.GetClientCertificate != nil {
		uCfg.GetClientCertificate = func(cri *utls.CertificateRequestInfo) (*utls.Certificate, error) {
			stdCRI := &tls.CertificateRequestInfo{
				AcceptableCAs: cri.AcceptableCAs,
				Version:       cri.Version,
			}
			for _, s := range cri.SignatureSchemes {
				stdCRI.SignatureSchemes = append(stdCRI.SignatureSchemes, tls.SignatureScheme(s))
			}
			c, err := cfg.GetClientCertificate(stdCRI)
			if err != nil || c == nil {
				return nil, err
			}
			return &utls.Certificate{
				Certificate:                 c.Certificate,
				PrivateKey:                  c.PrivateKey,
				OCSPStaple:                  c.OCSPStaple,
				SignedCertificateTimestamps: c.SignedCertificateTimestamps,
				Leaf:                        c.Leaf,
			}, nil
		}
	}
	return uCfg
}

type utlsConnWrapper struct {
	*utls.UConn
	nextProtos   []string
	randomPad    bool
	mixedCaseSNI bool
	configured   bool
}

func (c *utlsConnWrapper) HandshakeContext(ctx context.Context) error {
	if !c.configured {
		if err := c.BuildHandshakeState(); err != nil {
			return err
		}
		var hasPadding bool
		insertIdx := len(c.Extensions)
		for i, ext := range c.Extensions {
			switch e := ext.(type) {
			case *utls.ALPNExtension:
				if len(c.nextProtos) > 0 {
					e.AlpnProtocols = append([]string(nil), c.nextProtos...)
				}
			case *utls.SNIExtension:
				if c.mixedCaseSNI && e.ServerName != "" {
					e.ServerName = randomizeHostCase(e.ServerName)
				}
			case *utls.UtlsPaddingExtension:
				hasPadding = true
				if c.randomPad {
					padLen := randomIntRange(32, 160)
					e.GetPaddingLen = func(_ int) (int, bool) {
						return padLen, true
					}
				}
			case utls.PreSharedKeyExtension:
				if i < insertIdx {
					insertIdx = i
				}
			}
		}
		if c.randomPad && !hasPadding {
			if insertIdx > 0 {
				if _, ok := c.Extensions[insertIdx-1].(*utls.UtlsGREASEExtension); ok {
					insertIdx--
				}
			}
			padLen := randomIntRange(32, 160)
			padExt := &utls.UtlsPaddingExtension{
				GetPaddingLen: func(_ int) (int, bool) {
					return padLen, true
				},
			}
			c.Extensions = slices.Insert(c.Extensions, insertIdx, utls.TLSExtension(padExt))
		}
		if err := c.BuildHandshakeState(); err != nil {
			return err
		}
		c.configured = true
	}
	return c.UConn.HandshakeContext(ctx)
}

func (c *utlsConnWrapper) ConnectionState() tls.ConnectionState {
	state := c.UConn.ConnectionState()
	return tls.ConnectionState{
		Version:                     state.Version,
		HandshakeComplete:           state.HandshakeComplete,
		DidResume:                   state.DidResume,
		CipherSuite:                 state.CipherSuite,
		NegotiatedProtocol:          state.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  state.NegotiatedProtocolIsMutual,
		ServerName:                  state.ServerName,
		PeerCertificates:            state.PeerCertificates,
		VerifiedChains:              state.VerifiedChains,
		SignedCertificateTimestamps: state.SignedCertificateTimestamps,
		OCSPResponse:                state.OCSPResponse,
		TLSUnique:                   state.TLSUnique,
	}
}

func randomizeHostCase(host string) string {
	if host == "" {
		return host
	}
	var b strings.Builder
	b.Grow(len(host))
	flipped := false
	for _, r := range host {
		if unicode.IsLetter(r) && randomIntRange(0, 1) == 1 {
			r = unicode.ToUpper(r)
			flipped = true
		} else {
			r = unicode.ToLower(r)
		}
		b.WriteRune(r)
	}
	res := b.String()
	// Ensure at least one letter is uppercased when host contains ASCII letters
	// so mixed-case randomization is deterministic in effect.
	if !flipped {
		runes := []rune(res)
		for i, r := range runes {
			if unicode.IsLetter(r) {
				runes[i] = unicode.ToUpper(r)
				break
			}
		}
		res = string(runes)
	}
	return res
}
