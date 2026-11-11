package warp

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// GenerateWireGuardKeypair generates an X25519 keypair for WireGuard.
func GenerateWireGuardKeypair() (privBase64, pubBase64 string, err error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate X25519 key: %w", err)
	}
	privBase64 = base64.StdEncoding.EncodeToString(priv.Bytes())
	pubBase64 = base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())
	return privBase64, pubBase64, nil
}

// GenerateMASQUEKeypair generates an ECDSA P-256 keypair and a self-signed mTLS client certificate for MASQUE.
func GenerateMASQUEKeypair() (privBase64, pubPKIXBase64, certPEM string, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate P-256 key: %w", err)
	}

	// Encode private key to PKCS#8 DER base64
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to marshal private key: %w", err)
	}
	privBase64 = base64.StdEncoding.EncodeToString(privDER)

	// Encode public key to PKIX DER base64 for Cloudflare API PATCH
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubPKIXBase64 = base64.StdEncoding.EncodeToString(pubDER)

	// Generate self-signed client certificate (valid for 10 years)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Cloudflare WARP Client",
			Organization: []string{"Cloudflare, Inc."},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to create client certificate: %w", err)
	}

	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	return privBase64, pubPKIXBase64, certPEM, nil
}

// ParseMASQUETLSCertificate parses the MASQUE client certificate and base64 private key into a tls.Certificate.
func ParseMASQUETLSCertificate(certPEM, privBase64 string) (tls.Certificate, error) {
	if certPEM == "" || privBase64 == "" {
		return tls.Certificate{}, errors.New("empty certificate or private key")
	}

	privDER, err := base64.StdEncoding.DecodeString(privBase64)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("invalid base64 private key: %w", err)
	}

	privKey, err := x509.ParsePKCS8PrivateKey(privDER)
	if err != nil {
		// Try parsing as EC private key
		privKey, err = x509.ParseECPrivateKey(privDER)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("failed to parse private key: %w", err)
		}
	}

	certBlock, _ := pem.Decode([]byte(certPEM))
	if certBlock == nil {
		return tls.Certificate{}, errors.New("failed to decode certificate PEM block")
	}

	return tls.Certificate{
		Certificate: [][]byte{certBlock.Bytes},
		PrivateKey:  privKey,
	}, nil
}
