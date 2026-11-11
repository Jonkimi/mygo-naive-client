package warp

import (
	"testing"
)

func TestGenerateWireGuardKeypair(t *testing.T) {
	priv, pub, err := GenerateWireGuardKeypair()
	if err != nil {
		t.Fatalf("GenerateWireGuardKeypair failed: %v", err)
	}
	if len(priv) < 40 || len(pub) < 40 {
		t.Errorf("expected valid base64 keys, got priv=%q pub=%q", priv, pub)
	}
}

func TestGenerateMASQUEKeypair(t *testing.T) {
	priv, pub, cert, err := GenerateMASQUEKeypair()
	if err != nil {
		t.Fatalf("GenerateMASQUEKeypair failed: %v", err)
	}
	if len(priv) == 0 || len(pub) == 0 || len(cert) == 0 {
		t.Errorf("empty key/cert generated")
	}

	parsedCert, err := ParseMASQUETLSCertificate(cert, priv)
	if err != nil {
		t.Fatalf("ParseMASQUETLSCertificate failed: %v", err)
	}
	if len(parsedCert.Certificate) == 0 {
		t.Errorf("expected non-empty certificate slice")
	}
}

func TestParseClientIDReserved(t *testing.T) {
	// Base64 of 3 bytes [1, 2, 3]
	b64 := "AQID"
	res, err := ParseClientIDReserved(b64)
	if err != nil {
		t.Fatalf("ParseClientIDReserved base64 failed: %v", err)
	}
	if len(res) != 3 || res[0] != 1 || res[1] != 2 || res[2] != 3 {
		t.Errorf("unexpected reserved bytes: %v", res)
	}

	// Comma separated
	res2, err := ParseClientIDReserved("10, 20, 30")
	if err != nil {
		t.Fatalf("ParseClientIDReserved comma failed: %v", err)
	}
	if len(res2) != 3 || res2[0] != 10 || res2[1] != 20 || res2[2] != 30 {
		t.Errorf("unexpected reserved bytes: %v", res2)
	}
}
