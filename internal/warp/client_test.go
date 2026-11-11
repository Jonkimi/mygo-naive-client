package warp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClient_RegisterWireGuard_And_EnrollMASQUE(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/v0a1909051800/reg") && r.Method == http.MethodPost {
			resp := regResponse{
				ID:   "device-123",
				Type: "PC",
				Token: "token-abc-xyz",
			}
			resp.Account.ID = "acc-456"
			resp.Account.AccountType = "free"
			resp.Account.License = "lic-789"
			resp.Config.ClientID = "AQID"
			resp.Config.Interface.Addresses.V4 = "172.16.0.2/32"
			resp.Config.Interface.Addresses.V6 = "2606:4700:110:8a36::2/128"
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		if strings.Contains(r.URL.Path, "/v0a4471/reg/device-123") && r.Method == http.MethodPatch {
			auth := r.Header.Get("Authorization")
			if auth != "Bearer token-abc-xyz" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			resp := regResponse{
				ID: "device-123",
			}
			resp.Config.Interface.Addresses.V4 = "172.16.0.2/32"
			resp.Config.Interface.Addresses.V6 = "2606:4700:110:8a36::2/128"
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		if strings.Contains(r.URL.Path, "/account") && r.Method == http.MethodPut {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"account_type": "unlimited",
				"license":      "custom-warp-plus-license",
			})
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	cli := NewClient(ts.Client())
	cli.BaseURL = ts.URL

	ctx := context.Background()
	acc, err := cli.RegisterWireGuard(ctx)
	if err != nil {
		t.Fatalf("RegisterWireGuard failed: %v", err)
	}

	if acc.DeviceID != "device-123" || acc.AccessToken != "token-abc-xyz" {
		t.Errorf("unexpected account: %+v", acc)
	}
	if len(acc.Reserved) != 3 || acc.Reserved[0] != 1 {
		t.Errorf("unexpected reserved bytes: %v", acc.Reserved)
	}

	// Test MASQUE enrollment
	if err := cli.EnrollMASQUE(ctx, acc); err != nil {
		t.Fatalf("EnrollMASQUE failed: %v", err)
	}
	if acc.MASQUEPrivateKey == "" || acc.MASQUEPublicKey == "" || acc.MASQUECertPEM == "" {
		t.Errorf("expected MASQUE credentials to be populated, got: %+v", acc)
	}

	// Test License Binding
	if err := cli.BindLicense(ctx, acc, "custom-warp-plus-license"); err != nil {
		t.Fatalf("BindLicense failed: %v", err)
	}
	if acc.AccountType != "unlimited" {
		t.Errorf("expected account type unlimited, got %s", acc.AccountType)
	}

	// Test ProvisionAll
	fullAcc, err := cli.ProvisionAll(ctx, Account{}, "custom-warp-plus-license")
	if err != nil {
		t.Fatalf("ProvisionAll failed: %v", err)
	}
	if fullAcc.DeviceID != "device-123" || fullAcc.AccountType != "unlimited" {
		t.Errorf("unexpected provision result: %+v", fullAcc)
	}
}
