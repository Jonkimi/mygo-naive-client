package warp

import (
	"crypto/tls"
	"net"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	DefaultAPIURL = "https://api.cloudflareclient.com"
	clientUA      = "okhttp/3.12.1"
	cfClientVer   = "a-6.30-3596"
)

// Client interacts with the Cloudflare WARP registration API.
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

// NewClient returns a new Cloudflare WARP API client with Anycast IP fallback for Mainland China.
func NewClient(httpClient *http.Client) *Client {
	if httpClient == nil {
		dialer := &net.Dialer{Timeout: 8 * time.Second}
		tr := &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, _ := net.SplitHostPort(addr)
				if host == "api.cloudflareclient.com" {
					// Direct Anycast IPs bypass DNS pollution in Mainland China while preserving SNI TLS verification
					ips := []string{"162.159.192.1", "162.159.193.1", "162.159.195.1", "162.159.200.1"}
					var lastErr error
					for _, ip := range ips {
						subCtx, subCancel := context.WithTimeout(ctx, 2*time.Second)
						conn, err := dialer.DialContext(subCtx, network, net.JoinHostPort(ip, port))
						subCancel()
						if err == nil {
							return conn, nil
						}
						lastErr = err
					}
					if conn, err := dialer.DialContext(ctx, network, addr); err == nil {
						return conn, nil
					}
					return nil, lastErr
				}
				return dialer.DialContext(ctx, network, addr)
			},
			TLSClientConfig: &tls.Config{
				ServerName: "api.cloudflareclient.com",
			},
			ForceAttemptHTTP2:   true,
			TLSHandshakeTimeout: 8 * time.Second,
		}
		httpClient = &http.Client{
			Transport: tr,
			Timeout:   15 * time.Second,
		}
	}
	return &Client{
		BaseURL:    DefaultAPIURL,
		HTTPClient: httpClient,
	}
}

func randomHex(n int) string {
	bytes := make([]byte, n)
	_, _ = rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

type regResponse struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Key     string `json:"key"`
	Account struct {
		ID          string `json:"id"`
		AccountType string `json:"account_type"`
		License     string `json:"license"`
	} `json:"account"`
	Config struct {
		ClientID string `json:"client_id"`
		Peers    []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				V4   string `json:"v4"`
				V6   string `json:"v6"`
				Host string `json:"host"`
			} `json:"endpoint"`
		} `json:"peers"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
	} `json:"config"`
	Token string `json:"token"`
}

// RegisterWireGuard registers a new WireGuard device with Cloudflare.
func (c *Client) RegisterWireGuard(ctx context.Context) (*Account, error) {
	priv, pub, err := GenerateWireGuardKeypair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate WireGuard key: %w", err)
	}

	reqBody := map[string]any{
		"key":           pub,
		"install_id":    "",
		"fcm_token":     "",
		"tos":           time.Now().Format(time.RFC3339Nano),
		"model":         "PC",
		"serial_number": randomHex(8),
		"locale":        "en_US",
	}
	bodyData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	url := strings.TrimRight(c.BaseURL, "/") + "/v0a1909051800/reg"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyData))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("User-Agent", clientUA)
	req.Header.Set("CF-Client-Version", cfClientVer)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("network error registering device: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("registration failed (HTTP %d): %s", resp.StatusCode, string(respBytes))
	}

	var reg regResponse
	if err := json.Unmarshal(respBytes, &reg); err != nil {
		return nil, fmt.Errorf("failed to parse registration response: %w", err)
	}

	reserved, _ := ParseClientIDReserved(reg.Config.ClientID)
	peerKey := DefaultWireGuardPubKey
	if len(reg.Config.Peers) > 0 && reg.Config.Peers[0].PublicKey != "" {
		peerKey = reg.Config.Peers[0].PublicKey
	}

	ipv4 := reg.Config.Interface.Addresses.V4
	if ipv4 == "" {
		ipv4 = DefaultIPv4
	}
	ipv6 := reg.Config.Interface.Addresses.V6
	if ipv6 == "" {
		ipv6 = DefaultIPv6
	}

	return &Account{
		DeviceID:        reg.ID,
		AccessToken:     reg.Token,
		AccountID:       reg.Account.ID,
		AccountType:     reg.Account.AccountType,
		LicenseKey:      reg.Account.License,
		WGPrivateKey:    priv,
		WGPublicKey:     pub,
		WGPeerPublicKey: peerKey,
		ClientID:        reg.Config.ClientID,
		Reserved:        reserved,
		IPv4:            ipv4,
		IPv6:            ipv6,
	}, nil
}

// EnrollMASQUE enrolls a dedicated ECDSA P-256 keypair for MASQUE on Cloudflare.
func (c *Client) EnrollMASQUE(ctx context.Context, acc *Account) error {
	if acc == nil {
		return errors.New("nil account")
	}

	priv, pubPKIX, certPEM, err := GenerateMASQUEKeypair()
	if err != nil {
		return fmt.Errorf("failed to generate MASQUE keypair: %w", err)
	}

	// Ensure a dedicated device exists for MASQUE so patching secp256r1 doesn't overwrite WireGuard's key
	token := acc.MASQUEToken
	deviceID := acc.MASQUEDeviceID
	if deviceID == "" || token == "" || deviceID == acc.DeviceID {
		masqueDev, err := c.RegisterWireGuard(ctx)
		if err != nil {
			return err
		}
		deviceID = masqueDev.DeviceID
		token = masqueDev.AccessToken
		acc.MASQUEDeviceID = masqueDev.DeviceID
		acc.MASQUEToken = masqueDev.AccessToken
		if acc.DeviceID == "" {
			acc.DeviceID = masqueDev.DeviceID
			acc.AccessToken = masqueDev.AccessToken
			acc.AccountID = masqueDev.AccountID
			acc.AccountType = masqueDev.AccountType
			acc.LicenseKey = masqueDev.LicenseKey
			acc.WGPrivateKey = masqueDev.WGPrivateKey
			acc.WGPublicKey = masqueDev.WGPublicKey
			acc.WGPeerPublicKey = masqueDev.WGPeerPublicKey
			acc.ClientID = masqueDev.ClientID
			acc.Reserved = masqueDev.Reserved
			acc.IPv4 = masqueDev.IPv4
			acc.IPv6 = masqueDev.IPv6
		}
	}

	patchBody := map[string]any{
		"key":      pubPKIX,
		"key_type": "secp256r1",
	}
	data, err := json.Marshal(patchBody)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v0a4471/reg/%s", strings.TrimRight(c.BaseURL, "/"), deviceID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("User-Agent", clientUA)
	req.Header.Set("CF-Client-Version", cfClientVer)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("network error enrolling MASQUE key: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("MASQUE enrollment failed (HTTP %d): %s", resp.StatusCode, string(bodyBytes))
	}

	var patchResp regResponse
	_ = json.Unmarshal(bodyBytes, &patchResp)

	acc.MASQUEDeviceID = deviceID
	acc.MASQUEToken = token
	acc.MASQUEPrivateKey = priv
	acc.MASQUEPublicKey = pubPKIX
	acc.MASQUECertPEM = certPEM
	if patchResp.Config.Interface.Addresses.V4 != "" {
		acc.MASQUEIPv4 = patchResp.Config.Interface.Addresses.V4
	} else {
		acc.MASQUEIPv4 = acc.IPv4
	}
	if patchResp.Config.Interface.Addresses.V6 != "" {
		acc.MASQUEIPv6 = patchResp.Config.Interface.Addresses.V6
	} else {
		acc.MASQUEIPv6 = acc.IPv6
	}
	return nil
}

// BindLicense binds a WARP+ license key to the registered account.
func (c *Client) BindLicense(ctx context.Context, acc *Account, licenseKey string) error {
	licenseKey = strings.TrimSpace(licenseKey)
	if licenseKey == "" {
		return errors.New("license key cannot be empty")
	}
	if acc == nil || acc.DeviceID == "" || acc.AccessToken == "" {
		return errors.New("account not registered")
	}

	bodyData, _ := json.Marshal(map[string]string{
		"license": licenseKey,
	})

	url := fmt.Sprintf("%s/v0a1909051800/reg/%s/account", strings.TrimRight(c.BaseURL, "/"), acc.DeviceID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(bodyData))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+acc.AccessToken)
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("User-Agent", clientUA)
	req.Header.Set("CF-Client-Version", cfClientVer)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("network error binding license: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("bind license failed (HTTP %d): %s", resp.StatusCode, string(bodyBytes))
	}

	var updateResp struct {
		AccountType string `json:"account_type"`
		License     string `json:"license"`
	}
	if err := json.Unmarshal(bodyBytes, &updateResp); err == nil {
		if updateResp.AccountType != "" {
			acc.AccountType = updateResp.AccountType
		}
		if updateResp.License != "" {
			acc.LicenseKey = updateResp.License
		}
	}
	return nil
}

// ProvisionAll runs one-click registration for both WireGuard and MASQUE, and optionally binds a license key.
func (c *Client) ProvisionAll(ctx context.Context, existing Account, licenseKey string) (Account, error) {
	acc := existing
	if acc.DeviceID == "" || acc.WGPrivateKey == "" || (acc.MASQUEDeviceID != "" && acc.MASQUEDeviceID == acc.DeviceID) {
		fresh, err := c.RegisterWireGuard(ctx)
		if err != nil {
			return existing, err
		}
		acc = *fresh
	}

	if acc.MASQUEPrivateKey == "" || acc.MASQUECertPEM == "" || acc.MASQUEDeviceID == "" || acc.MASQUEDeviceID == acc.DeviceID {
		_ = c.EnrollMASQUE(ctx, &acc)
	}

	if licenseKey != "" {
		_ = c.BindLicense(ctx, &acc, licenseKey)
	}
	return acc, nil
}
