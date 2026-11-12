package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/egoist/mygo"

	"naive-client/internal/config"
	"naive-client/internal/routing"
	"naive-client/internal/tailnet"
	"naive-client/internal/updater"
	"naive-client/internal/warp"
	"naive-client/locales"
)

const (
	appearanceSystem = "system"
	appearanceLight  = "light"
	appearanceDark   = "dark"

	appIconBoth    = "dock-and-menubar"
	appIconDock    = "dock"
	appIconMenubar = "menubar"

	defaultProbeURL     = "https://cp.cloudflare.com/generate_204"
	defaultWarpProbeURL = "http://connect.rom.miui.com/generate_204"
	defaultDownloadURL  = "https://speed.cloudflare.com/__down?bytes=10000000"
)

// PersistedState holds the client settings and configured NaiveProxy services.
type PersistedState struct {
	Services                []config.Service    `json:"services"`
	Language                string              `json:"language,omitempty"`
	Appearance              string              `json:"appearance,omitempty"`
	AppIcon                 string              `json:"appIcon,omitempty"`
	SidebarCollapsed        bool                `json:"sidebarCollapsed,omitempty"`
	GatewayEnabled          bool                `json:"gatewayEnabled"`
	GatewayPort             int                 `json:"gatewayPort,omitempty"`
	DomesticDNS             string              `json:"domesticDns,omitempty"`
	RemoteDNS               string              `json:"remoteDns,omitempty"`
	BootstrapDNS            string              `json:"bootstrapDns,omitempty"`
	BootstrapDoH            string              `json:"bootstrapDoH,omitempty"` // Deprecated alias
	RemoteDoH               string              `json:"remoteDoH,omitempty"`    // Deprecated alias
	PreferIPv4              bool                `json:"preferIpv4"`
	TrafficMode             string              `json:"trafficMode,omitempty"`
	SystemProxyBypass       []string            `json:"systemProxyBypass,omitempty"`
	RoutingRules            []routing.Rule      `json:"routingRules,omitempty"`
	RoutingFinal            routing.RouteAction `json:"routingFinal,omitempty"`
	AutoCheckUpdate         bool                `json:"autoCheckUpdate"`
	AutoCheckXray           bool                `json:"autoCheckXray"`
	AutoUpdateCore          bool                `json:"autoUpdateCore"`
	AutoUpdateXray          bool                `json:"autoUpdateXray"`
	UseRunningServiceForUpd bool                `json:"useRunningServiceForUpdate"`
	AutoProbeOnStart        bool                `json:"autoProbeOnStart"`
	AutoProbePeriodic       bool                `json:"autoProbePeriodic"`
	AutoProbeInterval       int                 `json:"autoProbeInterval"`
	GitHubMirror            string              `json:"githubMirror,omitempty"`
	UpdateProxy             string              `json:"updateProxy,omitempty"`
	ProbeURL                string              `json:"probeUrl,omitempty"`
	DownloadTestURL         string              `json:"downloadTestUrl,omitempty"`
	CustomNaiveBinaryPath   string              `json:"customNaiveBinaryPath,omitempty"`
	LastKnownRemoteTag      string              `json:"lastKnownRemoteTag,omitempty"`
	InstalledNaiveTag       string              `json:"installedNaiveTag,omitempty"`
	InstalledNaiveSHA256    string              `json:"installedNaiveSha256,omitempty"`
	CustomXrayBinaryPath    string              `json:"customXrayBinaryPath,omitempty"`
	LastKnownRemoteXrayTag  string              `json:"lastKnownRemoteXrayTag,omitempty"`
	InstalledXrayTag        string              `json:"installedXrayTag,omitempty"`
	InstalledXraySHA256     string              `json:"installedXraySha256,omitempty"`
	LastKnownRemoteGeodataTag string            `json:"lastKnownRemoteGeodataTag,omitempty"`
	InstalledGeodataTag     string              `json:"installedGeodataTag,omitempty"`
	BlockerEnabled          bool                `json:"blockerEnabled"`
	BlockerBlockAds         bool                `json:"blockerBlockAds"`
	BlockerSubscriptions    []string            `json:"blockerSubscriptions,omitempty"`
	BlockerAllowlist        []string            `json:"blockerAllowlist,omitempty"`
	BlockerDenylist         []string            `json:"blockerDenylist,omitempty"`

	// Tailnet integration (ADR-0007)
	TailnetEnabled         bool     `json:"tailnetEnabled"`
	TailnetMode            string   `json:"tailnetMode,omitempty"` // "auto", "host", "embedded", "off"
	TailnetControlURL      string   `json:"tailnetControlUrl,omitempty"`
	TailnetAuthKey         string   `json:"tailnetAuthKey,omitempty"`
	TailnetHostname        string   `json:"tailnetHostname,omitempty"`
	TailnetAcceptRoutes    bool     `json:"tailnetAcceptRoutes"`
	TailnetExitNode        string   `json:"tailnetExitNode,omitempty"`
	TailnetExposeMixedPort bool     `json:"tailnetExposeMixedPort"`
	TailnetAdvertiseExit   bool     `json:"tailnetAdvertiseExit"`
	TailnetAdvertiseRoutes []string `json:"tailnetAdvertiseRoutes,omitempty"`

	// Cloudflare integration (WARP egress & Tunnel ingress)
	Cloudflare warp.Config `json:"cloudflare"`

	// Engine diagnostic log level ("debug", "info", "warn", "error")
	LogLevel string `json:"logLevel,omitempty"`
}

func normalizeLogLevel(lvl string) string {
	switch strings.ToLower(strings.TrimSpace(lvl)) {
	case "debug":
		return "debug"
	case "info":
		return "info"
	case "warn", "warning":
		return "warn"
	case "error":
		return "error"
	default:
		return "warn"
	}
}

func defaultPersistedState() PersistedState {
	return PersistedState{
		Services:                []config.Service{},
		Language:                locales.LangSystem,
		Appearance:              appearanceSystem,
		AppIcon:                 appIconBoth,
		GatewayEnabled:          true,
		GatewayPort:             10809,
		PreferIPv4:              true,
		TrafficMode:             "port",
		RoutingRules:            routing.DefaultPresets(),
		RoutingFinal:            routing.RouteAction{Type: routing.ActionProxyPool},
		AutoCheckUpdate:         true,
		AutoCheckXray:           true,
		AutoUpdateCore:          true,
		AutoUpdateXray:          true,
		UseRunningServiceForUpd: true,
		AutoProbeOnStart:        true,
		AutoProbePeriodic:       true,
		AutoProbeInterval:       5,
		ProbeURL:                defaultProbeURL,
		DownloadTestURL:         defaultDownloadURL,
		BlockerEnabled:          true,
		BlockerBlockAds:         true,
		BlockerSubscriptions:    []string{},
		BlockerAllowlist:        []string{},
		BlockerDenylist:         []string{},
		TailnetEnabled:          false,
		TailnetMode:             "auto",
		TailnetAcceptRoutes:     true,
		TailnetExposeMixedPort:  false,
		TailnetAdvertiseExit:    false,
		TailnetAdvertiseRoutes:  []string{},
		Cloudflare: warp.Config{
			DefaultMode: warp.ModeAuto,
			Tunnel: warp.TunnelConfig{
				HAConnections: 4,
				Protocol:      "auto",
			},
		},
		LogLevel:                "warn",
	}
}

func (s *PersistedState) tailnetConfig() tailnet.Config {
	mode := tailnet.Mode(s.TailnetMode)
	if mode == "" {
		mode = tailnet.ModeAuto
	}
	return tailnet.Config{
		Enabled:           s.TailnetEnabled,
		Mode:              mode,
		ControlURL:        s.TailnetControlURL,
		AuthKey:           s.TailnetAuthKey,
		Hostname:          s.TailnetHostname,
		AcceptRoutes:      s.TailnetAcceptRoutes,
		ExitNode:          s.TailnetExitNode,
		ExposeMixedPort:   s.TailnetExposeMixedPort,
		AdvertiseExitNode: s.TailnetAdvertiseExit,
		AdvertiseRoutes:   s.TailnetAdvertiseRoutes,
	}
}

func (a *app) userDataDir() string {
	if a.dataDir != "" {
		return a.dataDir
	}
	dir, err := mygo.App.Path(mygo.PathUserData)
	if err != nil || dir == "" {
		dir = filepath.Join(os.TempDir(), "naive-client")
	}
	a.dataDir = dir
	return dir
}

func (a *app) stateFilePath() string {
	return filepath.Join(a.userDataDir(), "state.json")
}

func (a *app) defaultBinaryPath() string {
	return filepath.Join(a.userDataDir(), "bin", updater.BinaryFilename(runtime.GOOS))
}

func (a *app) resolveBinaryPath() string {
	if p := strings.TrimSpace(a.state.CustomNaiveBinaryPath); p != "" {
		return p
	}
	return a.defaultBinaryPath()
}

func (a *app) defaultXrayBinaryPath() string {
	return filepath.Join(a.userDataDir(), "bin", updater.XrayBinaryFilename(runtime.GOOS))
}

func (a *app) resolveXrayBinaryPath() string {
	if p := strings.TrimSpace(a.state.CustomXrayBinaryPath); p != "" {
		return p
	}
	return a.defaultXrayBinaryPath()
}

const (
	secretTailnetAuthKey    = "tailnet-auth-key"
	secretWarpWGPrivKey     = "cloudflare-warp-wg-privkey"
	secretWarpMasquePrivKey = "cloudflare-warp-masque-privkey"
	secretCloudflareToken   = "cloudflare-tunnel-token"
)

func (a *app) tailnetKeyFile() string {
	return filepath.Join(a.userDataDir(), ".tailnet-key")
}

func (a *app) cloudflareSecretFile(name string) string {
	return filepath.Join(a.userDataDir(), "."+name)
}

func (a *app) readSecretString(key string) string {
	if !mygo.IsDev() && !a.headless {
		val, err := mygo.Secrets.Get(key)
		if err == nil && len(val) > 0 {
			return string(val)
		}
		if errors.Is(err, mygo.ErrSecretNotFound) {
			return ""
		}
	}
	raw, err := os.ReadFile(a.cloudflareSecretFile(key))
	if err == nil {
		return strings.TrimSpace(string(raw))
	}
	return ""
}

func (a *app) writeSecretString(key, val string) {
	val = strings.TrimSpace(val)
	if !mygo.IsDev() && !a.headless {
		if val == "" {
			_ = mygo.Secrets.Delete(key)
		} else {
			err := mygo.Secrets.Set(key, []byte(val))
			if err == nil {
				_ = os.Remove(a.cloudflareSecretFile(key))
				return
			}
		}
	}
	path := a.cloudflareSecretFile(key)
	if val == "" {
		_ = os.Remove(path)
		return
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	_ = os.WriteFile(path, []byte(val), 0o600)
}

func (a *app) readCloudflareSecrets(cfg *warp.Config) {
	if wgKey := a.readSecretString(secretWarpWGPrivKey); wgKey != "" {
		cfg.Account.WGPrivateKey = wgKey
	}
	if mKey := a.readSecretString(secretWarpMasquePrivKey); mKey != "" {
		cfg.Account.MASQUEPrivateKey = mKey
	}
	if tok := a.readSecretString(secretCloudflareToken); tok != "" {
		cfg.Tunnel.Token = tok
	}
}

func (a *app) writeCloudflareSecrets(cfg *warp.Config) {
	a.writeSecretString(secretWarpWGPrivKey, cfg.Account.WGPrivateKey)
	a.writeSecretString(secretWarpMasquePrivKey, cfg.Account.MASQUEPrivateKey)
	a.writeSecretString(secretCloudflareToken, cfg.Tunnel.Token)
}

func (a *app) readTailnetAuthKey() string {
	if !mygo.IsDev() && !a.headless {
		val, err := mygo.Secrets.Get(secretTailnetAuthKey)
		if err == nil && len(val) > 0 {
			return string(val)
		}
		if errors.Is(err, mygo.ErrSecretNotFound) {
			return ""
		}
	}
	raw, err := os.ReadFile(a.tailnetKeyFile())
	if err == nil {
		return strings.TrimSpace(string(raw))
	}
	return ""
}

func (a *app) writeTailnetAuthKey(key string) {
	key = strings.TrimSpace(key)
	if !mygo.IsDev() && !a.headless {
		if key == "" {
			_ = mygo.Secrets.Delete(secretTailnetAuthKey)
		} else {
			err := mygo.Secrets.Set(secretTailnetAuthKey, []byte(key))
			if err == nil {
				_ = os.Remove(a.tailnetKeyFile())
				return
			}
		}
	}
	path := a.tailnetKeyFile()
	if key == "" {
		_ = os.Remove(path)
		return
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	_ = os.WriteFile(path, []byte(key), 0o600)
}

func (a *app) loadState() {
	a.stateLoaded = true
	st := defaultPersistedState()
	raw, err := os.ReadFile(a.stateFilePath())
	var needsResave bool
	if err == nil && len(raw) > 0 {
		_ = json.Unmarshal(raw, &st)
	}

	if st.InstalledGeodataTag == "" && a.localGeodataVersion != "" {
		st.InstalledGeodataTag = a.localGeodataVersion
		needsResave = true
	}

	if len(st.Services) == 0 {
		if bakRaw, err := os.ReadFile(a.stateFilePath() + ".bak"); err == nil && len(bakRaw) > 0 {
			var bakSt PersistedState
			if json.Unmarshal(bakRaw, &bakSt) == nil && len(bakSt.Services) > 0 {
				st.Services = bakSt.Services
				needsResave = true
			}
		}
		if len(st.Services) == 0 {
			if recovered := a.recoverServicesFromConfigs(); len(recovered) > 0 {
				st.Services = recovered
				needsResave = true
			}
		}
	}
	authKey := a.readTailnetAuthKey()
	if authKey != "" {
		st.TailnetAuthKey = authKey
	} else if st.TailnetAuthKey != "" {
		// Migration: persist plaintext key from older state.json into secure store
		a.writeTailnetAuthKey(st.TailnetAuthKey)
		needsResave = true
	}

	a.readCloudflareSecrets(&st.Cloudflare)
	if st.Cloudflare.Account.WGPrivateKey != "" || st.Cloudflare.Account.MASQUEPrivateKey != "" || st.Cloudflare.Tunnel.Token != "" {
		// Migration: persist plaintext secrets from state.json into secure store
		a.writeCloudflareSecrets(&st.Cloudflare)
		needsResave = true
	}
	if st.Appearance == "" {
		st.Appearance = appearanceSystem
	}
	if st.GatewayPort <= 0 {
		st.GatewayPort = 10809
	}
	if st.TrafficMode == "" {
		st.TrafficMode = "port"
	}
	st.LogLevel = normalizeLogLevel(st.LogLevel)
	if len(st.RoutingRules) == 0 {
		st.RoutingRules = routing.DefaultPresets()
	} else {
		var cleanedRules []routing.Rule
		hasLanDirect := false
		for i := range st.RoutingRules {
			r := st.RoutingRules[i]
			if r.ID == "preset-telegram" {
				r.ID = "preset-gfw"
				r.Name = "GFW 专线"
				r.Description = "加速受 GFW 阻断的境外网站与服务"
				r.GeoSite = []string{"gfw"}
				r.Action = routing.RouteAction{Type: routing.ActionProxyTag, Tag: "GFW", Tags: []string{"GFW"}}
			}
			if r.ID == "preset-cn-direct" {
				// Merged into preset-lan-direct ("直连")
				continue
			}
			if r.ID == "preset-lan-direct" {
				hasLanDirect = true
				r.Name = "直连"
				r.Description = "直连，不走代理"
				r.GeoSite = []string{"cn"}
				r.GeoIP = []string{"cn", "private"}
				if len(r.IPCidr) == 0 {
					r.IPCidr = []string{
						"127.0.0.0/8",
						"10.0.0.0/8",
						"172.16.0.0/12",
						"192.168.0.0/16",
						"169.254.0.0/16",
						"::1/128",
						"fc00::/7",
						"fe80::/10",
					}
				}
				if len(r.DomainSuffix) == 0 {
					r.DomainSuffix = []string{
						"local",
						"localhost",
						"internal",
						"lan",
					}
				}
			}
			switch r.ID {
			case "preset-block-ads":
				r.Name = "广告拦截"
				r.DomainSuffix = nil
				r.IPCidr = nil
			case "preset-ai-services":
				r.Name = "AI 服务"
				r.DomainSuffix = nil
				r.IPCidr = nil
			case "preset-streaming":
				r.Name = "流媒体服务"
				r.DomainSuffix = nil
				r.IPCidr = nil
			case "preset-gfw":
				r.DomainSuffix = nil
				r.IPCidr = nil
			}
			cleanedRules = append(cleanedRules, r)
		}
		if !hasLanDirect {
			cleanedRules = append(cleanedRules, routing.DefaultPresets()[4])
		}
		st.RoutingRules = cleanedRules
		for _, r := range st.RoutingRules {
			if isCategoryAdsBlockRule(r) {
				st.BlockerBlockAds = r.Enabled
				break
			}
		}
	}
	if st.RoutingFinal.Type == "" {
		st.RoutingFinal = routing.RouteAction{Type: routing.ActionProxyPool}
	}
	if st.AppIcon == "" {
		st.AppIcon = appIconBoth
	}
	if strings.TrimSpace(st.ProbeURL) == "" {
		st.ProbeURL = defaultProbeURL
	}
	if strings.TrimSpace(st.DownloadTestURL) == "" {
		st.DownloadTestURL = defaultDownloadURL
	}
	if st.AutoProbeInterval <= 0 {
		st.AutoProbeInterval = 5
	}
	for i := range st.Services {
		if st.Services[i].EffectiveEngine() == config.EngineSingBox {
			st.Services[i].Listens = nil
		} else if len(st.Services[i].Listens) == 0 {
			st.Services[i].Listens = []string{"socks://127.0.0.1:1080"}
		}
	}
	a.state = st
	a.gatewayPortInput = fmt.Sprintf("%d", st.GatewayPort)
	a.syncBuiltinWarpService()
	a.syncRouter()
	a.syncBlocker()
	if a.tailnetMgr != nil {
		a.tailnetMgr.UpdateConfig(st.tailnetConfig())
	}
	if needsResave {
		a.saveState()
	}
}

func (a *app) saveState() {
	if !a.stateLoaded {
		return
	}
	a.syncBuiltinWarpService()
	a.syncRouter()
	if a.tailnetMgr != nil {
		a.tailnetMgr.UpdateConfig(a.state.tailnetConfig())
	}
	a.writeTailnetAuthKey(a.state.TailnetAuthKey)
	a.writeCloudflareSecrets(&a.state.Cloudflare)

	toPersist := a.state
	toPersist.TailnetAuthKey = "" // never store plaintext auth key in state.json
	toPersist.Cloudflare.Account.WGPrivateKey = ""
	toPersist.Cloudflare.Account.MASQUEPrivateKey = ""
	toPersist.Cloudflare.Tunnel.Token = ""

	if len(toPersist.Services) == 0 {
		if rawExisting, err := os.ReadFile(a.stateFilePath()); err == nil && len(rawExisting) > 0 {
			var prev PersistedState
			if json.Unmarshal(rawExisting, &prev) == nil && len(prev.Services) > 0 {
				_ = os.WriteFile(a.stateFilePath()+".bak", rawExisting, 0o600)
			}
		}
	}

	dir := a.userDataDir()
	_ = os.MkdirAll(dir, 0o755)
	raw, err := json.MarshalIndent(toPersist, "", "  ")
	if err != nil {
		return
	}
	tmp := a.stateFilePath() + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err == nil {
		_ = os.Rename(tmp, a.stateFilePath())
	}
}

func (a *app) recoverServicesFromConfigs() []config.Service {
	cfgDir := filepath.Join(a.userDataDir(), "configs")
	entries, err := os.ReadDir(cfgDir)
	if err != nil {
		return nil
	}

	prodServices := make(map[string]string)
	prodStatePath := filepath.Join(filepath.Dir(a.userDataDir()), "Naive Client", "state.json")
	if prodRaw, err := os.ReadFile(prodStatePath); err == nil {
		var prodSt PersistedState
		if json.Unmarshal(prodRaw, &prodSt) == nil {
			for _, s := range prodSt.Services {
				for _, p := range s.Proxies {
					prodServices[p] = s.Name
				}
			}
		}
	}

	var recovered []config.Service
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "service-") || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		if strings.HasSuffix(e.Name(), "-xray.json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(cfgDir, e.Name()))
		if err != nil || len(raw) == 0 {
			continue
		}

		id := strings.TrimSuffix(strings.TrimPrefix(e.Name(), "service-"), ".json")
		var naiveCfg struct {
			Listen string `json:"listen"`
			Proxy  string `json:"proxy"`
			Log    string `json:"log"`
		}
		if err := json.Unmarshal(raw, &naiveCfg); err != nil || naiveCfg.Proxy == "" {
			continue
		}

		name := prodServices[naiveCfg.Proxy]
		if name == "" {
			name = "Node " + id
		}

		recovered = append(recovered, config.Service{
			ID:        id,
			Name:      name,
			AutoStart: true,
			Listens:   []string{naiveCfg.Listen},
			Proxies:   []string{naiveCfg.Proxy},
			EnableLog: true,
		})
	}

	sort.Slice(recovered, func(i, j int) bool {
		return recovered[i].ID < recovered[j].ID
	})
	return recovered
}

func (a *app) nextAvailableListenPort() int {
	used := make(map[int]bool)
	for _, svc := range a.state.Services {
		for _, l := range svc.Listens {
			if p, err := config.ParseListenURI(l); err == nil && p.Port > 0 {
				used[p.Port] = true
			}
		}
	}
	for port := 1080; port < 20000; port++ {
		if !used[port] {
			return port
		}
	}
	return 1080
}

func (a *app) generateServiceID() string {
	return fmt.Sprintf("svc-%d-%d", time.Now().UnixNano(), len(a.state.Services)+1)
}
