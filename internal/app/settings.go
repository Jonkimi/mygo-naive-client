package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/egoist/mygo"

	"naive-client/internal/config"
	"naive-client/internal/routing"
	"naive-client/internal/updater"
	"naive-client/locales"
)

const (
	appearanceSystem = "system"
	appearanceLight  = "light"
	appearanceDark   = "dark"

	appIconBoth    = "dock-and-menubar"
	appIconDock    = "dock"
	appIconMenubar = "menubar"

	defaultProbeURL    = "https://cp.cloudflare.com/generate_204"
	defaultDownloadURL = "https://speed.cloudflare.com/__down?bytes=10000000"
)

// PersistedState holds the client settings and configured NaiveProxy services.
type PersistedState struct {
	Services                []config.Service `json:"services"`
	Language                string           `json:"language,omitempty"`
	Appearance              string           `json:"appearance,omitempty"`
	AppIcon                 string           `json:"appIcon,omitempty"`
	SidebarCollapsed        bool             `json:"sidebarCollapsed,omitempty"`
	GatewayEnabled          bool             `json:"gatewayEnabled"`
	GatewayPort             int              `json:"gatewayPort,omitempty"`
	BootstrapDoH            string           `json:"bootstrapDoH,omitempty"`
	RemoteDoH               string           `json:"remoteDoH,omitempty"`
	TrafficMode             string           `json:"trafficMode,omitempty"`
	SystemProxyBypass       []string         `json:"systemProxyBypass,omitempty"`
	RoutingRules            []routing.Rule   `json:"routingRules,omitempty"`
	RoutingFinal            routing.RouteAction `json:"routingFinal,omitempty"`
	AutoCheckUpdate         bool             `json:"autoCheckUpdate"`
	AutoUpdateCore          bool             `json:"autoUpdateCore"`
	UseRunningServiceForUpd bool             `json:"useRunningServiceForUpdate"`
	GitHubMirror            string           `json:"githubMirror,omitempty"`
	UpdateProxy             string           `json:"updateProxy,omitempty"`
	ProbeURL                string           `json:"probeUrl,omitempty"`
	DownloadTestURL         string           `json:"downloadTestUrl,omitempty"`
	CustomNaiveBinaryPath   string           `json:"customNaiveBinaryPath,omitempty"`
	LastKnownRemoteTag      string           `json:"lastKnownRemoteTag,omitempty"`
	InstalledNaiveTag       string           `json:"installedNaiveTag,omitempty"`
	InstalledNaiveSHA256    string           `json:"installedNaiveSha256,omitempty"`
}

func defaultPersistedState() PersistedState {
	return PersistedState{
		Services:                []config.Service{},
		Language:                locales.LangSystem,
		Appearance:              appearanceSystem,
		AppIcon:                 appIconBoth,
		GatewayEnabled:          true,
		GatewayPort:             10809,
		TrafficMode:             "port",
		RoutingRules:            routing.DefaultPresets(),
		RoutingFinal:            routing.RouteAction{Type: routing.ActionProxyPool},
		AutoCheckUpdate:         true,
		AutoUpdateCore:          true,
		UseRunningServiceForUpd: true,
		ProbeURL:                defaultProbeURL,
		DownloadTestURL:         defaultDownloadURL,
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

func (a *app) loadState() {
	st := defaultPersistedState()
	raw, err := os.ReadFile(a.stateFilePath())
	if err == nil && len(raw) > 0 {
		_ = json.Unmarshal(raw, &st)
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
				// Merged into preset-lan-direct ("绕过大陆及局域网")
				continue
			}
			if r.ID == "preset-lan-direct" {
				hasLanDirect = true
				r.Name = "绕过大陆及局域网"
				r.Description = "中国大陆网站与局域网私有网段直连，不走代理"
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
	for i := range st.Services {
		if len(st.Services[i].Listens) == 0 {
			st.Services[i].Listens = []string{"socks://127.0.0.1:1080"}
		}
	}
	a.state = st
	a.syncRouter()
}

func (a *app) saveState() {
	a.syncRouter()
	dir := a.userDataDir()
	_ = os.MkdirAll(dir, 0o755)
	raw, err := json.MarshalIndent(a.state, "", "  ")
	if err != nil {
		return
	}
	tmp := a.stateFilePath() + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err == nil {
		_ = os.Rename(tmp, a.stateFilePath())
	}
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
