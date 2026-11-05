package i18n

import (
	"fmt"
	"os"
	"strings"
)

// Lang represents a supported language code.
type Lang string

const (
	LangSystem Lang = "system"
	LangZhHans Lang = "zh-Hans"
	LangEn     Lang = "en"
)

// Catalog holds all user-facing strings and formatters.
type Catalog struct {
	Code string

	// Navigation
	NavNodes    string
	NavRouting  string
	NavInsights string
	NavTailnet  string
	NavSettings string

	// Topbar & Master Switch
	MasterGateway        string
	ModePortOnly         string
	ModeSysProxy         string
	ModeTun              string
	TailnetNotConnected  string
	TailnetConnected     string

	// Nodes Page Toolbar & Badges
	NodesTitle           string
	AutoSelectPool       string
	SearchPlaceholder    string
	NewNode              string
	NewService           string
	ImportClipboard      string
	SpeedTestAll         string
	NoNodes              string
	NoNodesDesc          string
	AddNode              string
	ImportFromClipboard  string
	DirectNoProxy        string
	AllStoppedBadge      string
	ActionStartAll       string
	ActionStopAll        string
	ActionBatchTest      string
	ActionSettings       string

	// Node Status & Badges
	StatusStarting       string
	StatusRunning        string
	StatusError          string
	StatusStopped        string
	TagManagedNaive      string
	TagExternalProxy     string
	TagAutoStart         string
	CoreLocal            string
	CoreNotInstalled     string

	// Node Actions & Details
	ActionStart          string
	ActionStop           string
	ActionLatency        string
	ActionDownload       string
	ActionLogs           string
	ActionEdit           string
	ActionMore           string
	ActionCopyV2rayN     string
	ActionCopyNaive      string
	ActionClone          string
	ActionDelete         string
	DeleteConfirmTitle   string
	DeleteConfirmMsg     string
	Confirm              string
	Cancel               string
	LabelLocalListen     string
	LabelRemoteNode      string
	LatencyTesting       string
	LatencyFailed        string
	DownloadTesting      string
	DownloadFailed       string
	NoRemoteConfigured   string

	// Log Drawer
	LogDrawerTitle       string
	LogAutoScroll        string
	LogClear             string
	LogClose             string

	// Settings Page & Preferences
	SettingsTitle        string
	LanguageLabel        string
	LanguageDesc         string
	LanguageSystem       string
	LanguageZhHans       string
	LanguageEn           string
	AutoStartLabel       string
	AutoStartDesc        string
	AppearanceLabel      string
	AppearanceDesc       string
	ThemeLabel           string
	AppearanceSystem     string
	AppearanceLight      string
	AppearanceDark       string
	AppIconLabel         string
	AppIconBoth          string
	AppIconDock          string
	AppIconMenubar       string
	ClientSectionTitle   string
	ClientVersionLabel   string
	ClientAutoCheckLabel string
	ClientAutoDlLabel    string
	CheckClientUpdates   string
	CoreSectionTitle     string
	CoreVersionLabel     string
	CheckUpdates         string
	CheckingUpdates      string
	UpToDate             string
	Updating             string
	InstallCore          string
	CoreAutoCheckLabel   string
	CoreAutoUpdateLabel  string
	CoreUseRunningProxy  string
	GitHubMirrorLabel    string
	GitHubMirrorHint     string
	UpdateProxyLabel     string
	CustomCorePathLabel  string
	CustomCorePathHint   string
	TelemetrySectionTitle string
	ProbeURLLabel        string
	DownloadURLLabel     string
	SaveSettings         string

	// Editor Modal
	EditNodeTitle        string
	NewNodeTitle         string
	EditorTabBasic       string
	EditorTabAdvanced    string
	EditorTabPreview     string
	EditorAutoStartDesc  string
	EditorSaveEdit       string
	EditorSaveCreate     string
	NodeKindLabel        string
	NodeKindManaged      string
	NodeKindExternal     string
	NodeNameLabel        string
	ExternalURILabel     string
	ExternalURIHint      string
	ListenPortLabel      string
	EditorListenHint     string
	ProxyURILabel        string
	ProxyURIHint         string
	EditorProxyHintFull  string
	TagsLabel            string
	TagsHint             string
	EditorConcurrencyLabel string
	EditorNoPQLabel      string
	EditorTunnelTimeoutLabel string
	EditorIdleTimeoutLabel string
	EditorExtraHeadersLabel string
	EditorHostRulesLabel string
	EditorResolverRangeLabel string
	EditorEnableLogLabel string
	EditorLogFileLabel   string
	EditorLogFileHint    string
	EditorNetLogLabel    string
	EditorSSLKeyLogLabel string
	EditorExtraJSONLabel string
	Save                 string

	// Import & Delete
	ImportTitle          string
	ImportDesc           string
	ImportBtn            string
	DeleteTitle          string

	// Tray & Menus
	TrayShow             string
	TrayHide             string
	TrayQuit             string
	MenuAbout            string
	MenuPreferences      string
	MenuFile             string
	MenuEdit             string
	MenuView             string
	MenuWindow           string
}

// RunningCount formats the running service counter summary.
func (c *Catalog) RunningCount(running, total int) string {
	if c.Code == string(LangZhHans) {
		return fmt.Sprintf("本地服务 (%d/%d 运行中)", running, total)
	}
	return fmt.Sprintf("Services (%d/%d running)", running, total)
}

// RunningCountBadge formats the running badge in the toolbar.
func (c *Catalog) RunningCountBadge(running int) string {
	if c.Code == string(LangZhHans) {
		return fmt.Sprintf("%d 个运行中", running)
	}
	return fmt.Sprintf("%d Running", running)
}

// LocalServicesLabel formats the local services counter title in the toolbar.
func (c *Catalog) LocalServicesLabel(total int) string {
	if c.Code == string(LangZhHans) {
		return fmt.Sprintf("本地服务 (%d)", total)
	}
	return fmt.Sprintf("Services (%d)", total)
}

// For returns the Catalog corresponding to the specified language.
// If lang is LangSystem or empty, DetectSystemLang() is used.
func For(lang Lang) *Catalog {
	switch lang {
	case LangZhHans:
		return ZhHans
	case LangEn:
		return En
	case LangSystem, "":
		if DetectSystemLang() == LangZhHans {
			return ZhHans
		}
		return En
	default:
		return En
	}
}

// DetectSystemLang detects system locale from standard environment variables.
func DetectSystemLang() Lang {
	for _, env := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		val := os.Getenv(env)
		if val != "" {
			lower := strings.ToLower(val)
			if strings.HasPrefix(lower, "zh") {
				return LangZhHans
			}
		}
	}
	return LangEn
}
