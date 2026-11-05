package i18n

// En is the English catalog.
var En = &Catalog{
	Code: string(LangEn),

	// Navigation
	NavNodes:    "Nodes",
	NavRouting:  "Routing",
	NavInsights: "Insights",
	NavTailnet:  "Tailnet",
	NavSettings: "Settings",

	// Topbar & Master Switch
	MasterGateway:       "Gateway",
	ModePortOnly:        "Port :10808",
	ModeSysProxy:        "System Proxy",
	ModeTun:             "TUN Mode",
	TailnetNotConnected: "Disconnected",
	TailnetConnected:    "Connected",

	// Nodes Page
	NodesTitle:          "Nodes",
	AutoSelectPool:      "Auto-Select Pool",
	SearchPlaceholder:   "Search name or address...",
	NewNode:             "New Node",
	SpeedTestAll:        "Test All",
	NoNodes:             "No Nodes Configured",
	NoNodesDesc:         "Click '+New Node' or paste a proxy configuration from clipboard",
	AddNode:             "Add Node",
	ImportFromClipboard: "Import from Clipboard",
	DirectNoProxy:       "Direct (No Proxy)",

	// Node Status & Badges
	StatusStarting:   "Starting",
	StatusRunning:    "Running",
	StatusError:      "Error",
	StatusStopped:    "Stopped",
	TagManagedNaive:  "NAIVE",
	TagExternalProxy: "EXTERNAL",
	TagAutoStart:     "AutoStart",

	// Node Actions
	ActionStart:        "Start",
	ActionStop:         "Stop",
	ActionLatency:      "Ping",
	ActionLogs:         "Logs",
	ActionEdit:         "Edit",
	ActionMore:         "More",
	ActionCopyV2rayN:   "Copy V2rayN Link",
	ActionCopyNaive:    "Copy Naive Link",
	ActionClone:        "Clone",
	ActionDelete:       "Delete",
	DeleteConfirmTitle: "Confirm Deletion",
	DeleteConfirmMsg:   "Are you sure you want to delete this node? This cannot be undone.",
	Confirm:            "Confirm",
	Cancel:             "Cancel",

	// Log Drawer
	LogDrawerTitle: "Live Logs",
	LogAutoScroll:  "Auto Scroll",
	LogClear:       "Clear",
	LogClose:       "Close",

	// Settings Page
	SettingsTitle:    "Preferences",
	LanguageLabel:    "Display Language",
	LanguageDesc:     "Choose the interface display language (takes effect immediately)",
	LanguageSystem:   "System Default",
	LanguageZhHans:   "简体中文 (Simplified Chinese)",
	LanguageEn:       "English",
	AutoStartLabel:   "Launch at Login",
	AutoStartDesc:    "Automatically launch in the background when logging into the OS",
	CoreSectionTitle: "NaiveProxy Core",
	CoreVersionLabel: "Core Version",
	CheckUpdates:     "Check for Updates",
	CheckingUpdates:  "Checking for updates...",
	UpToDate:         "Up to date",
	Updating:         "Updating core...",
	InstallCore:      "Download & Install Core",

	// Editor Modal
	EditNodeTitle:    "Edit Node",
	NewNodeTitle:     "New Node",
	NodeKindLabel:    "Node Type",
	NodeKindManaged:  "NaiveProxy (Managed)",
	NodeKindExternal: "External Proxy (SOCKS5 / HTTP)",
	NodeNameLabel:    "Node Name",
	ExternalURILabel: "External Proxy URI",
	ExternalURIHint:  "socks5://[user:pass@]host:port or http://[user:pass@]host:port",
	ListenPortLabel:  "Local Listen Port",
	ProxyURILabel:    "Remote Proxy URI",
	ProxyURIHint:     "https://user:pass@example.com:443",
	TagsLabel:        "Server Tags",
	TagsHint:         "Comma separated tags, e.g. hk, fast, ai",
	Save:             "Save",

	// Tray & Menus
	TrayShow:        "Show Window",
	TrayHide:        "Hide Window",
	TrayQuit:        "Quit Naive Client",
	MenuAbout:       "About Naive Client",
	MenuPreferences: "Preferences...",
	MenuFile:        "File",
	MenuEdit:        "Edit",
	MenuView:        "View",
	MenuWindow:      "Window",
}
