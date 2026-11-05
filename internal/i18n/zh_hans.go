package i18n

// ZhHans is the Simplified Chinese catalog.
var ZhHans = &Catalog{
	Code: string(LangZhHans),

	// Navigation
	NavNodes:    "节点与概览",
	NavRouting:  "分流规则",
	NavInsights: "洞察与拦截",
	NavTailnet:  "组网",
	NavSettings: "全局设置",

	// Topbar & Master Switch
	MasterGateway:       "统一网关",
	ModePortOnly:        "仅端口 :10808",
	ModeSysProxy:        "系统代理",
	ModeTun:             "TUN 增强",
	TailnetNotConnected: "未连接",
	TailnetConnected:    "已连接",

	// Nodes Page
	NodesTitle:          "节点管理",
	AutoSelectPool:      "自动优选池",
	SearchPlaceholder:   "搜索节点名称或地址...",
	NewNode:             "新建节点",
	SpeedTestAll:        "全部测速",
	NoNodes:             "暂无配置节点",
	NoNodesDesc:         "点击上方「+新建」或直接从剪贴板导入节点配置",
	AddNode:             "添加节点",
	ImportFromClipboard: "从剪贴板导入",
	DirectNoProxy:       "直连 (无代理)",

	// Node Status & Badges
	StatusStarting:   "启动中",
	StatusRunning:    "运行中",
	StatusError:      "异常",
	StatusStopped:    "已停止",
	TagManagedNaive:  "NAIVE",
	TagExternalProxy: "EXTERNAL",
	TagAutoStart:     "自启动",

	// Node Actions
	ActionStart:        "启动",
	ActionStop:         "停止",
	ActionLatency:      "测速",
	ActionLogs:         "日志",
	ActionEdit:         "编辑",
	ActionMore:         "更多",
	ActionCopyV2rayN:   "复制 V2rayN 链接",
	ActionCopyNaive:    "复制 Naive 链接",
	ActionClone:        "克隆节点",
	ActionDelete:       "删除节点",
	DeleteConfirmTitle: "确认删除节点",
	DeleteConfirmMsg:   "确定要删除该节点吗？此操作无法撤销。",
	Confirm:            "确认",
	Cancel:             "取消",

	// Log Drawer
	LogDrawerTitle: "实时日志",
	LogAutoScroll:  "自动滚动",
	LogClear:       "清空日志",
	LogClose:       "关闭",

	// Settings Page
	SettingsTitle:    "全局偏好设置",
	LanguageLabel:    "显示语言",
	LanguageDesc:     "选择客户端界面的显示语言（免重启即时生效）",
	LanguageSystem:   "跟随系统",
	LanguageZhHans:   "简体中文 (Simplified Chinese)",
	LanguageEn:       "English (英语)",
	AutoStartLabel:   "开机自启动",
	AutoStartDesc:    "在系统登录时自动在后台启动客户端",
	CoreSectionTitle: "NaiveProxy 核心",
	CoreVersionLabel: "核心版本",
	CheckUpdates:     "检测更新",
	CheckingUpdates:  "正在检查更新...",
	UpToDate:         "已是最新版本",
	Updating:         "正在更新核心...",
	InstallCore:      "下载并安装核心",

	// Editor Modal
	EditNodeTitle:    "编辑节点",
	NewNodeTitle:     "新建节点",
	NodeKindLabel:    "节点类型",
	NodeKindManaged:  "NaiveProxy (内置托管)",
	NodeKindExternal: "外部代理 (SOCKS5 / HTTP)",
	NodeNameLabel:    "节点名称",
	ExternalURILabel: "外部代理地址",
	ExternalURIHint:  "socks5://[user:pass@]host:port 或 http://[user:pass@]host:port",
	ListenPortLabel:  "本地监听端口",
	ProxyURILabel:    "远端代理地址",
	ProxyURIHint:     "https://user:pass@example.com:443",
	TagsLabel:        "服务器标签",
	TagsHint:         "多个标签以英文逗号分隔，如: hk, fast, ai",
	Save:             "保存",

	// Tray & Menus
	TrayShow:        "显示主窗口",
	TrayHide:        "隐藏主窗口",
	TrayQuit:        "退出 Naive Client",
	MenuAbout:       "关于 Naive Client",
	MenuPreferences: "偏好设置...",
	MenuFile:        "文件",
	MenuEdit:        "编辑",
	MenuView:        "视图",
	MenuWindow:      "窗口",
}
