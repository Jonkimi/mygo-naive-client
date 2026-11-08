package app

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/egoist/mygo/ui"

	"naive-client/internal/boxengine"
	"naive-client/internal/config"
	"naive-client/internal/runner"
)

var editorProtocols = []config.Protocol{
	config.ProtoNaive,
	config.ProtoVLESS,
	config.ProtoVMess,
	config.ProtoTrojan,
	config.ProtoShadowsocks,
	config.ProtoHysteria2,
	config.ProtoTUIC,
	config.ProtoSOCKS5,
	config.ProtoHTTP,
}

var editorProtocolNames = []string{
	"NaiveProxy",
	"VLESS",
	"VMess",
	"Trojan",
	"Shadowsocks",
	"Hysteria2",
	"TUIC",
	"SOCKS5 (External)",
	"HTTP (External)",
}

type editorForm struct {
	open      bool
	isNew     bool
	tab       int
	scroll    ui.ScrollState
	errText   string
	svcID     string
	name      string
	autoStart bool
	tagsInput string

	// Protocol & Execution Engine
	protoIndex  int
	engineIndex int // 0: Sing-Box, 1: Sidecar (for Naive, 1 is default; for VLESS/VMess/Trojan/Shadowsocks, 0 is default)

	// Sidecar Loopback
	autoLoopback bool
	listenInput  string

	// NaiveProxy
	proxyInput     string
	concurrencyStr string
	noPostQuantum  bool

	// Multi-protocol (VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC)
	server        string
	serverPort    string
	uuid          string
	password      string
	securityIndex int // 0: tls, 1: reality, 2: none
	sni           string
	alpnInput     string
	fingerprint   string
	publicKey     string
	shortID       string
	spiderX       string
	flowIndex     int // 0: xtls-rprx-vision, 1: none
	networkIndex  int // 0: tcp, 1: ws, 2: grpc, 3: xhttp
	path          string
	host          string
	serviceName   string
	method        string
	congestionCtl string
	zeroRTT       bool

	// External SOCKS5 / HTTP
	externalURI string

	// Advanced Naive fields
	tunnelTimeout string
	idleTimeout   string
	extraHeaders  string
	hostRules     string
	resolverRange string
	enableLog     bool
	logFile       string
	logNetLog     string
	sslKeyLogFile string
	extraJSON     string
}

func (a *app) openCreateServiceDialog() {
	port := a.nextAvailableListenPort()
	svc := config.DefaultService(a.generateServiceID(), port)
	svc.Name = a.catalog().DefaultNodeName(len(a.state.Services) + 1)
	a.populateEditorForm(svc, true)
}

func (a *app) openEditServiceDialog(svc config.Service) {
	a.populateEditorForm(svc, false)
}

func (a *app) populateEditorForm(svc config.Service, isNew bool) {
	proto := svc.EffectiveProtocol()
	protoIdx := 0
	for i, p := range editorProtocols {
		if p == proto {
			protoIdx = i
			break
		}
	}

	engineIdx := 0
	if svc.EffectiveEngine() == config.EngineSidecar {
		engineIdx = 1
	} else if isNew && proto == config.ProtoNaive {
		engineIdx = 1
	}

	autoLoop := true
	if len(svc.Listens) > 0 {
		ep, err := config.ParseListenURI(svc.PrimaryListen())
		if err == nil && ep.Port > 0 {
			autoLoop = false
		}
	}

	secIdx := 0
	switch strings.ToLower(svc.Security) {
	case "reality":
		secIdx = 1
	case "none":
		secIdx = 2
	default:
		secIdx = 0
	}

	flowIdx := 1
	if svc.Flow == "xtls-rprx-vision" {
		flowIdx = 0
	}

	netIdx := 0
	switch strings.ToLower(svc.Network) {
	case "ws":
		netIdx = 1
	case "grpc":
		netIdx = 2
	case "xhttp":
		netIdx = 3
	default:
		netIdx = 0
	}

	serverPortStr := ""
	if svc.ServerPort > 0 {
		serverPortStr = strconv.Itoa(svc.ServerPort)
	} else if proto != config.ProtoNaive && proto != config.ProtoSOCKS5 && proto != config.ProtoHTTP {
		serverPortStr = "443"
	}

	conc := ""
	if svc.InsecureConcurrency > 0 {
		conc = strconv.Itoa(svc.InsecureConcurrency)
	}
	tunnel := ""
	if svc.TunnelTimeout > 0 {
		tunnel = strconv.Itoa(svc.TunnelTimeout)
	}
	idle := ""
	if svc.IdleTimeout > 0 {
		idle = strconv.Itoa(svc.IdleTimeout)
	}

	listens := strings.Join(svc.Listens, ", ")
	if listens == "" {
		listens = "socks://127.0.0.1:1080"
	}
	proxies := strings.Join(svc.Proxies, "\n")

	method := svc.Method
	if method == "" && proto == config.ProtoShadowsocks {
		method = "2022-blake3-aes-128-gcm"
	}
	congestion := svc.CongestionController
	if congestion == "" && (proto == config.ProtoHysteria2 || proto == config.ProtoTUIC) {
		congestion = "bbr"
	}
	fingerprint := svc.Fingerprint
	if fingerprint == "" && (proto == config.ProtoVLESS || proto == config.ProtoVMess) {
		fingerprint = "chrome"
	}

	a.editor = editorForm{
		open:           true,
		isNew:          isNew,
		tab:            0,
		svcID:          svc.ID,
		name:           svc.Name,
		autoStart:      svc.AutoStart,
		tagsInput:      strings.Join(svc.Tags, ", "),
		protoIndex:     protoIdx,
		engineIndex:    engineIdx,
		autoLoopback:   autoLoop,
		listenInput:    listens,
		proxyInput:     proxies,
		server:         svc.Server,
		serverPort:     serverPortStr,
		uuid:           svc.UUID,
		password:       svc.Password,
		securityIndex:  secIdx,
		sni:            svc.SNI,
		alpnInput:      strings.Join(svc.ALPN, ", "),
		fingerprint:    fingerprint,
		publicKey:      svc.PublicKey,
		shortID:        svc.ShortID,
		spiderX:        svc.SpiderX,
		flowIndex:      flowIdx,
		networkIndex:   netIdx,
		path:           svc.Path,
		host:           svc.Host,
		serviceName:    svc.ServiceName,
		method:         method,
		congestionCtl:  congestion,
		zeroRTT:        svc.ZeroRTTHandshake,
		externalURI:    svc.ExternalURI,
		concurrencyStr: conc,
		tunnelTimeout:  tunnel,
		idleTimeout:    idle,
		extraHeaders:   strings.ReplaceAll(svc.ExtraHeaders, "\r\n", "\n"),
		hostRules:      svc.HostResolverRules,
		resolverRange:  svc.ResolverRange,
		enableLog:      svc.EnableLog,
		logFile:        svc.LogFile,
		logNetLog:      svc.LogNetLog,
		sslKeyLogFile:  svc.SSLKeyLogFile,
		noPostQuantum:  svc.NoPostQuantum,
		extraJSON:      svc.ExtraJSON,
	}
}

func (a *app) buildServiceFromEditor() (config.Service, error) {
	proto := editorProtocols[a.editor.protoIndex]
	var tags []string
	for _, part := range strings.Split(a.editor.tagsInput, ",") {
		if t := strings.TrimSpace(part); t != "" {
			tags = append(tags, strings.TrimPrefix(t, "#"))
		}
	}

	engine := config.EngineSingBox
	if a.editor.engineIndex == 1 {
		engine = config.EngineSidecar
	}

	var listens []string
	if engine == config.EngineSidecar {
		if a.editor.autoLoopback {
			listens = []string{"socks://127.0.0.1:0"}
		} else {
			listens = splitMultiValues(a.editor.listenInput)
		}
	} else if strings.TrimSpace(a.editor.listenInput) != "" && !a.editor.autoLoopback {
		listens = splitMultiValues(a.editor.listenInput)
	}

	if proto == config.ProtoSOCKS5 || proto == config.ProtoHTTP {
		svc := config.Service{
			ID:          a.editor.svcID,
			Name:        strings.TrimSpace(a.editor.name),
			AutoStart:   a.editor.autoStart,
			Kind:        config.KindExternalProxy,
			Protocol:    proto,
			Engine:      config.EngineSingBox,
			Tags:        tags,
			ExternalURI: strings.TrimSpace(a.editor.externalURI),
		}
		if err := svc.Validate(); err != nil {
			return svc, err
		}
		return svc, nil
	}

	if proto == config.ProtoNaive {
		svc := config.Service{
			ID:                a.editor.svcID,
			Name:              strings.TrimSpace(a.editor.name),
			AutoStart:         a.editor.autoStart,
			Kind:              config.KindManagedNaive,
			Protocol:          config.ProtoNaive,
			Engine:            engine,
			Tags:              tags,
			Listens:           listens,
			Proxies:           splitLinesNonEmpty(a.editor.proxyInput),
			ExtraHeaders:      strings.TrimSpace(a.editor.extraHeaders),
			HostResolverRules: strings.TrimSpace(a.editor.hostRules),
			ResolverRange:     strings.TrimSpace(a.editor.resolverRange),
			EnableLog:         a.editor.enableLog,
			LogFile:           strings.TrimSpace(a.editor.logFile),
			LogNetLog:         strings.TrimSpace(a.editor.logNetLog),
			SSLKeyLogFile:     strings.TrimSpace(a.editor.sslKeyLogFile),
			NoPostQuantum:     a.editor.noPostQuantum,
			ExtraJSON:         strings.TrimSpace(a.editor.extraJSON),
		}
		if s := strings.TrimSpace(a.editor.concurrencyStr); s != "" {
			if v, err := strconv.Atoi(s); err == nil {
				svc.InsecureConcurrency = v
			}
		}
		if s := strings.TrimSpace(a.editor.tunnelTimeout); s != "" {
			if v, err := strconv.Atoi(s); err == nil {
				svc.TunnelTimeout = v
			}
		}
		if s := strings.TrimSpace(a.editor.idleTimeout); s != "" {
			if v, err := strconv.Atoi(s); err == nil {
				svc.IdleTimeout = v
			}
		}
		if err := svc.Validate(); err != nil {
			return svc, err
		}
		return svc, nil
	}

	// Multi-protocol (VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC)
	port := 443
	if pStr := strings.TrimSpace(a.editor.serverPort); pStr != "" {
		if p, err := strconv.Atoi(pStr); err == nil && p > 0 && p <= 65535 {
			port = p
		}
	}

	sec := "tls"
	switch a.editor.securityIndex {
	case 1:
		sec = "reality"
	case 2:
		sec = "none"
	}

	flow := ""
	if a.editor.flowIndex == 0 && proto == config.ProtoVLESS {
		flow = "xtls-rprx-vision"
	}

	net := "tcp"
	switch a.editor.networkIndex {
	case 1:
		net = "ws"
	case 2:
		net = "grpc"
	case 3:
		net = "xhttp"
	}

	var alpn []string
	for _, part := range strings.Split(a.editor.alpnInput, ",") {
		if t := strings.TrimSpace(part); t != "" {
			alpn = append(alpn, t)
		}
	}

	svc := config.Service{
		ID:                   a.editor.svcID,
		Name:                 strings.TrimSpace(a.editor.name),
		AutoStart:            a.editor.autoStart,
		Kind:                 config.KindManagedNaive,
		Protocol:             proto,
		Engine:               engine,
		Tags:                 tags,
		Listens:              listens,
		Server:               strings.TrimSpace(a.editor.server),
		ServerPort:           port,
		UUID:                 strings.TrimSpace(a.editor.uuid),
		Password:             strings.TrimSpace(a.editor.password),
		Security:             sec,
		SNI:                  strings.TrimSpace(a.editor.sni),
		ALPN:                 alpn,
		Fingerprint:          strings.TrimSpace(a.editor.fingerprint),
		PublicKey:            strings.TrimSpace(a.editor.publicKey),
		ShortID:              strings.TrimSpace(a.editor.shortID),
		SpiderX:              strings.TrimSpace(a.editor.spiderX),
		Flow:                 flow,
		Network:              net,
		Path:                 strings.TrimSpace(a.editor.path),
		Host:                 strings.TrimSpace(a.editor.host),
		ServiceName:          strings.TrimSpace(a.editor.serviceName),
		Method:               strings.TrimSpace(a.editor.method),
		CongestionController: strings.TrimSpace(a.editor.congestionCtl),
		ZeroRTTHandshake:     a.editor.zeroRTT,
		ExtraJSON:            strings.TrimSpace(a.editor.extraJSON),
	}
	if s := strings.TrimSpace(a.editor.concurrencyStr); s != "" {
		if v, err := strconv.Atoi(s); err == nil {
			svc.InsecureConcurrency = v
		}
	}
	svc.NoPostQuantum = a.editor.noPostQuantum

	if err := svc.Validate(); err != nil {
		return svc, err
	}
	return svc, nil
}

func splitMultiValues(raw string) []string {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		for _, part := range strings.Split(line, ",") {
			if p := strings.TrimSpace(part); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

func splitLinesNonEmpty(raw string) []string {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		if p := strings.TrimSpace(line); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (a *app) renderEditorDialog(c *ui.Context, p palette) {
	ui.DialogBase(c.Key("service-editor-dialog"), &a.editor.open, func(backdrop, panel ui.Element) {
		backdrop.Background(ui.RGBA(0, 0, 0, 0.5))
		panel.Column().
			Width(580).Height(560).
			Padding(20).Gap(14).
			Radius(14).Background(p.card).Border(1, p.border).
			Shadow(0, 12, 36, 0, ui.RGBA(0, 0, 0, 0.3)).
			Children(func() {
				// Header
				cat := a.catalog()
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Children(func() {
					title := cat.EditNodeTitle()
					if a.editor.isNew {
						title = cat.NewNodeTitle()
					}
					ui.Text(c, title).FontSize(16).FontWeight(700).TextColor(p.text)
					segmentedControl(c.Key("editor-tabs"), p, &a.editor.tab, []string{
						cat.EditorTabBasic(),
						cat.EditorTabAdvanced(),
						cat.EditorTabPreview(),
					})
				})

				if a.editor.errText != "" {
					ui.Row(c.Key("editor-error-row")).
						AlignItems(ui.Center).Justify(ui.SpaceBetween).
						PaddingX(12).PaddingY(8).Radius(8).Background(p.redBg).Children(func() {
							ui.Text(c, a.editor.errText).FontSize(12).FontWeight(500).TextColor(p.red).Grow(1)
							btnCopy := ui.ButtonBase(c.Key("btn-copy-editor-error")).
								Label("btn-copy-editor-error").
								Padding(2, 6, 2, 6).Radius(4).
								Background(p.card).Border(1, p.borderSubtle).
								Tooltip(cat.ActionCopyError()).
								Children(func() {
									ui.Text(c, cat.BtnCopy()).FontSize(10).TextColor(p.textDim)
								})
							if btnCopy.Clicked() {
								a.writeClipboard(a.editor.errText, cat.ToastErrorCopied())
							}
						})
				}

				ui.Scroll(c.Key("editor-scroll")).
					TrackScroll(&a.editor.scroll).
					Grow(1).
					Padding(0, 4, 0, 0).
					Gap(12).
					Children(func() {
						switch a.editor.tab {
						case 0:
							a.renderEditorBasicTab(c, p)
						case 1:
							a.renderEditorAdvancedTab(c, p)
						case 2:
							a.renderEditorPreviewTab(c, p)
						}
					})

				// Footer
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).
					Padding(10, 0, 0, 0).BorderWidth(1, 0, 0, 0).BorderColor(p.borderSubtle).
					Children(func() {
						ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
							ui.Switch(c.Key("editor-autostart"), &a.editor.autoStart).
								Label(cat.EditorAutoStartDesc())
							ui.Text(c, cat.EditorAutoStartDesc()).FontSize(12).TextColor(p.text)
						})

						ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
							if ui.Button(c.Key("editor-cancel"), cat.Cancel()).Clicked() {
								a.editor.open = false
								a.editor.errText = ""
							}
							saveLabel := cat.EditorSaveEdit()
							if a.editor.isNew {
								saveLabel = cat.EditorSaveCreate()
							}
							if ui.PrimaryButton(c.Key("editor-save"), saveLabel).Clicked() {
								a.saveEditorService()
							}
						})
					})
			})
	})
}

func (a *app) renderEditorBasicTab(c *ui.Context, p palette) {
	cat := a.catalog()
	ui.Column(c).Gap(12).Children(func() {
		// Common info: Name & Tags
		labeledInput(c, p, "inp-name", cat.NodeNameLabel(), &a.editor.name, "HK-01")
		labeledInput(c, p, "inp-tags", cat.TagsLabel(), &a.editor.tagsInput, cat.TagsHint())

		// Protocol selection
		ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Children(func() {
			ui.Text(c, cat.ProtocolLabel()).FontSize(13).FontWeight(500).TextColor(p.text)
			curProto := editorProtocolNames[a.editor.protoIndex]
			if ui.Select(c.Key("inp-proto-select"), &curProto, editorProtocolNames).Label(cat.ProtocolLabel()).Width(240).Changed() {
				for i, name := range editorProtocolNames {
					if name == curProto {
						a.editor.protoIndex = i
						// Default engine based on protocol
						if editorProtocols[i] == config.ProtoNaive {
							a.editor.engineIndex = 1
						} else {
							a.editor.engineIndex = 0
						}
						break
					}
				}
			}
		})

		proto := editorProtocols[a.editor.protoIndex]

		// Execution engine selection
		switch proto {
		case config.ProtoNaive:
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Children(func() {
				ui.Column(c).Gap(2).Children(func() {
					ui.Text(c, cat.EngineLabel()).FontSize(13).FontWeight(500).TextColor(p.text)
					ui.Text(c, cat.CoreNaiveDesc()).FontSize(11).TextColor(p.textMuted)
				})
				// 0: SingBox, 1: Sidecar
				engineIdx := 0
				if a.editor.engineIndex == 1 {
					engineIdx = 1
				}
				if segmentedControl(c.Key("editor-naive-engine"), p, &engineIdx, []string{
					cat.EngineSingBox(),
					cat.EngineSidecarNaive(),
				}) {
					if engineIdx == 1 {
						a.editor.engineIndex = 1
					} else {
						a.editor.engineIndex = 0
					}
				}
			})
		case config.ProtoVLESS, config.ProtoVMess, config.ProtoTrojan, config.ProtoShadowsocks:
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Children(func() {
				ui.Column(c).Gap(2).Children(func() {
					ui.Text(c, cat.EngineLabel()).FontSize(13).FontWeight(500).TextColor(p.text)
					ui.Text(c, cat.CoreXrayDesc()).FontSize(11).TextColor(p.textMuted)
				})
				engineIdx := 0
				if a.editor.engineIndex == 1 {
					engineIdx = 1
				}
				if segmentedControl(c.Key("editor-xray-engine"), p, &engineIdx, []string{
					cat.EngineSingBox(),
					cat.EngineSidecarXray(),
				}) {
					if engineIdx == 1 {
						a.editor.engineIndex = 1
					} else {
						a.editor.engineIndex = 0
					}
				}
			})
		case config.ProtoHysteria2, config.ProtoTUIC:
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Children(func() {
				ui.Text(c, cat.EngineLabel()).FontSize(13).FontWeight(500).TextColor(p.text)
				tagPill(c, cat.EngineSingBoxOnly(), p.accentText, p.accentBg)
			})
		case config.ProtoSOCKS5, config.ProtoHTTP:
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Children(func() {
				ui.Text(c, cat.EngineLabel()).FontSize(13).FontWeight(500).TextColor(p.text)
				tagPill(c, cat.NodeKindExternal(), p.textMuted, p.elevated)
			})
		}

		// Loopback settings for Sidecar mode
		if a.editor.engineIndex == 1 && (proto == config.ProtoNaive || proto == config.ProtoVLESS || proto == config.ProtoVMess || proto == config.ProtoTrojan || proto == config.ProtoShadowsocks) {
			ui.Column(c).Gap(6).Padding(10).Radius(8).Background(p.surface).Border(1, p.borderSubtle).Children(func() {
				switchRow(c, p, "inp-auto-loopback", cat.AutoLoopbackPortLabel(), &a.editor.autoLoopback)
				ui.Text(c, cat.AutoLoopbackPortDesc()).FontSize(11).TextColor(p.textDim)
				if !a.editor.autoLoopback {
					labeledInput(c, p, "inp-listen", cat.ListenPortLabel(), &a.editor.listenInput, "socks://127.0.0.1:1080")
				}
			})
		}

		// Protocol-specific fields
		switch proto {
		case config.ProtoNaive:
			ui.Column(c).Gap(4).Children(func() {
				labeledInput(c, p, "inp-proxy", cat.ProxyURILabel(), &a.editor.proxyInput, cat.ProxyURIHint())
				ui.Text(c, cat.EditorProxyHintFull()).FontSize(11).TextColor(p.textMuted)
			})
			labeledInput(c, p, "inp-concurrency-basic", cat.EditorConcurrencyLabel(), &a.editor.concurrencyStr, "1")
			switchRow(c, p, "inp-nopq-basic", cat.EditorNoPQLabel(), &a.editor.noPostQuantum)

		case config.ProtoVLESS:
			ui.Row(c).AlignItems(ui.Center).Gap(12).Children(func() {
				ui.Box(c).Grow(1).Children(func() {
					labeledInput(c, p, "inp-vless-server", cat.ServerLabel(), &a.editor.server, "example.com")
				})
				ui.Box(c).Width(100).Children(func() {
					labeledInput(c, p, "inp-vless-port", cat.ServerPortLabel(), &a.editor.serverPort, "443")
				})
			})
			labeledInput(c, p, "inp-vless-uuid", cat.UuidLabel(), &a.editor.uuid, "a1b2c3d4-e5f6-7890-abcd-ef1234567890")

			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Children(func() {
				ui.Text(c, cat.SecurityLabel()).FontSize(13).FontWeight(500).TextColor(p.text)
				segmentedControl(c.Key("inp-vless-sec"), p, &a.editor.securityIndex, []string{"TLS", "REALITY", "None"})
			})

			if a.editor.securityIndex == 1 { // REALITY
				labeledInput(c, p, "inp-vless-pbk", cat.PublicKeyLabel(), &a.editor.publicKey, "publicKey...")
				ui.Row(c).AlignItems(ui.Center).Gap(12).Children(func() {
					ui.Box(c).Grow(1).Children(func() {
						labeledInput(c, p, "inp-vless-sid", cat.ShortIDLabel(), &a.editor.shortID, "shortId")
					})
					ui.Box(c).Grow(1).Children(func() {
						labeledInput(c, p, "inp-vless-spx", cat.SpiderXLabel(), &a.editor.spiderX, "/")
					})
				})
			}

			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Children(func() {
				ui.Text(c, cat.FlowLabel()).FontSize(13).FontWeight(500).TextColor(p.text)
				segmentedControl(c.Key("inp-vless-flow"), p, &a.editor.flowIndex, []string{"xtls-rprx-vision", "None"})
			})

			ui.Row(c).AlignItems(ui.Center).Gap(12).Children(func() {
				ui.Box(c).Grow(1).Children(func() {
					labeledInput(c, p, "inp-vless-sni", cat.SniLabel(), &a.editor.sni, "domain.com")
				})
				ui.Box(c).Grow(1).Children(func() {
					labeledInput(c, p, "inp-vless-fp", cat.FingerprintLabel(), &a.editor.fingerprint, "chrome")
				})
			})

			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Children(func() {
				ui.Text(c, cat.NetworkLabel()).FontSize(13).FontWeight(500).TextColor(p.text)
				segmentedControl(c.Key("inp-vless-net"), p, &a.editor.networkIndex, []string{"tcp", "ws", "grpc", "xhttp"})
			})

			if a.editor.networkIndex == 1 || a.editor.networkIndex == 3 { // ws, xhttp
				ui.Row(c).AlignItems(ui.Center).Gap(12).Children(func() {
					ui.Box(c).Grow(1).Children(func() {
						labeledInput(c, p, "inp-vless-path", cat.PathLabel(), &a.editor.path, "/")
					})
					ui.Box(c).Grow(1).Children(func() {
						labeledInput(c, p, "inp-vless-host", cat.HostHeaderLabel(), &a.editor.host, "")
					})
				})
			} else if a.editor.networkIndex == 2 { // grpc
				labeledInput(c, p, "inp-vless-service", cat.ServiceNameLabel(), &a.editor.serviceName, "GunService")
			}

		case config.ProtoVMess:
			ui.Row(c).AlignItems(ui.Center).Gap(12).Children(func() {
				ui.Box(c).Grow(1).Children(func() {
					labeledInput(c, p, "inp-vmess-server", cat.ServerLabel(), &a.editor.server, "example.com")
				})
				ui.Box(c).Width(100).Children(func() {
					labeledInput(c, p, "inp-vmess-port", cat.ServerPortLabel(), &a.editor.serverPort, "443")
				})
			})
			labeledInput(c, p, "inp-vmess-uuid", cat.UuidLabel(), &a.editor.uuid, "a1b2c3d4-e5f6-7890-abcd-ef1234567890")
			ui.Row(c).AlignItems(ui.Center).Gap(12).Children(func() {
				ui.Box(c).Grow(1).Children(func() {
					labeledInput(c, p, "inp-vmess-sni", cat.SniLabel(), &a.editor.sni, "domain.com")
				})
				ui.Box(c).Grow(1).Children(func() {
					labeledInput(c, p, "inp-vmess-fp", cat.FingerprintLabel(), &a.editor.fingerprint, "chrome")
				})
			})
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Children(func() {
				ui.Text(c, cat.NetworkLabel()).FontSize(13).FontWeight(500).TextColor(p.text)
				segmentedControl(c.Key("inp-vmess-net"), p, &a.editor.networkIndex, []string{"tcp", "ws", "grpc"})
			})
			if a.editor.networkIndex == 1 { // ws
				labeledInput(c, p, "inp-vmess-path", cat.PathLabel(), &a.editor.path, "/")
			} else if a.editor.networkIndex == 2 { // grpc
				labeledInput(c, p, "inp-vmess-service", cat.ServiceNameLabel(), &a.editor.serviceName, "")
			}

		case config.ProtoTrojan:
			ui.Row(c).AlignItems(ui.Center).Gap(12).Children(func() {
				ui.Box(c).Grow(1).Children(func() {
					labeledInput(c, p, "inp-trojan-server", cat.ServerLabel(), &a.editor.server, "example.com")
				})
				ui.Box(c).Width(100).Children(func() {
					labeledInput(c, p, "inp-trojan-port", cat.ServerPortLabel(), &a.editor.serverPort, "443")
				})
			})
			labeledInput(c, p, "inp-trojan-password", cat.PasswordLabel(), &a.editor.password, "password")
			labeledInput(c, p, "inp-trojan-sni", cat.SniLabel(), &a.editor.sni, "domain.com")
			labeledInput(c, p, "inp-trojan-alpn", cat.AlpnLabel(), &a.editor.alpnInput, "h2, http/1.1")

		case config.ProtoShadowsocks:
			ui.Row(c).AlignItems(ui.Center).Gap(12).Children(func() {
				ui.Box(c).Grow(1).Children(func() {
					labeledInput(c, p, "inp-ss-server", cat.ServerLabel(), &a.editor.server, "example.com")
				})
				ui.Box(c).Width(100).Children(func() {
					labeledInput(c, p, "inp-ss-port", cat.ServerPortLabel(), &a.editor.serverPort, "8388")
				})
			})
			labeledInput(c, p, "inp-ss-password", cat.PasswordLabel(), &a.editor.password, "password")
			labeledInput(c, p, "inp-ss-method", cat.SsMethodLabel(), &a.editor.method, "2022-blake3-aes-128-gcm")

		case config.ProtoHysteria2:
			ui.Row(c).AlignItems(ui.Center).Gap(12).Children(func() {
				ui.Box(c).Grow(1).Children(func() {
					labeledInput(c, p, "inp-hy2-server", cat.ServerLabel(), &a.editor.server, "example.com")
				})
				ui.Box(c).Width(100).Children(func() {
					labeledInput(c, p, "inp-hy2-port", cat.ServerPortLabel(), &a.editor.serverPort, "443")
				})
			})
			labeledInput(c, p, "inp-hy2-password", cat.PasswordLabel(), &a.editor.password, "password")
			labeledInput(c, p, "inp-hy2-sni", cat.SniLabel(), &a.editor.sni, "domain.com")
			labeledInput(c, p, "inp-hy2-cc", cat.CongestionCtlLabel(), &a.editor.congestionCtl, "bbr")

		case config.ProtoTUIC:
			ui.Row(c).AlignItems(ui.Center).Gap(12).Children(func() {
				ui.Box(c).Grow(1).Children(func() {
					labeledInput(c, p, "inp-tuic-server", cat.ServerLabel(), &a.editor.server, "example.com")
				})
				ui.Box(c).Width(100).Children(func() {
					labeledInput(c, p, "inp-tuic-port", cat.ServerPortLabel(), &a.editor.serverPort, "443")
				})
			})
			labeledInput(c, p, "inp-tuic-uuid", cat.UuidLabel(), &a.editor.uuid, "uuid")
			labeledInput(c, p, "inp-tuic-password", cat.PasswordLabel(), &a.editor.password, "password")
			labeledInput(c, p, "inp-tuic-sni", cat.SniLabel(), &a.editor.sni, "domain.com")
			switchRow(c, p, "inp-tuic-zerortt", cat.ZeroRTTLabel(), &a.editor.zeroRTT)

		case config.ProtoSOCKS5, config.ProtoHTTP:
			labeledInput(c, p, "inp-external-uri", cat.ExternalURILabel(), &a.editor.externalURI, cat.ExternalURIHint())
		}
	})
}

func (a *app) renderEditorAdvancedTab(c *ui.Context, p palette) {
	cat := a.catalog()
	proto := editorProtocols[a.editor.protoIndex]

	ui.Column(c).Gap(12).Children(func() {
		if proto == config.ProtoNaive {
			ui.Row(c).AlignItems(ui.Center).Gap(12).Children(func() {
				ui.Box(c).Grow(1).Children(func() {
					labeledInput(c, p, "inp-tunnel-timeout", cat.EditorTunnelTimeoutLabel(), &a.editor.tunnelTimeout, "")
				})
				ui.Box(c).Grow(1).Children(func() {
					labeledInput(c, p, "inp-idle-timeout", cat.EditorIdleTimeoutLabel(), &a.editor.idleTimeout, "")
				})
			})

			labeledInput(c, p, "inp-extra-headers", cat.EditorExtraHeadersLabel(), &a.editor.extraHeaders, "Header1: Value1")

			ui.Row(c).AlignItems(ui.Center).Gap(12).Children(func() {
				ui.Box(c).Grow(1).Children(func() {
					labeledInput(c, p, "inp-host-rules", cat.EditorHostRulesLabel(), &a.editor.hostRules, "MAP example.com 1.2.3.4")
				})
				ui.Box(c).Grow(1).Children(func() {
					labeledInput(c, p, "inp-resolver-range", cat.EditorResolverRangeLabel(), &a.editor.resolverRange, "100.64.0.0/10")
				})
			})

			switchRow(c, p, "inp-enable-log", cat.EditorEnableLogLabel(), &a.editor.enableLog)
			labeledInput(c, p, "inp-log-file", cat.EditorLogFileLabel(), &a.editor.logFile, cat.EditorLogFileHint())

			ui.Row(c).AlignItems(ui.Center).Gap(12).Children(func() {
				ui.Box(c).Grow(1).Children(func() {
					labeledInput(c, p, "inp-net-log", cat.EditorNetLogLabel(), &a.editor.logNetLog, "")
				})
				ui.Box(c).Grow(1).Children(func() {
					labeledInput(c, p, "inp-ssl-key-log", cat.EditorSSLKeyLogLabel(), &a.editor.sslKeyLogFile, "")
				})
			})

			labeledInput(c, p, "inp-extra-json", cat.EditorExtraJSONLabel(), &a.editor.extraJSON, `{"padding": true}`)
		} else {
			// Multi-protocol advanced options
			labeledInput(c, p, "inp-concurrency-adv", cat.EditorConcurrencyLabel(), &a.editor.concurrencyStr, "1")
			switchRow(c, p, "inp-nopq-adv", cat.EditorNoPQLabel(), &a.editor.noPostQuantum)

			if a.editor.engineIndex == 1 { // Sidecar
				switchRow(c, p, "inp-enable-log", cat.EditorEnableLogLabel(), &a.editor.enableLog)
				labeledInput(c, p, "inp-log-file", cat.EditorLogFileLabel(), &a.editor.logFile, cat.EditorLogFileHint())
			}

			ui.Column(c).Gap(4).Children(func() {
				labeledInput(c, p, "inp-extra-json", cat.EditorExtraJSONLabel(), &a.editor.extraJSON, `{"mux": {"enabled": true}}`)
				ui.Text(c, cat.EditorAdvancedCoreCustomDesc()).FontSize(11).TextColor(p.textMuted)
			})
		}
	})
}

func (a *app) renderEditorPreviewTab(c *ui.Context, p palette) {
	cat := a.catalog()
	svc, err := a.buildServiceFromEditor()
	if err != nil {
		ui.Row(c).PaddingX(12).PaddingY(10).Radius(8).Background(p.redBg).Children(func() {
			ui.Text(c, cat.ConfigValidationFailed(err.Error())).FontSize(12).TextColor(p.red)
		})
		return
	}

	ui.Column(c).Gap(10).Children(func() {
		// 1. Local link preview - only for Sidecar nodes (内置节点没有本地链接)
		if svc.EffectiveEngine() == config.EngineSidecar {
			v2rayURI := svc.V2rayNSocksURI()
			ui.Column(c).Gap(4).Padding(10).Radius(8).Background(p.codeBg).Border(1, p.borderSubtle).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
					ui.Text(c, cat.PreviewLocalLink()).FontSize(11).FontWeight(600).TextColor(p.textMuted)
					if actionChip(c.Key("preview-copy-local"), p, iconCopy, cat.BtnCopy(), false).Clicked() {
						a.writeClipboard(v2rayURI, cat.CopiedLocalLink())
					}
				})
				ui.Text(c, v2rayURI).FontSize(12).FontWeight(500).TextColor(p.accent)
			})
		}

		// 2. Share / Config link preview for all protocols
		shareURI := svc.ShareURI()
		if shareURI != "" {
			ui.Column(c).Gap(4).Padding(10).Radius(8).Background(p.codeBg).Border(1, p.borderSubtle).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
					ui.Text(c, cat.PreviewNaiveShareLink()).FontSize(11).FontWeight(600).TextColor(p.textMuted)
					if actionChip(c.Key("preview-copy-share"), p, iconCopy, cat.BtnCopy(), false).Clicked() {
						a.writeClipboard(shareURI, cat.CopiedNaiveShareLink())
					}
				})
				ui.Text(c, shareURI).FontSize(12).TextColor(p.text)
			})
		}

		// 3. Core Engine JSON Configuration
		if svc.EffectiveEngine() == config.EngineSidecar && svc.EffectiveProtocol() == config.ProtoNaive {
			rawJSON, _ := svc.ToConfigJSON()
			ui.Column(c).Gap(6).Padding(10).Radius(8).Background(p.codeBg).Border(1, p.borderSubtle).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
					ui.Text(c, cat.PreviewNaiveJSON()).FontSize(11).FontWeight(600).TextColor(p.textMuted)
					if actionChip(c.Key("preview-copy-json"), p, iconCopy, cat.BtnCopyJSON(), false).Clicked() {
						a.writeClipboard(string(rawJSON), cat.CopiedConfigJSON())
					}
				})
				ui.Text(c, string(rawJSON)).FontSize(11).TextColor(p.text)
			})
		} else if svc.EffectiveEngine() == config.EngineSidecar {
			cfgBytes, _ := runner.GenerateXrayConfig(svc, 1080)
			ui.Column(c).Gap(6).Padding(10).Radius(8).Background(p.codeBg).Border(1, p.borderSubtle).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
					ui.Text(c, cat.PreviewXrayJSON()).FontSize(11).FontWeight(600).TextColor(p.textMuted)
					if actionChip(c.Key("preview-copy-xray-json"), p, iconCopy, cat.BtnCopyJSON(), false).Clicked() {
						a.writeClipboard(string(cfgBytes), cat.CopiedXrayJSON())
					}
				})
				ui.Text(c, string(cfgBytes)).FontSize(11).TextColor(p.text)
			})
		} else {
			obMap := boxengine.BuildNativeOutbound(svc)
			obJSON, _ := json.MarshalIndent(obMap, "", "  ")
			ui.Column(c).Gap(6).Padding(10).Radius(8).Background(p.codeBg).Border(1, p.borderSubtle).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
					ui.Text(c, cat.PreviewSingBoxJSON()).FontSize(11).FontWeight(600).TextColor(p.textMuted)
					if actionChip(c.Key("preview-copy-sb-json"), p, iconCopy, cat.BtnCopyJSON(), false).Clicked() {
						a.writeClipboard(string(obJSON), cat.CopiedSingBoxJSON())
					}
				})
				ui.Text(c, string(obJSON)).FontSize(11).TextColor(p.text)
			})
		}
	})
}

func (a *app) saveEditorService() {
	svc, err := a.buildServiceFromEditor()
	if err != nil {
		a.editor.errText = err.Error()
		return
	}
	if a.editor.isNew {
		a.state.Services = append(a.state.Services, svc)
		a.toast(a.catalog().ToastServiceCreated(svc.Name))
	} else {
		for i := range a.state.Services {
			if a.state.Services[i].ID == svc.ID {
				a.state.Services[i] = svc
				break
			}
		}
		st := a.mgr.StatusOf(svc.ID).State
		if st == runner.StateRunning || st == runner.StateStarting {
			_ = a.mgr.Start(svc)
			a.toast(a.catalog().ToastServiceUpdatedRestarted(svc.Name))
		} else {
			a.toast(a.catalog().ToastServiceUpdated(svc.Name))
		}
	}
	a.saveState()
	a.syncRouter()
	a.rebuildTrayMenu()
	a.editor.open = false
	a.editor.errText = ""
}

// Import Dialog
func (a *app) openImportDialog() {
	clip := strings.TrimSpace(a.readClipboard())
	a.importDlg.open = true
	a.importDlg.errText = ""
	if clip != "" {
		a.importDlg.rawInput = clip
	}
}

func (a *app) renderImportDialog(c *ui.Context, p palette) {
	cat := a.catalog()
	ui.DialogBase(c.Key("import-dialog"), &a.importDlg.open, func(backdrop, panel ui.Element) {
		backdrop.Background(ui.RGBA(0, 0, 0, 0.5))
		panel.Column().
			Width(540).
			Padding(20).Gap(14).
			Radius(14).Background(p.card).Border(1, p.border).
			Shadow(0, 12, 36, 0, ui.RGBA(0, 0, 0, 0.3)).
			Children(func() {
				ui.Text(c, cat.ImportTitle()).FontSize(16).FontWeight(700).TextColor(p.text)
				ui.Text(c, cat.ImportDesc()).FontSize(12).TextColor(p.textMuted)

				if a.importDlg.errText != "" {
					ui.Row(c.Key("import-error-row")).
						AlignItems(ui.Center).Justify(ui.SpaceBetween).
						PaddingX(12).PaddingY(8).Radius(8).Background(p.redBg).Children(func() {
							ui.Text(c, a.importDlg.errText).FontSize(12).TextColor(p.red).Grow(1)
							btnCopy := ui.ButtonBase(c.Key("btn-copy-import-error")).
								Label("btn-copy-import-error").
								Padding(2, 6, 2, 6).Radius(4).
								Background(p.card).Border(1, p.borderSubtle).
								Tooltip(cat.ActionCopyError()).
								Children(func() {
									ui.Text(c, cat.BtnCopy()).FontSize(10).TextColor(p.textDim)
								})
							if btnCopy.Clicked() {
								a.writeClipboard(a.importDlg.errText, cat.ToastErrorCopied())
							}
						})
				}

				labeledTextArea(
					c, p,
					"import-raw-input",
					cat.ImportTitle(),
					&a.importDlg.rawInput,
					"https://user:pass@example.com#Node-1\nnaive+https://user:pass@example.com:443?security=tls&sni=sni.example.com#Node-2\nsocks5://1.2.3.4:1080",
					5, 10,
				)

				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Padding(6, 0, 0, 0).Children(func() {
					if actionChip(c.Key("import-read-clip"), p, iconPaste, cat.ImportClipboard(), false).Clicked() {
						a.importDlg.rawInput = strings.TrimSpace(a.readClipboard())
					}

					ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
						if ui.Button(c.Key("import-cancel"), cat.Cancel()).Clicked() {
							a.importDlg.open = false
							a.importDlg.errText = ""
						}
						if ui.PrimaryButton(c.Key("import-confirm"), cat.ImportBtn()).Clicked() {
							a.confirmImportDialog()
						}
					})
				})
			})
	})
}

func (a *app) confirmImportDialog() {
	used := make(map[int]bool)
	for _, svc := range a.state.Services {
		for _, l := range svc.Listens {
			if p, err := config.ParseListenURI(l); err == nil && p.Port > 0 {
				used[p.Port] = true
			}
		}
	}
	allocPort := func() int {
		for port := 1080; port < 20000; port++ {
			if !used[port] {
				used[port] = true
				return port
			}
		}
		return 1080
	}

	svcs, err := config.ParseImports(a.importDlg.rawInput, allocPort)
	if err != nil {
		a.importDlg.errText = err.Error()
		return
	}
	for i := range svcs {
		if err := svcs[i].Validate(); err != nil {
			a.importDlg.errText = a.catalog().ConfigValidationFailed(fmt.Sprintf("%s: %v", svcs[i].Name, err))
			return
		}
	}

	for i := range svcs {
		svcs[i].ID = a.generateServiceID()
		a.state.Services = append(a.state.Services, svcs[i])
	}
	a.importDlg.open = false
	a.importDlg.errText = ""
	a.importDlg.rawInput = ""
	a.saveState()
	a.syncRouter()
	a.rebuildTrayMenu()

	if len(svcs) == 1 {
		a.toast(a.catalog().ToastImportSingle(svcs[0].Name))
	} else {
		a.toast(a.catalog().ToastImportMultiple(len(svcs)))
	}
}

// Delete Confirmation Dialog
func (a *app) openDeleteServiceDialog(svc config.Service) {
	a.deleteDlg.open = true
	a.deleteDlg.svcID = svc.ID
	a.deleteDlg.svcName = svc.Name
}

func (a *app) renderDeleteDialog(c *ui.Context, p palette) {
	cat := a.catalog()
	ui.DialogBase(c.Key("delete-dialog"), &a.deleteDlg.open, func(backdrop, panel ui.Element) {
		backdrop.Background(ui.RGBA(0, 0, 0, 0.5))
		panel.Column().
			Width(400).
			Padding(20).Gap(14).
			Radius(14).Background(p.card).Border(1, p.border).
			Shadow(0, 12, 36, 0, ui.RGBA(0, 0, 0, 0.3)).
			Children(func() {
				ui.Text(c, cat.DeleteTitle()).FontSize(16).FontWeight(700).TextColor(p.text)
				prompt := cat.DeleteConfirmMsg()
				if a.deleteDlg.svcName != "" {
					prompt = fmt.Sprintf("「%s」: %s", a.deleteDlg.svcName, cat.DeleteConfirmMsg())
				}
				ui.Text(c, prompt).FontSize(13).TextColor(p.textMuted)

				ui.Row(c).AlignItems(ui.Center).Justify(ui.End).Gap(8).Padding(6, 0, 0, 0).Children(func() {
					if ui.Button(c.Key("delete-cancel"), cat.Cancel()).Clicked() {
						a.deleteDlg.open = false
					}
					if primaryPillButton(c.Key("delete-confirm"), p, iconTrash, cat.ActionDelete(), p.red, false).Clicked() {
						a.confirmDeleteService()
					}
				})
			})
	})
}

func (a *app) confirmDeleteService() {
	id := a.deleteDlg.svcID
	name := a.deleteDlg.svcName
	a.deleteDlg.open = false
	if id == "" {
		return
	}
	a.mgr.Remove(id)
	filtered := make([]config.Service, 0, len(a.state.Services))
	for _, s := range a.state.Services {
		if s.ID != id {
			filtered = append(filtered, s)
		}
	}
	a.state.Services = filtered
	delete(a.expandedLogs, id)
	a.saveState()
	a.syncRouter()
	a.rebuildTrayMenu()
	a.toast(a.catalog().ToastServiceDeleted(name))
}
