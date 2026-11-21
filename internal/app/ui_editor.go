package app

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/egoist/mygo/ui"

	"naive-client/internal/config"
	"naive-client/internal/runner"
	"naive-client/internal/warp"
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
	config.ProtoWARP,
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
	"Cloudflare WARP (Direct)",
}

type editorForm struct {
	open           bool
	isNew          bool
	returnToDrawer bool
	tab            int
	scroll         ui.ScrollState
	errText        string
	svcID          string
	name           string
	autoStart      bool
	tagsInput      string

	// Protocol & Execution Engine
	protoIndex  int
	protoName   string
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
	vmessSecIndex int // 0: tls, 1: none
	sni           string
	alpnInput     string
	alpnHandle    ui.Handle
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

	// Cloudflare WARP
	enableWARP         bool
	warpModeIndex      int // 0: Auto (H3 ➔ H2), 1: MASQUE, 2: WireGuard
	warpMasquePreferH2 bool
	warpEndpoint       string
	warpPrivateKey     string
	warpIPv4           string
	warpIPv6           string

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

func (a *app) clearActiveOverlaysForEditor() {
	a.openNodeMenuID = ""
	a.openBatchMenu = false
	a.activeLogDrawerID = ""
	a.activeRuleDrawerID = ""
	a.activeNodeDrawerID = ""
	a.nodeDrawerHelpOpen = false
}

func (a *app) openCreateServiceDialog() {
	a.clearActiveOverlaysForEditor()
	port := a.nextAvailableListenPort()
	svc := config.DefaultService(a.generateServiceID(), port)
	svc.Name = a.catalog().DefaultNodeName(len(a.state.Services) + 1)
	a.populateEditorForm(svc, true, false)
}

func (a *app) openEditServiceDialog(svc config.Service) {
	a.clearActiveOverlaysForEditor()
	a.populateEditorForm(svc, false, false)
}

func (a *app) openEditServiceFromDrawer(svc config.Service) {
	a.clearActiveOverlaysForEditor()
	a.populateEditorForm(svc, false, true)
}

func (a *app) dismissEditorDrawer(returnToDetails bool) {
	targetID := a.editor.svcID
	goBack := returnToDetails && a.editor.returnToDrawer && !a.editor.isNew && targetID != ""
	a.editor.open = false
	a.editor.errText = ""
	a.editor.returnToDrawer = false
	if goBack {
		a.activeNodeDrawerID = targetID
	}
}

func (a *app) populateEditorForm(svc config.Service, isNew, returnToDrawer bool) {
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

	vmessSecIdx := 0
	if !isNew && svc.EffectiveProtocol() == config.ProtoVMess && (strings.EqualFold(svc.Security, "none") || strings.TrimSpace(svc.Security) == "") {
		vmessSecIdx = 1
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
	if fingerprint == "" && (proto == config.ProtoVLESS || (proto == config.ProtoVMess && vmessSecIdx == 0)) {
		fingerprint = "chrome"
	}
	serviceName := svc.ServiceName
	if strings.EqualFold(strings.TrimSpace(svc.Network), "grpc") {
		serviceName = svc.EffectiveGRPCServiceName()
	}

	warpModeIdx := 1 // Chained proxy+WARP defaults to WireGuard
	if proto == config.ProtoWARP {
		warpModeIdx = 0 // Direct/local WARP defaults to MASQUE
		if a.state.Cloudflare.EffectiveDirectMode() == warp.ModeWireGuard {
			warpModeIdx = 1
		}
	} else if svc.IsTCPOnlyProxy() || a.state.Cloudflare.EffectiveChainedMode() == warp.ModeMASQUE {
		warpModeIdx = 0
	}
	warpMasquePreferH2 := a.state.Cloudflare.MasquePreferH2
	warpEndpoint := ""
	warpPrivKey := ""
	warpIPv4 := ""
	warpIPv6 := ""
	if svc.WARPConfig != nil {
		if !svc.IsTCPOnlyProxy() {
			switch svc.WARPConfig.Transport {
			case config.WarpTransportMasque:
				warpModeIdx = 0
			case config.WarpTransportWireGuard:
				warpModeIdx = 1
			}
			if svc.WARPConfig.MasquePreferH2 != nil {
				warpMasquePreferH2 = *svc.WARPConfig.MasquePreferH2
			}
		}
		warpEndpoint = svc.WARPConfig.Endpoint
		warpPrivKey = svc.WARPConfig.PrivateKey
		warpIPv4 = svc.WARPConfig.AddressIPv4
		warpIPv6 = svc.WARPConfig.AddressIPv6
	}

	a.editor = editorForm{
		open:               true,
		isNew:              isNew,
		returnToDrawer:     returnToDrawer,
		tab:                0,
		svcID:              svc.ID,
		name:               svc.Name,
		autoStart:          svc.AutoStart,
		tagsInput:          strings.Join(svc.Tags, ", "),
		protoIndex:         protoIdx,
		protoName:          editorProtocolNames[protoIdx],
		engineIndex:        engineIdx,
		autoLoopback:       autoLoop,
		listenInput:        listens,
		proxyInput:         proxies,
		server:             svc.Server,
		serverPort:         serverPortStr,
		uuid:               svc.UUID,
		password:           svc.Password,
		securityIndex:      secIdx,
		vmessSecIndex:      vmessSecIdx,
		sni:                svc.SNI,
		alpnInput:          strings.Join(svc.ALPN, ", "),
		fingerprint:        fingerprint,
		publicKey:          svc.PublicKey,
		shortID:            svc.ShortID,
		spiderX:            svc.SpiderX,
		flowIndex:          flowIdx,
		networkIndex:       netIdx,
		path:               svc.Path,
		host:               svc.Host,
		serviceName:        serviceName,
		method:             method,
		congestionCtl:      congestion,
		zeroRTT:            svc.ZeroRTTHandshake,
		externalURI:        svc.ExternalURI,
		enableWARP:         svc.EnableWARP,
		warpModeIndex:      warpModeIdx,
		warpMasquePreferH2: warpMasquePreferH2,
		warpEndpoint:       warpEndpoint,
		warpPrivateKey:     warpPrivKey,
		warpIPv4:           warpIPv4,
		warpIPv6:           warpIPv6,
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
	if proto == config.ProtoNaive || a.editor.engineIndex == 1 {
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

	attachWARP := func(s *config.Service) {
		if a.editor.enableWARP {
			transport := config.WarpTransportWireGuard
			preferH2 := a.editor.warpMasquePreferH2
			if s.IsTCPOnlyProxy() {
				transport = config.WarpTransportMasque
				preferH2 = true
			} else if a.editor.warpModeIndex == 0 {
				transport = config.WarpTransportMasque
			}
			s.EnableWARP = true
			s.WARPConfig = &config.WarpNodeConfig{
				Transport:      transport,
				MasquePreferH2: &preferH2,
				Endpoint:       strings.TrimSpace(a.editor.warpEndpoint),
				PrivateKey:     strings.TrimSpace(a.editor.warpPrivateKey),
				AddressIPv4:    strings.TrimSpace(a.editor.warpIPv4),
				AddressIPv6:    strings.TrimSpace(a.editor.warpIPv6),
			}
		}
	}

	if proto == config.ProtoWARP {
		transport := config.WarpTransportMasque
		if a.editor.warpModeIndex == 1 {
			transport = config.WarpTransportWireGuard
		}
		preferH2 := a.editor.warpMasquePreferH2
		svc := config.Service{
			ID:        a.editor.svcID,
			Name:      strings.TrimSpace(a.editor.name),
			AutoStart: a.editor.autoStart,
			Protocol:  config.ProtoWARP,
			Engine:    config.EngineSingBox,
			Tags:      tags,
			WARPConfig: &config.WarpNodeConfig{
				Transport:      transport,
				MasquePreferH2: &preferH2,
				Endpoint:       strings.TrimSpace(a.editor.warpEndpoint),
				PrivateKey:     strings.TrimSpace(a.editor.warpPrivateKey),
				AddressIPv4:    strings.TrimSpace(a.editor.warpIPv4),
				AddressIPv6:    strings.TrimSpace(a.editor.warpIPv6),
			},
		}
		if err := svc.Validate(); err != nil {
			return svc, err
		}
		return svc, nil
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
		attachWARP(&svc)
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
		attachWARP(&svc)
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
	if proto == config.ProtoVMess {
		if a.editor.vmessSecIndex == 1 {
			sec = "none"
		} else {
			sec = "tls"
		}
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
		if proto == config.ProtoVLESS {
			net = "xhttp"
		}
	}

	method := strings.TrimSpace(a.editor.method)
	if proto == config.ProtoVMess {
		method = config.NormalizeVMessSecurity(method)
	}

	var alpn []string
	for _, part := range strings.Split(a.editor.alpnInput, ",") {
		if t := strings.TrimSpace(part); t != "" {
			alpn = append(alpn, t)
		}
	}

	sni := strings.TrimSpace(a.editor.sni)
	fingerprint := strings.TrimSpace(a.editor.fingerprint)
	path := strings.TrimSpace(a.editor.path)
	host := strings.TrimSpace(a.editor.host)
	serviceName := strings.TrimSpace(a.editor.serviceName)

	if proto == config.ProtoVMess && sec == "none" {
		sni = ""
		fingerprint = ""
		alpn = nil
	}
	if proto == config.ProtoVLESS || proto == config.ProtoVMess {
		switch net {
		case "tcp":
			path, host, serviceName = "", "", ""
		case "ws", "xhttp":
			serviceName = ""
		case "grpc":
			path, host = "", ""
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
		SNI:                  sni,
		ALPN:                 alpn,
		Fingerprint:          fingerprint,
		PublicKey:            strings.TrimSpace(a.editor.publicKey),
		ShortID:              strings.TrimSpace(a.editor.shortID),
		SpiderX:              strings.TrimSpace(a.editor.spiderX),
		Flow:                 flow,
		Network:              net,
		Path:                 path,
		Host:                 host,
		ServiceName:          serviceName,
		Method:               method,
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
	attachWARP(&svc)

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

func (a *app) renderEditorDrawer(c *ui.Context, p palette) {
	cat := a.catalog()
	ui.Overlay(c, func() {
		if !a.editor.open {
			return
		}

		// Backdrop (fades in and out, click to dismiss)
		backdrop := ui.Box(c.Key("editor-drawer-backdrop")).
			Absolute().Top(0).Left(0).Right(0).Bottom(0).
			Background(ui.RGBA(0, 0, 0, 0.35)).
			Transition(ui.ElementTransition{
				Enter: &ui.Motion{Opacity: 0},
				Exit:  &ui.Motion{Opacity: 0},
			})
		if backdrop.Clicked() {
			a.dismissEditorDrawer(false)
		}

		// Slide-over drawer panel anchored to right edge (460px unified width)
		panel := ui.Column(c.Key("editor-drawer-panel")).
			Absolute().Top(0).Right(0).Bottom(0).Width(460).
			Modal().
			Transition(ui.ElementTransition{
				Enter: &ui.Motion{X: 460},
				Exit:  &ui.Motion{X: 460},
			}).
			Background(p.drawerBg).
			BorderWidth(0, 0, 0, 1).BorderColor(p.border).
			Shadow(0, 8, 36, 0, ui.RGBA(0, 0, 0, 0.4))

		if panel.OverlayShortcut(0, ui.KeyEscape) {
			a.dismissEditorDrawer(false)
		}

		panel.Children(func() {
			// Header
			ui.Row(c).
				AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(8).
				Padding(14, 20, 14, 20).
				BorderWidth(0, 0, 1, 0).BorderColor(p.borderSubtle).
				Children(func() {
					ui.Row(c).AlignItems(ui.Center).Gap(6).MinWidth(0).Shrink(1).Children(func() {
						if a.editor.returnToDrawer && !a.editor.isNew {
							backBtn := quietRowIconButton(c.Key("editor-back-header"), p, iconArrowLeft, cat.EditorBackToDetails(), false, false).
								Tooltip(cat.EditorBackToDetails())
							if backBtn.Clicked() {
								a.dismissEditorDrawer(true)
							}
						}
						title := cat.EditNodeTitle()
						if a.editor.isNew {
							title = cat.NewNodeTitle()
						}
						ui.Text(c, title).FontSize(15).FontWeight(700).TextColor(p.text).
							SingleLine().Ellipsis("…").MinWidth(0).Shrink(1)
					})

					ui.Row(c).AlignItems(ui.Center).Gap(6).Shrink(0).Children(func() {
						segmentedControl(c.Key("editor-tabs"), p, &a.editor.tab, []string{
							cat.EditorTabBasic(),
							cat.EditorTabAdvanced(),
							cat.EditorTabPreview(),
						})
						closeBtn := quietRowIconButton(c.Key("editor-close"), p, iconClose, cat.NodeDrawerClose(), false, false).
							Tooltip(cat.NodeDrawerClose())
						if closeBtn.Clicked() {
							a.dismissEditorDrawer(false)
						}
					})
				})

			if a.editor.errText != "" {
				ui.Box(c).Padding(12, 20, 0, 20).Children(func() {
					ui.Row(c.Key("editor-error-row")).
						AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(8).
						PaddingX(12).PaddingY(8).Radius(8).Background(p.redBg).
						Border(1, p.red.Alpha(0.24)).
						Children(func() {
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
				})
			}

			// Scrollable drawer body
			ui.Scroll(c.Key("editor-scroll")).
				TrackScroll(&a.editor.scroll).
				Grow(1).Fill().
				Background(p.surface).
				Padding(16, 20, 20, 20).
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

			// Sticky footer
			ui.Row(c).
				AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(8).
				Padding(12, 20, 14, 20).
				Background(p.drawerBg).
				BorderWidth(1, 0, 0, 0).BorderColor(p.borderSubtle).
				Children(func() {
					if a.editor.returnToDrawer && !a.editor.isNew {
						if subtleActionChip(c.Key("editor-back-to-details"), p, iconArrowLeft, cat.EditorBackToDetails(), false).Clicked() {
							a.dismissEditorDrawer(true)
						}
					} else {
						ui.Box(c)
					}

					ui.Row(c).AlignItems(ui.Center).Gap(8).Shrink(0).Children(func() {
						if ui.Button(c.Key("editor-cancel"), cat.Cancel()).Clicked() {
							a.dismissEditorDrawer(false)
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

func (a *app) syncEditorFieldsForProtocolSwitch(oldProto, newProto config.Protocol) {
	if newProto == config.ProtoNaive {
		a.editor.engineIndex = 1
	} else {
		a.editor.engineIndex = 0
	}
	if newProto != config.ProtoVLESS && a.editor.networkIndex >= 3 {
		a.editor.networkIndex = 0
	}
	if oldProto == config.ProtoVLESS && newProto == config.ProtoVMess {
		if a.editor.securityIndex == 2 {
			a.editor.vmessSecIndex = 1
		} else {
			a.editor.vmessSecIndex = 0
		}
	} else if oldProto == config.ProtoVMess && newProto == config.ProtoVLESS {
		if a.editor.vmessSecIndex == 1 {
			a.editor.securityIndex = 2
		} else if a.editor.securityIndex == 2 {
			a.editor.securityIndex = 0
		}
	}
	switch newProto {
	case config.ProtoVMess:
		if oldProto != config.ProtoVMess {
			a.editor.method = ""
		}
	case config.ProtoShadowsocks:
		if oldProto != config.ProtoShadowsocks || strings.TrimSpace(a.editor.method) == "" {
			a.editor.method = "2022-blake3-aes-128-gcm"
		}
	}
	if (newProto == config.ProtoVLESS || (newProto == config.ProtoVMess && a.editor.vmessSecIndex == 0)) && strings.TrimSpace(a.editor.fingerprint) == "" {
		a.editor.fingerprint = "chrome"
	}
}

func (a *app) renderALPNField(c *ui.Context, p palette, key string) {
	cat := a.catalog()
	options := []comboboxOption{
		{Value: "", Label: cat.AlpnAutoOption()},
		{Value: "http/1.1", Label: "http/1.1"},
		{Value: "h2", Label: "h2"},
		{Value: "h2, http/1.1", Label: "h2, http/1.1"},
		{Value: "h3", Label: "h3"},
		{Value: "h3, h2, http/1.1", Label: "h3, h2, http/1.1"},
	}
	labeledCombobox(
		c, p, key,
		cat.AlpnLabel(), cat.AlpnDropdownLabel(),
		&a.editor.alpnInput, &a.editor.alpnHandle,
		cat.AlpnPlaceholder(), options,
	)
}

func editorSectionCard(c *ui.Context, p palette, children func()) {
	ui.Column(c).Gap(10).Padding(14).Radius(10).
		Background(p.card).Border(1, p.borderSubtle).
		Children(children)
}

func (a *app) renderEditorServerPortRow(c *ui.Context, p palette, keyPrefix, portPlaceholder string) {
	cat := a.catalog()
	ui.Grid(c.Key("editor-srv-port-"+keyPrefix)).ColumnTracks(ui.Fr(3), ui.Fr(1)).Gap(10).Children(func() {
		labeledInput(c, p, "inp-"+keyPrefix+"-server", cat.ServerLabel(), &a.editor.server, "example.com")
		labeledInput(c, p, "inp-"+keyPrefix+"-port", cat.ServerPortLabel(), &a.editor.serverPort, portPlaceholder)
	})
}

func (a *app) renderEditorBasicTab(c *ui.Context, p palette) {
	proto := editorProtocols[a.editor.protoIndex]
	ui.Column(c).Gap(12).Children(func() {
		a.renderEditorIdentityCard(c, p)
		a.renderEditorProtocolEngineCard(c, p, proto)
		a.renderEditorConnectionCard(c, p, proto)
		if proto != config.ProtoWARP {
			a.renderEditorChainedWarpCard(c, p, proto)
		}
	})
}

func (a *app) renderEditorIdentityCard(c *ui.Context, p palette) {
	cat := a.catalog()
	editorSectionCard(c, p, func() {
		ui.Grid(c.Key("editor-identity-grid")).Columns(2).Gap(10).Children(func() {
			labeledInput(c, p, "inp-name", cat.NodeNameLabel(), &a.editor.name, "HK-01")
			labeledInput(c, p, "inp-tags", cat.TagsLabel(), &a.editor.tagsInput, cat.TagsHint())
		})
		ui.Box(c).FillWidth().Padding(8, 0, 0, 0).BorderWidth(1, 0, 0, 0).BorderColor(p.borderSubtle).Children(func() {
			switchRow(c, p, "editor-autostart", cat.EditorAutoStartDesc(), &a.editor.autoStart)
		})
	})
}

func (a *app) renderEditorProtocolEngineCard(c *ui.Context, p palette, proto config.Protocol) {
	cat := a.catalog()
	editorSectionCard(c, p, func() {
		// Protocol Type
		ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(10).Children(func() {
			ui.Text(c, cat.ProtocolLabel()).FontSize(12).FontWeight(600).TextColor(p.text).NoWrap()
			protoSel := ui.Select(c.Key("inp-proto-select"), &a.editor.protoName, editorProtocolNames).
				Label(cat.ProtocolLabel()).Width(220)
			if protoSel.Changed() {
				for i, name := range editorProtocolNames {
					if name == a.editor.protoName {
						oldProto := editorProtocols[a.editor.protoIndex]
						a.editor.protoIndex = i
						if oldProto != editorProtocols[i] {
							a.syncEditorFieldsForProtocolSwitch(oldProto, editorProtocols[i])
						}
						break
					}
				}
			} else if a.editor.protoIndex >= 0 && a.editor.protoIndex < len(editorProtocolNames) {
				a.editor.protoName = editorProtocolNames[a.editor.protoIndex]
			}
		})

		// Execution Engine
		ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(10).Children(func() {
			desc := cat.EditorEngineSwitchDesc()
			switch proto {
			case config.ProtoNaive:
				desc = cat.CoreNaiveDesc()
			case config.ProtoHysteria2, config.ProtoTUIC:
				desc = cat.EditorEngineFixedDesc()
			case config.ProtoSOCKS5, config.ProtoHTTP:
				desc = cat.EditorEngineExternalDesc()
			case config.ProtoWARP:
				desc = cat.EditorEngineWarpDesc()
			}
			ui.Column(c).Gap(2).MinWidth(0).Shrink(1).Children(func() {
				ui.Text(c, cat.EngineLabel()).FontSize(12).FontWeight(600).TextColor(p.text)
				ui.Text(c, desc).FontSize(11).TextColor(p.textDim).SingleLine().Ellipsis("…")
			})

			switch proto {
			case config.ProtoNaive:
				tagPill(c, cat.EngineSidecarNaive(), p.textMuted, p.elevated)
			case config.ProtoVLESS, config.ProtoVMess, config.ProtoTrojan, config.ProtoShadowsocks:
				segmentedControl(c.Key("editor-xray-engine"), p, &a.editor.engineIndex, []string{
					cat.EngineSingBox(),
					cat.EngineSidecarXray(),
				})
			case config.ProtoHysteria2, config.ProtoTUIC, config.ProtoWARP:
				tagPill(c, cat.EngineSingBoxOnly(), p.textMuted, p.elevated)
			case config.ProtoSOCKS5, config.ProtoHTTP:
				tagPill(c, cat.NodeKindExternal(), p.textMuted, p.elevated)
			}
		})

		// Sidecar Loopback Configuration
		hasSidecar := proto == config.ProtoNaive || proto == config.ProtoVLESS || proto == config.ProtoVMess || proto == config.ProtoTrojan || proto == config.ProtoShadowsocks
		if a.editor.engineIndex == 1 && hasSidecar {
			ui.Column(c).Gap(6).Padding(10, 0, 0, 0).BorderWidth(1, 0, 0, 0).BorderColor(p.borderSubtle).Children(func() {
				switchRow(c, p, "inp-auto-loopback", cat.AutoLoopbackPortLabel(), &a.editor.autoLoopback)
				ui.Text(c, cat.AutoLoopbackPortShortDesc()).FontSize(11).TextColor(p.textDim)
				if !a.editor.autoLoopback {
					labeledInput(c, p, "inp-listen", cat.ListenPortLabel(), &a.editor.listenInput, "socks://127.0.0.1:1080")
				}
			})
		}
	})
}

func (a *app) renderEditorConnectionCard(c *ui.Context, p palette, proto config.Protocol) {
	cat := a.catalog()
	cardTitle := cat.EditorGroupConnection()
	if proto == config.ProtoWARP {
		cardTitle = cat.EditorGroupWarpTransport()
	}

	editorSectionCard(c, p, func() {
		ui.Text(c, cardTitle).FontSize(11).FontWeight(700).TextColor(p.textDim)

		switch proto {
		case config.ProtoNaive:
			ui.Column(c).Gap(4).Children(func() {
				labeledInput(c, p, "inp-proxy", cat.ProxyURILabel(), &a.editor.proxyInput, cat.ProxyURIHint())
				ui.Text(c, cat.EditorProxyHintFull()).FontSize(11).TextColor(p.textDim)
			})
			labeledInput(c, p, "inp-concurrency-basic", cat.EditorConcurrencyLabel(), &a.editor.concurrencyStr, "1")
			switchRow(c, p, "inp-nopq-basic", cat.EditorNoPQLabel(), &a.editor.noPostQuantum)

		case config.ProtoVLESS:
			a.renderEditorServerPortRow(c, p, "vless", "443")
			labeledInput(c, p, "inp-vless-uuid", cat.UuidLabel(), &a.editor.uuid, "a1b2c3d4-e5f6-7890-abcd-ef1234567890")

			ui.Column(c).Gap(8).Padding(8, 0, 0, 0).BorderWidth(1, 0, 0, 0).BorderColor(p.borderSubtle).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(10).Children(func() {
					ui.Text(c, cat.SecurityLabel()).FontSize(12).FontWeight(500).TextColor(p.text)
					segmentedControl(c.Key("inp-vless-sec"), p, &a.editor.securityIndex, []string{"TLS", "REALITY", "None"})
				})

				if a.editor.securityIndex == 1 {
					labeledInput(c, p, "inp-vless-pbk", cat.PublicKeyLabel(), &a.editor.publicKey, "publicKey...")
					ui.Grid(c.Key("editor-vless-reality-grid")).Columns(2).Gap(10).Children(func() {
						labeledInput(c, p, "inp-vless-sid", cat.ShortIDLabel(), &a.editor.shortID, "shortId")
						labeledInput(c, p, "inp-vless-spx", cat.SpiderXLabel(), &a.editor.spiderX, "/")
					})
				}

				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(10).Children(func() {
					ui.Text(c, cat.FlowLabel()).FontSize(12).FontWeight(500).TextColor(p.text)
					segmentedControl(c.Key("inp-vless-flow"), p, &a.editor.flowIndex, []string{"xtls-rprx-vision", "None"})
				})

				if a.editor.securityIndex != 2 {
					ui.Grid(c.Key("editor-vless-tls-grid")).Columns(2).Gap(10).Children(func() {
						labeledInput(c, p, "inp-vless-sni", cat.SniLabel(), &a.editor.sni, "domain.com")
						labeledInput(c, p, "inp-vless-fp", cat.FingerprintLabel(), &a.editor.fingerprint, "chrome")
					})
				}
				if a.editor.securityIndex == 0 {
					a.renderALPNField(c, p, "inp-vless-alpn")
				}

				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(10).Children(func() {
					ui.Text(c, cat.NetworkLabel()).FontSize(12).FontWeight(500).TextColor(p.text)
					segmentedControl(c.Key("inp-vless-net"), p, &a.editor.networkIndex, []string{"tcp", "ws", "grpc", "xhttp"})
				})

				if a.editor.networkIndex == 1 || a.editor.networkIndex == 3 {
					ui.Grid(c.Key("editor-vless-ws-grid")).Columns(2).Gap(10).Children(func() {
						labeledInput(c, p, "inp-vless-path", cat.PathLabel(), &a.editor.path, "/")
						labeledInput(c, p, "inp-vless-host", cat.HostHeaderLabel(), &a.editor.host, "")
					})
				} else if a.editor.networkIndex == 2 {
					labeledInput(c, p, "inp-vless-service", cat.ServiceNameLabel(), &a.editor.serviceName, "GunService")
				}
			})

		case config.ProtoVMess:
			a.renderEditorServerPortRow(c, p, "vmess", "443")
			labeledInput(c, p, "inp-vmess-uuid", cat.UuidLabel(), &a.editor.uuid, "a1b2c3d4-e5f6-7890-abcd-ef1234567890")

			ui.Column(c).Gap(8).Padding(8, 0, 0, 0).BorderWidth(1, 0, 0, 0).BorderColor(p.borderSubtle).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(10).Children(func() {
					ui.Text(c, cat.SecurityLabel()).FontSize(12).FontWeight(500).TextColor(p.text)
					if segmentedControl(c.Key("inp-vmess-sec"), p, &a.editor.vmessSecIndex, []string{"TLS", "None"}) {
						if a.editor.vmessSecIndex == 0 && strings.TrimSpace(a.editor.fingerprint) == "" {
							a.editor.fingerprint = "chrome"
						}
					}
				})
				if a.editor.vmessSecIndex == 0 {
					ui.Grid(c.Key("editor-vmess-tls-grid")).Columns(2).Gap(10).Children(func() {
						labeledInput(c, p, "inp-vmess-sni", cat.SniLabel(), &a.editor.sni, "domain.com")
						labeledInput(c, p, "inp-vmess-fp", cat.FingerprintLabel(), &a.editor.fingerprint, "chrome")
					})
					a.renderALPNField(c, p, "inp-vmess-alpn")
				}
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(10).Children(func() {
					ui.Text(c, cat.NetworkLabel()).FontSize(12).FontWeight(500).TextColor(p.text)
					segmentedControl(c.Key("inp-vmess-net"), p, &a.editor.networkIndex, []string{"tcp", "ws", "grpc"})
				})
				if a.editor.networkIndex == 1 {
					ui.Grid(c.Key("editor-vmess-ws-grid")).Columns(2).Gap(10).Children(func() {
						labeledInput(c, p, "inp-vmess-path", cat.PathLabel(), &a.editor.path, "/")
						labeledInput(c, p, "inp-vmess-host", cat.HostHeaderLabel(), &a.editor.host, "")
					})
				} else if a.editor.networkIndex == 2 {
					labeledInput(c, p, "inp-vmess-service", cat.ServiceNameLabel(), &a.editor.serviceName, "")
				}
			})

		case config.ProtoTrojan:
			a.renderEditorServerPortRow(c, p, "trojan", "443")
			ui.Grid(c.Key("editor-trojan-grid")).Columns(2).Gap(10).Children(func() {
				labeledInput(c, p, "inp-trojan-password", cat.PasswordLabel(), &a.editor.password, "password")
				labeledInput(c, p, "inp-trojan-sni", cat.SniLabel(), &a.editor.sni, "domain.com")
			})
			a.renderALPNField(c, p, "inp-trojan-alpn")

		case config.ProtoShadowsocks:
			a.renderEditorServerPortRow(c, p, "ss", "8388")
			ui.Grid(c.Key("editor-ss-grid")).Columns(2).Gap(10).Children(func() {
				labeledInput(c, p, "inp-ss-password", cat.PasswordLabel(), &a.editor.password, "password")
				labeledInput(c, p, "inp-ss-method", cat.SsMethodLabel(), &a.editor.method, "2022-blake3-aes-128-gcm")
			})

		case config.ProtoHysteria2:
			a.renderEditorServerPortRow(c, p, "hy2", "443")
			labeledInput(c, p, "inp-hy2-password", cat.PasswordLabel(), &a.editor.password, "password")
			ui.Grid(c.Key("editor-hy2-grid")).Columns(2).Gap(10).Children(func() {
				labeledInput(c, p, "inp-hy2-sni", cat.SniLabel(), &a.editor.sni, "domain.com")
				labeledInput(c, p, "inp-hy2-cc", cat.CongestionCtlLabel(), &a.editor.congestionCtl, "bbr")
			})

		case config.ProtoTUIC:
			a.renderEditorServerPortRow(c, p, "tuic", "443")
			labeledInput(c, p, "inp-tuic-uuid", cat.UuidLabel(), &a.editor.uuid, "uuid")
			ui.Grid(c.Key("editor-tuic-grid")).Columns(2).Gap(10).Children(func() {
				labeledInput(c, p, "inp-tuic-password", cat.PasswordLabel(), &a.editor.password, "password")
				labeledInput(c, p, "inp-tuic-sni", cat.SniLabel(), &a.editor.sni, "domain.com")
			})
			switchRow(c, p, "inp-tuic-zerortt", cat.ZeroRTTLabel(), &a.editor.zeroRTT)

		case config.ProtoSOCKS5, config.ProtoHTTP:
			labeledInput(c, p, "inp-external-uri", cat.ExternalURILabel(), &a.editor.externalURI, cat.ExternalURIHint())

		case config.ProtoWARP:
			ui.Column(c).Gap(6).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(10).Children(func() {
					ui.Text(c, cat.CloudflareWarpTransport()).FontSize(12).FontWeight(500).TextColor(p.text)
					segmentedControl(c.Key("inp-warp-direct-transport"), p, &a.editor.warpModeIndex, []string{"MASQUE", "WireGuard"})
				})
				a.renderWarpTransportGuide(c, p, "editor-warp-direct", a.editor.warpModeIndex, true)
			})
			if a.editor.warpModeIndex == 0 {
				ui.Column(c).Gap(4).Padding(10).Radius(8).Background(p.surface).Border(1, p.borderSubtle).Children(func() {
					switchRow(c, p, "inp-warp-direct-prefer-h2", cat.CloudflareWarpPreferH2(), &a.editor.warpMasquePreferH2)
					ui.Text(c, cat.CloudflareWarpPreferH2Desc()).FontSize(11).TextColor(p.textMuted).LineHeight(1.35)
				})
			}
			labeledInput(c, p, "inp-warp-direct-endpoint", cat.CloudflareWarpCleanEndpoint(), &a.editor.warpEndpoint, cat.CloudflareWarpCleanEndpointPlaceholder())
		}
	})
}

func (a *app) renderEditorChainedWarpCard(c *ui.Context, p palette, proto config.Protocol) {
	cat := a.catalog()
	editorSectionCard(c, p, func() {
		if switchRow(c, p, "inp-enable-warp-toggle", cat.NodeEditorEnableWarp(), &a.editor.enableWARP) {
			if a.editor.enableWARP {
				if proto == config.ProtoNaive || proto == config.ProtoHTTP || a.state.Cloudflare.EffectiveChainedMode() == warp.ModeMASQUE {
					a.editor.warpModeIndex = 0
				} else {
					a.editor.warpModeIndex = 1
				}
			}
		}
		ui.Text(c, cat.NodeEditorEnableWarpDesc()).FontSize(11).TextColor(p.textDim).LineHeight(1.35)

		if a.editor.enableWARP {
			ui.Column(c).Gap(8).Padding(10, 0, 0, 0).BorderWidth(1, 0, 0, 0).BorderColor(p.borderSubtle).Children(func() {
				if proto == config.ProtoNaive || proto == config.ProtoHTTP {
					ui.Row(c).Gap(6).Padding(8, 10, 8, 10).Radius(6).Background(p.accentBg).Children(func() {
						ui.Text(c, cat.NodeEditorWarpNaiveNotice()).FontSize(11).TextColor(p.accentText).LineHeight(1.35)
					})
				} else {
					ui.Column(c).Gap(6).Children(func() {
						ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(10).Children(func() {
							ui.Text(c, cat.CloudflareWarpChainedTransport()).FontSize(12).FontWeight(500).TextColor(p.text)
							segmentedControl(c.Key("inp-warp-chained-transport"), p, &a.editor.warpModeIndex, []string{"MASQUE", "WireGuard"})
						})
						a.renderWarpTransportGuide(c, p, "editor-warp-chained", a.editor.warpModeIndex, true)
					})

					if a.editor.warpModeIndex == 0 {
						ui.Column(c).Gap(4).Padding(10).Radius(8).Background(p.surface).Border(1, p.borderSubtle).Children(func() {
							switchRow(c, p, "inp-warp-chained-prefer-h2", cat.CloudflareWarpPreferH2(), &a.editor.warpMasquePreferH2)
							ui.Text(c, cat.CloudflareWarpPreferH2Desc()).FontSize(11).TextColor(p.textMuted).LineHeight(1.35)
						})
					}
				}

				labeledInput(c, p, "inp-warp-chained-endpoint", cat.CloudflareWarpCleanEndpoint(), &a.editor.warpEndpoint, cat.CloudflareWarpChainedEndpointPlaceholder())
			})
		}
	})
}

func (a *app) renderEditorAdvancedTab(c *ui.Context, p palette) {
	cat := a.catalog()
	proto := editorProtocols[a.editor.protoIndex]

	ui.Column(c).Gap(12).Children(func() {
		if proto == config.ProtoWARP || a.editor.enableWARP {
			editorSectionCard(c, p, func() {
				ui.Text(c, cat.EditorGroupWarpTransport()).FontSize(11).FontWeight(700).TextColor(p.textDim)
				labeledInput(c, p, "inp-warp-privkey-adv", cat.WarpCustomPrivKeyLabel(), &a.editor.warpPrivateKey, cat.WarpCustomPrivKeyHint())
				ui.Grid(c.Key("editor-warp-ips-grid")).Columns(2).Gap(10).Children(func() {
					labeledInput(c, p, "inp-warp-ipv4-adv", cat.WarpCustomIPv4Label(), &a.editor.warpIPv4, "172.16.0.2/32")
					labeledInput(c, p, "inp-warp-ipv6-adv", cat.WarpCustomIPv6Label(), &a.editor.warpIPv6, "2606:4700:110:8a36::2/128")
				})
			})
		}

		editorSectionCard(c, p, func() {
			ui.Text(c, cat.EditorGroupAdvanced()).FontSize(11).FontWeight(700).TextColor(p.textDim)

			if proto == config.ProtoNaive {
				ui.Grid(c.Key("editor-naive-timeouts-grid")).Columns(2).Gap(10).Children(func() {
					labeledInput(c, p, "inp-tunnel-timeout", cat.EditorTunnelTimeoutLabel(), &a.editor.tunnelTimeout, "")
					labeledInput(c, p, "inp-idle-timeout", cat.EditorIdleTimeoutLabel(), &a.editor.idleTimeout, "")
				})
				labeledInput(c, p, "inp-extra-headers", cat.EditorExtraHeadersLabel(), &a.editor.extraHeaders, "Header1: Value1")
				ui.Grid(c.Key("editor-naive-rules-grid")).Columns(2).Gap(10).Children(func() {
					labeledInput(c, p, "inp-host-rules", cat.EditorHostRulesLabel(), &a.editor.hostRules, "MAP example.com 1.2.3.4")
					labeledInput(c, p, "inp-resolver-range", cat.EditorResolverRangeLabel(), &a.editor.resolverRange, "100.64.0.0/10")
				})
				switchRow(c, p, "inp-enable-log", cat.EditorEnableLogLabel(), &a.editor.enableLog)
				labeledInput(c, p, "inp-log-file", cat.EditorLogFileLabel(), &a.editor.logFile, cat.EditorLogFileHint())
				ui.Grid(c.Key("editor-naive-logs-grid")).Columns(2).Gap(10).Children(func() {
					labeledInput(c, p, "inp-net-log", cat.EditorNetLogLabel(), &a.editor.logNetLog, "")
					labeledInput(c, p, "inp-ssl-key-log", cat.EditorSSLKeyLogLabel(), &a.editor.sslKeyLogFile, "")
				})
				labeledInput(c, p, "inp-extra-json", cat.EditorExtraJSONLabel(), &a.editor.extraJSON, `{"padding": true}`)
			} else {
				labeledInput(c, p, "inp-concurrency-adv", cat.EditorConcurrencyLabel(), &a.editor.concurrencyStr, "1")
				switchRow(c, p, "inp-nopq-adv", cat.EditorNoPQLabel(), &a.editor.noPostQuantum)

				if a.editor.engineIndex == 1 {
					ui.Column(c).Gap(8).Padding(8, 0, 0, 0).BorderWidth(1, 0, 0, 0).BorderColor(p.borderSubtle).Children(func() {
						switchRow(c, p, "inp-enable-log", cat.EditorEnableLogLabel(), &a.editor.enableLog)
						labeledInput(c, p, "inp-log-file", cat.EditorLogFileLabel(), &a.editor.logFile, cat.EditorLogFileHint())
					})
				}

				ui.Column(c).Gap(4).Padding(8, 0, 0, 0).BorderWidth(1, 0, 0, 0).BorderColor(p.borderSubtle).Children(func() {
					labeledInput(c, p, "inp-extra-json", cat.EditorExtraJSONLabel(), &a.editor.extraJSON, `{"mux": {"enabled": true}}`)
					ui.Text(c, cat.EditorAdvancedCoreCustomDesc()).FontSize(11).TextColor(p.textDim).LineHeight(1.35)
				})
			}
		})
	})
}

func (a *app) renderEditorPreviewTab(c *ui.Context, p palette) {
	cat := a.catalog()
	svc, err := a.buildServiceFromEditor()
	if err != nil {
		ui.Row(c).PaddingX(12).PaddingY(10).Radius(8).Background(p.redBg).Border(1, p.red.Alpha(0.24)).Children(func() {
			ui.Text(c, cat.ConfigValidationFailed(err.Error())).FontSize(12).TextColor(p.red)
		})
		return
	}

	ui.Column(c).Gap(12).Children(func() {
		if svc.EffectiveEngine() == config.EngineSidecar {
			v2rayURI := svc.V2rayNSocksURI()
			editorSectionCard(c, p, func() {
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
					ui.Text(c, cat.PreviewLocalLink()).FontSize(11).FontWeight(600).TextColor(p.textMuted)
					if subtleActionChip(c.Key("preview-copy-local"), p, iconCopy, cat.BtnCopy(), false).Clicked() {
						a.writeClipboard(v2rayURI, cat.CopiedLocalLink())
					}
				})
				ui.Box(c).Padding(8).Radius(6).Background(p.codeBg).Border(1, p.borderSubtle).Children(func() {
					ui.Text(c, v2rayURI).Font("monospace").FontSize(11).FontWeight(500).TextColor(p.accent).LineHeight(1.35)
				})
			})
		}

		shareURI := svc.ShareURI()
		if shareURI != "" {
			editorSectionCard(c, p, func() {
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
					ui.Text(c, cat.PreviewNaiveShareLink()).FontSize(11).FontWeight(600).TextColor(p.textMuted)
					if subtleActionChip(c.Key("preview-copy-share"), p, iconCopy, cat.BtnCopy(), false).Clicked() {
						a.writeClipboard(shareURI, cat.CopiedNaiveShareLink())
					}
				})
				ui.Box(c).Padding(8).Radius(6).Background(p.codeBg).Border(1, p.borderSubtle).Children(func() {
					ui.Text(c, shareURI).Font("monospace").FontSize(11).TextColor(p.text).LineHeight(1.35)
				})
			})
		}

		jsonTitle, _ := nodeCoreJSONMeta(cat, svc)
		rawJSON, copiedToast := buildNodeCoreConfigJSON(cat, svc)
		editorSectionCard(c, p, func() {
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
				ui.Text(c, jsonTitle).FontSize(11).FontWeight(600).TextColor(p.textMuted).SingleLine().Ellipsis("…").Shrink(1).MinWidth(0)
				if subtleActionChip(c.Key("preview-copy-core-json"), p, iconCopy, cat.BtnCopyJSON(), false).Clicked() {
					a.writeClipboard(rawJSON, copiedToast)
				}
			})
			ui.Box(c).Padding(8).Radius(6).Background(p.codeBg).Border(1, p.borderSubtle).Children(func() {
				ui.Text(c, rawJSON).Font("monospace").FontSize(11).TextColor(p.text).LineHeight(1.35)
			})
		})
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
		a.refreshServicesSnapshot()
		st := a.mgr.StatusOf(svc.ID).State
		if st == runner.StateRunning || st == runner.StateStarting {
			_ = a.mgr.Start(svc)
			a.toast(a.catalog().ToastServiceUpdatedRestarted(svc.Name))
		} else {
			a.toast(a.catalog().ToastServiceUpdated(svc.Name))
		}
	}
	a.saveState()
	a.rebuildTrayMenu()
	returnID := ""
	if a.editor.returnToDrawer && !a.editor.isNew {
		returnID = svc.ID
	}
	a.editor.open = false
	a.editor.errText = ""
	a.editor.returnToDrawer = false
	if returnID != "" {
		a.activeNodeDrawerID = returnID
	}
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
	if a.openNodeMenuID == id {
		a.openNodeMenuID = ""
	}
	if a.activeNodeDrawerID == id {
		a.activeNodeDrawerID = ""
	}
	if a.activeLogDrawerID == id {
		a.activeLogDrawerID = ""
	}
	a.saveState()
	a.rebuildTrayMenu()
	a.toast(a.catalog().ToastServiceDeleted(name))
}
