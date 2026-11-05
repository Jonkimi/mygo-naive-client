package app

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/egoist/mygo/ui"

	"naive-client/internal/config"
	"naive-client/internal/runner"
)

type editorForm struct {
	open        bool
	isNew       bool
	tab         int
	kindIndex   int // 0: NaiveProxy, 1: External SOCKS5/HTTP
	scroll      ui.ScrollState
	errText     string
	svcID       string
	name        string
	autoStart   bool
	tagsInput   string
	externalURI string

	listenInput string
	proxyInput  string

	concurrencyStr string
	tunnelTimeout  string
	idleTimeout    string
	extraHeaders   string
	hostRules      string
	resolverRange  string
	enableLog      bool
	logFile        string
	logNetLog      string
	sslKeyLogFile  string
	noPostQuantum  bool
	extraJSON      string
}

func (a *app) openCreateServiceDialog() {
	port := a.nextAvailableListenPort()
	svc := config.DefaultService(a.generateServiceID(), port)
	svc.Name = fmt.Sprintf("Naive 节点 %d", len(a.state.Services)+1)
	a.populateEditorForm(svc, true)
}

func (a *app) openEditServiceDialog(svc config.Service) {
	a.populateEditorForm(svc, false)
}

func (a *app) populateEditorForm(svc config.Service, isNew bool) {
	if len(svc.Listens) == 0 {
		svc.Listens = []string{"socks://127.0.0.1:1080"}
	}
	listens := strings.Join(svc.Listens, ", ")
	proxies := strings.Join(svc.Proxies, "\n")

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

	kindIdx := 0
	if svc.EffectiveKind() == config.KindExternalProxy {
		kindIdx = 1
	}

	a.editor = editorForm{
		open:           true,
		isNew:          isNew,
		tab:            0,
		kindIndex:      kindIdx,
		svcID:          svc.ID,
		name:           svc.Name,
		autoStart:      svc.AutoStart,
		tagsInput:      strings.Join(svc.Tags, ", "),
		externalURI:    svc.ExternalURI,
		listenInput:    listens,
		proxyInput:     proxies,
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
	kind := config.KindManagedNaive
	if a.editor.kindIndex == 1 {
		kind = config.KindExternalProxy
	}

	var tags []string
	for _, part := range strings.Split(a.editor.tagsInput, ",") {
		if t := strings.TrimSpace(part); t != "" {
			tags = append(tags, strings.TrimPrefix(t, "#"))
		}
	}

	if kind == config.KindExternalProxy {
		svc := config.Service{
			ID:          a.editor.svcID,
			Name:        strings.TrimSpace(a.editor.name),
			AutoStart:   a.editor.autoStart,
			Kind:        config.KindExternalProxy,
			Tags:        tags,
			ExternalURI: strings.TrimSpace(a.editor.externalURI),
		}
		if err := svc.Validate(); err != nil {
			return svc, err
		}
		return svc, nil
	}

	svc := config.Service{
		ID:                a.editor.svcID,
		Name:              strings.TrimSpace(a.editor.name),
		AutoStart:         a.editor.autoStart,
		Kind:              config.KindManagedNaive,
		Tags:              tags,
		Listens:           splitMultiValues(a.editor.listenInput),
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
		v, err := strconv.Atoi(s)
		if err != nil {
			return svc, fmt.Errorf("insecure-concurrency 必须是整数")
		}
		svc.InsecureConcurrency = v
	}
	if s := strings.TrimSpace(a.editor.tunnelTimeout); s != "" {
		v, err := strconv.Atoi(s)
		if err != nil {
			return svc, fmt.Errorf("tunnel-timeout 必须是整数 (秒)")
		}
		svc.TunnelTimeout = v
	}
	if s := strings.TrimSpace(a.editor.idleTimeout); s != "" {
		v, err := strconv.Atoi(s)
		if err != nil {
			return svc, fmt.Errorf("idle-timeout 必须是整数 (秒)")
		}
		svc.IdleTimeout = v
	}

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
			Width(580).Height(520).
			Padding(20).Gap(14).
			Radius(14).Background(p.card).Border(1, p.border).
			Shadow(0, 12, 36, 0, ui.RGBA(0, 0, 0, 0.3)).
			Children(func() {
				// Header
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Children(func() {
					title := "编辑本地 Naive 服务"
					if a.editor.isNew {
						title = "新建本地 Naive 服务"
					}
					ui.Text(c, title).FontSize(16).FontWeight(700).TextColor(p.text)
					segmentedControl(c.Key("editor-tabs"), p, &a.editor.tab, []string{
						"基础配置",
						"高级参数 (USAGE.txt)",
						"配置预览",
					})
				})

				if a.editor.errText != "" {
					ui.Row(c).PaddingX(12).PaddingY(8).Radius(8).Background(p.redBg).Children(func() {
						ui.Text(c, a.editor.errText).FontSize(12).FontWeight(500).TextColor(p.red)
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
								Label("随客户端启动时自动运行该服务")
							ui.Text(c, "随客户端启动时自动运行该服务").FontSize(12).TextColor(p.text)
						})

						ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
							if ui.Button(c.Key("editor-cancel"), "取消").Clicked() {
								a.editor.open = false
								a.editor.errText = ""
							}
							saveLabel := "保存修改"
							if a.editor.isNew {
								saveLabel = "创建服务"
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
	ui.Column(c).Gap(12).Children(func() {
		ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Gap(12).Children(func() {
			ui.Text(c, "节点类型").FontSize(12).TextColor(p.text)
			segmentedControl(c.Key("editor-kind-segmented"), p, &a.editor.kindIndex, []string{
				"NaiveProxy (内置托管)",
				"外部代理 (SOCKS5/HTTP)",
			})
		})

		labeledInput(c, p, "inp-name", "服务名称 (Alias)", &a.editor.name, "例如: 香港 HK-01")
		labeledInput(c, p, "inp-tags", "服务器标签 (Tags，逗号分隔)", &a.editor.tagsInput, "例如: hk, fast, ai")

		if a.editor.kindIndex == 1 {
			labeledInput(c, p, "inp-external-uri", "外部代理地址", &a.editor.externalURI, "socks5://1.2.3.4:1080 或 http://user:pass@host:8080")
			return
		}

		ui.Column(c).Gap(4).Children(func() {
			labeledInput(c, p, "inp-listen", "本地监听地址 (listen)", &a.editor.listenInput, "socks://127.0.0.1:1080 或 http://127.0.0.1:8080 (多个用逗号分隔)")
			ui.Text(c, "支持协议: socks://, http://, redir://。可同时监听多个本地地址，以逗号分隔。").
				FontSize(11).TextColor(p.textMuted)
		})

		ui.Column(c).Gap(4).Children(func() {
			labeledInput(c, p, "inp-proxy", "远端代理地址 (proxy)", &a.editor.proxyInput, "https://user:pass@example.com:443 或 quic://user:pass@example.com")
			ui.Text(c, "支持 https://、quic://，支持用逗号串联前置代理链 (如 socks://1.2.3.4:1080,https://example.com)").
				FontSize(11).TextColor(p.textMuted)
		})

		labeledInput(c, p, "inp-concurrency-basic", "并发连接数 (insecure-concurrency)", &a.editor.concurrencyStr, "默认 1 (建议 1~4)")
		switchRow(c, p, "inp-nopq-basic", "禁用后量子密钥交换 (no-post-quantum)", &a.editor.noPostQuantum)
	})
}

func (a *app) renderEditorAdvancedTab(c *ui.Context, p palette) {
	ui.Column(c).Gap(12).Children(func() {
		ui.Row(c).AlignItems(ui.Center).Gap(12).Children(func() {
			ui.Box(c).Grow(1).Children(func() {
				labeledInput(c, p, "inp-tunnel-timeout", "隧道超时秒数 (tunnel-timeout)", &a.editor.tunnelTimeout, "默认留空")
			})
			ui.Box(c).Grow(1).Children(func() {
				labeledInput(c, p, "inp-idle-timeout", "空闲超时秒数 (idle-timeout)", &a.editor.idleTimeout, "默认留空")
			})
		})

		labeledInput(c, p, "inp-extra-headers", "自定义请求头 (extra-headers)", &a.editor.extraHeaders, "Header1: Value1; Header2: Value2")

		ui.Row(c).AlignItems(ui.Center).Gap(12).Children(func() {
			ui.Box(c).Grow(1).Children(func() {
				labeledInput(c, p, "inp-host-rules", "域名解析规则 (host-resolver-rules)", &a.editor.hostRules, "MAP example.com 1.2.3.4")
			})
			ui.Box(c).Grow(1).Children(func() {
				labeledInput(c, p, "inp-resolver-range", "虚拟解析网段 (resolver-range)", &a.editor.resolverRange, "例如: 100.64.0.0/10")
			})
		})

		switchRow(c, p, "inp-enable-log", "启用核心标准日志 (--log)", &a.editor.enableLog)
		labeledInput(c, p, "inp-log-file", "日志文件路径 (可选，留空输出到实时日志面板)", &a.editor.logFile, "留空则输出到实时日志面板")

		ui.Row(c).AlignItems(ui.Center).Gap(12).Children(func() {
			ui.Box(c).Grow(1).Children(func() {
				labeledInput(c, p, "inp-net-log", "NetLog 路径 (log-net-log)", &a.editor.logNetLog, "用于 Chrome NetLog 调试")
			})
			ui.Box(c).Grow(1).Children(func() {
				labeledInput(c, p, "inp-ssl-key-log", "SSL KeyLog 路径 (ssl-key-log-file)", &a.editor.sslKeyLogFile, "用于 Wireshark 解密调试")
			})
		})

		labeledInput(c, p, "inp-extra-json", "附加 JSON 字段 (extraJson)", &a.editor.extraJSON, `例如: {"padding": true}`)
	})
}

func (a *app) renderEditorPreviewTab(c *ui.Context, p palette) {
	svc, err := a.buildServiceFromEditor()
	if err != nil {
		ui.Row(c).PaddingX(12).PaddingY(10).Radius(8).Background(p.redBg).Children(func() {
			ui.Text(c, "配置校验未通过: "+err.Error()).FontSize(12).TextColor(p.red)
		})
		return
	}
	rawJSON, err := svc.ToConfigJSON()
	if err != nil {
		ui.Row(c).PaddingX(12).PaddingY(10).Radius(8).Background(p.redBg).Children(func() {
			ui.Text(c, "生成 JSON 失败: "+err.Error()).FontSize(12).TextColor(p.red)
		})
		return
	}

	v2rayURI := svc.V2rayNSocksURI()
	naiveURI := svc.NaiveShareURI()

	ui.Column(c).Gap(10).Children(func() {
		ui.Column(c).Gap(4).Padding(10).Radius(8).Background(p.codeBg).Border(1, p.borderSubtle).Children(func() {
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
				ui.Text(c, "本地接入链接").FontSize(11).FontWeight(600).TextColor(p.textMuted)
				if actionChip(c.Key("preview-copy-local"), p, iconCopy, "复制", false).Clicked() {
					a.writeClipboard(v2rayURI, "已复制本地链接")
				}
			})
			ui.Text(c, v2rayURI).FontSize(12).FontWeight(500).TextColor(p.accent)
		})

		if naiveURI != "" {
			ui.Column(c).Gap(4).Padding(10).Radius(8).Background(p.codeBg).Border(1, p.borderSubtle).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
					ui.Text(c, "NaiveProxy 节点分享链接").FontSize(11).FontWeight(600).TextColor(p.textMuted)
					if actionChip(c.Key("preview-copy-naive"), p, iconCopy, "复制", false).Clicked() {
						a.writeClipboard(naiveURI, "已复制 Naive 分享链接")
					}
				})
				ui.Text(c, naiveURI).FontSize(12).TextColor(p.text)
			})
		}

		ui.Column(c).Gap(6).Padding(10).Radius(8).Background(p.codeBg).Border(1, p.borderSubtle).Children(func() {
			ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Children(func() {
				ui.Text(c, "生成的 config.json").FontSize(11).FontWeight(600).TextColor(p.textMuted)
				if actionChip(c.Key("preview-copy-json"), p, iconCopy, "复制 JSON", false).Clicked() {
					a.writeClipboard(string(rawJSON), "已复制 config.json")
				}
			})
			ui.Text(c, string(rawJSON)).FontSize(11).TextColor(p.text)
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
		a.toast("已创建服务: " + svc.Name)
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
			a.toast("已保存并重启服务: " + svc.Name)
		} else {
			a.toast("已保存服务配置: " + svc.Name)
		}
	}
	a.saveState()
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
	ui.DialogBase(c.Key("import-dialog"), &a.importDlg.open, func(backdrop, panel ui.Element) {
		backdrop.Background(ui.RGBA(0, 0, 0, 0.5))
		panel.Column().
			Width(540).
			Padding(20).Gap(14).
			Radius(14).Background(p.card).Border(1, p.border).
			Shadow(0, 12, 36, 0, ui.RGBA(0, 0, 0, 0.3)).
			Children(func() {
				ui.Text(c, "导入服务配置").FontSize(16).FontWeight(700).TextColor(p.text)
				ui.Text(c, "支持多行批量导入（每行一条），格式仅支持 https://user:pass@example.com、naive+https://user:pass@example.com 或完整的 config.json").
					FontSize(12).TextColor(p.textMuted)

				if a.importDlg.errText != "" {
					ui.Row(c).PaddingX(12).PaddingY(8).Radius(8).Background(p.redBg).Children(func() {
						ui.Text(c, a.importDlg.errText).FontSize(12).TextColor(p.red)
					})
				}

				labeledTextArea(
					c, p,
					"import-raw-input",
					"链接或完整 config.json（支持多行粘贴）",
					&a.importDlg.rawInput,
					"https://user:pass@example.com#Node-1\nnaive+https://user:pass@example.com:443?security=tls&sni=sni.example.com#Node-2\n或粘贴完整的 config.json",
					5, 10,
				)

				ui.Row(c).AlignItems(ui.Center).Justify(ui.SpaceBetween).Padding(6, 0, 0, 0).Children(func() {
					if actionChip(c.Key("import-read-clip"), p, iconPaste, "读取剪贴板", false).Clicked() {
						a.importDlg.rawInput = strings.TrimSpace(a.readClipboard())
					}

					ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
						if ui.Button(c.Key("import-cancel"), "取消").Clicked() {
							a.importDlg.open = false
							a.importDlg.errText = ""
						}
						if ui.PrimaryButton(c.Key("import-confirm"), "解析并导入").Clicked() {
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
			a.importDlg.errText = fmt.Sprintf("服务 %q 配置不完整: %v", svcs[i].Name, err)
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
		a.toast("成功导入服务: " + svcs[0].Name)
	} else {
		a.toast(fmt.Sprintf("成功批量导入 %d 个服务", len(svcs)))
	}
}

// Delete Confirmation Dialog
func (a *app) openDeleteServiceDialog(svc config.Service) {
	a.deleteDlg.open = true
	a.deleteDlg.svcID = svc.ID
	a.deleteDlg.svcName = svc.Name
}

func (a *app) renderDeleteDialog(c *ui.Context, p palette) {
	ui.DialogBase(c.Key("delete-dialog"), &a.deleteDlg.open, func(backdrop, panel ui.Element) {
		backdrop.Background(ui.RGBA(0, 0, 0, 0.5))
		panel.Column().
			Width(400).
			Padding(20).Gap(14).
			Radius(14).Background(p.card).Border(1, p.border).
			Shadow(0, 12, 36, 0, ui.RGBA(0, 0, 0, 0.3)).
			Children(func() {
				ui.Text(c, "确认删除服务").FontSize(16).FontWeight(700).TextColor(p.text)
				ui.Text(c, fmt.Sprintf("确定要删除服务「%s」吗？如果该服务正在运行，将会自动停止。", a.deleteDlg.svcName)).
					FontSize(13).TextColor(p.textMuted)

				ui.Row(c).AlignItems(ui.Center).Justify(ui.End).Gap(8).Padding(6, 0, 0, 0).Children(func() {
					if ui.Button(c.Key("delete-cancel"), "取消").Clicked() {
						a.deleteDlg.open = false
					}
					if primaryPillButton(c.Key("delete-confirm"), p, iconTrash, "确认删除", p.red, false).Clicked() {
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
	a.rebuildTrayMenu()
	a.toast("已删除服务: " + name)
}
