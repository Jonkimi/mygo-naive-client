package locales

import (
	"testing"
)

func TestCatalogLanguages(t *testing.T) {
	// English source
	en := In("en")
	if en.NavNodes() != "Nodes" {
		t.Fatalf("expected 'Nodes', got %q", en.NavNodes())
	}
	if en.RunningCount(2, 5) != "Services (2/5 running)" {
		t.Fatalf("expected 'Services (2/5 running)', got %q", en.RunningCount(2, 5))
	}
	if en.RunningCountBadge(1) != "1 Running" {
		t.Fatalf("expected '1 Running', got %q", en.RunningCountBadge(1))
	}
	if en.RunningCountBadge(3) != "3 Running" {
		t.Fatalf("expected '3 Running', got %q", en.RunningCountBadge(3))
	}
	if en.LocalServicesLabel(4) != "Services (4)" {
		t.Fatalf("expected 'Services (4)', got %q", en.LocalServicesLabel(4))
	}
	if en.PresetRuleBlockAds() != "Block Ads" {
		t.Fatalf("expected 'Block Ads', got %q", en.PresetRuleBlockAds())
	}
	if en.PresetRuleAIServices() != "AI Services" {
		t.Fatalf("expected 'AI Services', got %q", en.PresetRuleAIServices())
	}
	if en.PresetRuleStreaming() != "Streaming Services" {
		t.Fatalf("expected 'Streaming Services', got %q", en.PresetRuleStreaming())
	}
	if en.PresetRuleGFW() != "GFW Proxy" {
		t.Fatalf("expected 'GFW Proxy', got %q", en.PresetRuleGFW())
	}
	if en.PresetRuleBypassLan() != "Direct" {
		t.Fatalf("expected 'Direct', got %q", en.PresetRuleBypassLan())
	}
	if en.TagBuiltin() != "Built-in" {
		t.Fatalf("expected 'Built-in', got %q", en.TagBuiltin())
	}
	if en.SidecarsRunning(2) != "2 Sidecars Running" {
		t.Fatalf("expected '2 Sidecars Running', got %q", en.SidecarsRunning(2))
	}
	if en.CoreNewVersion("v1.8.24") != "New Version v1.8.24" {
		t.Fatalf("expected 'New Version v1.8.24', got %q", en.CoreNewVersion("v1.8.24"))
	}

	if en.InsightsProtectionActive() != "Protection Active" {
		t.Fatalf("expected 'Protection Active', got %q", en.InsightsProtectionActive())
	}
	if en.ActionCopyError() != "Copy Error" {
		t.Fatalf("expected 'Copy Error', got %q", en.ActionCopyError())
	}
	if en.CoreMissingNaiveError() != "NaiveProxy core binary not found. Please install the core first." {
		t.Fatalf("expected NaiveProxy core missing error, got %q", en.CoreMissingNaiveError())
	}
	if en.RoutingDnsAlignmentTitle() != "DNS Resolution Strategy" {
		t.Fatalf("expected 'DNS Resolution Strategy', got %q", en.RoutingDnsAlignmentTitle())
	}
	if en.RoutingDnsDescDirect() == "" || en.RoutingDnsDescProxyPort() == "" || en.RoutingDnsDescTun() == "" {
		t.Fatalf("expected DNS descriptions to be present in en")
	}
	if en.DnsDomesticBadge() != "DoH: Domestic Direct" {
		t.Fatalf("expected 'DoH: Domestic Direct', got %q", en.DnsDomesticBadge())
	}

	// Simplified Chinese
	zh := In("zh-Hans")
	if zh.NavNodes() != "节点" {
		t.Fatalf("expected '节点', got %q", zh.NavNodes())
	}
	if zh.RunningCount(2, 5) != "本地服务 (2/5 运行中)" {
		t.Fatalf("expected '本地服务 (2/5 运行中)', got %q", zh.RunningCount(2, 5))
	}
	if zh.RunningCountBadge(1) != "1 个运行中" {
		t.Fatalf("expected '1 个运行中', got %q", zh.RunningCountBadge(1))
	}
	if zh.LocalServicesLabel(4) != "本地服务 (4)" {
		t.Fatalf("expected '本地服务 (4)', got %q", zh.LocalServicesLabel(4))
	}
	if zh.PresetRuleBlockAds() != "广告拦截" {
		t.Fatalf("expected '广告拦截', got %q", zh.PresetRuleBlockAds())
	}
	if zh.PresetRuleAIServices() != "AI 服务" {
		t.Fatalf("expected 'AI 服务', got %q", zh.PresetRuleAIServices())
	}
	if zh.PresetRuleStreaming() != "流媒体服务" {
		t.Fatalf("expected '流媒体服务', got %q", zh.PresetRuleStreaming())
	}
	if zh.PresetRuleGFW() != "GFW 专线" {
		t.Fatalf("expected 'GFW 专线', got %q", zh.PresetRuleGFW())
	}
	if zh.PresetRuleBypassLan() != "直连" {
		t.Fatalf("expected '直连', got %q", zh.PresetRuleBypassLan())
	}
	if zh.TagBuiltin() != "内置" {
		t.Fatalf("expected '内置', got %q", zh.TagBuiltin())
	}
	if zh.SidecarsRunning(2) != "2 个 Sidecar 运行中" {
		t.Fatalf("expected '2 个 Sidecar 运行中', got %q", zh.SidecarsRunning(2))
	}
	if zh.CoreNewVersion("v1.8.24") != "新版本 v1.8.24" {
		t.Fatalf("expected '新版本 v1.8.24', got %q", zh.CoreNewVersion("v1.8.24"))
	}
	if zh.InsightsProtectionActive() != "防护运行中" {
		t.Fatalf("expected '防护运行中', got %q", zh.InsightsProtectionActive())
	}
	if zh.ActionCopyError() != "复制错误" {
		t.Fatalf("expected '复制错误', got %q", zh.ActionCopyError())
	}
	if zh.CoreMissingNaiveError() != "未找到 NaiveProxy 核心文件，请先下载安装" {
		t.Fatalf("expected NaiveProxy core missing error, got %q", zh.CoreMissingNaiveError())
	}
	if zh.RoutingDnsAlignmentTitle() != "DNS 解析联动策略" {
		t.Fatalf("expected 'DNS 解析联动策略', got %q", zh.RoutingDnsAlignmentTitle())
	}
	if zh.RoutingDnsDescDirect() == "" || zh.RoutingDnsDescProxyPort() == "" || zh.RoutingDnsDescTun() == "" {
		t.Fatalf("expected DNS descriptions to be present in zh")
	}
	if zh.DnsDomesticBadge() != "DoH: 国内直连" {
		t.Fatalf("expected 'DoH: 国内直连', got %q", zh.DnsDomesticBadge())
	}
}
