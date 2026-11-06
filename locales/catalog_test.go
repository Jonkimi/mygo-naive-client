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
	if en.PresetRuleBypassLan() != "Bypass Mainland & LAN" {
		t.Fatalf("expected 'Bypass Mainland & LAN', got %q", en.PresetRuleBypassLan())
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
	if zh.PresetRuleBypassLan() != "绕过大陆及局域网" {
		t.Fatalf("expected '绕过大陆及局域网', got %q", zh.PresetRuleBypassLan())
	}
}
