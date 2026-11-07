package app

import (
	"fmt"
	"testing"

	"naive-client/internal/config"
	"naive-client/locales"
)

// Tests that when a service fails to start due to missing core, the card displays localized error,
// allows copying the error message, and provides one-click download and settings guidance buttons.
func TestServiceCard_ErrorBannerCopyAndMissingCoreGuidance(t *testing.T) {
	p1 := freeLocalPort(t)
	svc := config.Service{
		ID:       "svc-err-test",
		Name:     "Test-Missing-Core",
		Protocol: config.ProtoNaive,
		Engine:   config.EngineSidecar,
		Listens:  []string{fmt.Sprintf("socks://127.0.0.1:%d", p1)},
		Proxies:  []string{"https://user:pass@proxy.example.com"},
	}

	a, tt, _ := newTestApp(t, []config.Service{svc})

	// Inject a missing core error into the runner manager
	a.mgr.SetError("svc-err-test", "未找到 naive 核心文件，请先点击顶部栏下载安装")
	tt.Frame()

	// 1. Verify localized missing core error text appears in Simplified Chinese
	cat := a.catalog()
	if !tt.HasText(cat.CoreMissingNaiveError()) {
		t.Fatalf("expected card error banner to display localized missing core text %q, got texts: %v",
			cat.CoreMissingNaiveError(), tt.Texts())
	}

	// 2. Verify "前往设置" button switches tab to TabSettings
	if err := tt.Click("btn-goto-settings-svc-err-test"); err != nil {
		t.Fatalf("failed to click go to settings button: %v", err)
	}
	tt.Frame()
	if a.activeTab != TabSettings {
		t.Fatalf("expected activeTab to be TabSettings, got %v", a.activeTab)
	}

	// Switch back to TabNodes
	a.activeTab = TabNodes
	tt.Frame()

	// 3. Verify copy error button copies the error and toasts feedback
	if err := tt.Click("btn-copy-error-svc-err-test"); err != nil {
		t.Fatalf("failed to click copy error button: %v", err)
	}
	tt.Frame()

	if a.clipboardMem == "" {
		t.Fatalf("expected error message to be copied to clipboard")
	}
	if !tt.HasText(cat.ToastErrorCopied()) {
		t.Fatalf("expected toast %q after copying error, got texts: %v", cat.ToastErrorCopied(), tt.Texts())
	}

	// 4. Verify clicking install core button triggers seamless update
	if err := tt.Click("btn-install-core-svc-err-test"); err != nil {
		t.Fatalf("failed to click install core button: %v", err)
	}
	tt.Frame()
	if !a.updatingCore {
		t.Fatalf("expected updatingCore to be true after clicking install core button")
	}

	// 5. Test English locale switching on the error banner
	a.state.Language = locales.LangEn
	a.applyLanguagePolicy()
	tt.Frame()

	enCat := a.catalog()
	if !tt.HasText(enCat.CoreMissingNaiveError()) {
		t.Fatalf("expected English missing core error %q, got texts: %v",
			enCat.CoreMissingNaiveError(), tt.Texts())
	}
}

// Tests that tailnet error banner allows copying the error message.
func TestTailnetErrorBanner_CopyError(t *testing.T) {
	a, tt, _ := newTestApp(t, []config.Service{})

	a.activeTab = TabTailnet
	tt.Frame()

	// Set an error on tailnet manager
	testErr := "tailscale auth failed: key expired"
	a.tailnetMgr.SetError(testErr)
	tt.Frame()

	if !tt.HasText(testErr) {
		t.Fatalf("expected tailnet error banner to display %q, got texts: %v", testErr, tt.Texts())
	}

	// Click copy tailnet error
	if err := tt.Click("btn-copy-tailnet-error"); err != nil {
		t.Fatalf("failed to click btn-copy-tailnet-error: %v", err)
	}
	tt.Frame()

	if a.clipboardMem != testErr {
		t.Fatalf("expected clipboard = %q, got %q", testErr, a.clipboardMem)
	}
	if !tt.HasText(a.catalog().ToastErrorCopied()) {
		t.Fatalf("expected toast %q, got texts: %v", a.catalog().ToastErrorCopied(), tt.Texts())
	}
}
