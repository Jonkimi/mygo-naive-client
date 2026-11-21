package blocker

import (
	"testing"
	"time"
)

func TestExtractAppName(t *testing.T) {
	cases := []struct {
		name string
		path string
		want string
	}{
		{
			name: "empty",
			path: "   ",
			want: "",
		},
		{
			name: "chrome helper app bundle",
			path: "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/131.0.6778.86/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper",
			want: "Google Chrome",
		},
		{
			name: "chrome renderer helper app bundle",
			path: "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/131.0.6778.86/Helpers/Google Chrome Helper (Renderer).app/Contents/MacOS/Google Chrome Helper (Renderer)",
			want: "Google Chrome",
		},
		{
			name: "vscode plugin helper app bundle",
			path: "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (Plugin).app/Contents/MacOS/Code Helper (Plugin)",
			want: "Visual Studio Code",
		},
		{
			name: "slack gpu helper app bundle",
			path: "/Applications/Slack.app/Contents/Frameworks/Slack Helper (GPU).app/Contents/MacOS/Slack Helper (GPU)",
			want: "Slack",
		},
		{
			name: "lulu helper app bundle",
			path: "/Applications/LuLu.app/Contents/Library/LoginItems/LuLu Helper.app/Contents/MacOS/LuLu Helper",
			want: "LuLu",
		},
		{
			name: "app internal xpc service",
			path: "/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker",
			want: "Safari",
		},
		{
			name: "app internal resources binary",
			path: "/Applications/Docker.app/Contents/Resources/bin/docker",
			want: "Docker",
		},
		{
			name: "cryptex webkit networking xpc",
			path: "/System/Volumes/Preboot/Cryptexes/App/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking",
			want: "WebKit",
		},
		{
			name: "safari service outside app bundle",
			path: "/System/Library/PrivateFrameworks/SafariSafeBrowsing.framework/Versions/A/com.apple.Safari.SafeBrowsing.Service",
			want: "Safari",
		},
		{
			name: "apple system xpc daemon",
			path: "/usr/libexec/com.apple.nsurlsessiond",
			want: "nsurlsessiond",
		},
		{
			name: "standalone renderer helper name",
			path: "Google Chrome Helper (Renderer)",
			want: "Google Chrome",
		},
		{
			name: "standalone helper name",
			path: "Code Helper",
			want: "Code",
		},
		{
			name: "windows chrome exe",
			path: `C:\Program Files\Google\Chrome\Application\chrome.exe`,
			want: "chrome",
		},
		{
			name: "windows pseudo system process",
			path: ":System",
			want: "System",
		},
		{
			name: "unix cli curl",
			path: "/usr/bin/curl",
			want: "curl",
		},
		{
			name: "homebrew git remote helper",
			path: "/opt/homebrew/bin/git-remote-https",
			want: "git-remote-https",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExtractAppName(tc.path); got != tc.want {
				t.Fatalf("ExtractAppName(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

func TestQueryLogEntrySourceDisplayAndTooltip(t *testing.T) {
	dnsDaemon := QueryLogEntry{
		Source:      SourceDNS,
		Process:     "mDNSResponder",
		ProcessPath: "/usr/sbin/mDNSResponder",
	}
	if got := dnsDaemon.SourceDisplay(); got != "DNS" {
		t.Fatalf("expected DNS display for mDNSResponder, got %q", got)
	}
	if got := dnsDaemon.SourceTooltip(); got != "DNS · /usr/sbin/mDNSResponder" {
		t.Fatalf("unexpected DNS daemon tooltip: %q", got)
	}

	dnsApp := QueryLogEntry{
		Source:      SourceDNS,
		Process:     "curl",
		ProcessPath: "/usr/bin/curl",
	}
	if got := dnsApp.SourceDisplay(); got != "curl" {
		t.Fatalf("expected curl display on DNS entry, got %q", got)
	}

	gwHelper := QueryLogEntry{
		Source:      SourceGateway,
		Network:     "tcp",
		Process:     "Google Chrome",
		ProcessPath: "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/131.0.6778.86/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper",
	}
	if got := gwHelper.SourceDisplay(); got != "Google Chrome" {
		t.Fatalf("expected Google Chrome display, got %q", got)
	}
	wantTip := "Gateway (TCP) · Google Chrome (" + gwHelper.ProcessPath + ")"
	if got := gwHelper.SourceTooltip(); got != wantTip {
		t.Fatalf("SourceTooltip() = %q, want %q", got, wantTip)
	}

	gwFallback := QueryLogEntry{
		Source: SourceGateway,
	}
	if got := gwFallback.SourceDisplay(); got != "Gateway" {
		t.Fatalf("expected Gateway fallback, got %q", got)
	}
	if got := gwFallback.SourceTooltip(); got != "Gateway" {
		t.Fatalf("expected Gateway tooltip fallback, got %q", got)
	}
}

func TestQueryLogger_ProcessFilteringAndFolding(t *testing.T) {
	ql := NewQueryLogger(50)
	ql.SetDedupWindow(0)

	now := time.Now()
	id1 := ql.RecordAtWithChain("telemetry.example.com", SourceGateway, VerdictBlocked, "ad-rule", "ad-rule -> block", now)
	ql.SetProcessByLogID(id1, "", "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper")

	id2 := ql.RecordAtWithChain("telemetry.example.com", SourceGateway, VerdictBlocked, "ad-rule", "ad-rule -> block", now.Add(time.Second))
	ql.SetProcessByLogID(id2, "", "/Applications/Slack.app/Contents/MacOS/Slack")

	id3 := ql.RecordAtWithChain("api.github.com", SourceGateway, VerdictAllowed, "", "final -> direct", now.Add(2*time.Second))
	ql.SetProcessByLogID(id3, "", "/usr/bin/curl")

	// Search by process name across both GetFilteredEntries and GetFoldedEntries
	filtered, _ := ql.GetFilteredEntries("", "chrome", 10)
	if len(filtered) != 1 || filtered[0].ID != id1 || filtered[0].Process != "Google Chrome" {
		t.Fatalf("expected id1 matching 'chrome', got %+v", filtered)
	}

	foldedSearch, _ := ql.GetFoldedEntries("", "slack", 10)
	if len(foldedSearch) != 1 || foldedSearch[0].ID != id2 {
		t.Fatalf("expected id2 matching 'slack' in folded search, got %+v", foldedSearch)
	}

	// Blocked entries with different processes must not fold together
	allFolded, _ := ql.GetFoldedEntries("", "", 10)
	if len(allFolded) != 3 {
		t.Fatalf("expected 3 separate folded rows when processes differ, got %d: %+v", len(allFolded), allFolded)
	}
}
