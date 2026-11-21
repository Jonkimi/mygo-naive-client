package blocker

import (
	"strings"
)

// ExtractAppName normalizes a raw OS executable path into a user-facing
// application or program name, grouping macOS helper bundles and XPC services
// under their parent application.
func ExtractAppName(processPath string) string {
	raw := strings.TrimSpace(processPath)
	if raw == "" {
		return ""
	}
	raw = strings.TrimPrefix(raw, ":")
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	norm := strings.ReplaceAll(raw, "\\", "/")
	parts := strings.Split(norm, "/")
	segments := make([]string, 0, len(parts))
	for _, seg := range parts {
		if seg != "" {
			segments = append(segments, seg)
		}
	}
	if len(segments) == 0 {
		return ""
	}

	// 1. Outermost macOS .app bundle (left-to-right scan) so nested helpers like
	// Google Chrome Helper.app or Code Helper (Plugin).app resolve to the parent app.
	for _, seg := range segments {
		if len(seg) > 4 && strings.EqualFold(seg[len(seg)-4:], ".app") {
			return cleanHelperSuffix(seg[:len(seg)-4])
		}
	}

	base := segments[len(segments)-1]
	lowerBase := strings.ToLower(base)

	// 2. macOS system frameworks and XPC daemons outside .app bundles.
	for _, seg := range segments {
		if strings.EqualFold(seg, "WebKit.framework") {
			return "WebKit"
		}
	}
	if strings.HasPrefix(lowerBase, "com.apple.webkit.") {
		return "WebKit"
	}
	if strings.HasPrefix(lowerBase, "com.apple.safari.") {
		return "Safari"
	}

	for _, seg := range segments {
		if stripped, ok := stripBundleSuffix(seg, ".xpc", ".appex", ".systemextension"); ok {
			return cleanApplePrefix(cleanHelperSuffix(stripped))
		}
	}
	if strings.HasPrefix(lowerBase, "com.apple.") {
		return cleanApplePrefix(base)
	}

	// 3. Executable basename fallback (Windows / Linux / CLI tools).
	if len(base) > 4 && strings.EqualFold(base[len(base)-4:], ".exe") {
		base = base[:len(base)-4]
	}
	return cleanHelperSuffix(base)
}

func stripBundleSuffix(seg string, suffixes ...string) (string, bool) {
	for _, sfx := range suffixes {
		if len(seg) > len(sfx) && strings.EqualFold(seg[len(seg)-len(sfx):], sfx) {
			return seg[:len(seg)-len(sfx)], true
		}
	}
	return "", false
}

func cleanApplePrefix(name string) string {
	if len(name) > len("com.apple.") && strings.EqualFold(name[:len("com.apple.")], "com.apple.") {
		return name[len("com.apple."):]
	}
	return name
}

func cleanHelperSuffix(name string) string {
	if idx := strings.Index(name, " Helper ("); idx > 0 && strings.HasSuffix(name, ")") {
		name = name[:idx]
	}
	if strings.HasSuffix(name, " Helper") && len(name) > len(" Helper") {
		name = strings.TrimSuffix(name, " Helper")
	}
	return name
}

// IsSystemDNSDaemon reports whether processName belongs to an OS-level DNS
// resolver daemon whose identity should not obscure DNS query entries.
func IsSystemDNSDaemon(processName string) bool {
	switch strings.ToLower(strings.TrimSpace(processName)) {
	case "mdnsresponder", "mdnsresponderhelper", "systemd-resolved", "dnsmasq", "unbound":
		return true
	default:
		return false
	}
}

// SourceDisplay returns the label shown in the Insights "Source" column.
func (e QueryLogEntry) SourceDisplay() string {
	if e.Source == SourceDNS {
		if e.Process != "" && !IsSystemDNSDaemon(e.Process) {
			return e.Process
		}
		return string(SourceDNS)
	}
	if e.Process != "" {
		return e.Process
	}
	return string(e.Source)
}

// SourceTooltip returns the detailed stage and executable path shown on hover.
func (e QueryLogEntry) SourceTooltip() string {
	stage := string(e.Source)
	if e.Source == SourceGateway && e.Network != "" {
		stage = "Gateway (" + strings.ToUpper(e.Network) + ")"
	}
	if e.ProcessPath != "" {
		normPath := strings.ReplaceAll(e.ProcessPath, "\\", "/")
		if e.Process != "" && normPath != e.Process && !strings.HasSuffix(normPath, "/"+e.Process) {
			return stage + " · " + e.Process + " (" + e.ProcessPath + ")"
		}
		return stage + " · " + e.ProcessPath
	}
	if e.Process != "" {
		return stage + " · " + e.Process
	}
	return stage
}
