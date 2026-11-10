//go:build darwin

package tunhelper

import (
	"reflect"
	"testing"
)

// Regression guard for stale-DNS cleanup: if the key parser stops recognizing scutil's list
// format, entries left by a killed helper are never removed and system DNS stays broken.
func TestParseScutilKeys(t *testing.T) {
	out := "subKeys [0] = {\n  0 : x\n}\n  subKey [0] = State:/Network/Service/utun5/DNS\n  subKey [1] = State:/Network/Service/utun9/DNS\n"
	want := []string{"State:/Network/Service/utun5/DNS", "State:/Network/Service/utun9/DNS"}
	if got := parseScutilKeys(out); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if got := parseScutilKeys("  No keys found\n"); len(got) != 0 {
		t.Errorf("expected none, got %v", got)
	}
}
