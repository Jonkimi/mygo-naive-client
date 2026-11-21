//go:build darwin

package boxengine

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"naive-client/internal/blocker"
	"naive-client/internal/telemetry"
)

func TestFindDarwinConnectionOwnerByProcInfo_TCPAndUDP(t *testing.T) {
	selfPath, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable failed: %v", err)
	}
	selfBase := filepath.Base(selfPath)

	// 1. TCP IPv4
	tcp4Ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tcp4 listen failed: %v", err)
	}
	defer tcp4Ln.Close()
	tcp4Conn, err := net.Dial("tcp4", tcp4Ln.Addr().String())
	if err != nil {
		t.Fatalf("tcp4 dial failed: %v", err)
	}
	defer tcp4Conn.Close()

	src4 := tcp4Conn.LocalAddr().(*net.TCPAddr).AddrPort()
	dst4 := tcp4Conn.RemoteAddr().(*net.TCPAddr).AddrPort()
	owner4, err := findDarwinConnectionOwnerByProcInfo("tcp", src4, dst4)
	if err != nil {
		t.Fatalf("findDarwinConnectionOwnerByProcInfo(tcp4) failed: %v", err)
	}
	if !strings.HasSuffix(owner4.ProcessPath, "/"+selfBase) {
		t.Fatalf("expected tcp4 owner ending in /%s, got %q", selfBase, owner4.ProcessPath)
	}

	// Verify undersized internal PID/FD buffers expand and retry without truncating results.
	tinyFinder := &darwinProcFinder{
		ttl:    darwinProcSnapshotTTL,
		pidBuf: make([]int32, 4),
		fdBuf:  make([]byte, 16),
	}
	if got := tinyFinder.readPIDFDsLocked(int32(os.Getpid())); len(got) == 0 || len(tinyFinder.fdBuf) <= 16 {
		t.Fatalf("expected undersized fdBuf to expand and read FDs, got len(fds)=%d len(fdBuf)=%d", len(got), len(tinyFinder.fdBuf))
	}
	ownerResized, err := tinyFinder.find("tcp", src4, dst4)
	if err != nil {
		t.Fatalf("tinyFinder.find(tcp4) after buffer growth failed: %v", err)
	}
	if !strings.HasSuffix(ownerResized.ProcessPath, "/"+selfBase) {
		t.Fatalf("expected resized finder owner ending in /%s, got %q", selfBase, ownerResized.ProcessPath)
	}

	// 2. TCP IPv6
	if tcp6Ln, err := net.Listen("tcp6", "[::1]:0"); err == nil {
		defer tcp6Ln.Close()
		tcp6Conn, err := net.Dial("tcp6", tcp6Ln.Addr().String())
		if err != nil {
			t.Fatalf("tcp6 dial failed: %v", err)
		}
		defer tcp6Conn.Close()

		src6 := tcp6Conn.LocalAddr().(*net.TCPAddr).AddrPort()
		dst6 := tcp6Conn.RemoteAddr().(*net.TCPAddr).AddrPort()
		owner6, err := findDarwinConnectionOwnerByProcInfo("tcp", src6, dst6)
		if err != nil {
			t.Fatalf("findDarwinConnectionOwnerByProcInfo(tcp6) failed: %v", err)
		}
		if !strings.HasSuffix(owner6.ProcessPath, "/"+selfBase) {
			t.Fatalf("expected tcp6 owner ending in /%s, got %q", selfBase, owner6.ProcessPath)
		}
	}

	// 3. UDP wildcard bind fallback
	udp4, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("udp4 listen failed: %v", err)
	}
	defer udp4.Close()
	udpPort := udp4.LocalAddr().(*net.UDPAddr).Port
	ownerUDP, err := findDarwinConnectionOwnerByProcInfo(
		"udp",
		netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(udpPort)),
		netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 5353),
	)
	if err != nil {
		t.Fatalf("findDarwinConnectionOwnerByProcInfo(udp4) failed: %v", err)
	}
	if !strings.HasSuffix(ownerUDP.ProcessPath, "/"+selfBase) {
		t.Fatalf("expected udp4 owner ending in /%s, got %q", selfBase, ownerUDP.ProcessPath)
	}
}

// Regression: on macOS, net.inet.{tcp,udp}.pcblist_n hides other processes' sockets from
// unprivileged binaries, causing sing-box's default darwin searcher to miss external client
// apps (e.g. Chrome/Firefox/curl) while only seeing same-PID sockets in tests.
// Verify that an external child process connecting through mixed-in is identified and logged.
func TestEngine_ExternalProcessIdentification(t *testing.T) {
	curlPath, err := exec.LookPath("curl")
	if err != nil {
		t.Skip("curl not installed")
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	bl := blocker.NewEngine(blocker.Options{})
	eng, err := New(EngineOptions{
		ListenAddr:     "127.0.0.1:0",
		Tracker:        telemetry.NewTracker(),
		FailureMonitor: telemetry.NewFailureMonitor(100),
		Blocker:        bl,
		FinalAction:    "direct",
	})
	if err != nil {
		t.Fatalf("New Engine failed: %v", err)
	}
	if err := eng.Start(); err != nil {
		t.Fatalf("eng.Start failed: %v", err)
	}
	defer func() {
		_ = eng.Close()
	}()

	proxyAddr := fmt.Sprintf("http://127.0.0.1:%d", eng.Port())
	cmd := exec.Command(curlPath, "--silent", "--show-error", "--insecure", "--noproxy", "", "--proxy", proxyAddr, ts.URL+"/ping")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("curl via gateway failed: %v (output=%q)", err, string(out))
	}
	if string(out) != "ok" {
		t.Fatalf("unexpected curl response: %q", string(out))
	}

	deadline := time.Now().Add(500 * time.Millisecond)
	var found bool
	for time.Now().Before(deadline) {
		for _, entry := range bl.Logger().GetEntries(20) {
			if entry.Source == blocker.SourceGateway && entry.Domain == "127.0.0.1" && entry.Process == "curl" {
				if !strings.Contains(entry.ProcessPath, "curl") {
					t.Fatalf("expected ProcessPath to contain curl, got %q", entry.ProcessPath)
				}
				found = true
				break
			}
		}
		if found {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !found {
		t.Fatalf("expected external curl process to be recorded in QueryLogger, got entries: %+v", bl.Logger().GetEntries(20))
	}
}
