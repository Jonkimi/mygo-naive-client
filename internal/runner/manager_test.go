package runner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"naive-client/internal/config"
)

func writeFakeNaiveScript(t *testing.T, dir string, exitImmediately bool) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell script test on unix")
	}
	scriptPath := filepath.Join(dir, "naive")
	body := "#!/bin/sh\necho \"naive started with $1\"\n"
	if exitImmediately {
		body += "exit 1\n"
	} else {
		body += "trap 'exit 0' INT TERM\nwhile true; do sleep 0.1; done\n"
	}
	if err := os.WriteFile(scriptPath, []byte(body), 0o755); err != nil {
		t.Fatalf("failed to write fake script: %v", err)
	}
	return scriptPath
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func TestManagerConcurrentStartAndStopAll(t *testing.T) {
	dir := t.TempDir()
	bin := writeFakeNaiveScript(t, dir, false)

	mgr := NewManager(bin, dir, nil)
	p1 := freePort(t)
	p2 := freePort(t)

	svc1 := config.DefaultService("s1", p1)
	svc2 := config.DefaultService("s2", p2)

	if err := mgr.Start(svc1); err != nil {
		t.Fatalf("Start svc1 failed: %v", err)
	}
	if err := mgr.Start(svc2); err != nil {
		t.Fatalf("Start svc2 failed: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if mgr.StatusOf("s1").State == StateRunning && mgr.StatusOf("s2").State == StateRunning {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if mgr.StatusOf("s1").State != StateRunning || mgr.StatusOf("s2").State != StateRunning {
		t.Fatalf("expected both s1 and s2 running, got %v and %v", mgr.StatusOf("s1"), mgr.StatusOf("s2"))
	}

	stopped := mgr.StopAll()
	if len(stopped) != 2 {
		t.Errorf("StopAll returned %d services, want 2", len(stopped))
	}
	if mgr.StatusOf("s1").State != StateStopped || mgr.StatusOf("s2").State != StateStopped {
		t.Errorf("expected both stopped after StopAll, got %v and %v", mgr.StatusOf("s1").State, mgr.StatusOf("s2").State)
	}
}

func TestManagerExternalProxyLifecycle(t *testing.T) {
	// Manager with empty binPath (no naive binary required)
	mgr := NewManager("", t.TempDir(), nil)

	extSvc := config.Service{
		ID:          "ext-node",
		Name:        "External Node",
		Kind:        config.KindExternalProxy,
		ExternalURI: "socks5://127.0.0.1:1080",
	}

	if err := mgr.Start(extSvc); err != nil {
		t.Fatalf("Start external proxy failed: %v", err)
	}

	st := mgr.StatusOf("ext-node")
	if st.State != StateRunning {
		t.Fatalf("expected StateRunning, got %v", st.State)
	}

	running := mgr.RunningServices()
	if len(running) != 1 || running[0].ID != "ext-node" {
		t.Fatalf("expected RunningServices to contain ext-node, got: %+v", running)
	}

	if err := mgr.Stop("ext-node"); err != nil {
		t.Fatalf("Stop external proxy failed: %v", err)
	}

	st = mgr.StatusOf("ext-node")
	if st.State != StateStopped {
		t.Fatalf("expected StateStopped after stop, got %v", st.State)
	}
}

func TestManagerCrashBackoffAndPortCheck(t *testing.T) {
	dir := t.TempDir()
	bin := writeFakeNaiveScript(t, dir, true)

	mgr := NewManager(bin, dir, nil)
	mgr.BackoffMin = 10 * time.Millisecond

	port := freePort(t)
	svc := config.DefaultService("crash-svc", port)

	// Occupy port first to test pre-check
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	if err := mgr.Start(svc); err == nil {
		_ = ln.Close()
		t.Fatal("expected Start to fail when port is already occupied")
	}
	_ = ln.Close()

	// Now start crashing service and verify it transitions to StateError after maxCrashRestarts
	if err := mgr.Start(svc); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if mgr.StatusOf("crash-svc").State == StateError {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	st := mgr.StatusOf("crash-svc")
	if st.State != StateError {
		t.Fatalf("expected StateError after crash retries, got %v", st.State)
	}
	if !strings.Contains(st.LastError, "已重试 3 次") {
		t.Errorf("unexpected LastError: %q", st.LastError)
	}
}

// Check that ProbeServiceCtx and DownloadTestServiceCtx cancel immediately on context cancellation.
func TestManagerProbeAndDownloadCancel(t *testing.T) {
	dir := t.TempDir()
	bin := writeFakeNaiveScript(t, dir, false)

	mgr := NewManager(bin, dir, nil)
	p := freePort(t)
	svc := config.DefaultService("cancel-svc", p)

	if err := mgr.Start(svc); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer mgr.StopAll()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if mgr.StatusOf("cancel-svc").State == StateRunning {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := mgr.ProbeServiceCtx(ctx, svc, "http://127.0.0.1:9")
	if err == nil {
		t.Fatal("expected error from canceled ProbeServiceCtx, got nil")
	}
	if mgr.StatusOf("cancel-svc").Probing {
		t.Error("expected Probing to be false after cancel")
	}

	_, err = mgr.DownloadTestServiceCtx(ctx, svc, "http://127.0.0.1:9")
	if err == nil {
		t.Fatal("expected error from canceled DownloadTestServiceCtx, got nil")
	}
	if mgr.StatusOf("cancel-svc").SpeedTesting {
		t.Error("expected SpeedTesting to be false after cancel")
	}
}

// Tests that OnServiceStarted callback is dispatched on service launch for cold-start auto probing.
func TestManager_OnServiceStartedAndProbeCallbacks(t *testing.T) {
	dir := t.TempDir()
	bin := writeFakeNaiveScript(t, dir, false)
	mgr := NewManager(bin, dir, nil)

	var startedSvcID string
	var startedMu sync.Mutex
	mgr.OnServiceStarted = func(svc config.Service) {
		startedMu.Lock()
		startedSvcID = svc.ID
		startedMu.Unlock()
	}

	p := freePort(t)
	svc := config.DefaultService("cb-svc", p)
	if err := mgr.Start(svc); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer mgr.StopAll()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		startedMu.Lock()
		id := startedSvcID
		startedMu.Unlock()
		if id == "cb-svc" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	startedMu.Lock()
	id := startedSvcID
	startedMu.Unlock()
	if id != "cb-svc" {
		t.Fatalf("expected OnServiceStarted called with cb-svc, got %q", id)
	}

	var failedID string
	var failedErr error
	var failedMu sync.Mutex
	mgr.OnProbeFailure = func(id string, err error) {
		failedMu.Lock()
		failedID = id
		failedErr = err
		failedMu.Unlock()
	}

	// Probe against an unreachable local endpoint should invoke OnProbeFailure
	_, err := mgr.ProbeServiceCtx(context.Background(), svc, "http://127.0.0.1:9")
	if err == nil {
		t.Fatal("expected probe error on unreachable port, got nil")
	}
	failedMu.Lock()
	if failedID != "cb-svc" || failedErr == nil {
		t.Fatalf("expected OnProbeFailure called for cb-svc, got id=%q err=%v", failedID, failedErr)
	}
	failedMu.Unlock()
}

// Tests that EngineSingBox services run without child processes and delegate probing/download tests to ServiceDialer.
func TestManager_EngineSingBoxLifecycleAndProbing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	testServerURL := fmt.Sprintf("http://127.0.0.1:%d/probe", ln.Addr().(*net.TCPAddr).Port)
	downloadServerURL := fmt.Sprintf("http://127.0.0.1:%d/download", ln.Addr().(*net.TCPAddr).Port)

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 1024)
				n, _ := conn.Read(buf)
				reqStr := string(buf[:n])
				if strings.Contains(reqStr, "HEAD /probe") {
					_, _ = conn.Write([]byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"))
				} else if strings.Contains(reqStr, "GET /download") {
					payload := strings.Repeat("0123456789abcdef", 8192) // 128KB
					resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(payload), payload)
					_, _ = conn.Write([]byte(resp))
				}
			}(c)
		}
	}()

	dir := t.TempDir()
	mgr := NewManager("/nonexistent/bin/naive", dir, nil)

	svc := config.Service{
		ID:         "singbox-node-1",
		Name:       "SingBox VLESS Node",
		Protocol:   config.ProtoVLESS,
		Engine:     config.EngineSingBox,
		Server:     "vless.example.com",
		ServerPort: 443,
		UUID:       "00000000-0000-0000-0000-000000000001",
	}

	// 1. Start: should immediately be running without needing any external binary
	if err := mgr.Start(svc); err != nil {
		t.Fatalf("Start EngineSingBox failed: %v", err)
	}
	if mgr.StatusOf(svc.ID).State != StateRunning {
		t.Fatalf("expected StateRunning, got %v", mgr.StatusOf(svc.ID).State)
	}

	// 2. Setup ServiceDialer
	dialerCalled := false
	mgr.ServiceDialer = func(ctx context.Context, s config.Service, network, addr string) (net.Conn, error) {
		if s.ID == svc.ID {
			dialerCalled = true
		}
		var d net.Dialer
		return d.DialContext(ctx, "tcp", ln.Addr().String())
	}

	// 3. ProbeServiceCtx delegates to ServiceDialer
	rtt, err := mgr.ProbeServiceCtx(context.Background(), svc, testServerURL)
	if err != nil {
		t.Fatalf("ProbeServiceCtx failed: %v", err)
	}
	if !dialerCalled || rtt <= 0 {
		t.Fatalf("expected dialer called and positive rtt, got dialerCalled=%v, rtt=%v", dialerCalled, rtt)
	}

	// 4. DownloadTestServiceCtx delegates to ServiceDialer
	bps, err := mgr.DownloadTestServiceCtx(context.Background(), svc, downloadServerURL)
	if err != nil {
		t.Fatalf("DownloadTestServiceCtx failed: %v", err)
	}
	if bps <= 0 {
		t.Fatalf("expected positive bps, got %v", bps)
	}

	// 5. Stop
	if err := mgr.Stop(svc.ID); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	if mgr.StatusOf(svc.ID).State != StateStopped {
		t.Fatalf("expected StateStopped, got %v", mgr.StatusOf(svc.ID).State)
	}
}

// Tests that PreStartChecker rejects service startup before transitioning to running state.
func TestManager_PreStartCheckerRejection(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager("/nonexistent/bin/naive", dir, nil)
	mgr.PreStartChecker = func(svc config.Service) error {
		return errors.New("gateway engine startup failed")
	}

	startedCalled := false
	mgr.OnServiceStarted = func(svc config.Service) {
		startedCalled = true
	}

	svc := config.Service{
		ID:         "singbox-node-2",
		Name:       "SingBox Node",
		Protocol:   config.ProtoVLESS,
		Engine:     config.EngineSingBox,
		Server:     "vless.example.com",
		ServerPort: 443,
		UUID:       "00000000-0000-0000-0000-000000000002",
	}

	err := mgr.Start(svc)
	if err == nil || !strings.Contains(err.Error(), "gateway engine startup failed") {
		t.Fatalf("expected PreStartChecker error, got %v", err)
	}
	if startedCalled {
		t.Fatalf("expected OnServiceStarted not to be called on failure")
	}
	st := mgr.StatusOf(svc.ID)
	if st.State == StateRunning {
		t.Fatalf("expected State not to be StateRunning, got %v", st.State)
	}
	if !strings.Contains(st.LastError, "gateway engine startup failed") {
		t.Fatalf("expected LastError to record PreStartChecker failure, got %q", st.LastError)
	}
}
