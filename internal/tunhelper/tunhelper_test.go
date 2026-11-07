package tunhelper

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// Tests that a file descriptor can be passed across a Unix Domain Socket via SCM_RIGHTS.
func TestUnixSocket_PassFD(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix Domain Socket SCM_RIGHTS is not supported on Windows")
	}

	tempDir := t.TempDir()
	sockPath := filepath.Join(tempDir, "test-fd.sock")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// 1. Create a pipe to test FD passing
	rPipe, wPipe, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe failed: %v", err)
	}
	defer rPipe.Close()
	defer wPipe.Close()

	// 2. Start receiver
	recCh := make(chan *ReceivedDevice, 1)
	errCh := make(chan error, 1)
	go func() {
		dev, err := ListenForFD(ctx, sockPath)
		if err != nil {
			errCh <- err
			return
		}
		recCh <- dev
	}()

	// Allow listener to bind
	time.Sleep(50 * time.Millisecond)

	// 3. Sender sends wPipe's FD with name "utun99"
	go func() {
		if err := SendFD(sockPath, int(wPipe.Fd()), "utun99"); err != nil {
			errCh <- err
		}
	}()

	var received *ReceivedDevice
	select {
	case err := <-errCh:
		t.Fatalf("FD passing failed: %v", err)
	case dev := <-recCh:
		received = dev
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for FD")
	}

	if received == nil {
		t.Fatalf("received device is nil")
	}
	defer received.Close()

	if received.Name != "utun99" {
		t.Errorf("expected device name utun99, got %q", received.Name)
	}
	if received.FD <= 0 {
		t.Errorf("expected positive received FD, got %d", received.FD)
	}

	// 4. Verify the transferred FD is functional: write to it, read from rPipe
	file := os.NewFile(uintptr(received.FD), "transferred-pipe")
	defer file.Close()

	testMsg := "hello via scm_rights"
	if _, err := file.Write([]byte(testMsg)); err != nil {
		t.Fatalf("write to transferred FD failed: %v", err)
	}

	buf := make([]byte, len(testMsg))
	if _, err := io.ReadFull(rPipe, buf); err != nil {
		t.Fatalf("read from pipe failed: %v", err)
	}
	if string(buf) != testMsg {
		t.Errorf("expected %q, got %q", testMsg, string(buf))
	}
}

// Tests helper CLI argument parsing.
func TestIsHelper(t *testing.T) {
	if !IsHelper([]string{"naive-client", "--tun-helper", "--sock", "/tmp/tun.sock"}) {
		t.Errorf("expected IsHelper to be true when --tun-helper is present")
	}
	if IsHelper([]string{"naive-client", "--verbose"}) {
		t.Errorf("expected IsHelper to be false when --tun-helper is absent")
	}
}

// Tests command building for privileged execution across platforms.
func TestBuildPrivilegedCommand(t *testing.T) {
	cmd, args := BuildPrivilegedCommand("/opt/naive-client", "/tmp/tun.sock", false)
	if len(args) == 0 {
		t.Fatalf("expected non-empty args")
	}
	switch runtime.GOOS {
	case "darwin":
		if cmd != "osascript" {
			t.Errorf("expected osascript on darwin, got %s", cmd)
		}
	case "linux":
		if cmd != "pkexec" {
			t.Errorf("expected pkexec on linux, got %s", cmd)
		}
	default:
		// Windows or other
	}

	// When already running as root (isRoot = true), should execute directly
	directCmd, directArgs := BuildPrivilegedCommand("/opt/naive-client", "/tmp/tun.sock", true)
	if directCmd != "/opt/naive-client" {
		t.Errorf("expected direct binary execution when root, got %s", directCmd)
	}
	if len(directArgs) < 3 || directArgs[0] != "--tun-helper" || directArgs[2] != "/tmp/tun.sock" {
		t.Errorf("unexpected direct args: %v", directArgs)
	}
}

// Tests HelperClient coordinates socket listening, executor invocation, and device retrieval.
func TestHelperClient_RequestDevice(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix Domain Socket SCM_RIGHTS is not supported on Windows")
	}

	rPipe, wPipe, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer rPipe.Close()
	defer wPipe.Close()

	client := &HelperClient{
		IsRoot: true,
		Executor: func(ctx context.Context, name string, args ...string) error {
			sockPath := ""
			for i := 0; i < len(args)-1; i++ {
				if args[i] == "--sock" {
					sockPath = args[i+1]
					break
				}
			}
			if sockPath == "" {
				return errors.New("no sock path in args")
			}
			time.Sleep(20 * time.Millisecond)
			return SendFD(sockPath, int(wPipe.Fd()), "utun88")
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	dev, err := client.RequestDevice(ctx, "/path/to/bin")
	if err != nil {
		t.Fatalf("RequestDevice failed: %v", err)
	}
	defer dev.Close()

	if dev.Name != "utun88" {
		t.Errorf("expected name utun88, got %q", dev.Name)
	}
}

