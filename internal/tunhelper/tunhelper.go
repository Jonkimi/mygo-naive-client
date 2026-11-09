package tunhelper

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// ReceivedDevice represents a TUN device file descriptor received from the privileged helper.
type ReceivedDevice struct {
	FD       int
	Name     string
	SockPath string
}

// Close closes the underlying TUN file descriptor.
func (r *ReceivedDevice) Close() error {
	if r.FD > 0 {
		err := closeFD(r.FD)
		r.FD = -1
		return err
	}
	return nil
}

// IsHelper reports whether the command line arguments indicate a helper execution.
func IsHelper(args []string) bool {
	for _, a := range args {
		if a == "--tun-helper" {
			return true
		}
	}
	return false
}

// BuildPrivilegedCommand returns the command and arguments needed to spawn the helper with privileges.
func BuildPrivilegedCommand(helperBin string, sockPath string, isRoot bool) (string, []string) {
	if isRoot {
		return helperBin, []string{"--tun-helper", "--sock", sockPath}
	}
	switch runtime.GOOS {
	case "darwin":
		cmdStr := fmt.Sprintf("%q --tun-helper --sock %q", helperBin, sockPath)
		script := fmt.Sprintf("do shell script %q with administrator privileges", cmdStr)
		return "osascript", []string{"-e", script}
	case "linux":
		return "pkexec", []string{helperBin, "--tun-helper", "--sock", sockPath}
	default:
		return helperBin, []string{"--tun-helper", "--sock", sockPath}
	}
}

// CommandExecutor is used to spawn privileged helper processes.
type CommandExecutor func(ctx context.Context, name string, args ...string) error

func defaultCommandExecutor(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.Run()
}

// HelperClient coordinates launching the privileged helper and receiving the TUN FD.
type HelperClient struct {
	Executor CommandExecutor
	IsRoot   bool
}

// NewClient creates a new HelperClient.
func NewClient() *HelperClient {
	return &HelperClient{
		Executor: defaultCommandExecutor,
		IsRoot:   os.Geteuid() == 0,
	}
}

// RequestDevice starts a socket, spawns the helper, and returns the passed TUN device.
func (c *HelperClient) RequestDevice(ctx context.Context, helperBin string) (*ReceivedDevice, error) {
	tempDir := os.TempDir()
	sockPath := filepath.Join(tempDir, fmt.Sprintf("naive-tun-%d-%d.sock", os.Getpid(), os.Getuid()))

	devCh := make(chan *ReceivedDevice, 1)
	errCh := make(chan error, 1)

	go func() {
		dev, err := ListenForFD(ctx, sockPath)
		if err != nil {
			errCh <- err
			return
		}
		devCh <- dev
	}()

	cmdName, cmdArgs := BuildPrivilegedCommand(helperBin, sockPath, c.IsRoot)
	execErrCh := make(chan error, 1)
	go func() {
		execErrCh <- c.Executor(ctx, cmdName, cmdArgs...)
	}()

	select {
	case err := <-errCh:
		return nil, fmt.Errorf("listen for TUN FD: %w", err)
	case err := <-execErrCh:
		if err != nil {
			return nil, fmt.Errorf("execute TUN helper: %w", err)
		}
	case dev := <-devCh:
		return dev, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// In case exec returned before device arrived
	select {
	case dev := <-devCh:
		return dev, nil
	case err := <-errCh:
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// RunHelper executes the privileged helper logic: opens TUN and sends FD over Unix socket.
func RunHelper(args []string) error {
	fs := flag.NewFlagSet("tun-helper", flag.ContinueOnError)
	sockPath := fs.String("sock", "", "Path to unix domain socket")
	_ = fs.Bool("tun-helper", true, "Helper mode")

	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *sockPath == "" {
		return errors.New("missing required --sock parameter")
	}

	fd, name, err := OpenPlatformTUN()
	if err != nil {
		return fmt.Errorf("open platform tun: %w", err)
	}

	return SendFD(*sockPath, fd, name)
}
