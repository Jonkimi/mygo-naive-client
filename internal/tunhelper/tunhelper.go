package tunhelper

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

// Single source of truth for the TUN addressing. The sing-box tun inbound, the privileged
// helper (ifconfig / ip addr) and the macOS DynamicStore DNS entry must all derive from these.
const (
	// TunIPv4 is the local TUN address and TunIPv4Peer its point-to-point peer in the /30.
	TunIPv4     = "172.19.0.1"
	TunIPv4Peer = "172.19.0.2"
	// TunIPv4Netmask is the dotted form of TunIPv4Prefix's /30.
	TunIPv4Netmask = "255.255.255.252"
	TunIPv4Prefix  = TunIPv4 + "/30"

	TunIPv6       = "fdfe:dcba:9876::1"
	TunIPv6Prefix = TunIPv6 + "/126"

	// DNSAddress is the in-TUN DNS address. The sing-box tun inbound hijacks it, and the
	// macOS DynamicStore DNS entry points at it.
	DNSAddress = TunIPv4Peer
)

// ReceivedDevice represents a TUN device file descriptor received from the privileged helper.
type ReceivedDevice struct {
	FD       int
	Name     string
	SockPath string
	Conn     io.Closer
}

// Close closes the underlying TUN file descriptor and signals the helper to teardown routes and exit.
func (r *ReceivedDevice) Close() error {
	var errs []error
	if r.Conn != nil {
		if err := r.Conn.Close(); err != nil {
			errs = append(errs, err)
		}
		r.Conn = nil
	}
	if r.FD > 0 {
		if err := closeFD(r.FD); err != nil {
			errs = append(errs, err)
		}
		r.FD = -1
	}
	if len(errs) > 0 {
		return errs[0]
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
func BuildPrivilegedCommand(helperBin string, sockPath string, isRoot bool, excludeIPs ...string) (string, []string) {
	var args []string
	if len(excludeIPs) > 0 {
		args = []string{"--tun-helper", "--sock", sockPath, "--exclude-ips", strings.Join(excludeIPs, ",")}
	} else {
		args = []string{"--tun-helper", "--sock", sockPath}
	}
	if isRoot {
		return helperBin, args
	}
	switch runtime.GOOS {
	case "darwin":
		script := fmt.Sprintf("do shell script \"%s\" with administrator privileges", appleScriptEscape(shellCommand(helperBin, args)))
		return "osascript", []string{"-e", script}
	case "linux":
		return "pkexec", append([]string{helperBin}, args...)
	default:
		return helperBin, args
	}
}

// shellQuote wraps s in single quotes so sh treats it as one literal word (paths may contain spaces).
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// shellCommand joins the binary and args into a single sh command line with every word quoted.
func shellCommand(bin string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, shellQuote(bin))
	for _, a := range args {
		parts = append(parts, shellQuote(a))
	}
	return strings.Join(parts, " ")
}

// appleScriptEscape escapes s for use inside a double-quoted AppleScript string literal.
func appleScriptEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s)
}

// CommandExecutor is used to spawn privileged helper processes.
type CommandExecutor func(ctx context.Context, name string, args ...string) error

func defaultCommandExecutor(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if msg := strings.TrimSpace(string(out)); msg != "" {
			return fmt.Errorf("%w: %s", err, msg)
		}
		return err
	}
	return nil
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
func (c *HelperClient) RequestDevice(ctx context.Context, helperBin string, excludeIPs ...string) (*ReceivedDevice, error) {
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

	cmdName, cmdArgs := BuildPrivilegedCommand(helperBin, sockPath, c.IsRoot, excludeIPs...)
	execErrCh := make(chan error, 1)
	go func() {
		// Use Background context so the privileged helper is not killed when the handshake ctx completes.
		execErrCh <- c.Executor(context.Background(), cmdName, cmdArgs...)
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

// RunHelper executes the privileged helper logic: opens TUN, installs routes,
// transmits FD over Unix socket, and stays alive to clean up routes upon exit.
func RunHelper(args []string) error {
	fs := flag.NewFlagSet("tun-helper", flag.ContinueOnError)
	sockPath := fs.String("sock", "", "Path to unix domain socket")
	excludeIPsStr := fs.String("exclude-ips", "", "Comma-separated IPs to exclude from TUN")
	cleanup := fs.Bool("cleanup", false, "Clean up stale TUN routes and DNS entries and exit")
	_ = fs.Bool("tun-helper", true, "Helper mode")

	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *cleanup {
		return TeardownRoutes("", nil)
	}
	if *sockPath == "" {
		return errors.New("missing required --sock parameter")
	}

	var excludeIPs []string
	if *excludeIPsStr != "" {
		for _, ip := range strings.Split(*excludeIPsStr, ",") {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				excludeIPs = append(excludeIPs, ip)
			}
		}
	}

	fd, name, err := OpenPlatformTUN()
	if err != nil {
		return fmt.Errorf("open platform tun: %w", err)
	}
	defer func() {
		_ = closeFD(fd)
	}()

	if err := SetupRoutes(name, excludeIPs); err != nil {
		_ = TeardownRoutes(name, excludeIPs)
		return fmt.Errorf("setup routes: %w", err)
	}
	defer func() {
		_ = TeardownRoutes(name, excludeIPs)
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		<-sigCh
		_ = TeardownRoutes(name, excludeIPs)
		_ = closeFD(fd)
		os.Exit(0)
	}()

	return SendFDAndServe(*sockPath, fd, name)
}

