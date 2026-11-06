package sysproxy

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

type CommandExecutor func(name string, args ...string) ([]byte, error)

type RecoveryState struct {
	Dirty     bool      `json:"dirty"`
	Timestamp time.Time `json:"timestamp"`
	Addr      string    `json:"addr"`
}

type Sysproxy struct {
	mu           sync.Mutex
	exec         CommandExecutor
	recoveryPath string
	active       bool
}

func defaultExecutor(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).Output()
}

func New(recoveryPath string) *Sysproxy {
	return NewWithExecutor(defaultExecutor, recoveryPath)
}

func NewWithExecutor(executor CommandExecutor, recoveryPath string) *Sysproxy {
	if executor == nil {
		executor = defaultExecutor
	}
	return &Sysproxy{
		exec:         executor,
		recoveryPath: recoveryPath,
	}
}

func (s *Sysproxy) IsActive() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}

func (s *Sysproxy) RecoverIfDirty() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.recoveryPath == "" {
		return nil
	}

	data, err := os.ReadFile(s.recoveryPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var state RecoveryState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil
	}

	if !state.Dirty {
		return nil
	}

	// Dirty state detected: restore original unset proxy state
	_ = s.unsetLocked()

	// Clear dirty flag in recovery file
	state.Dirty = false
	state.Timestamp = time.Now()
	if updated, err := json.MarshalIndent(state, "", "  "); err == nil {
		_ = os.WriteFile(s.recoveryPath, updated, 0o600)
	}

	s.active = false
	return nil
}

func (s *Sysproxy) Set(addr string, bypass []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid proxy address %q: %w", addr, err)
	}

	if len(bypass) == 0 {
		bypass = []string{"127.0.0.1", "localhost", "192.168.0.0/16", "10.0.0.0/8", "*.local"}
	}

	// Write dirty recovery marker before touching system state
	if s.recoveryPath != "" {
		if err := os.MkdirAll(filepath.Dir(s.recoveryPath), 0o755); err == nil {
			rec := RecoveryState{
				Dirty:     true,
				Timestamp: time.Now(),
				Addr:      addr,
			}
			if b, err := json.MarshalIndent(rec, "", "  "); err == nil {
				_ = os.WriteFile(s.recoveryPath, b, 0o600)
			}
		}
	}

	switch runtime.GOOS {
	case "darwin":
		if err := s.setDarwin(host, port, bypass); err != nil {
			return err
		}
	case "windows":
		if err := s.setWindows(host, port, bypass); err != nil {
			return err
		}
	default: // Linux and others
		if err := s.setLinux(host, port, bypass); err != nil {
			return err
		}
	}

	s.active = true
	return nil
}

func (s *Sysproxy) Unset() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unsetLocked()
}

func (s *Sysproxy) unsetLocked() error {
	var unsetErr error
	switch runtime.GOOS {
	case "darwin":
		unsetErr = s.unsetDarwin()
	case "windows":
		unsetErr = s.unsetWindows()
	default:
		unsetErr = s.unsetLinux()
	}

	if s.recoveryPath != "" {
		rec := RecoveryState{
			Dirty:     false,
			Timestamp: time.Now(),
		}
		if b, err := json.MarshalIndent(rec, "", "  "); err == nil {
			_ = os.WriteFile(s.recoveryPath, b, 0o600)
		}
	}

	s.active = false
	return unsetErr
}

// macOS implementation using networksetup
func (s *Sysproxy) listDarwinServices() []string {
	out, err := s.exec("networksetup", "-listallnetworkservices")
	if err != nil {
		return []string{"Wi-Fi", "Ethernet"}
	}
	lines := strings.Split(string(out), "\n")
	var svcs []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "*") || strings.Contains(line, "An asterisk") {
			continue
		}
		svcs = append(svcs, line)
	}
	if len(svcs) == 0 {
		svcs = []string{"Wi-Fi", "Ethernet"}
	}
	return svcs
}

func (s *Sysproxy) setDarwin(host, port string, bypass []string) error {
	services := s.listDarwinServices()
	for _, svc := range services {
		_, _ = s.exec("networksetup", "-setwebproxy", svc, host, port)
		_, _ = s.exec("networksetup", "-setsecurewebproxy", svc, host, port)
		_, _ = s.exec("networksetup", "-setsocksfirewallproxy", svc, host, port)
		if len(bypass) > 0 {
			args := append([]string{"-setproxybypassdomains", svc}, bypass...)
			_, _ = s.exec("networksetup", args...)
		}
	}
	return nil
}

func (s *Sysproxy) unsetDarwin() error {
	services := s.listDarwinServices()
	for _, svc := range services {
		_, _ = s.exec("networksetup", "-setwebproxystate", svc, "off")
		_, _ = s.exec("networksetup", "-setsecurewebproxystate", svc, "off")
		_, _ = s.exec("networksetup", "-setsocksfirewallproxystate", svc, "off")
	}
	return nil
}

// Linux GNOME implementation using gsettings
func (s *Sysproxy) setLinux(host, port string, bypass []string) error {
	_, _ = s.exec("gsettings", "set", "org.gnome.system.proxy", "mode", "'manual'")
	_, _ = s.exec("gsettings", "set", "org.gnome.system.proxy.http", "host", host)
	_, _ = s.exec("gsettings", "set", "org.gnome.system.proxy.http", "port", port)
	_, _ = s.exec("gsettings", "set", "org.gnome.system.proxy.https", "host", host)
	_, _ = s.exec("gsettings", "set", "org.gnome.system.proxy.https", "port", port)
	_, _ = s.exec("gsettings", "set", "org.gnome.system.proxy.socks", "host", host)
	_, _ = s.exec("gsettings", "set", "org.gnome.system.proxy.socks", "port", port)
	return nil
}

func (s *Sysproxy) unsetLinux() error {
	_, _ = s.exec("gsettings", "set", "org.gnome.system.proxy", "mode", "'none'")
	return nil
}

// Windows implementation using reg.exe
func (s *Sysproxy) setWindows(host, port string, bypass []string) error {
	server := fmt.Sprintf("%s:%s", host, port)
	override := strings.Join(bypass, ";") + ";<local>"
	regPath := `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	_, _ = s.exec("reg", "add", regPath, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f")
	_, _ = s.exec("reg", "add", regPath, "/v", "ProxyServer", "/t", "REG_SZ", "/d", server, "/f")
	_, _ = s.exec("reg", "add", regPath, "/v", "ProxyOverride", "/t", "REG_SZ", "/d", override, "/f")
	return nil
}

func (s *Sysproxy) unsetWindows() error {
	regPath := `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	_, _ = s.exec("reg", "add", regPath, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f")
	return nil
}
