//go:build !windows && !darwin && !linux && !freebsd && !openbsd && !netbsd

package runner

import (
	"os"
	"os/exec"
)

func hideWindow(*exec.Cmd) {}

func prepareProcess(*exec.Cmd) {}

func attachProcess(*os.Process) {}

func terminateProcess(cmd *exec.Cmd) {
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}

func killProcessGroup(cmd *exec.Cmd) {
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}

func killStalePID(pid int) {
	if pid <= 1 || pid == os.Getpid() {
		return
	}
	if p, err := os.FindProcess(pid); err == nil {
		_ = p.Kill()
	}
}

func cleanupOrphanProcesses(workDir string) {}

func cleanupOrphansForConfig(cfgPath string) {}
