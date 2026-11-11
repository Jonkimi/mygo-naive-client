//go:build darwin || linux || freebsd || openbsd || netbsd

package runner

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func attachProcess(*os.Process) {}

func terminateProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	pid := cmd.Process.Pid
	if pid <= 1 {
		return
	}
	if err := syscall.Kill(-pid, syscall.SIGTERM); err != nil {
		_ = cmd.Process.Signal(syscall.SIGTERM)
	}
}

func killProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	pid := cmd.Process.Pid
	if pid <= 1 {
		return
	}
	if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil {
		_ = cmd.Process.Kill()
	}
}

func killStalePID(pid int) {
	if pid <= 1 || pid == os.Getpid() {
		return
	}
	// Send SIGTERM first
	_ = syscall.Kill(pid, syscall.SIGTERM)
	// Give it up to 150ms to exit cleanly, then SIGKILL
	time.Sleep(150 * time.Millisecond)
	_ = syscall.Kill(pid, syscall.SIGKILL)
}

func cleanStaleOrphans(workDir string) {
	if workDir == "" {
		return
	}
	out, err := exec.Command("ps", "-ww", "-eo", "pid,command").Output()
	if err != nil {
		out, err = exec.Command("ps", "-eo", "pid,command").Output()
		if err != nil {
			return
		}
	}
	myPid := os.Getpid()
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, workDir) {
			continue
		}
		if !strings.Contains(line, "naive") && !strings.Contains(line, "xray") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil || pid <= 1 || pid == myPid {
			continue
		}
		killStalePID(pid)
	}
}
