//go:build darwin || linux || freebsd || openbsd || netbsd

package runner

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// reclaimSidecarOnPort attempts to find and terminate any stale naive or xray process
// holding the specified port. Returns true if a process was found and killed.
func reclaimSidecarOnPort(port int) bool {
	if port <= 0 {
		return false
	}
	out, err := exec.Command("lsof", "-n", "-P", fmt.Sprintf("-iTCP:%d", port), "-sTCP:LISTEN").Output()
	if err != nil {
		return false
	}
	myPid := os.Getpid()
	lines := strings.Split(string(out), "\n")
	killedAny := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "COMMAND") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		comm := strings.ToLower(fields[0])
		if !strings.Contains(comm, "naive") && !strings.Contains(comm, "xray") {
			continue
		}
		pid, err := strconv.Atoi(fields[1])
		if err != nil || pid <= 1 || pid == myPid {
			continue
		}
		killStalePID(pid)
		killedAny = true
	}

	if killedAny {
		// Brief pause for OS to release the socket
		time.Sleep(100 * time.Millisecond)
	}
	return killedAny
}
