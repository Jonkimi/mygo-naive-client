package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func pidFilePath(workDir, svcID string) string {
	return filepath.Join(workDir, fmt.Sprintf("service-%s.pid", svcID))
}

func writePIDFile(workDir, svcID string, pid int) {
	if workDir == "" || svcID == "" || pid <= 0 {
		return
	}
	_ = os.WriteFile(pidFilePath(workDir, svcID), []byte(strconv.Itoa(pid)), 0o600)
}

func removePIDFile(workDir, svcID string) {
	if workDir == "" || svcID == "" {
		return
	}
	_ = os.Remove(pidFilePath(workDir, svcID))
}

func cleanServicePID(workDir, svcID string) {
	if workDir == "" || svcID == "" {
		return
	}
	pPath := pidFilePath(workDir, svcID)
	data, err := os.ReadFile(pPath)
	if err != nil {
		return
	}
	_ = os.Remove(pPath)
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 1 {
		return
	}
	killStalePID(pid)
}

func cleanPIDFiles(workDir string) {
	if workDir == "" {
		return
	}
	entries, err := os.ReadDir(workDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "service-") || !strings.HasSuffix(entry.Name(), ".pid") {
			continue
		}
		pPath := filepath.Join(workDir, entry.Name())
		data, err := os.ReadFile(pPath)
		_ = os.Remove(pPath)
		if err != nil {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil || pid <= 1 {
			continue
		}
		killStalePID(pid)
	}
}
