//go:build windows

package runner

import (
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	jobHandleOnce sync.Once
	jobHandle     windows.Handle
)

func initJobObject() windows.Handle {
	jobHandleOnce.Do(func() {
		h, err := windows.CreateJobObject(nil, nil)
		if err != nil {
			return
		}
		info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
			BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
				LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
			},
		}
		_, err = windows.SetInformationJobObject(
			h,
			windows.JobObjectExtendedLimitInformation,
			uintptr(unsafe.Pointer(&info)),
			uint32(unsafe.Sizeof(info)),
		)
		if err != nil {
			_ = windows.CloseHandle(h)
			return
		}
		jobHandle = h
	})
	return jobHandle
}

func hideWindow(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
}

func prepareProcess(cmd *exec.Cmd) {
	hideWindow(cmd)
}

func attachProcess(p *os.Process) {
	if p == nil {
		return
	}
	job := initJobObject()
	if job == 0 {
		return
	}
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(p.Pid))
	if err != nil {
		return
	}
	defer windows.CloseHandle(h)
	_ = windows.AssignProcessToJobObject(job, h)
}

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

func cleanupOrphanProcesses(workDir string) {
	// PID file cleanup in cleanPIDFiles is cross-platform and sufficient on Windows
}

func cleanupOrphansForConfig(cfgPath string) {}
