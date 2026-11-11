package runner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"naive-client/internal/config"
)

// State represents the runtime status of a single NaiveProxy service.
type State int

const (
	StateStopped State = iota
	StateStarting
	StateRunning
	StateError
)

func (s State) Label() string {
	switch s {
	case StateStarting:
		return "启动中"
	case StateRunning:
		return "运行中"
	case StateError:
		return "异常"
	default:
		return "已停止"
	}
}

// Status is a snapshot of a service's live state for the UI.
type Status struct {
	State         State
	PID           int
	AllocatedPort int
	StartedAt     time.Time
	Restarts      int
	LastError     string
	Latency       time.Duration
	Probing       bool
	ProbeError    string
	SpeedTesting  bool
	DownloadSpeed float64
	SpeedError    string
}

// Uptime returns how long the service has been running since StartedAt.
func (st Status) Uptime(now time.Time) time.Duration {
	if st.State != StateRunning || st.StartedAt.IsZero() {
		return 0
	}
	d := now.Sub(st.StartedAt)
	if d < 0 {
		return 0
	}
	return d
}

const maxCrashRestarts = 3

type instance struct {
	opMu       sync.Mutex
	svc        config.Service
	status     Status
	logs       *LogBuffer
	cancel     context.CancelFunc
	cmd        *exec.Cmd
	stopping   bool
	configPath string
	done       chan struct{}
}

// ServiceDialerFunc dials network connection for embedded engine services (e.g. EngineSingBox).
type ServiceDialerFunc func(ctx context.Context, svc config.Service, network, addr string) (net.Conn, error)

// PreStartCheckerFunc validates preconditions before starting a service.
type PreStartCheckerFunc func(svc config.Service) error

// Manager supervises multiple independent local NaiveProxy service processes.
type Manager struct {
	mu             sync.RWMutex
	binPath        string
	xrayBinPath    string
	logLevel       string
	workDir        string
	instances      map[string]*instance
	onChange       func()
	OnLog            func(id string)
	OnProbeSuccess   func(id string, rtt time.Duration)
	OnProbeFailure   func(id string, err error)
	OnServiceStarted func(svc config.Service)
	ServiceDialer    ServiceDialerFunc
	PreStartChecker  PreStartCheckerFunc
	BackoffMin     time.Duration // overridable in tests
}

// NewManager creates a process manager storing generated configs in workDir.
func NewManager(binPath, workDir string, onChange func()) *Manager {
	if onChange == nil {
		onChange = func() {}
	}
	cleanupOrphanProcesses(workDir)
	cleanPIDFiles(workDir)
	return &Manager{
		binPath:    binPath,
		workDir:    workDir,
		instances:  make(map[string]*instance),
		onChange:   onChange,
		BackoffMin: 600 * time.Millisecond,
	}
}

// BinaryPath returns the current naive binary path.
func (m *Manager) BinaryPath() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.binPath
}

// SetBinaryPath updates the naive binary path used for starting services.
func (m *Manager) SetBinaryPath(path string) {
	m.mu.Lock()
	m.binPath = path
	m.mu.Unlock()
}

// XrayBinaryPath returns the current xray binary path.
func (m *Manager) XrayBinaryPath() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.xrayBinPath
}

// SetXrayBinaryPath updates the xray binary path used for starting services.
func (m *Manager) SetXrayBinaryPath(path string) {
	m.mu.Lock()
	m.xrayBinPath = path
	m.mu.Unlock()
}

// SetLogLevel updates the log level used when generating Xray sidecar configs.
func (m *Manager) SetLogLevel(level string) {
	m.mu.Lock()
	m.logLevel = level
	m.mu.Unlock()
}

// BinaryExists reports whether the configured naive binary exists on disk.
func (m *Manager) BinaryExists() bool {
	p := m.BinaryPath()
	if p == "" {
		return false
	}
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// XrayBinaryExists reports whether the configured xray binary exists on disk.
func (m *Manager) XrayBinaryExists() bool {
	p := m.XrayBinaryPath()
	if p == "" {
		return false
	}
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// StatusOf returns a snapshot of the runtime status for service id.
func (m *Manager) StatusOf(id string) Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if inst, ok := m.instances[id]; ok {
		return inst.status
	}
	return Status{State: StateStopped}
}

// RunningServiceIDs returns a set of IDs for all services currently in StateRunning.
func (m *Manager) RunningServiceIDs() map[string]bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	res := make(map[string]bool, len(m.instances))
	for id, inst := range m.instances {
		if inst.status.State == StateRunning {
			res[id] = true
		}
	}
	return res
}

// RunningOrStartingCount returns the total number of services currently in StateRunning or StateStarting.
func (m *Manager) RunningOrStartingCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	count := 0
	for _, inst := range m.instances {
		if inst.status.State == StateRunning || inst.status.State == StateStarting {
			count++
		}
	}
	return count
}

// LogsOf returns the LogBuffer for service id, creating one if needed.
func (m *Manager) LogsOf(id string) *LogBuffer {
	m.mu.Lock()
	defer m.mu.Unlock()
	inst := m.ensureInstanceLocked(id)
	return inst.logs
}

func (m *Manager) ensureInstanceLocked(id string) *instance {
	inst, ok := m.instances[id]
	if !ok {
		inst = &instance{
			logs: NewLogBuffer(defaultMaxLines, func() {
				if m.OnLog != nil {
					m.OnLog(id)
				}
			}),
		}
		m.instances[id] = inst
	}
	return inst
}

// RunningIDs returns the IDs of all services currently running or starting.
func (m *Manager) RunningIDs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var ids []string
	for id, inst := range m.instances {
		if inst.status.State == StateRunning || inst.status.State == StateStarting {
			ids = append(ids, id)
		}
	}
	return ids
}

// AllocatedPorts returns a map of service ID to allocated loopback port for all running services.
func (m *Manager) AllocatedPorts() map[string]int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ports := make(map[string]int)
	for id, inst := range m.instances {
		if inst.status.State == StateRunning && inst.status.AllocatedPort > 0 {
			ports[id] = inst.status.AllocatedPort
		}
	}
	return ports
}

// RunningServices returns the service configurations of all currently running services.
func (m *Manager) RunningServices() []config.Service {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []config.Service
	for _, inst := range m.instances {
		if inst.status.State == StateRunning || inst.status.State == StateStarting {
			out = append(out, inst.svc)
		}
	}
	return out
}

// AllocateFreePort binds a temporary tcp listener on 127.0.0.1:0 to find an available port.
func AllocateFreePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port, nil
}

// CheckPortsAvailable verifies that all TCP ports in svc.Listens can be bound locally.
// If a port is occupied by a stale sidecar process, it attempts reclamation before failing.
func CheckPortsAvailable(svc config.Service) error {
	for _, raw := range svc.Listens {
		ep, err := config.ParseListenURI(raw)
		if err != nil {
			return err
		}
		if ep.Port == 0 {
			continue // dynamic port
		}
		ln, err := net.Listen("tcp", ep.ListenAddr())
		if err != nil {
			if reclaimSidecarOnPort(ep.Port) {
				ln2, err2 := net.Listen("tcp", ep.ListenAddr())
				if err2 == nil {
					_ = ln2.Close()
					continue
				}
			}
			return fmt.Errorf("本地端口 %s 已被占用或无权限监听: %w", ep.ListenAddr(), err)
		}
		_ = ln.Close()
	}
	return nil
}

// Start validates svc, checks port availability, writes config, and starts the sidecar process
// with automatic crash supervision. For KindExternalProxy, it enables the proxy directly without a subprocess.
func (m *Manager) Start(svc config.Service) error {
	if err := svc.Validate(); err != nil {
		return err
	}

	m.mu.Lock()
	inst := m.ensureInstanceLocked(svc.ID)
	m.mu.Unlock()

	inst.opMu.Lock()
	defer inst.opMu.Unlock()

	if m.PreStartChecker != nil {
		if err := m.PreStartChecker(svc); err != nil {
			m.setError(svc.ID, err.Error())
			return err
		}
	}
	// Stop existing run of this service if any
	_ = m.stopLocked(svc.ID, inst)
	cleanServicePID(m.workDir, svc.ID)

	if svc.EffectiveKind() == config.KindExternalProxy || svc.EffectiveEngine() == config.EngineSingBox {
		m.mu.Lock()
		inst.svc = svc
		inst.stopping = false
		inst.cancel = nil
		inst.done = nil
		inst.cmd = nil
		inst.status = Status{
			State:     StateRunning,
			StartedAt: time.Now(),
		}
		if svc.EffectiveEngine() == config.EngineSingBox {
			inst.logs.AppendLine(fmt.Sprintf("[%s] 原生节点已就绪: %s", time.Now().Format("15:04:05"), svc.Name))
		} else {
			inst.logs.AppendLine(fmt.Sprintf("[%s] 外部代理已启用: %s", time.Now().Format("15:04:05"), svc.RedactedProxy()))
		}
		startedCb := m.OnServiceStarted
		m.mu.Unlock()
		m.onChange()
		if startedCb != nil {
			startedCb(inst.svc)
		}
		return nil
	}

	allocatedPort := 0
	listens := make([]string, len(svc.Listens))
	copy(listens, svc.Listens)

	if len(listens) == 0 {
		p, err := AllocateFreePort()
		if err != nil {
			m.setError(svc.ID, fmt.Sprintf("无法分配空闲端口: %v", err))
			return err
		}
		allocatedPort = p
		listens = []string{fmt.Sprintf("socks://127.0.0.1:%d", allocatedPort)}
	} else {
		for i, raw := range listens {
			ep, err := config.ParseListenURI(raw)
			if err == nil {
				if ep.Port == 0 {
					if allocatedPort == 0 {
						p, err := AllocateFreePort()
						if err != nil {
							m.setError(svc.ID, fmt.Sprintf("无法分配空闲端口: %v", err))
							return err
						}
						allocatedPort = p
					}
					host := ep.Addr
					if host == "" || host == "0.0.0.0" || host == "::" {
						host = "127.0.0.1"
					}
					listens[i] = fmt.Sprintf("%s://%s:%d", ep.Proto, host, allocatedPort)
				} else if allocatedPort == 0 {
					allocatedPort = ep.Port
				}
			}
		}
	}
	svc.Listens = listens

	m.mu.Lock()
	workDir := m.workDir
	naiveBin := m.binPath
	xrayBin := m.xrayBinPath
	logLevel := m.logLevel
	m.mu.Unlock()

	isXray := svc.EffectiveProtocol() != config.ProtoNaive
	var bin string
	if isXray {
		bin = xrayBin
		if bin == "" {
			err := errors.New("未找到 xray 核心文件，请先下载安装")
			m.setError(svc.ID, err.Error())
			return err
		}
		if _, err := os.Stat(bin); err != nil {
			err := fmt.Errorf("xray 核心文件不存在 (%s)，请先下载核心", bin)
			m.setError(svc.ID, err.Error())
			return err
		}
	} else {
		bin = naiveBin
		if bin == "" {
			err := errors.New("未找到 naive 核心文件，请先点击顶部栏下载安装")
			m.setError(svc.ID, err.Error())
			return err
		}
		if _, err := os.Stat(bin); err != nil {
			err := fmt.Errorf("naive 核心文件不存在 (%s)，请先下载核心", bin)
			m.setError(svc.ID, err.Error())
			return err
		}
	}

	var cfgBytes []byte
	var cfgPath string
	var cmdArgs []string

	if isXray {
		var err error
		cfgBytes, err = GenerateXrayConfigWithLogLevel(svc, allocatedPort, logLevel)
		if err != nil {
			m.setError(svc.ID, err.Error())
			return err
		}
		cfgPath = filepath.Join(workDir, fmt.Sprintf("service-%s-xray.json", svc.ID))
		cmdArgs = []string{"run", "-c", cfgPath}
	} else {
		var err error
		cfgBytes, err = svc.ToConfigJSON()
		if err != nil {
			m.setError(svc.ID, err.Error())
			return err
		}
		cfgPath = filepath.Join(workDir, fmt.Sprintf("service-%s.json", svc.ID))
		cmdArgs = []string{cfgPath}
	}

	cleanupOrphansForConfig(cfgPath)

	if err := CheckPortsAvailable(svc); err != nil {
		m.setError(svc.ID, err.Error())
		return err
	}

	if err := os.MkdirAll(workDir, 0o700); err != nil {
		m.setError(svc.ID, err.Error())
		return err
	}

	if err := os.WriteFile(cfgPath, cfgBytes, 0o600); err != nil {
		m.setError(svc.ID, err.Error())
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	m.mu.Lock()
	inst.svc = svc
	inst.configPath = cfgPath
	inst.cancel = cancel
	inst.stopping = false
	inst.done = done
	inst.status = Status{
		State:         StateStarting,
		AllocatedPort: allocatedPort,
	}
	m.mu.Unlock()
	inst.logs.AppendLine(fmt.Sprintf("[%s] 正在启动服务 %s (%s)...", time.Now().Format("15:04:05"), svc.Name, svc.PrimaryListen()))
	m.onChange()

	go m.supervise(ctx, inst, bin, cmdArgs, done)
	return nil
}

// SetError marks a service as error state with the given message.
func (m *Manager) SetError(id, msg string) {
	m.setError(id, msg)
}

func (m *Manager) setError(id, msg string) {
	m.mu.Lock()
	inst := m.ensureInstanceLocked(id)
	inst.status.State = StateError
	inst.status.LastError = msg
	inst.status.PID = 0
	m.mu.Unlock()
	inst.logs.AppendLine("[错误] " + msg)
	m.onChange()
}

func (m *Manager) supervise(ctx context.Context, inst *instance, bin string, args []string, done chan struct{}) {
	defer close(done)

	restarts := 0
	for {
		if ctx.Err() != nil {
			return
		}

		cmd := exec.Command(bin, args...)
		cmd.Stdout = inst.logs
		cmd.Stderr = inst.logs
		prepareProcess(cmd)

		if err := cmd.Start(); err != nil {
			m.mu.Lock()
			if !inst.stopping {
				inst.status.State = StateError
				inst.status.LastError = fmt.Sprintf("进程启动失败: %v", err)
				inst.status.PID = 0
			}
			m.mu.Unlock()
			inst.logs.AppendLine(fmt.Sprintf("[错误] 启动失败: %v", err))
			m.onChange()
			return
		}

		pid := cmd.Process.Pid
		attachProcess(cmd.Process)
		writePIDFile(m.workDir, inst.svc.ID, pid)
		startedAt := time.Now()
		m.mu.Lock()
		inst.cmd = cmd
		inst.status.State = StateRunning
		inst.status.PID = pid
		inst.status.StartedAt = startedAt
		inst.status.Restarts = restarts
		inst.status.LastError = ""
		startedCb := m.OnServiceStarted
		m.mu.Unlock()
		inst.logs.AppendLine(fmt.Sprintf("[%s] 服务已启动 (PID: %d)", startedAt.Format("15:04:05"), pid))
		m.onChange()
		if startedCb != nil {
			startedCb(inst.svc)
		}

		waitDone := make(chan error, 1)
		go func() {
			waitDone <- cmd.Wait()
		}()

		var waitErr error
		select {
		case <-ctx.Done():
			terminateProcess(cmd)
			select {
			case waitErr = <-waitDone:
			case <-time.After(300 * time.Millisecond):
				killProcessGroup(cmd)
				select {
				case waitErr = <-waitDone:
				case <-time.After(300 * time.Millisecond):
				}
			}
		case waitErr = <-waitDone:
		}

		removePIDFile(m.workDir, inst.svc.ID, pid)

		m.mu.Lock()
		stopping := inst.stopping || ctx.Err() != nil
		if inst.cmd == cmd {
			inst.cmd = nil
			inst.status.PID = 0
		}
		m.mu.Unlock()

		if stopping {
			m.mu.Lock()
			if inst.done == done {
				inst.status.State = StateStopped
				inst.status.StartedAt = time.Time{}
			}
			m.mu.Unlock()
			inst.logs.AppendLine(fmt.Sprintf("[%s] 服务已停止", time.Now().Format("15:04:05")))
			m.onChange()
			return
		}

		// Reset restart counter if the process ran stably for at least 30 seconds.
		if time.Since(startedAt) > 30*time.Second {
			restarts = 0
		}
		restarts++
		errMsg := "进程意外退出"
		if waitErr != nil {
			errMsg = fmt.Sprintf("进程退出: %v", waitErr)
		}

		if restarts > maxCrashRestarts {
			m.mu.Lock()
			inst.status.State = StateError
			inst.status.LastError = fmt.Sprintf("%s (已重试 %d 次失败)", errMsg, maxCrashRestarts)
			inst.status.StartedAt = time.Time{}
			m.mu.Unlock()
			inst.logs.AppendLine(fmt.Sprintf("[异常] %s，达到最大重试次数 (%d)，停止守护", errMsg, maxCrashRestarts))
			m.onChange()
			return
		}

		backoff := m.BackoffMin * time.Duration(1<<(restarts-1))
		m.mu.Lock()
		inst.status.State = StateStarting
		inst.status.Restarts = restarts
		inst.status.LastError = fmt.Sprintf("%s，正在进行第 %d/%d 次重启...", errMsg, restarts, maxCrashRestarts)
		m.mu.Unlock()
		inst.logs.AppendLine(fmt.Sprintf("[守护] %s，将在 %v 后尝试第 %d/%d 次重启...", errMsg, backoff, restarts, maxCrashRestarts))
		m.onChange()

		select {
		case <-ctx.Done():
			m.mu.Lock()
			inst.status.State = StateStopped
			m.mu.Unlock()
			m.onChange()
			return
		case <-time.After(backoff):
		}
	}
}

// Stop terminates a running service and waits for its process to exit.
func (m *Manager) Stop(id string) error {
	m.mu.Lock()
	inst, ok := m.instances[id]
	if !ok {
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()

	inst.opMu.Lock()
	defer inst.opMu.Unlock()
	return m.stopLocked(id, inst)
}

func (m *Manager) stopLocked(id string, inst *instance) error {
	m.mu.Lock()
	if inst.status.State != StateRunning && inst.status.State != StateStarting && inst.done == nil {
		if inst.status.State == StateError {
			inst.status.State = StateStopped
			inst.status.LastError = ""
		}
		m.mu.Unlock()
		m.onChange()
		return nil
	}

	if inst.svc.EffectiveKind() == config.KindExternalProxy || inst.svc.EffectiveEngine() == config.EngineSingBox {
		inst.status.State = StateStopped
		inst.status.PID = 0
		inst.status.StartedAt = time.Time{}
		if inst.svc.EffectiveEngine() == config.EngineSingBox {
			inst.logs.AppendLine(fmt.Sprintf("[%s] 原生节点已停止", time.Now().Format("15:04:05")))
		} else {
			inst.logs.AppendLine(fmt.Sprintf("[%s] 外部代理已停止", time.Now().Format("15:04:05")))
		}
		m.mu.Unlock()
		m.onChange()
		return nil
	}

	inst.stopping = true
	cancel := inst.cancel
	done := inst.done
	cmd := inst.cmd
	m.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if done != nil {
		select {
		case <-done:
		case <-time.After(1 * time.Second):
			m.mu.Lock()
			activeCmd := inst.cmd
			if activeCmd == nil {
				activeCmd = cmd
			}
			m.mu.Unlock()
			if activeCmd != nil {
				killProcessGroup(activeCmd)
			}
			select {
			case <-done:
			case <-time.After(500 * time.Millisecond):
			}
		}
	}
	return nil
}

// StopAll stops all running services and returns the list of services that were running
// so they can be seamlessly restarted after a binary update.
func (m *Manager) StopAll() []config.Service {
	running := m.RunningServices()
	var wg sync.WaitGroup
	for _, svc := range running {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			_ = m.Stop(id)
		}(svc.ID)
	}
	wg.Wait()
	return running
}

// Remove stops the service and cleans up its instance state and config file.
func (m *Manager) Remove(id string) {
	_ = m.Stop(id)
	m.mu.Lock()
	if inst, ok := m.instances[id]; ok {
		if inst.configPath != "" {
			_ = os.Remove(inst.configPath)
		}
		delete(m.instances, id)
	}
	m.mu.Unlock()
	m.onChange()
}

// ProbeServiceCtx synchronously measures latency through the service's primary listen endpoint,
// respecting the provided context for cancellation. The service must be in StateRunning.
func (m *Manager) ProbeServiceCtx(ctx context.Context, svc config.Service, probeURL string) (time.Duration, error) {
	m.mu.Lock()
	inst := m.ensureInstanceLocked(svc.ID)
	if inst.status.State != StateRunning || inst.status.Probing {
		m.mu.Unlock()
		return 0, errors.New("服务未在运行中或正在测速")
	}
	inst.status.Probing = true
	inst.status.ProbeError = ""
	m.mu.Unlock()
	m.onChange()

	var rtt time.Duration
	var err error
	if svc.EffectiveEngine() == config.EngineSingBox && m.ServiceDialer != nil {
		probeCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
		tr := &http.Transport{
			DialContext: func(c context.Context, network, addr string) (net.Conn, error) {
				return m.ServiceDialer(c, svc, network, addr)
			},
		}
		rtt, err = ProbeWithTransport(probeCtx, tr, probeURL)
		cancel()
	} else {
		var ep config.ListenEndpoint
		ep, err = svc.OutboundEndpoint()
		if err == nil {
			probeCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
			rtt, err = Probe(probeCtx, ep, probeURL)
			cancel()
		}
	}

	m.mu.Lock()
	inst.status.Probing = false
	if ctx.Err() != nil {
		inst.logs.AppendLine("[测速] 延迟测试已取消")
		m.mu.Unlock()
		m.onChange()
		return 0, ctx.Err()
	}
	if err != nil {
		inst.status.Latency = 0
		inst.status.ProbeError = err.Error()
		inst.logs.AppendLine(fmt.Sprintf("[测速] 延迟测试失败: %v", err))
		m.mu.Unlock()
		if m.OnProbeFailure != nil {
			m.OnProbeFailure(svc.ID, err)
		}
	} else {
		inst.status.Latency = rtt
		inst.status.ProbeError = ""
		inst.logs.AppendLine(fmt.Sprintf("[测速] 延迟测试成功: %d ms", max(1, rtt.Milliseconds())))
		m.mu.Unlock()
		if m.OnProbeSuccess != nil {
			m.OnProbeSuccess(svc.ID, rtt)
		}
	}
	m.onChange()
	return rtt, err
}

// ProbeService asynchronously measures latency through the service's primary listen endpoint.
// The service must be in StateRunning.
func (m *Manager) ProbeService(svc config.Service, probeURL string) {
	go func() {
		_, _ = m.ProbeServiceCtx(context.Background(), svc, probeURL)
	}()
}

// DownloadTestServiceCtx synchronously measures download throughput through the service's primary listen endpoint,
// respecting the provided context for cancellation. The service must be in StateRunning.
func (m *Manager) DownloadTestServiceCtx(ctx context.Context, svc config.Service, downloadURL string) (float64, error) {
	m.mu.Lock()
	inst := m.ensureInstanceLocked(svc.ID)
	if inst.status.State != StateRunning || inst.status.SpeedTesting {
		m.mu.Unlock()
		return 0, errors.New("服务未在运行中或正在测速")
	}
	inst.status.SpeedTesting = true
	inst.status.SpeedError = ""
	inst.status.DownloadSpeed = 0
	m.mu.Unlock()
	m.onChange()

	var bps float64
	var err error
	if svc.EffectiveEngine() == config.EngineSingBox && m.ServiceDialer != nil {
		speedCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
		tr := &http.Transport{
			DialContext: func(c context.Context, network, addr string) (net.Conn, error) {
				return m.ServiceDialer(c, svc, network, addr)
			},
		}
		bps, err = MeasureDownloadSpeedWithTransport(speedCtx, tr, downloadURL, func(sample float64) {
			m.mu.Lock()
			inst.status.DownloadSpeed = sample
			m.mu.Unlock()
			m.onChange()
		})
		cancel()
	} else {
		var ep config.ListenEndpoint
		ep, err = svc.OutboundEndpoint()
		if err == nil {
			speedCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
			bps, err = MeasureDownloadSpeed(speedCtx, ep, downloadURL, func(sample float64) {
				m.mu.Lock()
				inst.status.DownloadSpeed = sample
				m.mu.Unlock()
				m.onChange()
			})
			cancel()
		}
	}

	m.mu.Lock()
	inst.status.SpeedTesting = false
	if ctx.Err() != nil {
		inst.logs.AppendLine("[测速] 下载测速已取消")
		m.mu.Unlock()
		m.onChange()
		return 0, ctx.Err()
	}
	if err != nil {
		inst.status.DownloadSpeed = 0
		inst.status.SpeedError = err.Error()
		inst.logs.AppendLine(fmt.Sprintf("[测速] 下载测速失败: %v", err))
	} else {
		inst.status.DownloadSpeed = bps
		inst.status.SpeedError = ""
		inst.logs.AppendLine(fmt.Sprintf("[测速] 下载测速完成: %s", FormatSpeed(bps)))
	}
	m.mu.Unlock()
	m.onChange()
	return bps, err
}

// DownloadTestService asynchronously measures download throughput through the service's primary listen endpoint.
// The service must be in StateRunning.
func (m *Manager) DownloadTestService(svc config.Service, downloadURL string) {
	go func() {
		_, _ = m.DownloadTestServiceCtx(context.Background(), svc, downloadURL)
	}()
}

// FirstRunningEndpoint returns the ListenEndpoint of the first running SOCKS or HTTP service,
// useful for accelerating GitHub release checks and downloads through an active tunnel.
func (m *Manager) FirstRunningEndpoint() (config.ListenEndpoint, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, inst := range m.instances {
		if inst.status.State == StateRunning {
			if ep, err := config.ParseListenURI(inst.svc.PrimaryListen()); err == nil {
				if ep.Proto == "socks" || ep.Proto == "http" {
					return ep, true
				}
			}
		}
	}
	return config.ListenEndpoint{}, false
}
