package zengobox

// Manager supervises the proxy core process: start, stop, restart, crash
// recovery with a bounded restart policy, and netfilter lifecycle. It
// replaces the legacy 10-second blind-restart watchdog (see cores.go).
//
// All failures are returned as errors, never panics. Whenever a start
// fails midway, netfilter state is cleaned up so the device is never left
// with a half-installed rule set.

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"bfr-webui-go/internal/logger"
	"bfr-webui-go/internal/zengobox/netfilter"
)

// ErrNeedsSetup is returned when no proxy core binary is installed yet.
// The frontend reacts by showing the setup wizard.
var ErrNeedsSetup = errors.New("proxy core binary not installed: run the setup wizard first")

// CoreStatus is the JSON shape served by /api/zengobox/status.
type CoreStatus struct {
	Running       bool   `json:"running"`
	PID           int    `json:"pid"`
	Core          string `json:"core"`
	NeedsSetup    bool   `json:"needs_setup"`
	EffectiveMode string `json:"effective_mode"`
	Crashed       bool   `json:"crashed"`
}

// Manager is a process supervisor for one proxy core instance.
type Manager struct {
	mu      sync.Mutex
	cmd     *exec.Cmd
	logFile *os.File
	runDir  string
	// restarts holds timestamps of automatic restarts for the policy window.
	restarts []time.Time
	crashed  bool
	// stopReq is set by Stop so a racing supervise loop never restarts.
	stopReq bool
}

var (
	mgrOnce sync.Once
	mgr     *Manager
)

// GetManager returns the process-wide singleton Manager.
func GetManager() *Manager {
	mgrOnce.Do(func() { mgr = &Manager{} })
	return mgr
}

// validConfigName guards the core config file name against path traversal.
// The name comes from our own config, but defense in depth is cheap.
func validConfigName(name string) bool {
	if name == "" || strings.Contains(name, "/") || strings.Contains(name, "\\") || strings.Contains(name, "..") {
		return false
	}
	return strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".json")
}

// coreArgs builds the core command line for a config file.
func coreArgs(binName, cfgPath string) []string {
	if strings.Contains(strings.ToLower(binName), "sing-box") {
		return []string{"run", "-c", cfgPath}
	}
	// clash / mihomo / premium
	return []string{"-f", cfgPath}
}

// coreConfigPath locates the active core config file: first the
// ZenGoBox-managed path, then legacy clash locations for clash-likes.
// Phase 3 (setup wizard / core-config editor) will create it when missing.
func coreConfigPath(cfg *ZengoConfig) (string, error) {
	binName := cfg.Core.BinName
	name := cfg.Core.ConfigNames[binName]
	if name == "" {
		if strings.Contains(strings.ToLower(binName), "sing-box") {
			name = "config.json"
		} else {
			name = "config.yaml"
		}
	}
	if !validConfigName(name) {
		return "", fmt.Errorf("invalid core config name %q", name)
	}
	if p := filepath.Join(cfg.EffectiveBoxDir(), name); fileExists(p) {
		return p, nil
	}
	if !strings.Contains(strings.ToLower(binName), "sing-box") {
		if lp := DetectConfigPath(); lp != "" && fileExists(lp) {
			return lp, nil
		}
	}
	return "", fmt.Errorf("core config file %q not found in %s", name, cfg.EffectiveBoxDir())
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// livePIDLocked reports the PID of a running core, either the one this
// Manager spawned or one found via the PID file (covers webui restarts).
func (m *Manager) livePIDLocked() (int, bool) {
	if m.cmd != nil && m.cmd.Process != nil {
		if err := m.cmd.Process.Signal(syscall.Signal(0)); err == nil {
			return m.cmd.Process.Pid, true
		}
	}
	if m.runDir != "" {
		if data, err := os.ReadFile(filepath.Join(m.runDir, netfilter.PIDFileName)); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && pid > 0 {
				if err := syscall.Kill(pid, 0); err == nil {
					return pid, true
				}
			}
		}
	}
	return 0, false
}

// Status returns the current daemon state. It never shells out.
func (m *Manager) Status() CoreStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := CoreStatus{Crashed: m.crashed}
	if cfg, err := GetConfig(); err == nil {
		st.Core = cfg.Core.BinName
		st.EffectiveMode = cfg.Network.Mode
		if st.EffectiveMode == "" {
			st.EffectiveMode = "tproxy"
		}
		if s, err := os.Stat(cfg.CoreBinary()); err != nil || s.IsDir() {
			st.NeedsSetup = true
		}
	}
	if pid, ok := m.livePIDLocked(); ok {
		st.Running = true
		st.PID = pid
	}
	return st
}

// Start launches the core under supervision. It is idempotent: starting an
// already-running core is a no-op.
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg, err := GetConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	return m.startLocked(cfg)
}

func (m *Manager) startLocked(cfg *ZengoConfig) error {
	if _, ok := m.livePIDLocked(); ok {
		return nil
	}
	bin := cfg.CoreBinary()
	if s, err := os.Stat(bin); err != nil || s.IsDir() {
		return ErrNeedsSetup
	}
	cfgPath, err := coreConfigPath(cfg)
	if err != nil {
		return err
	}
	runDir := cfg.EffectiveRunDir()
	if err := os.MkdirAll(runDir, 0755); err != nil {
		return fmt.Errorf("create run dir: %w", err)
	}

	// 1. Clean remnants first (mirrors service.sh): a stale TPROXY rule
	// set from a crashed core would otherwise blackhole the network.
	_ = netfilter.CleanAll(runDir)

	// 2. Install netfilter for the configured mode. On failure, remove
	// whatever was partially installed before returning.
	rc := netfilterConfig(cfg)
	if err := netfilter.Apply(rc); err != nil {
		_ = netfilter.Remove()
		return fmt.Errorf("apply netfilter: %w", err)
	}

	// 3. Spawn the core detached in its own process group.
	logPath := filepath.Join(runDir, "core.log")
	lf, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		_ = netfilter.Remove()
		return fmt.Errorf("open core log: %w", err)
	}
	cmd := exec.Command(bin, coreArgs(cfg.Core.BinName, cfgPath)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout = lf
	cmd.Stderr = lf
	if err := cmd.Start(); err != nil {
		lf.Close()
		_ = netfilter.Remove()
		return fmt.Errorf("start core: %w", err)
	}
	if err := os.WriteFile(filepath.Join(runDir, netfilter.PIDFileName),
		[]byte(strconv.Itoa(cmd.Process.Pid)), 0644); err != nil {
		logger.Get().Warnf("zengobox", "write pid file: %v", err)
	}

	m.cmd = cmd
	m.logFile = lf
	m.runDir = runDir
	m.crashed = false
	m.stopReq = false
	m.restarts = nil

	// 4. Take over supervision from the legacy watchdog so the two never
	// fight over the same core processes.
	suppressLegacyWatchdog()
	SetWatchdog(false)

	go m.supervise(cfg)
	logger.Get().Infof("zengobox", "core %s started (pid %d)", cfg.Core.BinName, cmd.Process.Pid)
	return nil
}

// Stop terminates the core, cleans netfilter state and the PID file.
func (m *Manager) Stop() error {
	m.mu.Lock()
	m.stopReq = true
	m.crashed = false
	cmd := m.cmd
	m.mu.Unlock()

	if cmd != nil && cmd.Process != nil {
		pid := cmd.Process.Pid
		// SIGTERM the whole process group, then wait up to 3s.
		_ = syscall.Kill(-pid, syscall.SIGTERM)
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if err := syscall.Kill(pid, 0); err != nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		// Make sure it is gone. The supervise loop does the Wait().
		_ = syscall.Kill(-pid, syscall.SIGKILL)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.cmd = nil
	if m.logFile != nil {
		m.logFile.Close()
		m.logFile = nil
	}
	runDir := m.runDir
	if runDir == "" {
		if cfg, err := GetConfig(); err == nil {
			runDir = cfg.EffectiveRunDir()
		}
	}
	if runDir != "" {
		_ = netfilter.CleanAll(runDir)
	}
	logger.Get().Infof("zengobox", "core stopped")
	return nil
}

// Restart is Stop followed by Start.
func (m *Manager) Restart() error {
	if err := m.Stop(); err != nil {
		return err
	}
	// Small settle delay so the old process group is fully gone.
	time.Sleep(500 * time.Millisecond)
	return m.Start()
}

// supervise waits for the core to exit and applies the restart policy.
// It runs in its own goroutine; exactly one exists per started core.
func (m *Manager) supervise(cfg *ZengoConfig) {
	cmd := m.cmd
	lf := m.logFile
	waitErr := cmd.Wait()
	if lf != nil {
		lf.Close()
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.cmd = nil
	m.logFile = nil
	if m.stopReq {
		return // intentional stop: stay down
	}
	logger.Get().Warnf("zengobox", "core exited unexpectedly: %v", waitErr)
	_ = netfilter.CleanAll(m.runDir)
	_ = os.Remove(filepath.Join(m.runDir, netfilter.PIDFileName))

	if !m.allowRestartLocked(cfg) {
		m.crashed = true
		logger.Get().Errorf("zengobox", "restart policy exhausted, giving up (manual start required)")
		return
	}
	m.restarts = append(m.restarts, time.Now())
	backoff := parseBackoff(cfg)
	// Sleep without holding the lock so Stop()/Start() stay responsive.
	m.mu.Unlock()
	time.Sleep(backoff)
	m.mu.Lock()
	if m.stopReq {
		return
	}
	if err := m.startLocked(cfg); err != nil {
		m.crashed = true
		logger.Get().Errorf("zengobox", "auto-restart failed: %v", err)
	}
}

// allowRestartLocked implements max_restarts per restart_window.
func (m *Manager) allowRestartLocked(cfg *ZengoConfig) bool {
	maxR := cfg.Process.MaxRestarts
	if maxR <= 0 {
		maxR = 5
	}
	window := parseWindow(cfg)
	now := time.Now()
	kept := m.restarts[:0]
	for _, t := range m.restarts {
		if now.Sub(t) <= window {
			kept = append(kept, t)
		}
	}
	m.restarts = kept
	return len(kept) < maxR
}

func parseWindow(cfg *ZengoConfig) time.Duration {
	if d, err := time.ParseDuration(cfg.Process.RestartWindow); err == nil && d > 0 {
		return d
	}
	return 5 * time.Minute
}

func parseBackoff(cfg *ZengoConfig) time.Duration {
	if d, err := time.ParseDuration(cfg.Process.RestartBackoff); err == nil && d >= 0 {
		return d
	}
	return 3 * time.Second
}

// netfilterConfig translates the master config into netfilter.RuleConfig.
func netfilterConfig(cfg *ZengoConfig) *netfilter.RuleConfig {
	return &netfilter.RuleConfig{
		Mode:            cfg.Network.Mode,
		TProxyPort:      cfg.Network.TProxyPort,
		RedirPort:       cfg.Network.RedirPort,
		IPv6:            cfg.Network.IPv6,
		QUICBlock:       cfg.Network.QUICBlock,
		ClashDNSForward: cfg.Network.ClashDNSForward,
		ClashDNSPort:    cfg.Network.ClashDNSPort,
		ProxyMode:       cfg.Proxy.Mode,
		Packages:        cfg.Proxy.Packages,
		GIDs:            cfg.Proxy.GIDs,
		AllowIfaces:     cfg.Proxy.APList.Allow,
		IgnoreIfaces:    cfg.Proxy.APList.Ignore,
	}
}
