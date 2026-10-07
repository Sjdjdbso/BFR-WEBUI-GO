package zengobox

// Core detection, process control, Clash API mode, log streaming and the
// legacy watchdog — moved from the retired internal/proxy package
// ("box for root" controller) so existing callers (e.g. the Telegram bot)
// keep working. The watchdog and ControlService are superseded by Manager
// (zengobox.go) in Phase 2; they remain here as a compatibility layer.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"bfr-webui-go/internal/config"
)

type CoreInfo struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Exists  bool   `json:"exists"`
	Running bool   `json:"running"`
	PID     int    `json:"pid"`
	Memory  string `json:"memory"`
}

type LogHub struct {
	mu        sync.RWMutex
	listeners map[chan string]bool
}

// M-7: dedicated HTTP client with timeout for Clash API requests.
var clashHTTPClient = &http.Client{
	Timeout: 5 * time.Second,
}

var (
	hub = &LogHub{
		listeners: make(map[chan string]bool),
	}

	// L-4: allow overriding hardcoded base paths via environment variables.
	boxBasePath   = envOrDefault("BFR_BOX_BASE", "/data/adb/box")
	clashBasePath = envOrDefault("BFR_CLASH_BASE", "/data/adb/clash")
	// ZenGoBox-managed core binaries (populated by the setup wizard).
	zengoBinDir = filepath.Join(config.GetPersistentDataDir(), "zengobox", "bin")

	possibleCores = []string{
		zengoBinDir + "/sing-box",
		zengoBinDir + "/mihomo",
		zengoBinDir + "/clash",
		boxBasePath + "/bin/mihomo",
		clashBasePath + "/clash",
		"/data/adb/modules/box4magisk/bin/mihomo",
		"/data/adb/modules/clash_for_magisk/bin/clash",
		"/system/bin/mihomo",
		"/system/bin/clash",
	}

	watchdogEnabled = false
	watchdogMux     sync.Mutex
)

// envOrDefault returns the value of the environment variable if set, else the fallback.
func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func init() {
	go runWatchdog()
}

// legacyWatchdogSuppressed is set once the ZenGoBox Manager takes ownership
// of proxy core supervision (Phase 2). The old 10-second "restart blindly"
// watchdog must never fight the Manager over the same core processes, so
// runWatchdog becomes a no-op from that point on.
var legacyWatchdogSuppressed bool

func suppressLegacyWatchdog() {
	watchdogMux.Lock()
	defer watchdogMux.Unlock()
	legacyWatchdogSuppressed = true
	watchdogEnabled = false
}

func isLegacyWatchdogSuppressed() bool {
	watchdogMux.Lock()
	defer watchdogMux.Unlock()
	return legacyWatchdogSuppressed
}

func SetWatchdog(enable bool) {
	watchdogMux.Lock()
	defer watchdogMux.Unlock()
	watchdogEnabled = enable
}

func GetWatchdog() bool {
	watchdogMux.Lock()
	defer watchdogMux.Unlock()
	return watchdogEnabled
}

func runWatchdog() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if isLegacyWatchdogSuppressed() {
			continue
		}
		if GetWatchdog() {
			cores := DetectCores()
			anyRunning := false
			for _, c := range cores {
				if c.Running {
					anyRunning = true
					break
				}
			}
			if !anyRunning {
				_ = ControlService("start")
			}
		}
	}
}

func getCandidateCorePaths() []string {
	paths := make([]string, len(possibleCores))
	copy(paths, possibleCores)

	seen := make(map[string]bool)
	for _, p := range paths {
		seen[p] = true
	}

	// 1. Dynamic PATH lookup
	for _, coreName := range []string{"sing-box", "mihomo", "clash"} {
		if path, err := exec.LookPath(coreName); err == nil && path != "" {
			if !seen[path] {
				seen[path] = true
				paths = append(paths, path)
			}
		}
	}

	// 2. Scan Magisk / Root modules directory for bin/mihomo and bin/clash
	modulesDir := "/data/adb/modules"
	if entries, err := os.ReadDir(modulesDir); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			for _, coreName := range []string{"sing-box", "mihomo", "clash"} {
				candPath := filepath.Join(modulesDir, entry.Name(), "bin", coreName)
				if !seen[candPath] {
					if _, err := os.Stat(candPath); err == nil {
						seen[candPath] = true
						paths = append(paths, candPath)
					}
				}
			}
		}
	}

	return paths
}

func coreNameForPath(p string) string {
	lower := strings.ToLower(p)
	switch {
	case strings.Contains(lower, "sing-box"):
		return "sing-box"
	case strings.Contains(lower, "clash"):
		return "clash"
	default:
		return "mihomo"
	}
}

func DetectCores() []CoreInfo {
	var list []CoreInfo
	paths := getCandidateCorePaths()
	seenPaths := make(map[string]bool)

	for _, p := range paths {
		if seenPaths[p] {
			continue
		}
		seenPaths[p] = true

		info := CoreInfo{
			Name: coreNameForPath(p),
			Path: p,
		}

		if _, err := os.Stat(p); err == nil {
			info.Exists = true
			pid, running := checkRunning(info.Name)
			info.Running = running
			info.PID = pid
			if running && pid > 0 {
				info.Memory = getMemoryUsage(pid)
			}
		}
		list = append(list, info)
	}
	return list
}

func findPID(name string) (int, bool) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, false
	}

	nameLower := strings.ToLower(name)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}

		commPath := fmt.Sprintf("/proc/%d/comm", pid)
		if commBytes, err := os.ReadFile(commPath); err == nil {
			commStr := strings.TrimSpace(string(commBytes))
			if strings.EqualFold(commStr, name) || strings.Contains(strings.ToLower(commStr), nameLower) {
				return pid, true
			}
		}

		cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
		if cmdlineBytes, err := os.ReadFile(cmdlinePath); err == nil && len(cmdlineBytes) > 0 {
			cmdStr := strings.ReplaceAll(string(cmdlineBytes), "\x00", " ")
			cmdStr = strings.TrimSpace(cmdStr)
			fields := strings.Fields(cmdStr)
			if len(fields) > 0 {
				base := filepath.Base(fields[0])
				if strings.EqualFold(base, name) || strings.Contains(strings.ToLower(cmdStr), nameLower) {
					return pid, true
				}
			}
		}
	}

	return 0, false
}

func checkRunning(name string) (int, bool) {
	if pid, ok := findPID(name); ok {
		return pid, true
	}
	out, err := exec.Command(config.SUBin, "-c", "pidof "+name).Output()
	if err == nil {
		fields := strings.Fields(string(out))
		if len(fields) > 0 {
			pid, _ := strconv.Atoi(fields[0])
			return pid, true
		}
	}
	return 0, false
}

func getMemoryUsage(pid int) string {
	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	if data, err := os.ReadFile(statusPath); err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "VmRSS:") {
				return strings.TrimSpace(line)
			}
		}
	}

	out, err := exec.Command(config.SUBin, "-c", fmt.Sprintf("cat /proc/%d/status | grep RSS", pid)).Output()
	if err == nil {
		return strings.TrimSpace(string(out))
	}
	return "N/A"
}

func ControlService(action string) error {
	var cmdStr string
	switch action {
	case "start":
		if _, ok := checkRunning("mihomo"); ok {
			return nil
		}
		if _, ok := checkRunning("clash"); ok {
			return nil
		}
		if _, ok := checkRunning("sing-box"); ok {
			return nil
		}
		cmdStr = fmt.Sprintf(
			"if [ -f %s/scripts/box.service ]; then %s/scripts/box.service start; elif [ -f %s/scripts/clash.service ]; then %s/scripts/clash.service start; else %s -c mihomo -d %s/bin/ & fi",
			boxBasePath, boxBasePath, clashBasePath, clashBasePath, config.SUBin, boxBasePath,
		)
	case "stop":
		SetWatchdog(false)
		cmdStr = fmt.Sprintf(
			"if [ -f %s/scripts/box.service ]; then %s/scripts/box.service stop; elif [ -f %s/scripts/clash.service ]; then %s/scripts/clash.service stop; else killall mihomo clash sing-box 2>/dev/null || true; fi",
			boxBasePath, boxBasePath, clashBasePath, clashBasePath,
		)
	case "restart":
		cmdStr = fmt.Sprintf(
			"if [ -f %s/scripts/box.service ]; then %s/scripts/box.service restart; elif [ -f %s/scripts/clash.service ]; then %s/scripts/clash.service restart; else killall mihomo clash sing-box 2>/dev/null; sleep 1; mihomo -d %s/bin/ & fi",
			boxBasePath, boxBasePath, clashBasePath, clashBasePath, boxBasePath,
		)
	default:
		return fmt.Errorf("unknown action: %s", action)
	}

	out, err := exec.Command(config.SUBin, "-c", cmdStr).CombinedOutput()
	if err != nil {
		return fmt.Errorf("control error: %v, out: %s", err, string(out))
	}
	return nil
}

func BroadcastLog(msg string) {
	hub.mu.RLock()
	defer hub.mu.RUnlock()
	for ch := range hub.listeners {
		select {
		case ch <- msg:
		default:
		}
	}
}

func StreamLogs(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	logChan := make(chan string, 50)
	hub.mu.Lock()
	hub.listeners[logChan] = true
	hub.mu.Unlock()

	defer func() {
		hub.mu.Lock()
		delete(hub.listeners, logChan)
		hub.mu.Unlock()
		close(logChan)
	}()

	// L-4: use env-overridable base path for log file detection.
	logFile := boxBasePath + "/run/runs.log"
	if _, err := os.Stat(logFile); err != nil {
		logFile = clashBasePath + "/run/runs.log"
	}

	cmd := exec.Command(config.SUBin, "-c", "tail -n 50 -f "+logFile)
	stdout, err := cmd.StdoutPipe()
	if err == nil {
		if err := cmd.Start(); err == nil {
			defer func() {
				_ = cmd.Process.Kill()
			}()
			go func() {
				scanner := bufio.NewScanner(stdout)
				for scanner.Scan() {
					BroadcastLog(scanner.Text())
				}
			}()
		}
	}

	notify := r.Context().Done()
	for {
		select {
		case <-notify:
			return
		case msg := <-logChan:
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		}
	}
}

func GetMode() string {
	// M-7: use dedicated clashHTTPClient with timeout.
	resp, err := clashHTTPClient.Get(config.ClashAPI + "/configs")
	if err != nil {
		return "Rule"
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), `"mode":"Global"`) {
		return "Global"
	}
	if strings.Contains(string(body), `"mode":"Direct"`) {
		return "Direct"
	}
	return "Rule"
}

func SetMode(mode string) error {
	// M-2/B-1: use json.Marshal for the payload instead of fmt.Sprintf.
	payload, err := json.Marshal(map[string]string{"mode": mode})
	if err != nil {
		return fmt.Errorf("failed to marshal mode payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPatch, config.ClashAPI+"/configs", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	// M-7: use dedicated clashHTTPClient with timeout.
	resp, err := clashHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func DetectConfigPath() string {
	// L-4: allow overriding base paths via environment variables.
	paths := []string{
		boxBasePath + "/clash/config.yaml",
		boxBasePath + "/config.yaml",
		clashBasePath + "/config.yaml",
		"/data/adb/modules/box4magisk/config.yaml",
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return paths[0]
}

func ReadConfig() (string, string, error) {
	p := DetectConfigPath()
	data, err := os.ReadFile(p)
	if err != nil {
		return p, "", err
	}
	return p, string(data), nil
}

func SaveConfig(content string) error {
	p := DetectConfigPath()
	dir := filepath.Dir(p)
	_ = os.MkdirAll(dir, 0755)
	return os.WriteFile(p, []byte(content), 0644)
}
