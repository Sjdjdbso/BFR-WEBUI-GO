package handlers

// ZenGoBox API handlers — the replacement for the legacy /api/proxy/*
// "box for root" controller. JSON contracts match the zengobox.js v1.4.41
// frontend (PascalCase config keys, {running,pid,core,...} status shape).

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"bfr-webui-go/internal/config"
	"bfr-webui-go/internal/logger"
	"bfr-webui-go/internal/zengobox"
)

// validNetworkModes mirrors the Network.Mode whitelist in zengobox.js.
var validNetworkModes = map[string]bool{
	"tproxy": true, "redirect": true, "mixed": true, "enhance": true,
	"tun": true, "ebpf": true, "hybrid": true,
}

var validProxyModes = map[string]bool{
	"blacklist": true, "whitelist": true, "core": true,
}

var validLogLevels = map[string]bool{
	"debug": true, "info": true, "warn": true, "error": true,
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": msg})
}

// HandleZengoboxStatus reports daemon state for the setup wizard,
// main dashboard and polling loop (every 3s).
func HandleZengoboxStatus(w http.ResponseWriter, r *http.Request) {
	cfg, err := zengobox.GetConfig()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to load config: "+err.Error())
		return
	}

	running := false
	pid := 0
	for _, c := range zengobox.DetectCores() {
		if c.Running && (c.Name == cfg.Core.BinName || cfg.Core.BinName == "") {
			running = true
			pid = c.PID
			break
		}
	}

	binPath := cfg.CoreBinary()
	needsSetup := true
	if st, err := os.Stat(binPath); err == nil && !st.IsDir() {
		needsSetup = false
	}

	coreVersion := cfg.Core.Version
	if coreVersion == "" {
		coreVersion = "unknown"
	}
	if needsSetup {
		coreVersion = "not installed"
	}

	mode := cfg.Network.Mode
	if mode == "" {
		mode = "tproxy"
	}

	writeJSON(w, map[string]interface{}{
		"running":        running,
		"pid":            pid,
		"core":           cfg.Core.BinName,
		"core_version":   coreVersion,
		"mode":           mode,
		"effective_mode": mode, // hybrid tier resolution lands in Phase 2
		"hotspot":        false,
		"needs_setup":    needsSetup,
	})
}

// HandleZengoboxConfig serves the master config (GET) and saves it (POST).
// The frontend always POSTs the complete config object, never a delta.
func HandleZengoboxConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		cfg, err := zengobox.GetConfig()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to load config: "+err.Error())
			return
		}
		writeJSON(w, cfg)
		return
	}

	if r.Method == http.MethodPost {
		var cfg zengobox.ZengoConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			writeJSONError(w, http.StatusBadRequest, "Invalid config body")
			return
		}
		if err := validateZengoConfig(&cfg); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := cfg.Save(zengobox.ConfigPath()); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to save config: "+err.Error())
			return
		}
		logger.Get().Infof("zengobox", "Master config saved")
		writeJSON(w, map[string]interface{}{"success": true})
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func validateZengoConfig(cfg *zengobox.ZengoConfig) error {
	if cfg.Network.Mode != "" && !validNetworkModes[strings.ToLower(cfg.Network.Mode)] {
		return fmt.Errorf("invalid network mode: %q", cfg.Network.Mode)
	}
	if cfg.Proxy.Mode != "" && !validProxyModes[strings.ToLower(cfg.Proxy.Mode)] {
		return fmt.Errorf("invalid proxy mode: %q", cfg.Proxy.Mode)
	}
	if cfg.Log.Level != "" && !validLogLevels[strings.ToLower(cfg.Log.Level)] {
		return fmt.Errorf("invalid log level: %q", cfg.Log.Level)
	}
	if cfg.Network.TProxyPort < 0 || cfg.Network.TProxyPort > 65535 {
		return fmt.Errorf("invalid tproxy port: %d", cfg.Network.TProxyPort)
	}
	if cfg.Network.RedirPort < 0 || cfg.Network.RedirPort > 65535 {
		return fmt.Errorf("invalid redirect port: %d", cfg.Network.RedirPort)
	}
	if cfg.Process.MaxRestarts < 0 || cfg.Process.MaxRestarts > 100 {
		return fmt.Errorf("invalid max_restarts: %d", cfg.Process.MaxRestarts)
	}
	return nil
}

// HandleZengoboxSysinfo returns device info used by the settings page
// (CPU core count hint for the cpuset field).
func HandleZengoboxSysinfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{
		"cpu_cores": runtime.NumCPU(),
	})
}

// zengoboxApp is one row in the per-app routing picker.
type zengoboxApp struct {
	Package string `json:"package"`
	Label   string `json:"label"`
	System  bool   `json:"system"`
}

// HandleZengoboxApps lists installed packages for the per-app routing picker.
// Labels are best-effort (package name); system flag comes from the APK path.
func HandleZengoboxApps(w http.ResponseWriter, r *http.Request) {
	out, err := config.ExecSuTimeout(15*time.Second, "pm list packages -f 2>/dev/null")
	apps := []zengoboxApp{}
	if err == nil {
		seen := map[string]bool{}
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "package:") {
				continue
			}
			rest := strings.TrimPrefix(line, "package:")
			// format: /path/base.apk=com.example.app
			pkg := rest
			apkPath := ""
			if i := strings.LastIndex(rest, "="); i >= 0 {
				apkPath = rest[:i]
				pkg = rest[i+1:]
			}
			if pkg == "" || seen[pkg] {
				continue
			}
			seen[pkg] = true
			system := strings.Contains(apkPath, "/system/") ||
				strings.Contains(apkPath, "/product/") ||
				strings.Contains(apkPath, "/vendor/") ||
				strings.Contains(apkPath, "/system_ext/")
			apps = append(apps, zengoboxApp{Package: pkg, Label: pkg, System: system})
		}
	}
	writeJSON(w, map[string]interface{}{"apps": apps})
}

// statusPayload converts a Manager status into the frontend's shape.
func statusPayload(st zengobox.CoreStatus) map[string]interface{} {
	mode := st.EffectiveMode
	if mode == "" {
		mode = "tproxy"
	}
	return map[string]interface{}{
		"running":        st.Running,
		"pid":            st.PID,
		"core":           st.Core,
		"mode":           mode,
		"effective_mode": mode,
		"needs_setup":    st.NeedsSetup,
		"crashed":        st.Crashed,
	}
}

// HandleZengoboxStart launches the proxy core under Manager supervision
// (POST only). On missing core binary it reports needs_setup so the
// frontend shows the setup wizard instead of a generic error.
func HandleZengoboxStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	mgr := zengobox.GetManager()
	if err := mgr.Start(); err != nil {
		if errors.Is(err, zengobox.ErrNeedsSetup) {
			writeJSON(w, map[string]interface{}{
				"success": false, "needs_setup": true, "error": err.Error(),
			})
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "start failed: "+err.Error())
		return
	}
	writeJSON(w, map[string]interface{}{"success": true, "status": statusPayload(mgr.Status())})
}

// HandleZengoboxStop terminates the core and cleans netfilter state.
func HandleZengoboxStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	mgr := zengobox.GetManager()
	if err := mgr.Stop(); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "stop failed: "+err.Error())
		return
	}
	writeJSON(w, map[string]interface{}{"success": true, "status": statusPayload(mgr.Status())})
}

// HandleZengoboxRestart is Stop followed by Start.
func HandleZengoboxRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	mgr := zengobox.GetManager()
	if err := mgr.Restart(); err != nil {
		if errors.Is(err, zengobox.ErrNeedsSetup) {
			writeJSON(w, map[string]interface{}{
				"success": false, "needs_setup": true, "error": err.Error(),
			})
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "restart failed: "+err.Error())
		return
	}
	writeJSON(w, map[string]interface{}{"success": true, "status": statusPayload(mgr.Status())})
}

// maxLogLines bounds the /api/zengobox/logs response (frontend polls it).
const maxLogLines = 200
// HandleZengoboxLogs returns the tail of the core log file.
func HandleZengoboxLogs(w http.ResponseWriter, r *http.Request) {
	cfg, err := zengobox.GetConfig()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to load config: "+err.Error())
		return
	}
	logs := []string{}
	if data, err := os.ReadFile(filepath.Join(cfg.EffectiveRunDir(), "core.log")); err == nil {
		lines := strings.Split(string(data), "\n")
		if len(lines) > maxLogLines {
			lines = lines[len(lines)-maxLogLines:]
		}
		for _, l := range lines {
			if strings.TrimSpace(l) != "" {
				logs = append(logs, l)
			}
		}
	}
	writeJSON(w, map[string]interface{}{"logs": logs})
}
// HandleZengoboxAccounts serves raw proxy account files (GET) and saves
// them (POST). Query: ?file=AKUN-ID|AKUN-SG&core=clash|sing-box.
// GET returns plain text (the frontend reads it with res.text()).
// POST takes {"content": "<full file text>"} and replaces the file.
func HandleZengoboxAccounts(w http.ResponseWriter, r *http.Request) {
	file := r.URL.Query().Get("file")
	core := r.URL.Query().Get("core")

	if r.Method == http.MethodGet {
		text, err := zengobox.ReadAccounts(file, core)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(text))
		return
	}

	if r.Method == http.MethodPost {
		var body struct {
			Content string `json:"content"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSONError(w, http.StatusBadRequest, "Invalid body")
			return
		}
		if err := zengobox.WriteAccounts(file, core, body.Content); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		logger.Get().Infof("zengobox", "accounts saved: %s (%s)", file, core)
		writeJSON(w, map[string]interface{}{"success": true})
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// HandleZengoboxConvert converts one share link into a proxy definition.
// Query: ?core=clash|sing-box. Body: {"link": "vmess://..."}.
// Response: {"yaml": "- name: ..."} for clash, or the JSON outbound object
// for sing-box — exactly what zengobox.js v1.4.41 expects.
func HandleZengoboxConvert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	core := r.URL.Query().Get("core")
	var body struct {
		Link string `json:"link"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid body")
		return
	}
	if strings.TrimSpace(body.Link) == "" {
		writeJSONError(w, http.StatusBadRequest, "link is required")
		return
	}
	// Gather taken names from both account files so the new name is unique.
	taken := map[string]bool{}
	for _, f := range []string{"AKUN-ID.yaml", "AKUN-SG.yaml", "AKUN-ID.json", "AKUN-SG.json"} {
		if names, err := zengobox.ExistingNames(f, core); err == nil {
			for n := range names {
				taken[n] = true
			}
		}
	}
	out, err := zengobox.ConvertLink(body.Link, core, taken)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, out)
}

// coreConfigFile resolves the managed core config file for ?core=.
func coreConfigFile(core string) (string, error) {
	c := strings.ToLower(strings.TrimSpace(core))
	if c != "clash" && c != "sing-box" {
		return "", fmt.Errorf("invalid core %q (want clash|sing-box)", core)
	}
	cfg, err := zengobox.GetConfig()
	if err != nil {
		return "", err
	}
	name := cfg.Core.ConfigNames[c]
	if name == "" {
		if c == "sing-box" {
			name = "config.json"
		} else {
			name = "config.yaml"
		}
	}
	if strings.Contains(name, "/") || strings.Contains(name, "..") {
		return "", fmt.Errorf("invalid config name %q", name)
	}
	return filepath.Join(cfg.EffectiveBoxDir(), name), nil
}

// HandleZengoboxCoreConfig serves (GET) and saves (POST) the raw core
// config file. Query: ?core=clash|sing-box. POST takes {"content": "..."}
// and restarts the daemon afterwards, mirroring v1.4.41.
func HandleZengoboxCoreConfig(w http.ResponseWriter, r *http.Request) {
	core := r.URL.Query().Get("core")
	p, err := coreConfigFile(core)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	if r.Method == http.MethodGet {
		data, err := os.ReadFile(p)
		if err != nil {
			if os.IsNotExist(err) {
				// Fall back to the legacy clash config location.
				if strings.ToLower(core) == "clash" {
					if _, legacy, lerr := zengobox.ReadConfig(); lerr == nil {
						w.Header().Set("Content-Type", "text/plain; charset=utf-8")
						_, _ = w.Write([]byte(legacy))
						return
					}
				}
				writeJSONError(w, http.StatusNotFound, "core config not found")
				return
			}
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write(data)
		return
	}

	if r.Method == http.MethodPost {
		var body struct {
			Content string `json:"content"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSONError(w, http.StatusBadRequest, "Invalid body")
			return
		}
		if len(body.Content) > 2<<20 {
			writeJSONError(w, http.StatusBadRequest, "content too large")
			return
		}
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := os.WriteFile(p, []byte(body.Content), 0644); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		logger.Get().Infof("zengobox", "core config saved for %s", core)
		// Auto-restart so the new config takes effect (v1.4.41 behavior).
		mgr := zengobox.GetManager()
		if st := mgr.Status(); st.Running {
			if err := mgr.Restart(); err != nil {
				writeJSON(w, map[string]interface{}{
					"success": true, "restart_error": err.Error(),
				})
				return
			}
		}
		writeJSON(w, map[string]interface{}{"success": true})
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// HandleZengoboxSetup starts the setup wizard (POST). Body:
// {"core": "clash"|"sing-box"|"all", "version": "1.14.1",
//  "dashboard": "<zip URL>"|"none"}. Progress goes to run/setup.log.
func HandleZengoboxSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req zengobox.SetupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid body")
		return
	}
	if err := zengobox.StartSetup(req); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]interface{}{"success": true})
}

// HandleZengoboxSetupLog returns the raw setup log as plain text.
// The frontend polls it every second during installation.
func HandleZengoboxSetupLog(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(zengobox.SetupLog()))
}
