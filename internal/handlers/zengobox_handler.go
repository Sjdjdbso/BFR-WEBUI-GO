package handlers

// ZenGoBox API handlers — the replacement for the legacy /api/proxy/*
// "box for root" controller. JSON contracts match the zengobox.js v1.4.41
// frontend (PascalCase config keys, {running,pid,core,...} status shape).

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
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
