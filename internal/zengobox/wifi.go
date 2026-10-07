package zengobox

// Smart WiFi watcher: polls the current WiFi SSID and starts/stops the
// proxy core according to Wifi.UseOnWifi / Wifi.UseOnDisconnect, with
// optional SSID blacklist/whitelist matching.
//
// Poll-based (dumpsys wifi) so no new dependencies are needed. Only runs
// when Wifi.Enabled is set. All actions are logged; state changes are
// debounced so the core is never flapped.

import (
	"regexp"
	"strings"
	"time"

	"bfr-webui-go/internal/config"
	"bfr-webui-go/internal/logger"
)

// ssidRe extracts SSID: "name" from dumpsys wifi output.
var ssidRe = regexp.MustCompile(`SSID:\s*"([^"]+)"`)

// currentSSID returns the connected WiFi SSID, or "" when disconnected.
// An error is returned only when the dumpsys call itself fails.
func currentSSID() (string, error) {
	out, err := config.ExecSuTimeout(15*time.Second, "dumpsys wifi 2>/dev/null | grep -m1 -i 'mWifiInfo'")
	if err != nil {
		return "", err
	}
	m := ssidRe.FindStringSubmatch(string(out))
	if len(m) < 2 {
		return "", nil
	}
	ssid := strings.TrimSpace(m[1])
	if ssid == "" || ssid == "<unknown ssid>" {
		return "", nil
	}
	return ssid, nil
}

// ssidAllowed reports whether the SSID passes the blacklist/whitelist.
func ssidAllowed(cfg *ZengoConfig, ssid string) bool {
	if !cfg.Wifi.SSIDMatching || len(cfg.Wifi.SSIDList) == 0 {
		return true
	}
	inList := false
	for _, s := range cfg.Wifi.SSIDList {
		if strings.EqualFold(strings.TrimSpace(s), ssid) {
			inList = true
			break
		}
	}
	if strings.ToLower(cfg.Wifi.SSIDMode) == "whitelist" {
		return inList
	}
	return !inList // blacklist (default)
}

// runWifiWatcher is the poll loop; see StartBackground.
func runWifiWatcher() {
	const poll = 30 * time.Second
	const debounce = 60 * time.Second
	var lastAction time.Time
	var lastState string // "wifi" | "disconnected" | ""

	for {
		time.Sleep(poll)
		cfg, err := GetConfig()
		if err != nil || !cfg.Wifi.Enabled {
			continue
		}
		ssid, err := currentSSID()
		if err != nil {
			logger.Get().Warnf("zengobox", "wifi watcher: dumpsys failed: %v", err)
			continue
		}
		onWifi := ssid != "" && ssidAllowed(cfg, ssid)
		want := "disconnected"
		if onWifi {
			want = "wifi"
		}
		if want == lastState || time.Since(lastAction) < debounce {
			continue
		}
		mgr := GetManager()
		st := mgr.Status()
		switch {
		case onWifi && cfg.Wifi.UseOnWifi:
			if !st.Running {
				logger.Get().Infof("zengobox", "wifi watcher: connected to %q, starting core", ssid)
				if err := mgr.Start(); err != nil {
					logger.Get().Errorf("zengobox", "wifi watcher: start failed: %v", err)
					continue
				}
			}
		case !onWifi && cfg.Wifi.UseOnDisconnect:
			if !st.Running {
				logger.Get().Infof("zengobox", "wifi watcher: disconnected, starting core")
				if err := mgr.Start(); err != nil {
					logger.Get().Errorf("zengobox", "wifi watcher: start failed: %v", err)
					continue
				}
			}
		case onWifi && !cfg.Wifi.UseOnWifi:
			if st.Running {
				logger.Get().Infof("zengobox", "wifi watcher: connected to %q, stopping core", ssid)
				if err := mgr.Stop(); err != nil {
					logger.Get().Errorf("zengobox", "wifi watcher: stop failed: %v", err)
					continue
				}
			}
		case !onWifi && !cfg.Wifi.UseOnDisconnect:
			if st.Running {
				logger.Get().Infof("zengobox", "wifi watcher: disconnected, stopping core")
				if err := mgr.Stop(); err != nil {
					logger.Get().Errorf("zengobox", "wifi watcher: stop failed: %v", err)
					continue
				}
			}
		}
		lastState = want
		lastAction = time.Now()
	}
}
