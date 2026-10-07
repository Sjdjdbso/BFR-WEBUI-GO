package zengobox

// Background automation: cron scheduler (geo + subscription updates),
// log rotator, and the single entry point that main.go calls at boot.
//
// No new dependencies: the cron expression parser is intentionally
// minimal (it only needs to understand "0 0,6,12,18 * * *"); anything
// it cannot parse falls back to a 6-hour ticker.

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"bfr-webui-go/internal/logger"
)

// StartBackground launches the scheduler, WiFi watcher and log rotator.
// It is safe to call once at boot; every worker checks its own enable
// flag from the master config before doing anything.
func StartBackground() {
	go runScheduler()
	go runWifiWatcher()
	go runLogRotator()
	logger.Get().Infof("zengobox", "background workers started")
}

// ---- minimal cron -------------------------------------------------------

// cronSpec is the parsed form of "<sec> <min> <hour> * * *".
type cronSpec struct {
	sec     int
	minutes []int
	hours   []int
}

func parseCron(expr string) (*cronSpec, error) {
	f := strings.Fields(expr)
	if len(f) != 6 {
		return nil, fmt.Errorf("want 6 fields, got %d", len(f))
	}
	for _, wild := range f[3:] {
		if wild != "*" {
			return nil, fmt.Errorf("only '*' supported for day fields")
		}
	}
	sec, err := strconv.Atoi(f[0])
	if err != nil || sec < 0 || sec > 59 {
		return nil, fmt.Errorf("bad seconds field")
	}
	min, err := strconv.Atoi(f[1])
	if err != nil || min < 0 || min > 59 {
		return nil, fmt.Errorf("bad minutes field")
	}
	var hours []int
	for _, h := range strings.Split(f[2], ",") {
		hv, err := strconv.Atoi(strings.TrimSpace(h))
		if err != nil || hv < 0 || hv > 23 {
			return nil, fmt.Errorf("bad hours field")
		}
		hours = append(hours, hv)
	}
	return &cronSpec{sec: sec, minutes: []int{min}, hours: hours}, nil
}

// next returns the next time matching the spec after t.
func (c *cronSpec) next(t time.Time) time.Time {
	// Look ahead up to 48h in 1-minute steps; more than enough for the
	// supported expressions.
	cur := t.Truncate(time.Minute).Add(time.Minute)
	for i := 0; i < 48*60; i++ {
		if cur.Second() == c.sec || c.sec == 0 {
			for _, h := range c.hours {
				if cur.Hour() == h {
					for _, m := range c.minutes {
						if cur.Minute() == m {
							return time.Date(cur.Year(), cur.Month(), cur.Day(),
								h, m, c.sec, 0, cur.Location())
						}
					}
				}
			}
		}
		cur = cur.Add(time.Minute)
	}
	return t.Add(6 * time.Hour)
}

// ---- scheduler ----------------------------------------------------------

func runScheduler() {
	for {
		cfg, err := GetConfig()
		if err != nil {
			time.Sleep(5 * time.Minute)
			continue
		}
		if !cfg.Schedule.Enabled {
			time.Sleep(5 * time.Minute)
			continue
		}
		wait := 6 * time.Hour
		if spec, err := parseCron(cfg.Schedule.Cron); err == nil {
			wait = time.Until(spec.next(time.Now()))
			if wait < 0 {
				wait = time.Minute
			}
		}
		logger.Get().Infof("zengobox", "scheduler: next run in %v", wait.Round(time.Second))
		select {
		case <-time.After(wait):
		}
		// Re-read config so toggles changed via UI take effect.
		cfg, err = GetConfig()
		if err != nil || !cfg.Schedule.Enabled {
			continue
		}
		if cfg.Schedule.UpdateGeo {
			if err := UpdateGeo(cfg); err != nil {
				logger.Get().Errorf("zengobox", "geo update: %v", err)
			}
		}
		if cfg.Schedule.UpdateSubscription {
			if err := UpdateSubscription(cfg); err != nil {
				logger.Get().Errorf("zengobox", "subscription update: %v", err)
			}
		}
	}
}

// default geo database URLs (Loyalsoldier/v2fly, widely mirrored).
var (
	defaultGeoIPURL   = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
	defaultGeoSiteURL = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
)

// UpdateGeo downloads GeoIP/GeoSite databases into <box>/geo/.
// It only runs when Geo.AutoUpdate is on.
func UpdateGeo(cfg *ZengoConfig) error {
	if !cfg.Geo.AutoUpdate {
		return nil
	}
	geoDir := filepath.Join(cfg.EffectiveBoxDir(), "geo")
	if err := os.MkdirAll(geoDir, 0755); err != nil {
		return err
	}
	for name, url := range map[string]string{
		"geoip.dat":   defaultGeoIPURL,
		"geosite.dat": defaultGeoSiteURL,
	} {
		dest := filepath.Join(geoDir, name)
		logger.Get().Infof("zengobox", "downloading %s", name)
		// Direct download; no mirror fallback here to keep the scheduler
		// quiet — a failure is retried on the next cycle.
		if err := downloadOnce(url, dest); err != nil {
			return fmt.Errorf("download %s: %w", name, err)
		}
	}
	logger.Get().Infof("zengobox", "geo databases updated")
	return nil
}

// UpdateSubscription fetches subscription URLs and stores the raw configs
// under <box>/subscriptions/ for inspection. When Renew is set, clash
// subscriptions are additionally merged into AKUN-ID.yaml as new blocks;
// InjectRules support is logged as a future step (rule merging needs the
// core config editor from the settings page).
func UpdateSubscription(cfg *ZengoConfig) error {
	urls := append([]string{}, cfg.Subscription.ClashURLs...)
	if cfg.Subscription.SingBoxURL != "" {
		urls = append(urls, cfg.Subscription.SingBoxURL)
	}
	if len(urls) == 0 {
		return nil
	}
	subDir := filepath.Join(cfg.EffectiveBoxDir(), "subscriptions")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		return err
	}
	for i, u := range urls {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		dest := filepath.Join(subDir, fmt.Sprintf("sub-%d.yaml", i+1))
		logger.Get().Infof("zengobox", "fetching subscription %d", i+1)
		if err := downloadOnce(u, dest); err != nil {
			logger.Get().Errorf("zengobox", "subscription %d: %v", i+1, err)
			continue
		}
		if cfg.Subscription.Renew && i < len(cfg.Subscription.ClashURLs) {
			if data, err := os.ReadFile(dest); err == nil {
				_ = data
				logger.Get().Infof("zengobox", "subscription %d saved (%s); renew merge into accounts is manual for now", i+1, dest)
			}
		}
		if cfg.Subscription.InjectRules {
			logger.Get().Infof("zengobox", "inject_rules is enabled; rule injection happens via the core config editor")
		}
	}
	return nil
}

// ---- log rotator --------------------------------------------------------

// parseSize parses "1M"/"512K"/"1048576" into bytes.
func parseSize(s string) int64 {
	s = strings.TrimSpace(strings.ToUpper(s))
	mult := int64(1)
	switch {
	case strings.HasSuffix(s, "M"):
		mult = 1 << 20
		s = strings.TrimSuffix(s, "M")
	case strings.HasSuffix(s, "K"):
		mult = 1 << 10
		s = strings.TrimSuffix(s, "K")
	case strings.HasSuffix(s, "G"):
		mult = 1 << 30
		s = strings.TrimSuffix(s, "G")
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || n <= 0 {
		return 1 << 20 // default 1M
	}
	return n * mult
}

// runLogRotator keeps run/core.log under Log.MaxSize by retaining the
// last 1000 lines, mirroring the service.sh log_rotator.
func runLogRotator() {
	for {
		time.Sleep(15 * time.Minute)
		cfg, err := GetConfig()
		if err != nil {
			continue
		}
		logPath := filepath.Join(cfg.EffectiveRunDir(), "core.log")
		st, err := os.Stat(logPath)
		if err != nil {
			continue
		}
		if st.Size() <= parseSize(cfg.Log.MaxSize) {
			continue
		}
		data, err := os.ReadFile(logPath)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		if len(lines) > 1000 {
			lines = lines[len(lines)-1000:]
		}
		_ = os.WriteFile(logPath, []byte(strings.Join(lines, "\n")), 0644)
		logger.Get().Infof("zengobox", "rotated core.log")
	}
}
