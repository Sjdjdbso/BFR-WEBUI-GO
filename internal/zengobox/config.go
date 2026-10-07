// Package zengobox implements the ZenGoBox-style proxy core manager for BFR.
// It replaces the legacy internal/proxy "box for root" controller.
//
// The master configuration schema (54 YAML tags) was recovered from the
// AWD OS ZenGoBox master config and its Go binary's struct tags. JSON keys
// use PascalCase to stay compatible with the zengobox.js v1.4.41 frontend.
package zengobox

import (
	"fmt"
	"os"
	"path/filepath"

	"bfr-webui-go/internal/config"

	"gopkg.in/yaml.v3"
)

// ZengoConfig is the master configuration for the proxy core manager.
type ZengoConfig struct {
	Core         CoreConfig         `yaml:"core"         json:"Core"`
	Network      NetworkConfig      `yaml:"network"      json:"Network"`
	Proxy        ProxyConfig        `yaml:"proxy"        json:"Proxy"`
	Process      ProcessConfig      `yaml:"process"      json:"Process"`
	Cgroup       CgroupConfig       `yaml:"cgroup"       json:"Cgroup"`
	Subscription SubscriptionConfig `yaml:"subscription" json:"Subscription"`
	Geo          GeoConfig          `yaml:"geo"          json:"Geo"`
	Schedule     ScheduleConfig     `yaml:"schedule"     json:"Schedule"`
	Wifi         WifiConfig         `yaml:"wifi"         json:"Wifi"`
	Log          LogConfig          `yaml:"log"          json:"Log"`
	Paths        PathsConfig        `yaml:"paths"        json:"Paths"`
}

type CoreConfig struct {
	BinName     string            `yaml:"bin_name"     json:"BinName"`     // "sing-box" | "clash"
	BinList     []string          `yaml:"bin_list"     json:"BinList"`     // ["sing-box","clash"]
	ClashOption string            `yaml:"clash_option" json:"ClashOption"` // "mihomo" | "premium"
	APISecret   string            `yaml:"api_secret"   json:"APISecret"`
	ConfigNames map[string]string `yaml:"config_names" json:"ConfigNames"` // clash: config.yaml, sing-box: config.json
	Version     string            `yaml:"version"      json:"Version"`     // installed core version, e.g. "1.14.1"
}

type NetworkConfig struct {
	Mode            string `yaml:"mode"              json:"Mode"` // tproxy|redirect|mixed|enhance|tun|ebpf|hybrid
	TProxyPort      int    `yaml:"tproxy_port"       json:"TProxyPort"`
	RedirPort       int    `yaml:"redir_port"        json:"RedirPort"`
	IPv6            bool   `yaml:"ipv6"              json:"IPv6"`
	QUICBlock       bool   `yaml:"quic_block"        json:"QUICBlock"`
	ClashDNSForward bool   `yaml:"clash_dns_forward" json:"ClashDNSForward"`
	ClashDNSPort    int    `yaml:"clash_dns_port"    json:"ClashDNSPort"`
}

type ProxyConfig struct {
	Mode     string   `yaml:"mode"     json:"Mode"` // blacklist|whitelist|core
	Packages []string `yaml:"packages" json:"Packages"`
	GIDs     []int    `yaml:"gids"     json:"GIDs"`
	APList   APList   `yaml:"ap_list"  json:"APList"`
}

type APList struct {
	Allow  []string `yaml:"allow"  json:"Allow"`
	Ignore []string `yaml:"ignore" json:"Ignore"`
}

type ProcessConfig struct {
	UserGroup      string `yaml:"user_group"     json:"UserGroup"`
	MaxRestarts    int    `yaml:"max_restarts"    json:"MaxRestarts"`
	RestartWindow  string `yaml:"restart_window" json:"RestartWindow"`   // e.g. "5m"
	RestartBackoff string `yaml:"restart_backoff" json:"RestartBackoff"` // e.g. "3s"
}

type CgroupConfig struct {
	MemCG  MemCGConfig  `yaml:"memcg"  json:"MemCG"`
	CPUSet CPUSetConfig `yaml:"cpuset" json:"CPUSet"`
	BlkIO  BlkIOConfig  `yaml:"blkio"  json:"BlkIO"`
}

type MemCGConfig struct {
	Enabled bool   `yaml:"enabled" json:"Enabled"`
	Limit   string `yaml:"limit"   json:"Limit"` // e.g. "100M"
}

type CPUSetConfig struct {
	Enabled bool   `yaml:"enabled" json:"Enabled"`
	Cores   string `yaml:"cores"   json:"Cores"` // e.g. "0-3"
}

type BlkIOConfig struct {
	Enabled bool `yaml:"enabled" json:"Enabled"`
}

type SubscriptionConfig struct {
	ClashURLs   []string `yaml:"clash_urls"   json:"ClashURLs"`
	SingBoxURL  string   `yaml:"singbox_url"  json:"SingBoxURL"`
	Renew       bool     `yaml:"renew"        json:"Renew"`
	InjectRules bool     `yaml:"inject_rules" json:"InjectRules"`
}

type GeoConfig struct {
	AutoUpdate bool `yaml:"auto_update" json:"AutoUpdate"`
}

type ScheduleConfig struct {
	Enabled            bool   `yaml:"enabled"             json:"Enabled"`
	Cron               string `yaml:"cron"               json:"Cron"`
	UpdateGeo          bool   `yaml:"update_geo"          json:"UpdateGeo"`
	UpdateSubscription bool   `yaml:"update_subscription" json:"UpdateSubscription"`
}

type WifiConfig struct {
	Enabled         bool     `yaml:"enabled"           json:"Enabled"`
	UseOnWifi       bool     `yaml:"use_on_wifi"       json:"UseOnWifi"`
	UseOnDisconnect bool     `yaml:"use_on_disconnect" json:"UseOnDisconnect"`
	SSIDMatching    bool     `yaml:"ssid_matching"     json:"SSIDMatching"`
	SSIDMode        string   `yaml:"ssid_mode"         json:"SSIDMode"` // blacklist|whitelist
	SSIDList        []string `yaml:"ssid_list"         json:"SSIDList"`
}

type LogConfig struct {
	Level   string `yaml:"level"    json:"Level"` // debug|info|warn|error
	MaxSize string `yaml:"max_size" json:"MaxSize"`
	Toast   bool   `yaml:"toast"    json:"Toast"`
}

type PathsConfig struct {
	BoxDir string `yaml:"box_dir" json:"BoxDir"`
	BinDir string `yaml:"bin_dir" json:"BinDir"`
	RunDir string `yaml:"run_dir" json:"RunDir"`
	LogDir string `yaml:"log_dir" json:"LogDir"`
}

// baseDir is the root directory for all ZenGoBox state.
func baseDir() string {
	return filepath.Join(config.GetPersistentDataDir(), "zengobox")
}

// ConfigPath returns the path of the master config file.
func ConfigPath() string {
	return filepath.Join(baseDir(), "zengobox.yaml")
}

// DefaultRunDir returns the default run directory without loading any
// config (used by one-shot tools like --clean-netfilter).
func DefaultRunDir() string {
	return filepath.Join(baseDir(), "run")
}

// DefaultConfig returns a ZengoConfig with safe defaults mirroring the
// ZenGoBox master config (tproxy mode, sing-box core, QUIC block on).
func DefaultConfig() *ZengoConfig {
	return &ZengoConfig{
		Core: CoreConfig{
			BinName:     "sing-box",
			BinList:     []string{"sing-box", "clash"},
			ClashOption: "mihomo",
			APISecret:   "",
			ConfigNames: map[string]string{
				"clash":    "config.yaml",
				"sing-box": "config.json",
			},
			Version: "",
		},
		Network: NetworkConfig{
			Mode:            "tproxy",
			TProxyPort:      9898,
			RedirPort:       9797,
			IPv6:            false,
			QUICBlock:       true,
			ClashDNSForward: false,
			ClashDNSPort:    7874,
		},
		Proxy: ProxyConfig{
			Mode:     "blacklist",
			Packages: []string{},
			GIDs:     []int{},
			APList: APList{
				Allow:  []string{"ap+", "wlan+", "rndis+", "swlan+", "ncm+", "eth+"},
				Ignore: []string{},
			},
		},
		Process: ProcessConfig{
			UserGroup:      "root:net_admin",
			MaxRestarts:    5,
			RestartWindow:  "5m",
			RestartBackoff: "3s",
		},
		Cgroup: CgroupConfig{
			MemCG:  MemCGConfig{Enabled: false, Limit: "100M"},
			CPUSet: CPUSetConfig{Enabled: false, Cores: ""},
			BlkIO:  BlkIOConfig{Enabled: false},
		},
		Subscription: SubscriptionConfig{
			ClashURLs:   []string{},
			SingBoxURL:  "",
			Renew:       false,
			InjectRules: false,
		},
		Geo: GeoConfig{AutoUpdate: false},
		Schedule: ScheduleConfig{
			Enabled:            false,
			Cron:               "0 0,6,12,18 * * *",
			UpdateGeo:          false,
			UpdateSubscription: false,
		},
		Wifi: WifiConfig{
			Enabled:         false,
			UseOnWifi:       false,
			UseOnDisconnect: true,
			SSIDMatching:    false,
			SSIDMode:        "blacklist",
			SSIDList:        []string{},
		},
		Log: LogConfig{
			Level:   "info",
			MaxSize: "1M",
			Toast:   true,
		},
		Paths: PathsConfig{}, // resolved dynamically by the Effective* helpers
	}
}

// EffectiveBoxDir returns the configured box dir or the default.
func (c *ZengoConfig) EffectiveBoxDir() string {
	if c.Paths.BoxDir != "" {
		return c.Paths.BoxDir
	}
	return baseDir()
}

// EffectiveBinDir returns the configured bin dir or the default.
func (c *ZengoConfig) EffectiveBinDir() string {
	if c.Paths.BinDir != "" {
		return c.Paths.BinDir
	}
	return filepath.Join(c.EffectiveBoxDir(), "bin")
}

// EffectiveRunDir returns the configured run dir or the default.
func (c *ZengoConfig) EffectiveRunDir() string {
	if c.Paths.RunDir != "" {
		return c.Paths.RunDir
	}
	return filepath.Join(c.EffectiveBoxDir(), "run")
}

// EffectiveLogDir returns the configured log dir or the default.
func (c *ZengoConfig) EffectiveLogDir() string {
	if c.Paths.LogDir != "" {
		return c.Paths.LogDir
	}
	return c.EffectiveRunDir()
}

// CoreBinary returns the absolute path of the configured proxy core binary.
func (c *ZengoConfig) CoreBinary() string {
	bin := c.Core.BinName
	if bin == "" {
		bin = "sing-box"
	}
	return filepath.Join(c.EffectiveBinDir(), bin)
}

// Load reads a master config from path.
func Load(path string) (*ZengoConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg ZengoConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse zengobox.yaml: %w", err)
	}
	return &cfg, nil
}

// Save writes the master config to path, creating parent dirs as needed.
func (c *ZengoConfig) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// GetConfig returns the current master config, creating defaults on first run.
func GetConfig() (*ZengoConfig, error) {
	p := ConfigPath()
	cfg, err := Load(p)
	if err == nil {
		return cfg, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	cfg = DefaultConfig()
	if err := cfg.Save(p); err != nil {
		return nil, err
	}
	return cfg, nil
}
