package netfilter

// Cleaner is a Go port of scripts/net_cleaner.sh: emergency cleanup of
// tunnel & netfilter remnants left behind when the proxy core dies.
// Prevents "blocked internet" (blackhole) caused by stale TPROXY
// iptables/ip-rule entries.
//
// All functions are idempotent and only touch resources owned by us
// (see constants.go). Safe to run any time, even with nothing installed.

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"bfr-webui-go/internal/config"
)

// reSafeToken validates dynamically discovered names (interfaces, devices)
// before they are interpolated into shell commands.
var reSafeToken = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

func safeToken(s string) bool {
	return reSafeToken.MatchString(s) && s != "" && len(s) < 64
}

// run executes cmdStr as root with a timeout, returning combined output.
// Non-zero exit is returned as an error; callers that expect failure
// (e.g. delete-until-gone loops) should ignore it explicitly.
func run(d time.Duration, cmdStr string) ([]byte, error) {
	return config.ExecSuTimeout(d, cmdStr)
}

// CleanChains removes our custom chains from iptables/ip6tables.
// ipt must be "iptables" or "ip6tables".
func CleanChains(ipt string) error {
	if ipt != "iptables" && ipt != "ip6tables" {
		return fmt.Errorf("invalid iptables binary: %q", ipt)
	}
	for _, c := range Chains {
		if !safeToken(c.Table) || !safeToken(c.Chain) {
			continue
		}
		// Remove jumps from built-in chains (may have several references).
		for _, base := range []string{"PREROUTING", "OUTPUT"} {
			for {
				_, err := run(10*time.Second, fmt.Sprintf(
					"%s -t %s -D %s -j %s 2>/dev/null", ipt, c.Table, base, c.Chain))
				if err != nil {
					break
				}
			}
		}
		// Flush then delete the custom chain (best-effort, idempotent).
		_, _ = run(10*time.Second, fmt.Sprintf(
			"%s -t %s -F %s 2>/dev/null", ipt, c.Table, c.Chain))
		_, _ = run(10*time.Second, fmt.Sprintf(
			"%s -t %s -X %s 2>/dev/null", ipt, c.Table, c.Chain))
	}
	return nil
}

// CleanRouting removes fwmark ip rules and flushes routing table 2024 (v4+v6).
func CleanRouting() error {
	for {
		_, err := run(10*time.Second, fmt.Sprintf(
			"ip rule del fwmark %s table %s 2>/dev/null", FwMark, TableID))
		if err != nil {
			break
		}
	}
	for {
		_, err := run(10*time.Second, fmt.Sprintf(
			"ip -6 rule del fwmark %s table %s 2>/dev/null", FwMark, TableID))
		if err != nil {
			break
		}
	}
	_, _ = run(10*time.Second, fmt.Sprintf("ip route flush table %s 2>/dev/null", TableID))
	_, _ = run(10*time.Second, fmt.Sprintf("ip -6 route flush table %s 2>/dev/null", TableID))
	return nil
}

// CleanProcesses kills leftover core processes and removes the PID file.
// runDir is the ZenGoBox run directory (holds core.pid).
func CleanProcesses(runDir string) error {
	for _, name := range CoreProcs {
		if !safeToken(name) {
			continue
		}
		out, err := run(10*time.Second, fmt.Sprintf("pgrep -x %s 2>/dev/null", name))
		if err != nil || len(bytes.TrimSpace(out)) == 0 {
			continue
		}
		_, _ = run(10*time.Second, fmt.Sprintf("killall %s 2>/dev/null", name))
		_, _ = run(1*time.Second, "sleep 1")
		if out2, err2 := run(10*time.Second, fmt.Sprintf("pgrep -x %s 2>/dev/null", name)); err2 == nil && len(bytes.TrimSpace(out2)) > 0 {
			_, _ = run(10*time.Second, fmt.Sprintf("killall -9 %s 2>/dev/null", name))
		}
	}
	if runDir != "" {
		_ = os.Remove(filepath.Join(runDir, PIDFileName))
	}
	return nil
}

// CleanTun deletes leftover tunnel interfaces.
func CleanTun() error {
	for _, iface := range TunIfaces {
		if !safeToken(iface) {
			continue
		}
		if _, err := run(10*time.Second, fmt.Sprintf("ip link show %s 2>/dev/null", iface)); err != nil {
			continue
		}
		_, _ = run(10*time.Second, fmt.Sprintf("ip link del %s 2>/dev/null", iface))
	}
	return nil
}

// CleanEBPF removes clsact qdiscs and sing-box virtual interfaces (sb[dt]*),
// then flushes the route cache.
func CleanEBPF() error {
	if out, err := run(10*time.Second, "tc qdisc show 2>/dev/null"); err == nil {
		for _, dev := range parseClsactDevs(string(out)) {
			if safeToken(dev) {
				_, _ = run(10*time.Second, fmt.Sprintf("tc qdisc del dev %s clsact 2>/dev/null", dev))
			}
		}
	}
	if out, err := run(10*time.Second, "ip -o link show 2>/dev/null"); err == nil {
		for _, dev := range parseSbDevs(string(out)) {
			if safeToken(dev) {
				_, _ = run(10*time.Second, fmt.Sprintf("ip link del %s 2>/dev/null", dev))
			}
		}
	}
	_, _ = run(10*time.Second, "ip route flush cache 2>/dev/null")
	_, _ = run(10*time.Second, "ip -6 route flush cache 2>/dev/null")
	return nil
}

// parseClsactDevs extracts device names that have a clsact qdisc.
func parseClsactDevs(tcOut string) []string {
	var devs []string
	for _, line := range strings.Split(tcOut, "\n") {
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "dev" && i+1 < len(fields) {
				devs = append(devs, fields[i+1])
			}
		}
	}
	return devs
}

// parseSbDevs extracts sing-box virtual interface names (sb[dt]*).
func parseSbDevs(ipOut string) []string {
	var devs []string
	for _, line := range strings.Split(ipOut, "\n") {
		// format: "<idx>: <name>[@...]: <...>"
		parts := strings.SplitN(line, ": ", 3)
		if len(parts) < 2 {
			continue
		}
		name := strings.Split(parts[1], "@")[0]
		if len(name) >= 3 && (strings.HasPrefix(name, "sbd") || strings.HasPrefix(name, "sbt")) {
			devs = append(devs, name)
		}
	}
	return devs
}

// CleanAll runs every cleanup step in order. It is called before the core
// starts and after the core exits/crashes, mirroring service.sh behavior.
func CleanAll(runDir string) error {
	_ = CleanChains("iptables")
	_ = CleanChains("ip6tables")
	_ = CleanRouting()
	_ = CleanProcesses(runDir)
	_ = CleanTun()
	_ = CleanEBPF()
	return nil
}
