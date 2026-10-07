package netfilter

// Apply installs netfilter rules for the proxy core and Remove tears them
// down again. Only the tproxy and redirect modes are implemented; every
// other mode returns a clear not-implemented error.
//
// All operations touch only our own chains (see constants.go) and are
// idempotent: Apply may be called repeatedly and Remove() is always safe.
// On any failure Apply calls Remove() first so a half-installed rule set
// is never left behind.
//
// NOTE: rule order and match criteria were reconstructed from the AWD OS
// net_cleaner.sh chain layout (ZENNODE_*/CLASH_DNS_*), the string fragments
// found in its Go binary (mangle/OUTPUT/fwmark/TPROXY/RETURN) and standard
// clash/sing-box tproxy practice. They MUST be verified on a real device
// with iptables-save / ip rule before being trusted in production.

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

// RuleConfig carries everything Apply needs. It lives in the netfilter
// package (instead of reusing zengobox.ZengoConfig) to avoid an import
// cycle with the parent package; the Manager translates the master config
// into this struct.
type RuleConfig struct {
	Mode            string   // tproxy|redirect (others: not implemented)
	TProxyPort      int      // default 9898
	RedirPort       int      // default 9797
	IPv6            bool     // also install ip6tables rules
	QUICBlock       bool     // DROP udp/443 to force TCP fallback
	ClashDNSForward bool     // hijack port 53 into the core
	ClashDNSPort    int      // default 7874
	ProxyMode       string   // blacklist|whitelist|core
	Packages        []string // Android package names for per-app rules
	GIDs            []int    // group IDs for per-app rules
	AllowIfaces     []string // e.g. ["ap+","wlan+"]; empty = all interfaces
	IgnoreIfaces    []string // e.g. ["lo"]; always bypassed
}

var (
	// reIfacePat validates interface patterns. '+' is the iptables
	// wildcard (ap+, wlan+). '*' is deliberately rejected: it would be
	// expanded by the shell and is never needed here.
	reIfacePat = regexp.MustCompile(`^[a-zA-Z0-9.+_-]+$`)
	rePkgName  = regexp.MustCompile(`^[a-zA-Z0-9._]+$`)
	reUserID   = regexp.MustCompile(`userId=(\d+)`)
)

func validPort(p int) bool { return p > 0 && p <= 65535 }

// runCmds executes commands one by one so a failure is localized to the
// exact command. Shell idioms (;, ||, 2>/dev/null) are used inside single
// command strings for idempotency; the exit status observed is the last
// command's, which is the meaningful one.
func runCmds(cmds []string) error {
	for i, c := range cmds {
		if out, err := run(15*time.Second, c); err != nil {
			return fmt.Errorf("netfilter command %d/%d failed: %q: %v (out: %s)",
				i+1, len(cmds), c, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// ensureChain creates a chain if missing, then flushes it so re-applying
// always starts from a clean slate.
func chainResetCmds(ipt, table string, chains ...string) []string {
	var cmds []string
	for _, ch := range chains {
		cmds = append(cmds, fmt.Sprintf(
			"%s -t %s -N %s 2>/dev/null; %s -t %s -F %s", ipt, table, ch, ipt, table, ch))
	}
	return cmds
}

// ensureJump adds "base cond -j target" only when it is not already there.
func ensureJumpCmd(ipt, table, base, cond, target string) string {
	rule := strings.TrimSpace(base + " " + cond + " " + target)
	return fmt.Sprintf(
		"%s -t %s -C %s 2>/dev/null || %s -t %s -A %s",
		ipt, table, rule, ipt, table, rule)
}

// Apply installs the rule set for rc.Mode.
func Apply(rc *RuleConfig) error {
	if rc == nil {
		return fmt.Errorf("nil rule config")
	}
	mode := strings.ToLower(strings.TrimSpace(rc.Mode))
	var err error
	switch mode {
	case "", "tproxy":
		err = applyTproxy(rc)
	case "redirect":
		err = applyRedirect(rc)
	case "mixed", "enhance", "tun", "ebpf", "hybrid":
		return fmt.Errorf("network mode %q is not implemented yet (tproxy and redirect are supported)", rc.Mode)
	default:
		return fmt.Errorf("unknown network mode %q", rc.Mode)
	}
	if err != nil {
		_ = Remove()
		return err
	}
	return nil
}

// Remove deletes everything Apply may have installed. Process lifecycle is
// the Manager's job, so unlike CleanAll this does not kill processes.
func Remove() error {
	_ = CleanChains("iptables")
	_ = CleanChains("ip6tables")
	_ = CleanRouting()
	_ = CleanTun()
	_ = CleanEBPF()
	return nil
}

// tables returns ["iptables"] plus "ip6tables" when IPv6 is enabled.
func (rc *RuleConfig) tables() []string {
	if rc.IPv6 {
		return []string{"iptables", "ip6tables"}
	}
	return []string{"iptables"}
}

func (rc *RuleConfig) validateIfaces() error {
	for _, p := range rc.AllowIfaces {
		if !reIfacePat.MatchString(p) {
			return fmt.Errorf("invalid allow interface pattern %q", p)
		}
	}
	for _, p := range rc.IgnoreIfaces {
		if !reIfacePat.MatchString(p) {
			return fmt.Errorf("invalid ignore interface pattern %q", p)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// tproxy mode
// ---------------------------------------------------------------------------

func applyTproxy(rc *RuleConfig) error {
	if !validPort(rc.TProxyPort) {
		return fmt.Errorf("invalid tproxy port %d", rc.TProxyPort)
	}
	if err := rc.validateIfaces(); err != nil {
		return err
	}
	tproxy := fmt.Sprintf("-j TPROXY --on-port %d --tproxy-mark %s", rc.TProxyPort, FwMarkShort)

	var cmds []string
	for _, ipt := range rc.tables() {
		v6 := ipt == "ip6tables"

		cmds = append(cmds, chainResetCmds(ipt, "mangle",
			"ZENNODE_DIVERT", "ZENNODE_EXTERNAL", "ZENNODE_LOCAL")...)

		// DIVERT: packets already owned by a local socket take the local
		// path instead of being re-proxied.
		cmds = append(cmds,
			fmt.Sprintf("%s -t mangle -A ZENNODE_DIVERT -j MARK --set-mark %s", ipt, FwMarkShort),
			fmt.Sprintf("%s -t mangle -A ZENNODE_DIVERT -j ACCEPT", ipt),
		)

		// ---- ZENNODE_EXTERNAL (PREROUTING): traffic from tethered clients.
		cmds = append(cmds, fmt.Sprintf("%s -t mangle -A ZENNODE_EXTERNAL -m socket -j ZENNODE_DIVERT", ipt))
		if v6 {
			cmds = append(cmds, fmt.Sprintf("%s -t mangle -A ZENNODE_EXTERNAL -d ::1/128 -j RETURN", ipt))
		}
		for _, ig := range rc.IgnoreIfaces {
			cmds = append(cmds, fmt.Sprintf("%s -t mangle -A ZENNODE_EXTERNAL -i %s -j RETURN", ipt, ig))
		}
		if rc.QUICBlock {
			cmds = append(cmds, fmt.Sprintf("%s -t mangle -A ZENNODE_EXTERNAL -p udp --dport 443 -j DROP", ipt))
		}
		if len(rc.AllowIfaces) > 0 {
			// Allow-list: only intercept on the listed interfaces.
			for _, al := range rc.AllowIfaces {
				cmds = append(cmds, fmt.Sprintf("%s -t mangle -A ZENNODE_EXTERNAL -i %s -p tcp %s", ipt, al, tproxy))
				cmds = append(cmds, fmt.Sprintf("%s -t mangle -A ZENNODE_EXTERNAL -i %s -p udp %s", ipt, al, tproxy))
			}
			cmds = append(cmds, fmt.Sprintf("%s -t mangle -A ZENNODE_EXTERNAL -j RETURN", ipt))
		} else {
			cmds = append(cmds, fmt.Sprintf("%s -t mangle -A ZENNODE_EXTERNAL -p tcp %s", ipt, tproxy))
			cmds = append(cmds, fmt.Sprintf("%s -t mangle -A ZENNODE_EXTERNAL -p udp %s", ipt, tproxy))
		}

		// ---- ZENNODE_LOCAL (OUTPUT): locally generated traffic.
		// Never proxy root's traffic: the core itself runs as root and
		// re-proxying it would loop forever.
		cmds = append(cmds, fmt.Sprintf("%s -t mangle -A ZENNODE_LOCAL -m owner --uid-owner 0 -j RETURN", ipt))
		if v6 {
			cmds = append(cmds, fmt.Sprintf("%s -t mangle -A ZENNODE_LOCAL -d ::1/128 -j RETURN", ipt))
		}
		cmds = append(cmds, ownerBypassCmds(ipt, rc)...)
		if rc.QUICBlock {
			cmds = append(cmds, fmt.Sprintf("%s -t mangle -A ZENNODE_LOCAL -p udp --dport 443 -j DROP", ipt))
		}
		if strings.ToLower(rc.ProxyMode) == "whitelist" {
			cmds = append(cmds, ownerProxyCmds(ipt, rc, tproxy)...)
			cmds = append(cmds, fmt.Sprintf("%s -t mangle -A ZENNODE_LOCAL -j RETURN", ipt))
		} else {
			// blacklist (default) and "core": proxy everything else.
			cmds = append(cmds, fmt.Sprintf("%s -t mangle -A ZENNODE_LOCAL -p tcp %s", ipt, tproxy))
			cmds = append(cmds, fmt.Sprintf("%s -t mangle -A ZENNODE_LOCAL -p udp %s", ipt, tproxy))
		}
	}

	// Hook the custom chains into the built-ins (idempotent).
	for _, ipt := range rc.tables() {
		cmds = append(cmds, ensureJumpCmd(ipt, "mangle", "PREROUTING", "", "-j ZENNODE_EXTERNAL"))
		cmds = append(cmds, ensureJumpCmd(ipt, "mangle", "OUTPUT", "", "-j ZENNODE_LOCAL"))
	}

	// Policy routing for marked packets.
	cmds = append(cmds,
		fmt.Sprintf("ip rule del fwmark %s table %s 2>/dev/null; ip rule add fwmark %s table %s", FwMark, TableID, FwMark, TableID),
		fmt.Sprintf("ip route del local default dev lo table %s 2>/dev/null; ip route add local default dev lo table %s", TableID, TableID),
	)
	if rc.IPv6 {
		cmds = append(cmds,
			fmt.Sprintf("ip -6 rule del fwmark %s table %s 2>/dev/null; ip -6 rule add fwmark %s table %s", FwMark, TableID, FwMark, TableID),
			fmt.Sprintf("ip -6 route del local default dev lo table %s 2>/dev/null; ip -6 route add local default dev lo table %s", TableID, TableID),
		)
	}

	if rc.ClashDNSForward {
		cmds = append(cmds, dnsHijackCmds(rc)...)
	}

	return runCmds(cmds)
}

// ownerBypassCmds builds per-app/per-GID RETURN rules for blacklist mode.
// Packages whose UID cannot be resolved are skipped (best effort); this is
// logged by uidForPackage's caller via the returned error being ignored
// here only after validation of the package name itself.
func ownerBypassCmds(ipt string, rc *RuleConfig) []string {
	if strings.ToLower(rc.ProxyMode) != "blacklist" {
		return nil
	}
	var cmds []string
	for _, pkg := range rc.Packages {
		uid, err := uidForPackage(pkg)
		if err != nil {
			continue
		}
		cmds = append(cmds, fmt.Sprintf("%s -t mangle -A ZENNODE_LOCAL -m owner --uid-owner %d -j RETURN", ipt, uid))
	}
	for _, gid := range rc.GIDs {
		if gid < 0 {
			continue
		}
		cmds = append(cmds, fmt.Sprintf("%s -t mangle -A ZENNODE_LOCAL -m owner --gid-owner %d -j RETURN", ipt, gid))
	}
	return cmds
}

// ownerProxyCmds builds per-app/per-GID TPROXY jumps for whitelist mode.
func ownerProxyCmds(ipt string, rc *RuleConfig, tproxy string) []string {
	var cmds []string
	for _, pkg := range rc.Packages {
		uid, err := uidForPackage(pkg)
		if err != nil {
			continue
		}
		cmds = append(cmds, fmt.Sprintf("%s -t mangle -A ZENNODE_LOCAL -m owner --uid-owner %d -p tcp %s", ipt, uid, tproxy))
		cmds = append(cmds, fmt.Sprintf("%s -t mangle -A ZENNODE_LOCAL -m owner --uid-owner %d -p udp %s", ipt, uid, tproxy))
	}
	for _, gid := range rc.GIDs {
		if gid < 0 {
			continue
		}
		cmds = append(cmds, fmt.Sprintf("%s -t mangle -A ZENNODE_LOCAL -m owner --gid-owner %d -p tcp %s", ipt, gid, tproxy))
		cmds = append(cmds, fmt.Sprintf("%s -t mangle -A ZENNODE_LOCAL -m owner --gid-owner %d -p udp %s", ipt, gid, tproxy))
	}
	return cmds
}

// uidCache avoids repeated dumpsys calls for the same package.
var uidCache = struct {
	sync.Mutex
	m map[string]int
}{m: make(map[string]int)}

// uidForPackage resolves an Android package name to its UID via dumpsys.
// Best effort: returns an error when the package cannot be resolved and the
// caller decides whether to skip or fail.
func uidForPackage(pkg string) (int, error) {
	if !rePkgName.MatchString(pkg) {
		return 0, fmt.Errorf("invalid package name %q", pkg)
	}
	uidCache.Lock()
	if uid, ok := uidCache.m[pkg]; ok {
		uidCache.Unlock()
		return uid, nil
	}
	uidCache.Unlock()

	out, err := run(10*time.Second, fmt.Sprintf("dumpsys package %s 2>/dev/null | grep -m1 userId=", pkg))
	if err != nil {
		return 0, fmt.Errorf("dumpsys failed for %q", pkg)
	}
	m := reUserID.FindSubmatch(out)
	if m == nil {
		return 0, fmt.Errorf("no userId found for %q", pkg)
	}
	var uid int
	if _, err := fmt.Sscanf(string(m[1]), "%d", &uid); err != nil {
		return 0, fmt.Errorf("bad userId for %q", pkg)
	}
	uidCache.Lock()
	uidCache.m[pkg] = uid
	uidCache.Unlock()
	return uid, nil
}

// dnsHijackCmds redirects port 53 into the core's DNS listener.
func dnsHijackCmds(rc *RuleConfig) []string {
	port := rc.ClashDNSPort
	if !validPort(port) {
		port = 7874
	}
	var cmds []string
	for _, ipt := range rc.tables() {
		cmds = append(cmds, chainResetCmds(ipt, "nat", "CLASH_DNS_LOCAL", "CLASH_DNS_EXTERNAL")...)
		for _, proto := range []string{"udp", "tcp"} {
			cmds = append(cmds, ensureJumpCmd(ipt, "nat", "OUTPUT", "-p "+proto+" --dport 53", "-j CLASH_DNS_LOCAL"))
			cmds = append(cmds, ensureJumpCmd(ipt, "nat", "PREROUTING", "-p "+proto+" --dport 53", "-j CLASH_DNS_EXTERNAL"))
			cmds = append(cmds, fmt.Sprintf("%s -t nat -A CLASH_DNS_LOCAL -p %s -j REDIRECT --to-ports %d", ipt, proto, port))
			cmds = append(cmds, fmt.Sprintf("%s -t nat -A CLASH_DNS_EXTERNAL -p %s -j REDIRECT --to-ports %d", ipt, proto, port))
		}
	}
	return cmds
}

// ---------------------------------------------------------------------------
// redirect mode (basic; needs device verification)
// ---------------------------------------------------------------------------

func applyRedirect(rc *RuleConfig) error {
	if !validPort(rc.RedirPort) {
		return fmt.Errorf("invalid redirect port %d", rc.RedirPort)
	}
	if err := rc.validateIfaces(); err != nil {
		return err
	}
	var cmds []string
	for _, ipt := range rc.tables() {
		cmds = append(cmds, chainResetCmds(ipt, "nat", "ZENNODE_LOCAL", "ZENNODE_EXTERNAL")...)
		// Locally generated TCP goes through the redirect port.
		// (Root bypass mirrors the tproxy rationale: the core runs as root.)
		cmds = append(cmds, fmt.Sprintf("%s -t nat -A ZENNODE_LOCAL -m owner --uid-owner 0 -j RETURN", ipt))
		for _, ig := range rc.IgnoreIfaces {
			cmds = append(cmds, fmt.Sprintf("%s -t nat -A ZENNODE_LOCAL -o %s -j RETURN", ipt, ig))
		}
		cmds = append(cmds, fmt.Sprintf("%s -t nat -A ZENNODE_LOCAL -p tcp -j REDIRECT --to-ports %d", ipt, rc.RedirPort))
		// Forwarded (tethered) TCP.
		for _, ig := range rc.IgnoreIfaces {
			cmds = append(cmds, fmt.Sprintf("%s -t nat -A ZENNODE_EXTERNAL -i %s -j RETURN", ipt, ig))
		}
		if len(rc.AllowIfaces) > 0 {
			for _, al := range rc.AllowIfaces {
				cmds = append(cmds, fmt.Sprintf("%s -t nat -A ZENNODE_EXTERNAL -i %s -p tcp -j REDIRECT --to-ports %d", ipt, al, rc.RedirPort))
			}
			cmds = append(cmds, fmt.Sprintf("%s -t nat -A ZENNODE_EXTERNAL -j RETURN", ipt))
		} else {
			cmds = append(cmds, fmt.Sprintf("%s -t nat -A ZENNODE_EXTERNAL -p tcp -j REDIRECT --to-ports %d", ipt, rc.RedirPort))
		}
		cmds = append(cmds, ensureJumpCmd(ipt, "nat", "OUTPUT", "-p tcp", "-j ZENNODE_LOCAL"))
		cmds = append(cmds, ensureJumpCmd(ipt, "nat", "PREROUTING", "-p tcp", "-j ZENNODE_EXTERNAL"))
	}
	if rc.ClashDNSForward {
		cmds = append(cmds, dnsHijackCmds(rc)...)
	}
	return runCmds(cmds)
}
