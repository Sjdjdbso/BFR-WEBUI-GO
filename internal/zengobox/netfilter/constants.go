// Package netfilter manages the iptables/ip-rule/tc state owned by the
// ZenGoBox proxy manager. Ported from scripts/net_cleaner.sh of the AWD OS
// Magisk module.
//
// Design rules (mirroring net_cleaner.sh):
//   - Only touch resources owned by us: chains ZENNODE_* / CLASH_DNS_*,
//     fwmark 0x1000000, routing table 2024. Never touch Android built-in
//     rules (table ccmni1, dummy0, ...).
//   - Every operation is idempotent: safe to run repeatedly, even when no
//     rules are installed.
package netfilter

const (
	// FwMark is the packet mark used for TPROXY routing (0x1000000).
	// MUST match the mark used by Apply and the cleaner.
	FwMark = "16777216/16777216"
	// FwMarkShort is the same mark in hex, used by `ip rule`.
	FwMarkShort = "0x1000000"
	// TableID is the routing table id for marked packets.
	TableID = "2024"
)

// ChainRef identifies one custom chain in one table.
type ChainRef struct {
	Table string
	Chain string
}

// Chains lists every custom chain owned by the proxy manager.
var Chains = []ChainRef{
	{Table: "mangle", Chain: "ZENNODE_DIVERT"},
	{Table: "mangle", Chain: "ZENNODE_EXTERNAL"},
	{Table: "mangle", Chain: "ZENNODE_LOCAL"},
	{Table: "nat", Chain: "ZENNODE_EXTERNAL"},
	{Table: "nat", Chain: "ZENNODE_LOCAL"},
	{Table: "nat", Chain: "CLASH_DNS_EXTERNAL"},
	{Table: "nat", Chain: "CLASH_DNS_LOCAL"},
}

// TunIfaces lists tunnel interface names that may be left behind by the
// proxy core and must be removed during cleanup.
var TunIfaces = []string{"tun0", "utun", "tun", "awd-tun", "zengobox"}

// CoreProcs lists proxy core process names managed by this package.
var CoreProcs = []string{"sing-box", "clash", "mihomo"}

// PIDFileName is the basename of the PID file written under the run dir.
const PIDFileName = "core.pid"
