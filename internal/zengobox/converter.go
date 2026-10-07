package zengobox

// Link converter: vmess://, vless:// and trojan:// share links become
// proxy definitions for clash (YAML block) or sing-box (JSON outbound).
//
// The frontend (zengobox.js v1.4.41) sends {link} and expects back either
// {"yaml": "- name: ...\n  type: ..."} for clash, or a JSON outbound object
// for sing-box, which it then appends to the account file itself.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ProxyNode is the normalized form of one proxy share link.
type ProxyNode struct {
	Type     string // vmess | vless | trojan
	Name     string
	Server   string
	Port     int
	UUID     string // vmess/vless id, trojan password
	AlterID  int    // vmess only
	Cipher   string // vmess/vless encryption
	TLS      bool
	SNI      string
	Network  string // ws | tcp | grpc | h2 ...
	Path     string
	Host     string
	Flow     string // vless xtls flow
	Fp       string // uTLS fingerprint
	Alpn     string
	AllowInsecure bool
}

// vmessJSON mirrors the JSON payload inside a vmess:// link.
type vmessJSON struct {
	V   string `json:"v"`
	Ps  string `json:"ps"`
	Add string `json:"add"`
	Port string `json:"port"`
	ID  string `json:"id"`
	Aid string `json:"aid"`
	Net string `json:"net"`
	Type string `json:"type"`
	Host string `json:"host"`
	Path string `json:"path"`
	TLS string `json:"tls"`
	SNI string `json:"sni"`
	Fp  string `json:"fp"`
	Alpn string `json:"alpn"`
}

func b64decode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	// Be liberal: try raw URL encoding first, then standard.
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

func atoiSafe(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

func parseVmess(link string) (*ProxyNode, error) {
	raw := strings.TrimPrefix(link, "vmess://")
	data, err := b64decode(raw)
	if err != nil {
		return nil, fmt.Errorf("vmess: bad base64 payload: %w", err)
	}
	var v vmessJSON
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("vmess: bad JSON payload: %w", err)
	}
	if v.Add == "" || v.ID == "" {
		return nil, fmt.Errorf("vmess: missing address or id")
	}
	n := &ProxyNode{
		Type:    "vmess",
		Name:    v.Ps,
		Server:  v.Add,
		Port:    atoiSafe(v.Port),
		UUID:    v.ID,
		AlterID: atoiSafe(v.Aid),
		Cipher:  "auto",
		Network: v.Net,
		Path:    v.Path,
		Host:    v.Host,
		SNI:     v.SNI,
		Fp:      v.Fp,
		Alpn:    v.Alpn,
	}
	if n.Port == 0 {
		n.Port = 443
	}
	if strings.ToLower(v.TLS) == "tls" {
		n.TLS = true
	}
	if n.Name == "" {
		n.Name = fmt.Sprintf("%s:%d", n.Server, n.Port)
	}
	return n, nil
}

func parseURLLink(link, typ string) (*ProxyNode, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("%s: bad URL: %w", typ, err)
	}
	n := &ProxyNode{Type: typ}
	// userinfo holds uuid (vless) or password (trojan)
	if u.User != nil {
		n.UUID = u.User.Username()
	}
	n.Server = u.Hostname()
	n.Port = atoiSafe(u.Port())
	if n.Port == 0 {
		n.Port = 443
	}
	q := u.Query()
	fragment := u.Fragment
	if fragment != "" {
		if decoded, err := url.QueryUnescape(fragment); err == nil {
			fragment = decoded
		}
		n.Name = fragment
	}
	switch typ {
	case "vless":
		n.Cipher = q.Get("encryption")
		if n.Cipher == "" {
			n.Cipher = "none"
		}
		n.Flow = q.Get("flow")
		n.Network = q.Get("type")
		if n.Network == "" {
			n.Network = "tcp"
		}
		n.Path = q.Get("path")
		n.Host = q.Get("host")
		n.SNI = q.Get("sni")
		if n.SNI == "" {
			n.SNI = q.Get("serverName")
		}
		n.Fp = q.Get("fp")
		n.Alpn = q.Get("alpn")
		if strings.ToLower(q.Get("security")) == "tls" {
			n.TLS = true
		}
		if q.Get("allowInsecure") == "1" || strings.ToLower(q.Get("insecure")) == "1" {
			n.AllowInsecure = true
		}
	case "trojan":
		n.Network = q.Get("type")
		if n.Network == "" {
			n.Network = "tcp"
		}
		n.Path = q.Get("path")
		n.Host = q.Get("host")
		n.SNI = q.Get("sni")
		if n.SNI == "" {
			n.SNI = n.Server
		}
		n.Fp = q.Get("fp")
		n.Alpn = q.Get("alpn")
		n.TLS = true // trojan is always TLS
		if q.Get("allowInsecure") == "1" || strings.ToLower(q.Get("insecure")) == "1" {
			n.AllowInsecure = true
		}
	}
	if n.Server == "" || n.UUID == "" {
		return nil, fmt.Errorf("%s: missing server or credential", typ)
	}
	if n.Name == "" {
		n.Name = fmt.Sprintf("%s:%d", n.Server, n.Port)
	}
	if n.Network == "" {
		n.Network = "tcp"
	}
	return n, nil
}

// ParseLink parses one share link into a normalized ProxyNode.
func ParseLink(link string) (*ProxyNode, error) {
	link = strings.TrimSpace(link)
	switch {
	case strings.HasPrefix(link, "vmess://"):
		return parseVmess(link)
	case strings.HasPrefix(link, "vless://"):
		return parseURLLink(link, "vless")
	case strings.HasPrefix(link, "trojan://"):
		return parseURLLink(link, "trojan")
	default:
		scheme := link
		if i := strings.Index(link, "://"); i > 0 {
			scheme = link[:i]
		}
		return nil, fmt.Errorf("unsupported link scheme %q (supported: vmess, vless, trojan)", scheme)
	}
}

// uniqueName appends #n until the name is not taken.
func uniqueName(base string, taken map[string]bool) string {
	if base == "" {
		base = "proxy"
	}
	name := base
	for i := 2; taken[name]; i++ {
		name = fmt.Sprintf("%s#%d", base, i)
	}
	taken[name] = true
	return name
}

func yamlQuote(s string) string {
	if strings.ContainsAny(s, ":#{}[],&*!|>'\"%@`") || strings.TrimSpace(s) != s || s == "" {
		return strconv.Quote(s)
	}
	return s
}

// ToClash renders the node as a clash YAML proxy block.
func (n *ProxyNode) ToClash(taken map[string]bool) string {
	name := uniqueName(n.Name, taken)
	var b strings.Builder
	fmt.Fprintf(&b, "- name: %s\n", yamlQuote(name))
	fmt.Fprintf(&b, "  type: %s\n", n.Type)
	fmt.Fprintf(&b, "  server: %s\n", yamlQuote(n.Server))
	fmt.Fprintf(&b, "  port: %d\n", n.Port)
	switch n.Type {
	case "vmess":
		fmt.Fprintf(&b, "  uuid: %s\n", yamlQuote(n.UUID))
		fmt.Fprintf(&b, "  alterId: %d\n", n.AlterID)
		fmt.Fprintf(&b, "  cipher: %s\n", yamlQuote(n.Cipher))
	case "vless":
		fmt.Fprintf(&b, "  uuid: %s\n", yamlQuote(n.UUID))
		fmt.Fprintf(&b, "  cipher: %s\n", yamlQuote(n.Cipher))
		if n.Flow != "" {
			fmt.Fprintf(&b, "  flow: %s\n", yamlQuote(n.Flow))
		}
	case "trojan":
		fmt.Fprintf(&b, "  password: %s\n", yamlQuote(n.UUID))
	}
	if n.TLS {
		b.WriteString("  tls: true\n")
		if n.SNI != "" {
			fmt.Fprintf(&b, "  sni: %s\n", yamlQuote(n.SNI))
		}
		if n.Fp != "" {
			fmt.Fprintf(&b, "  fingerprint: %s\n", yamlQuote(n.Fp))
		}
		if n.Alpn != "" {
			fmt.Fprintf(&b, "  alpn: [%s]\n", yamlQuote(n.Alpn))
		}
		if n.AllowInsecure {
			b.WriteString("  skip-cert-verify: true\n")
		}
	}
	if n.Network != "" && n.Network != "tcp" {
		fmt.Fprintf(&b, "  network: %s\n", yamlQuote(n.Network))
		switch n.Network {
		case "ws":
			if n.Path != "" || n.Host != "" {
				b.WriteString("  ws-opts:\n")
				if n.Path != "" {
					fmt.Fprintf(&b, "    path: %s\n", yamlQuote(n.Path))
				}
				if n.Host != "" {
					fmt.Fprintf(&b, "    headers:\n      Host: %s\n", yamlQuote(n.Host))
				}
			}
		case "grpc":
			b.WriteString("  grpc-opts:\n")
			if n.Path != "" {
				fmt.Fprintf(&b, "    grpc-service-name: %s\n", yamlQuote(strings.Trim(n.Path, "/")))
			}
		}
	}
	return b.String()
}

// ToSingBox renders the node as a sing-box outbound object.
func (n *ProxyNode) ToSingBox(taken map[string]bool) map[string]interface{} {
	tag := uniqueName(n.Name, taken)
	ob := map[string]interface{}{
		"type":   n.Type,
		"tag":    tag,
		"server": n.Server,
		"server_port": n.Port,
	}
	switch n.Type {
	case "vmess":
		ob["uuid"] = n.UUID
		ob["alter_id"] = n.AlterID
		ob["security"] = n.Cipher
		if n.Cipher == "" {
			ob["security"] = "auto"
		}
	case "vless":
		ob["uuid"] = n.UUID
		ob["flow"] = n.Flow
	case "trojan":
		ob["password"] = n.UUID
	}
	if n.TLS {
		tls := map[string]interface{}{"enabled": true}
		if n.SNI != "" {
			tls["server_name"] = n.SNI
		}
		if n.Fp != "" {
			tls["utls"] = map[string]interface{}{"enabled": true, "fingerprint": n.Fp}
		}
		if n.Alpn != "" {
			tls["alpn"] = strings.Split(n.Alpn, ",")
		}
		if n.AllowInsecure {
			tls["insecure"] = true
		}
		ob["tls"] = tls
	}
	if n.Network != "" && n.Network != "tcp" {
		transport := map[string]interface{}{"type": n.Network}
		switch n.Network {
		case "ws":
			if n.Path != "" {
				transport["path"] = n.Path
			}
			if n.Host != "" {
				transport["headers"] = map[string]string{"Host": n.Host}
			}
		case "grpc":
			if n.Path != "" {
				transport["service_name"] = strings.Trim(n.Path, "/")
			}
		}
		ob["transport"] = transport
	}
	return ob
}

// ConvertLink parses one share link and renders it for the given core.
// For clash it returns map[string]string{"yaml": block}; for sing-box it
// returns the outbound object. taken holds already-used names/tags so the
// new one stays unique.
func ConvertLink(link, core string, taken map[string]bool) (interface{}, error) {
	if !validAccountCore(core) {
		return nil, fmt.Errorf("invalid core %q (want clash|sing-box)", core)
	}
	node, err := ParseLink(link)
	if err != nil {
		return nil, err
	}
	if taken == nil {
		taken = map[string]bool{}
	}
	if strings.ToLower(core) == "clash" {
		return map[string]string{"yaml": node.ToClash(taken)}, nil
	}
	return node.ToSingBox(taken), nil
}
