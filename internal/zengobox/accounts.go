package zengobox

// Accounts manager: raw proxy account files per server group.
//
// Layout (under the box dir):
//
//	<box>/accounts/AKUN-ID.yaml   clash format  ("proxies:\n- name: ...")
//	<box>/accounts/AKUN-SG.yaml
//	<box>/accounts/AKUN-ID.json   sing-box format ({"outbounds":[...]} or [...])
//	<box>/accounts/AKUN-SG.json
//
// The frontend always sends the complete file content on save (never a
// delta), mirroring the zengobox.js v1.4.41 flow: convert link -> append
// client-side -> POST full file.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// accountFileRe is a strict whitelist: only the two known groups may be
// managed, which makes path traversal impossible by construction.
var accountFileRe = regexp.MustCompile(`^(AKUN-ID|AKUN-SG)\.(yaml|yml|json)$`)

// validAccountFile reports whether name is an allowed account file name.
func validAccountFile(name string) bool {
	return accountFileRe.MatchString(name)
}

// validAccountCore reports whether core selects a supported proxy core.
func validAccountCore(core string) bool {
	c := strings.ToLower(strings.TrimSpace(core))
	return c == "clash" || c == "sing-box"
}

// AccountsDir returns the directory holding the account files,
// creating it on demand.
func AccountsDir() (string, error) {
	cfg, err := GetConfig()
	if err != nil {
		return "", fmt.Errorf("load config: %w", err)
	}
	dir := filepath.Join(cfg.EffectiveBoxDir(), "accounts")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("create accounts dir: %w", err)
	}
	return dir, nil
}

// accountPath resolves a whitelisted file name to its absolute path.
func accountPath(file string) (string, error) {
	if !validAccountFile(file) {
		return "", fmt.Errorf("invalid account file name %q (want AKUN-ID|AKUN-SG .yaml/.yml/.json)", file)
	}
	dir, err := AccountsDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, file), nil
}

// ReadAccounts returns the raw text of an account file.
// A missing file is not an error: it reads as empty (new group).
func ReadAccounts(file, core string) (string, error) {
	if !validAccountCore(core) {
		return "", fmt.Errorf("invalid core %q (want clash|sing-box)", core)
	}
	p, err := accountPath(file)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read account file: %w", err)
	}
	return string(data), nil
}

// WriteAccounts replaces an account file with the full content supplied
// by the frontend. Content is capped to guard against runaway uploads.
const maxAccountFileSize = 2 << 20 // 2 MiB

func WriteAccounts(file, core, content string) error {
	if !validAccountCore(core) {
		return fmt.Errorf("invalid core %q (want clash|sing-box)", core)
	}
	if len(content) > maxAccountFileSize {
		return fmt.Errorf("account content too large (%d bytes, max %d)", len(content), maxAccountFileSize)
	}
	p, err := accountPath(file)
	if err != nil {
		return err
	}
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		return fmt.Errorf("write account file: %w", err)
	}
	return nil
}

// AppendAccountBlock appends one converted proxy block to an account file.
// It is used by internal flows (subscription refresh); the interactive
// frontend appends client-side and calls WriteAccounts instead.
func AppendAccountBlock(file, core, block string) error {
	if !validAccountCore(core) {
		return fmt.Errorf("invalid core %q (want clash|sing-box)", core)
	}
	block = strings.TrimSpace(block)
	if block == "" {
		return fmt.Errorf("empty account block")
	}
	p, err := accountPath(file)
	if err != nil {
		return err
	}
	cur, _ := os.ReadFile(p)
	text := strings.TrimSpace(string(cur))
	lower := strings.ToLower(core)
	if lower == "clash" {
		if text == "" {
			text = "proxies:"
		} else if !strings.Contains(text, "proxies:") {
			text = "proxies:\n" + text
		}
		text = strings.TrimRight(text, "\n") + "\n" + block + "\n"
	} else {
		// sing-box JSON is merged by the caller via ConvertLink; here we
		// only support the simple object-array form.
		if text == "" {
			text = "{\n  \"outbounds\": [\n" + block + "\n  ]\n}"
		} else {
			return fmt.Errorf("sing-box account merge needs a full-file rewrite; use WriteAccounts")
		}
	}
	if len(text) > maxAccountFileSize {
		return fmt.Errorf("account file would exceed %d bytes", maxAccountFileSize)
	}
	if err := os.WriteFile(p, []byte(text), 0644); err != nil {
		return fmt.Errorf("write account file: %w", err)
	}
	return nil
}

// ExistingNames extracts the set of proxy names/tags already present in an
// account file, used to keep converted names unique.
func ExistingNames(file, core string) (map[string]bool, error) {
	text, err := ReadAccounts(file, core)
	if err != nil {
		return nil, err
	}
	taken := map[string]bool{}
	if strings.ToLower(core) == "clash" {
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "- name:") {
				name := strings.TrimSpace(strings.TrimPrefix(line, "- name:"))
				name = strings.Trim(name, `"'`)
				if name != "" {
					taken[name] = true
				}
			}
		}
	}
	// sing-box names are extracted by the caller from the JSON it builds.
	return taken, nil
}
