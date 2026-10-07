package zengobox

// Setup wizard backend: downloads a proxy core binary (and optionally a
// web dashboard) into the box dir, asynchronously with progress written to
// run/setup.log. The frontend polls GET /api/zengobox/setup_log and reacts
// to the "Setup complete!" / "[SETUP_FAILED]" markers, mirroring the
// zengobox.js v1.4.41 flow.
//
// Release asset URLs are formed at runtime from the GitHub Releases API
// (the backend is URL-agnostic); if github.com fails twice, ghproxy.com
// is tried as a fallback.

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"bfr-webui-go/internal/logger"
)

// setupTimeout bounds the whole download phase (core + dashboard).
const setupTimeout = 10 * time.Minute

var (
	setupMu      sync.Mutex
	setupRunning bool
)

func setupLogPath() (string, error) {
	cfg, err := GetConfig()
	if err != nil {
		return "", err
	}
	runDir := cfg.EffectiveRunDir()
	if err := os.MkdirAll(runDir, 0755); err != nil {
		return "", err
	}
	return filepath.Join(runDir, "setup.log"), nil
}

func appendSetupLog(path, format string, args ...interface{}) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "[%s] ", time.Now().Format("15:04:05"))
	fmt.Fprintf(f, format, args...)
	if !strings.HasSuffix(format, "\n") {
		fmt.Fprintln(f)
	}
}

// SetupRequest mirrors the v1.4.41 frontend body.
type SetupRequest struct {
	Core      string `json:"core"`      // "clash" | "sing-box" | "all"
	Version   string `json:"version"`   // e.g. "1.14.1"
	Dashboard string `json:"dashboard"` // zip URL or "none"
}

// StartSetup launches the installation in the background. It is a no-op
// while another setup is running (the frontend auto-resumes by polling).
func StartSetup(req SetupRequest) error {
	setupMu.Lock()
	if setupRunning {
		setupMu.Unlock()
		return nil
	}
	setupRunning = true
	setupMu.Unlock()

	go func() {
		defer func() {
			setupMu.Lock()
			setupRunning = false
			setupMu.Unlock()
		}()
		runSetup(req)
	}()
	return nil
}

// SetupLog returns the current setup log text.
func SetupLog() string {
	p, err := setupLogPath()
	if err != nil {
		return ""
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return string(data)
}

var httpClient = &http.Client{Timeout: 2 * time.Minute}

// githubAsset queries the GitHub Releases API for one tag and returns the
// download URL of the first asset whose name contains wantSub.
func githubAsset(repo, tag, wantSub string) (string, error) {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/releases/tags/%s", repo, tag)
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "bfr-webui-go")
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github api %s: %s", apiURL, resp.Status)
	}
	var rel struct {
		Assets []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", fmt.Errorf("decode release: %w", err)
	}
	for _, a := range rel.Assets {
		if strings.Contains(a.Name, wantSub) {
			return a.BrowserDownloadURL, nil
		}
	}
	return "", fmt.Errorf("no asset containing %q in %s %s", wantSub, repo, tag)
}

// download fetches url to dest, trying ghproxy as fallback on failure.
func download(logPath, url, dest string) error {
	var lastErr error
	urls := []string{url, "https://ghproxy.com/" + url}
	for i, u := range urls {
		if i == 1 {
			appendSetupLog(logPath, "github failed, trying ghproxy mirror...")
		}
		if err := downloadOnce(u, dest); err != nil {
			lastErr = err
			appendSetupLog(logPath, "download failed: %v", err)
			continue
		}
		return nil
	}
	return fmt.Errorf("all mirrors failed: %w", lastErr)
}

func downloadOnce(url, dest string) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "bfr-webui-go")
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(f, resp.Body); err != nil {
		return err
	}
	return nil
}

// extractArchive unpacks .gz (single file), .tar.gz or .zip into dir and
// returns the list of extracted file paths.
func extractArchive(src, dir string) ([]string, error) {
	if strings.HasSuffix(src, ".zip") {
		return unzip(src, dir)
	}
	if strings.HasSuffix(src, ".tar.gz") || strings.HasSuffix(src, ".tgz") {
		return untarGz(src, dir)
	}
	if strings.HasSuffix(src, ".gz") {
		return ungzip(src, dir)
	}
	return nil, fmt.Errorf("unknown archive type: %s", src)
}

func ungzip(src, dir string) ([]string, error) {
	f, err := os.Open(src)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gr.Close()
	name := strings.TrimSuffix(filepath.Base(src), ".gz")
	out := filepath.Join(dir, name)
	w, err := os.Create(out)
	if err != nil {
		return nil, err
	}
	defer w.Close()
	if _, err := io.Copy(w, gr); err != nil {
		return nil, err
	}
	return []string{out}, nil
}

func untarGz(src, dir string) ([]string, error) {
	f, err := os.Open(src)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gr.Close()
	tr := tar.NewReader(gr)
	var out []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return out, err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		// Strip a single top-level directory (release tarballs nest files).
		name := hdr.Name
		if i := strings.Index(name, "/"); i >= 0 {
			name = name[i+1:]
		}
		if name == "" || strings.Contains(name, "..") {
			continue
		}
		dest := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
			return out, err
		}
		w, err := os.Create(dest)
		if err != nil {
			return out, err
		}
		if _, err := io.Copy(w, tr); err != nil {
			w.Close()
			return out, err
		}
		w.Close()
		out = append(out, dest)
	}
	return out, nil
}

func unzip(src, dir string) ([]string, error) {
	r, err := zip.OpenReader(src)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	var out []string
	for _, f := range r.File {
		name := f.Name
		if i := strings.Index(name, "/"); i >= 0 {
			name = name[i+1:] // strip top-level dir (gh-pages zips)
		}
		if name == "" || strings.Contains(name, "..") {
			continue
		}
		dest := filepath.Join(dir, name)
		if f.FileInfo().IsDir() {
			_ = os.MkdirAll(dest, 0755)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
			return out, err
		}
		rc, err := f.Open()
		if err != nil {
			return out, err
		}
		w, err := os.Create(dest)
		if err != nil {
			rc.Close()
			return out, err
		}
		_, err = io.Copy(w, rc)
		w.Close()
		rc.Close()
		if err != nil {
			return out, err
		}
		out = append(out, dest)
	}
	return out, nil
}

// installCore downloads and installs one proxy core binary.
func installCore(logPath, binDir, core, version string) error {
	tag := version
	if !strings.HasPrefix(tag, "v") {
		tag = "v" + tag
	}
	var repo, want, binName string
	switch core {
	case "clash":
		repo = "MetaCubeX/mihomo"
		want = "mihomo-android-arm64"
		binName = "mihomo"
	case "sing-box":
		repo = "SagerNet/sing-box"
		want = "android-arm64"
		binName = "sing-box"
	default:
		return fmt.Errorf("unknown core %q", core)
	}
	appendSetupLog(logPath, "resolving %s release %s...", core, tag)
	assetURL, err := githubAsset(repo, tag, want)
	if err != nil {
		return fmt.Errorf("resolve %s asset: %w", core, err)
	}
	appendSetupLog(logPath, "downloading %s", assetURL)
	tmp, err := os.CreateTemp("", "zengobox-core-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpPath)
	if err := download(logPath, assetURL, tmpPath); err != nil {
		return err
	}
	stage, err := os.MkdirTemp("", "zengobox-stage-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	files, err := extractArchive(tmpPath, stage)
	if err != nil {
		return fmt.Errorf("extract %s: %w", core, err)
	}
	// Find the binary: prefer an exact name match, else the largest file.
	var picked string
	var biggest int64
	_ = filepath.Walk(stage, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if filepath.Base(p) == binName {
			picked = p
		}
		if info.Size() > biggest {
			biggest = info.Size()
		}
		return nil
	})
	_ = files
	if picked == "" {
		// Fall back to the largest extracted file.
		_ = filepath.Walk(stage, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			if info.Size() == biggest {
				picked = p
			}
			return nil
		})
	}
	if picked == "" {
		return fmt.Errorf("no binary found in %s archive", core)
	}
	dest := filepath.Join(binDir, binName)
	if err := os.MkdirAll(binDir, 0755); err != nil {
		return err
	}
	data, err := os.ReadFile(picked)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dest, data, 0755); err != nil {
		return err
	}
	appendSetupLog(logPath, "installed %s -> %s", core, dest)
	return nil
}

// installDashboard downloads and extracts a dashboard zip.
func installDashboard(logPath, dashDir, url string) error {
	if url == "" || strings.ToLower(url) == "none" {
		appendSetupLog(logPath, "dashboard skipped")
		return nil
	}
	appendSetupLog(logPath, "downloading dashboard %s", url)
	tmp, err := os.CreateTemp("", "zengobox-dash-*.zip")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpPath)
	if err := download(logPath, url, tmpPath); err != nil {
		return err
	}
	if err := os.MkdirAll(dashDir, 0755); err != nil {
		return err
	}
	files, err := unzip(tmpPath, dashDir)
	if err != nil {
		return fmt.Errorf("extract dashboard: %w", err)
	}
	appendSetupLog(logPath, "dashboard extracted (%d files)", len(files))
	return nil
}

func runSetup(req SetupRequest) {
	logPath, err := setupLogPath()
	if err != nil {
		logger.Get().Errorf("zengobox", "setup: %v", err)
		return
	}
	// Fresh log per run so the frontend auto-resume logic stays simple.
	_ = os.WriteFile(logPath, []byte("Starting setup...\n"), 0644)
	done := make(chan error, 1)
	go func() { done <- doSetup(logPath, req) }()
	select {
	case err := <-done:
		if err != nil {
			appendSetupLog(logPath, "[SETUP_FAILED] %v", err)
			logger.Get().Errorf("zengobox", "setup failed: %v", err)
		} else {
			appendSetupLog(logPath, "Setup complete!")
			logger.Get().Infof("zengobox", "setup complete")
		}
	case <-time.After(setupTimeout):
		appendSetupLog(logPath, "[SETUP_FAILED] timed out after %v", setupTimeout)
	}
}

func doSetup(logPath string, req SetupRequest) error {
	cfg, err := GetConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	core := strings.ToLower(strings.TrimSpace(req.Core))
	if core == "" {
		core = "all"
	}
	version := strings.TrimSpace(req.Version)
	if version == "" {
		return fmt.Errorf("core version is required")
	}
	binDir := cfg.EffectiveBinDir()
	cores := []string{}
	switch core {
	case "clash", "sing-box":
		cores = []string{core}
	case "all":
		cores = []string{"clash", "sing-box"}
	default:
		return fmt.Errorf("unknown core %q (want clash|sing-box|all)", req.Core)
	}
	for _, c := range cores {
		if err := installCore(logPath, binDir, c, version); err != nil {
			return err
		}
	}
	dashDir := filepath.Join(cfg.EffectiveBoxDir(), "dashboard")
	if err := installDashboard(logPath, dashDir, req.Dashboard); err != nil {
		return err
	}
	// Remember the installed version in the master config.
	cfg.Core.Version = strings.TrimPrefix(version, "v")
	if core != "all" {
		cfg.Core.BinName = core
	}
	if err := cfg.Save(ConfigPath()); err != nil {
		appendSetupLog(logPath, "warning: could not save version: %v", err)
	}
	return nil
}
