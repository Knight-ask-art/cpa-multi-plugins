// umid_provision.go — v0.8.60: self-provisioning of the official UMID
// identity bridge (runtime-info) for hosts without the desktop client.
//
// Why (live-proven 2026-10-08, account u673e7fcc Intl): device-targeted
// campaign rows (the daily "100 Credits" CLAIM_BENEFIT) are gated in TWO
// places on the authenticity of the Cosy-Machine* identity:
//
//  1. the campaigns LIST drops the row for derived/simulated identities —
//     the same account went invisible → visible the moment a real
//     runtime-info identity was presented;
//  2. the claim POST needs a device anchor for the same-person dedup — a
//     header-less claim 503s with SAME_PERSON_DEPENDENCY_UNAVAILABLE and a
//     derived-identity claim 503s with RISK_DEPENDENCY_UNAVAILABLE
//     (v0.8.53, live 2026-10-04 CN). Only a real bridge output passed both.
//
// Source (qoder2api-hub _install_umid.py, cross-verified): the official npm
// package @qoder-ai/qodercli embeds all five platform builds of the bridge
// as long base64 string literals inside package/bundle/
// qoder-worker-runtime.mjs. Extraction is deterministic:
//
//	registry metadata → dist.tarball (+ sha512 integrity)
//	tarball → bundle member → scan base64 literals (≥4000 chars)
//	magic-identify (ELF e_machine / Mach-O cputype / PE machine)
//	size heuristic 400KB..2MB (the 7.3MB PE blob is a different module)
//	atomic install <state>/umid/runtime-info[.exe], chmod 0755
//
// Escape hatches: QD_UMID_BIN (explicit binary) still wins over all of
// this; QD_UMID_AUTO=0/false/no disables provisioning entirely. Failures
// fall back to the derived identity and retry after a 6h cooldown.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	// umidRegistryURLDefault is the official npm registry location of the
	// CLI package that embeds the identity bridge components.
	umidRegistryURLDefault = "https://registry.npmjs.org/@qoder-ai/qodercli"
	umidBundleMember       = "package/bundle/qoder-worker-runtime.mjs"
	umidBlobMinChars       = 4000
	umidBlobSizeMin        = 400 * 1024
	umidBlobSizeMax        = 2 * 1024 * 1024
	umidTarballCap         = 80 << 20
	umidBundleCap          = 64 << 20
	umidFetchTimeout       = 120 * time.Second
	umidRetryCooldown      = 6 * time.Hour
	umidProvisionerUAT     = "cpa-multi-plugins qoder umid-provision"

	// v0.8.67: the official bridge is two files. runtime-info.exe loads its
	// sibling sgsdk.dll (the Alibaba UMID SDK) at startup; without it the
	// binary panics, the plugin falls back to the simulated identity and the
	// device-targeted rows stay hidden. The npm bundle carries the DLL as a
	// second blob (the ~7.3MB PE the 2MB size heuristic used to skip).
	umidSdkName    = "sgsdk.dll"
	umidSdkBlobMin = 2 * 1024 * 1024 // larger than the 400KB..2MB bridge itself
	umidSdkBlobMax = 32 * 1024 * 1024
)

var (
	// umidRegistryURL is a var so tests can point it at a stub server.
	umidRegistryURL = umidRegistryURLDefault

	// umidProvisionRunMu serializes provisioning attempts across regions/
	// goroutines; umidProvisionStateMu guards the cached outcome below.
	umidProvisionRunMu sync.Mutex

	umidProvisionStateMu sync.Mutex
	umidProvisionPath    string    // last successful install (process cache)
	umidProvisionErr     string    // last failure text ("" when none)
	umidProvisionAt      time.Time // last attempt (cooldown anchor)
	umidRepairErr        string    // last bridge verification/repair failure

	// umidBridgeProbeMu tracks the one-time health check of a bridge found on
	// disk (probed) and whether it is unusable and needs re-provisioning
	// (legacy).
	umidBridgeProbeMu struct {
		probed bool
		legacy bool
	}

	// umidHTTPFetch is the single network touchpoint (test stub point).
	umidHTTPFetch = umidHTTPFetchProd

	// umidStateDirOverride is nil in production; tests point it at a t.TempDir.
	umidStateDirOverride func() string
)

// umidProvisionEnabled reports whether auto-provisioning is on. Default on;
// QD_UMID_AUTO=0/false/no turns it off (operators who ship their own binary
// via QD_UMID_BIN or an official client install and want zero egress).
func umidProvisionEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("QD_UMID_AUTO"))) {
	case "0", "false", "no", "off":
		return false
	}
	return true
}

// umidProvisionDir is where the plugin keeps its self-provisioned bridge.
func umidProvisionDir() string {
	if umidStateDirOverride != nil {
		return umidStateDirOverride()
	}
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return filepath.Join(os.TempDir(), ".cpa-multi-plugins", "umid")
	}
	return filepath.Join(home, ".cpa-multi-plugins", "umid")
}

func umidProvisionedExePath() string {
	name := "runtime-info"
	if runtime.GOOS == "windows" {
		name = "runtime-info.exe"
	}
	return filepath.Join(umidProvisionDir(), name)
}

// umidProvisionLastError returns the last provisioning failure, if any.
func umidProvisionLastError() string {
	umidProvisionStateMu.Lock()
	defer umidProvisionStateMu.Unlock()
	return umidProvisionErr
}

// provisionedRuntimeInfo returns the plugin-managed official bridge,
// provisioning it on first use, or "" when unavailable (derived fallback
// stays in charge). Cached on disk forever and in-process for the lifetime;
// failed attempts retry after umidRetryCooldown.
func provisionedRuntimeInfo() string {
	if !umidProvisionEnabled() {
		return ""
	}
	umidProvisionStateMu.Lock()
	p := umidProvisionPath
	umidProvisionStateMu.Unlock()
	if p != "" {
		return p
	}
	disk := umidProvisionedExePath()
	if st, err := os.Stat(disk); err == nil && !st.IsDir() && st.Size() > umidBlobSizeMin {
		// v0.8.67: a provisioned bridge is only usable together with its
		// sgsdk.dll. Health-check once per process; on failure try to repair
		// the pair from a byte-identical official copy on disk (and, when the
		// cache is incomplete, from the npm bundle in provisionUmidBridge).
		umidProvisionRunMu.Lock()
		probed := umidBridgeProbeMu.probed
		umidProvisionRunMu.Unlock()
		if !probed {
			uid := umidProbeUID()
			exe, ok := ensureProvisionedBridgeVerified(uid)
			umidProvisionRunMu.Lock()
			if ok {
				umidProvisionStateMu.Lock()
				umidProvisionPath = exe
				umidProvisionStateMu.Unlock()
			} else {
				// The pair cannot be repaired from disk; drop the cached
				// runtime-info so the npm provisioning leg gets a turn (it
				// now installs the companion DLL too), keeping the disk pair
				// intact until that leg succeeds.
				umidBridgeProbeMu.probed = true
				umidBridgeProbeMu.legacy = true
			}
			umidProvisionRunMu.Unlock()
			if ok {
				return exe
			}
		}
		umidProvisionRunMu.Lock()
		legacy := umidBridgeProbeMu.legacy
		umidProvisionRunMu.Unlock()
		if !legacy {
			umidProvisionStateMu.Lock()
			umidProvisionPath = disk
			umidProvisionStateMu.Unlock()
			return disk
		}
	}

	umidProvisionRunMu.Lock()
	defer umidProvisionRunMu.Unlock()
	// re-check under the run lock: a concurrent attempt may have finished
	if st, err := os.Stat(disk); err == nil && !st.IsDir() && st.Size() > umidBlobSizeMin && !umidBridgeProbeMu.legacy {
		umidProvisionStateMu.Lock()
		umidProvisionPath = disk
		umidProvisionErr = ""
		umidProvisionStateMu.Unlock()
		return disk
	}
	umidProvisionStateMu.Lock()
	if !umidProvisionAt.IsZero() && time.Since(umidProvisionAt) < umidRetryCooldown {
		umidProvisionStateMu.Unlock()
		return ""
	}
	umidProvisionStateMu.Unlock()

	exe, err := provisionUmidBridge()
	umidProvisionStateMu.Lock()
	umidProvisionAt = time.Now()
	if err == nil {
		// Provisioning itself is not proof the pair runs: verify before
		// handing the bridge to the identity chain.
		if umidBridgeWorks(exe, umidProbeUID()) {
			umidProvisionErr = ""
			umidProvisionPath = exe
			umidProvisionStateMu.Unlock()
			return exe
		}
		err = fmt.Errorf("provisioned bridge does not run (companion %s missing or wrong)", umidSdkName)
	}
	umidProvisionErr = err.Error()
	umidProvisionStateMu.Unlock()
	return ""
}

// umidProbeUID is the account id used for identity health probes. Any
// well-formed uid works: the bridge's machine identity is machine-level.
const umidProbeUIDDefault = "00000000-0000-0000-0000-000000000000"

func umidProbeUID() string {
	if v := strings.TrimSpace(os.Getenv("QD_UMID_PROBE_UID")); v != "" {
		return v
	}
	return umidProbeUIDDefault
}

// umidRegistryMeta is the slice of npm registry metadata we need.
type umidRegistryMeta struct {
	Version   string
	Tarball   string
	Integrity string
}

// parseUmidRegistryMeta picks dist-tags.latest out of the full registry doc.
func parseUmidRegistryMeta(body []byte) (umidRegistryMeta, error) {
	var doc struct {
		DistTags map[string]string `json:"dist-tags"`
		Versions map[string]struct {
			Dist struct {
				Tarball   string `json:"tarball"`
				Integrity string `json:"integrity"`
			} `json:"dist"`
		} `json:"versions"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return umidRegistryMeta{}, fmt.Errorf("registry metadata not JSON: %w", err)
	}
	latest := strings.TrimSpace(doc.DistTags["latest"])
	entry, ok := doc.Versions[latest]
	if latest == "" || !ok || strings.TrimSpace(entry.Dist.Tarball) == "" {
		return umidRegistryMeta{}, errors.New("registry metadata missing dist-tags.latest tarball")
	}
	return umidRegistryMeta{
		Version:   latest,
		Tarball:   entry.Dist.Tarball,
		Integrity: entry.Dist.Integrity,
	}, nil
}

// umidHTTPFetchProd is the production fetcher: one bounded GET, size-capped.
func umidHTTPFetchProd(url string, timeout time.Duration) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", umidProvisionerUAT)
	req.Header.Set("Accept", "*/*")
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d for %s", resp.StatusCode, url)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, umidTarballCap+1))
	if err != nil {
		return nil, err
	}
	if len(body) > umidTarballCap {
		return nil, errors.New("download exceeds size cap")
	}
	return body, nil
}

// umidVerifyIntegrity checks the npm sha512-<base64> integrity line.
// Missing/unsupported integrity returns nil (skip — same as the hub tool).
func umidVerifyIntegrity(data []byte, integrity string) error {
	algo, b64, ok := strings.Cut(strings.TrimSpace(integrity), "-")
	if !ok || algo != "sha512" || b64 == "" {
		return nil
	}
	want, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil // malformed integrity line — skip rather than block
	}
	got := sha512.Sum512(data)
	if !bytes.Equal(got[:], want) {
		return errors.New("npm tarball sha512 integrity mismatch")
	}
	return nil
}

// umidExtractBundle pulls the worker-runtime bundle text out of the tarball.
func umidExtractBundle(tgz []byte) (string, error) {
	gz, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		return "", fmt.Errorf("tarball not gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return "", fmt.Errorf("tarball has no %s", umidBundleMember)
		}
		if err != nil {
			return "", err
		}
		name := strings.TrimPrefix(hdr.Name, "./")
		if name != umidBundleMember {
			continue
		}
		raw, err := io.ReadAll(io.LimitReader(tr, umidBundleCap+1))
		if err != nil {
			return "", err
		}
		if len(raw) > umidBundleCap {
			return "", errors.New("bundle exceeds size cap")
		}
		return string(raw), nil
	}
}

// Go's regexp caps repeat counts at 1000, so the pattern below matches
// runs of 1000+ base64 chars and scanUmidBlobs filters to the real
// umidBlobMinChars threshold (the hub tool's 4000) explicitly. Native
// bridge components are ~0.5-1MB encoded, far above either bound.
var umidBlobRe = regexp.MustCompile(`['"]([A-Za-z0-9+/=]{1000,})['"]`)

// scanUmidBlobs decodes every long base64 literal in the bundle text.
func scanUmidBlobs(text string) [][]byte {
	matches := umidBlobRe.FindAllStringSubmatch(text, -1)
	out := make([][]byte, 0, len(matches))
	for _, m := range matches {
		if len(m[1]) < umidBlobMinChars {
			continue
		}
		if b, err := base64.StdEncoding.DecodeString(m[1]); err == nil {
			out = append(out, b)
			continue
		}
		if b, err := base64.RawStdEncoding.DecodeString(m[1]); err == nil {
			out = append(out, b)
		}
	}
	return out
}

// umidBlobLabelFor maps GOOS/GOARCH onto the embedded component label.
// Unsupported combinations return "" (provisioning stays off for them).
func umidBlobLabelFor(goos, arch string) string {
	switch arch {
	case "amd64":
		switch goos {
		case "linux":
			return "elf-x86_64"
		case "darwin":
			return "macho-x86_64"
		case "windows":
			return "pe-x86_64"
		}
	case "arm64":
		switch goos {
		case "linux":
			return "elf-aarch64"
		case "darwin":
			return "macho-arm64"
		case "windows":
			return "pe-aarch64"
		}
	}
	return ""
}

// identifyUmidBlob magic-sniffs one decoded blob.
func identifyUmidBlob(data []byte) string {
	if len(data) >= 4 && bytes.Equal(data[:4], []byte{0x00, 'a', 's', 'm'}) {
		return "wasm"
	}
	if len(data) >= 20 && bytes.Equal(data[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		if data[4] != 2 || data[5] != 1 { // 64-bit little-endian only
			return "unknown"
		}
		switch uint16(data[18]) | uint16(data[19])<<8 {
		case 0x3E:
			return "elf-x86_64"
		case 0xB7:
			return "elf-aarch64"
		}
		return "unknown"
	}
	if len(data) >= 8 && bytes.Equal(data[:4], []byte{0xcf, 0xfa, 0xed, 0xfe}) {
		cpu := uint32(data[4]) | uint32(data[5])<<8 | uint32(data[6])<<16 | uint32(data[7])<<24
		switch cpu {
		case 0x01000007:
			return "macho-x86_64"
		case 0x0100000C:
			return "macho-arm64"
		}
		return "unknown"
	}
	if len(data) >= 0x40 && data[0] == 'M' && data[1] == 'Z' {
		off := uint32(data[0x3C]) | uint32(data[0x3D])<<8 | uint32(data[0x3E])<<16 | uint32(data[0x3F])<<24
		if int(off)+6 <= len(data) && bytes.Equal(data[off:off+4], []byte{'P', 'E', 0, 0}) {
			machine := uint16(data[off+4]) | uint16(data[off+5])<<8
			switch machine {
			case 0x8664:
				return "pe-x86_64"
			case 0xAA64:
				return "pe-aarch64"
			}
		}
	}
	return "unknown"
}

// selectUmidBlob picks the component matching want: magic first, then the
// 400KB..2MB heuristic (real bridges live there; the 7.3MB PE blob is some
// other native module), smallest wins.
// selectUmidSdkBlob picks the companion DLL blob for one GOOS/arch: the PE/DLL
// component (magic-identified) within the SDK size window. The bridge binary
// itself is already chosen by selectUmidBlob; the 2MB..32MB window and the
// DLL magic keep the two apart.
func selectUmidSdkBlob(blobs [][]byte, wantOS, wantArch string) []byte {
	want := umidBlobLabelFor(wantOS, wantArch)
	if want == "" {
		// sgsdk ships as a Windows DLL; other platforms have no companion.
		return nil
	}
	var best []byte
	for _, b := range blobs {
		if len(b) < umidSdkBlobMin || len(b) > umidSdkBlobMax {
			continue
		}
		if identifyUmidBlob(b) != want {
			continue
		}
		if best == nil || len(b) < len(best) {
			best = b
		}
	}
	return best
}

func selectUmidBlob(blobs [][]byte, want string) []byte {
	if want == "" {
		return nil
	}
	var best []byte
	for _, b := range blobs {
		if identifyUmidBlob(b) != want {
			continue
		}
		if best == nil {
			best = b
			continue
		}
		inRange := func(b []byte) bool { return len(b) >= umidBlobSizeMin && len(b) <= umidBlobSizeMax }
		switch {
		case inRange(b) && !inRange(best):
			best = b
		case inRange(b) == inRange(best) && len(b) < len(best):
			best = b
		}
	}
	return best
}

// recordUmidRepairError stores the last verification/repair failure so the
// panel diagnostics can say why the bridge is not in use ("" clears it).
func recordUmidRepairError(msg string) {
	umidProvisionStateMu.Lock()
	umidRepairErr = msg
	umidProvisionStateMu.Unlock()
}

// umidRepairLastError returns the last repair failure ("" when none).
func umidRepairLastError() string {
	umidProvisionStateMu.Lock()
	defer umidProvisionStateMu.Unlock()
	return umidRepairErr
}

// umidSdkPath is the companion DLL the bridge loads from its own directory.
func umidSdkPath() string {
	return filepath.Join(umidProvisionDir(), umidSdkName)
}

// umidBridgeWorks runs the bridge with the official stdin dialect and reports
// whether it answered with a complete identity. v0.8.67: a provisioned
// runtime-info that panics on a missing sgsdk.dll (exit 101, "Failed to load
// sgsdk.dll") used to be cached on disk forever and shadow every legitimate
// attempt — the file is installed, yet every request silently falls back to
// the simulated identity. Health-checking the pair turns that into a state the
// plugin can repair.
func umidBridgeWorks(exe, uid string) bool {
	data := runRuntimeInfo(exe, uid)
	if data == nil {
		return false
	}
	return strings.TrimSpace(strField(data, "machineToken")) != "" &&
		strings.TrimSpace(strField(data, "machineType")) != "" &&
		strings.TrimSpace(strField(data, "machineCode")) != ""
}

// copyFileAtomic writes src to dst through a temp file + rename.
func copyFileAtomic(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// findVerifiedRuntimeInfo searches the host for the official client's umid
// directory — a runtime-info next to its sgsdk.dll — and returns the matching
// DLL path. Order: QD_UMID_BIN's directory, the known client layouts, then a
// shallow walk of the usual install roots. Every candidate must be
// byte-identical to the bridge we will run (same build), which is why the
// bridge's own hash is the primary key.
func findVerifiedRuntimeInfo(bridgeExe string) (string, bool) {
	bridgeSum, err := fileSha256(bridgeExe)
	if err != nil {
		return "", false
	}
	seen := map[string]bool{}
	check := func(dir string) (string, bool) {
		if dir == "" || seen[dir] {
			return "", false
		}
		seen[dir] = true
		exe := filepath.Join(dir, "runtime-info.exe")
		dll := filepath.Join(dir, umidSdkName)
		if _, err := os.Stat(exe); err != nil {
			return "", false
		}
		if _, err := os.Stat(dll); err != nil {
			return "", false
		}
		sum, err := fileSha256(exe)
		if err != nil || sum != bridgeSum {
			return "", false
		}
		return dll, true
	}
	if p := strings.TrimSpace(os.Getenv("QD_UMID_BIN")); p != "" {
		if dll, ok := check(filepath.Dir(p)); ok {
			return dll, true
		}
	}
	home, _ := os.UserHomeDir()
	if home != "" {
		// Official CN CLI bundle: ~/.qoder-cn/.bin/umid-<platform>-<hash>/
		for _, root := range []string{filepath.Join(home, ".qoder-cn", ".bin"), filepath.Join(home, ".qoder", ".bin")} {
			entries, err := os.ReadDir(root)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if !e.IsDir() || !strings.HasPrefix(e.Name(), "umid-") {
					continue
				}
				if dll, ok := check(filepath.Join(root, e.Name())); ok {
					return dll, true
				}
			}
		}
		// Desktop client layouts (launcher state.ini / Programs).
		base := os.Getenv("LOCALAPPDATA")
		if strings.TrimSpace(base) == "" {
			base = filepath.Join(home, "AppData", "Local")
		}
		for _, name := range []string{"Qoder", "Qoder CN", "QoderCN"} {
			for _, launcher := range []string{name + " Launcher", "Launcher"} {
				if d := iniValue(filepath.Join(base, name, launcher, "state.ini"), "installDir"); d != "" {
					if dll, ok := check(filepath.Join(d, "resources", "umid")); ok {
						return dll, true
					}
				}
			}
			if dll, ok := check(filepath.Join(base, "Programs", name, "resources", "umid")); ok {
				return dll, true
			}
		}
	}
	return "", false
}

func fileSha256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ensureProvisionedBridgeVerified returns the plugin-managed bridge only when
// the runtime-info + sgsdk.dll pair actually runs. A bridge that is on disk but
// broken (missing/incorrect DLL) is repaired from a verified official copy
// when one exists; otherwise it reports false so the caller falls back to the
// simulated identity instead of silently sending a broken one.
func ensureProvisionedBridgeVerified(uid string) (string, bool) {
	exe := umidProvisionedExePath()
	if _, err := os.Stat(exe); err != nil {
		return "", false
	}
	if umidBridgeWorks(exe, uid) {
		return exe, true
	}
	dll, ok := findVerifiedRuntimeInfo(exe)
	if !ok {
		recordUmidRepairError("verified official copy not found (no runtime-info + " + umidSdkName + " pair on disk)")
		return "", false
	}
	if err := copyFileAtomic(dll, umidSdkPath()); err != nil {
		recordUmidRepairError("install " + umidSdkName + ": " + err.Error())
		return "", false
	}
	recordUmidRepairError("")
	if umidBridgeWorks(exe, uid) {
		return exe, true
	}
	return "", false
}

// installUmidBridge atomically writes the component and marks it executable.
func installUmidBridge(data []byte) (string, error) {
	dir := umidProvisionDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	target := umidProvisionedExePath()
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return "", err
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, target); err != nil {
		os.Remove(tmp)
		return "", err
	}
	return target, nil
}

// provisionUmidBridge runs the full extraction pipeline once.
func provisionUmidBridge() (string, error) {
	want := umidBlobLabelFor(runtime.GOOS, runtime.GOARCH)
	if want == "" {
		return "", fmt.Errorf("no official identity bridge component for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	metaBody, err := umidHTTPFetch(umidRegistryURL, umidFetchTimeout)
	if err != nil {
		return "", fmt.Errorf("npm registry: %w", err)
	}
	meta, err := parseUmidRegistryMeta(metaBody)
	if err != nil {
		return "", err
	}
	tgz, err := umidHTTPFetch(meta.Tarball, umidFetchTimeout)
	if err != nil {
		return "", fmt.Errorf("npm tarball: %w", err)
	}
	if err := umidVerifyIntegrity(tgz, meta.Integrity); err != nil {
		return "", err
	}
	text, err := umidExtractBundle(tgz)
	if err != nil {
		return "", err
	}
	blobs := scanUmidBlobs(text)
	blob := selectUmidBlob(blobs, want)
	if blob == nil {
		return "", fmt.Errorf("official bundle carries no %s component", want)
	}
	exe, err := installUmidBridge(blob)
	if err != nil {
		return "", err
	}
	// v0.8.67: runtime-info.exe loads sgsdk.dll from its own directory and
	// panics without it. Older versions installed only the bridge, which is
	// why the provisioned identity never actually ran on this host. Install
	// the companion when the bundle carries one; a bundle without it leaves
	// the bridge unverifiable and provisionedRuntimeInfo reports it.
	if sdk := selectUmidSdkBlob(blobs, runtime.GOOS, runtime.GOARCH); sdk != nil {
		if err := installUmidSdkBridge(sdk); err != nil {
			return "", fmt.Errorf("install %s: %w", umidSdkName, err)
		}
	}
	return exe, nil
}

// installUmidSdkBridge atomically writes the companion DLL next to the bridge.
func installUmidSdkBridge(data []byte) error {
	dir := umidProvisionDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	target := umidSdkPath()
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return err
	}
	if err := os.Rename(tmp, target); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
