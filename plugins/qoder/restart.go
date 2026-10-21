// restart.go — v0.8.73: restart the CPA host from the panel.
//
// The host reads a plugin's model catalog only when the plugin registers, so a
// new client-facing id (model_ids) is not routable until CPA restarts. Saving
// from the panel can therefore schedule the restart itself:
//
//	plugin (inside the CPA process)
//	  → writes restart-cpa.ps1 into the plugin state dir
//	  → asks WMI (Win32_Process.Create) to run it, so it is NOT a child of
//	    CPA and is not killed by the same job object that kills CPA
//	  → returns the HTTP response immediately
//	helper process
//	  → sleeps ~2.5s (lets the response reach the browser)
//	  → runs the operator's own launcher: start-pebrel.ps1 (CPA + OMC in
//	    Pebrel) or start.bat next to the executable, else relaunches the
//	    binary with its original arguments
//	  → if CPA is still not listening afterwards, starts the binary directly
//	    so a broken launcher can never leave the host down
//
// Everything it did is appended to restart.log next to the helper, because the
// CPA pane that would normally show plugin logs is being replaced.
package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// restartSettleDelay is how long the helper waits before doing anything:
	// the save response and the browser's first poll both need to get out.
	restartSettleDelay = 2500 * time.Millisecond
	// restartDebounce collapses double clicks: a second save within this
	// window reports the restart already in flight instead of stacking two.
	restartDebounce = 25 * time.Second
	// restartHelperName / restartLogName live in the plugin state dir
	// (~/.cpa-multi-plugins/qoder) next to model_ids.json.
	restartHelperName = "restart-cpa.ps1"
	restartLogName    = "restart.log"
	// cpaPort is the API port the helper waits on after the launcher returns.
	cpaPort = 8317
)

var processStartAt = time.Now()

var (
	restartMu          sync.Mutex
	restartScheduledAt time.Time
	restartReason      string

	restartCfgMu       sync.RWMutex
	restartOnModelIDs  = true
	restartScriptValue string
)

// spawnRestartHelper is a seam for tests (never spawn processes there).
var spawnRestartHelper = spawnPowerShellDetached

// restartPlan is what the helper should run.
type restartPlan struct {
	Kind   string `json:"kind"`   // start-pebrel | start-bat | self
	Target string `json:"target"` // script or executable path
}

// setRestartConfig installs the config switches (configure()).
func setRestartConfig(on bool, script string) {
	restartCfgMu.Lock()
	changed := restartOnModelIDs != on || restartScriptValue != strings.TrimSpace(script)
	restartOnModelIDs = on
	restartScriptValue = strings.TrimSpace(script)
	restartCfgMu.Unlock()
	if changed {
		log.Printf("qoder: restart_on_model_ids=%v restart_script=%q", on, script)
	}
}

func restartOnSaveEnabled() bool {
	restartCfgMu.RLock()
	defer restartCfgMu.RUnlock()
	return restartOnModelIDs
}

func configuredRestartScript() string {
	restartCfgMu.RLock()
	defer restartCfgMu.RUnlock()
	return restartScriptValue
}

// resolveRestartPlan picks the launcher. Order: configured restart_script,
// then the launcher the operator already uses inside the CPA directory, then
// a plain re-exec of this binary with its original arguments.
func resolveRestartPlan() (restartPlan, bool) {
	exe, _ := os.Executable()
	if exe != "" {
		exe = filepath.Clean(exe)
	}
	return resolveRestartPlanIn(filepath.Dir(exe), exe, configuredRestartScript())
}

func resolveRestartPlanIn(dir, exe, configured string) (restartPlan, bool) {
	if p := strings.TrimSpace(configured); p != "" {
		if stat, err := os.Stat(p); err == nil && !stat.IsDir() {
			return planForPath(p, "custom"), true
		}
	}
	for _, name := range []string{"start-pebrel.ps1", "start.ps1"} {
		p := filepath.Join(dir, name)
		if stat, err := os.Stat(p); err == nil && !stat.IsDir() {
			return restartPlan{Kind: "start-pebrel", Target: p}, true
		}
	}
	for _, name := range []string{"start.bat", "start.cmd"} {
		p := filepath.Join(dir, name)
		if stat, err := os.Stat(p); err == nil && !stat.IsDir() {
			return restartPlan{Kind: "start-bat", Target: p}, true
		}
	}
	if exe != "" {
		if stat, err := os.Stat(exe); err == nil && !stat.IsDir() {
			return restartPlan{Kind: "self", Target: exe}, true
		}
	}
	return restartPlan{}, false
}

// planForPath classifies a configured launcher by extension.
func planForPath(p, fallbackKind string) restartPlan {
	switch strings.ToLower(filepath.Ext(p)) {
	case ".ps1":
		return restartPlan{Kind: "start-pebrel", Target: p}
	case ".bat", ".cmd":
		return restartPlan{Kind: "start-bat", Target: p}
	}
	return restartPlan{Kind: fallbackKind, Target: p}
}

// modelIDsDir is the plugin state directory (the parent of the umid dir).
func modelIDsDir() string {
	return filepath.Clean(filepath.Join(umidProvisionDir(), "..", "qoder"))
}

func restartLogPath() string    { return filepath.Join(modelIDsDir(), restartLogName) }
func restartHelperPath() string { return filepath.Join(modelIDsDir(), restartHelperName) }

// psQuote renders a PowerShell single-quoted literal.
func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// psArgList renders Start-Process -ArgumentList for pre-quoted args.
func psArgList(quoted []string) string {
	if len(quoted) == 0 {
		return "@()"
	}
	return "@(" + strings.Join(quoted, ", ") + ")"
}

// ownInvocation describes how to start this binary again by hand.
func ownInvocation() (exe string, args []string, dir string) {
	exe, _ = os.Executable()
	exe = filepath.Clean(exe)
	for _, a := range os.Args[1:] {
		args = append(args, a)
	}
	dir, _ = os.Getwd()
	return exe, args, dir
}

func quotedArgs() string {
	_, args, _ := ownInvocation()
	out := make([]string, 0, len(args))
	for _, a := range args {
		out = append(out, psQuote(a))
	}
	return psArgList(out)
}

// buildRestartScript renders the helper. It is a plain file (not an inline
// -Command) so the log stays readable and the operator can rerun it by hand.
func buildRestartScript(plan restartPlan, pid int, reason string, delay time.Duration) string {
	var b strings.Builder
	b.WriteString("# generated by the CPA qoder plugin — restarts CPA so changed model ids register\n")
	b.WriteString("$ErrorActionPreference = 'Continue'\n")
	b.WriteString("$log = " + psQuote(restartLogPath()) + "\n")
	b.WriteString("function qdlog([string]$m) {\n")
	b.WriteString("  try { Add-Content -Path $log -Value ('[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] ' + $m) -Encoding utf8 } catch {}\n")
	b.WriteString("}\n")
	b.WriteString("qdlog " + psQuote("restart requested (reason="+reason+", pid="+strconv.Itoa(pid)+", plan="+plan.Kind+")") + "\n")
	b.WriteString("Start-Sleep -Milliseconds " + strconv.Itoa(int(delay/time.Millisecond)) + "\n")

	exe, _, wd := ownInvocation()
	startDirect := func() {
		b.WriteString("  Start-Process -FilePath " + psQuote(exe) +
			" -ArgumentList " + quotedArgs() + " -WorkingDirectory " + psQuote(wd) + "\n")
	}

	if plan.Kind == "self" {
		// No launcher on disk: stop this process, then start it again with
		// the same executable, arguments and working directory.
		b.WriteString("try {\n")
		b.WriteString("  qdlog " + psQuote("stopping pid "+strconv.Itoa(pid)) + "\n")
		b.WriteString("  Stop-Process -Id " + strconv.Itoa(pid) + " -Force -ErrorAction SilentlyContinue\n")
		b.WriteString("  Start-Sleep -Milliseconds 1200\n")
		startDirect()
		b.WriteString("  qdlog 'relaunched'\n")
		b.WriteString("} catch { qdlog ('relaunch failed: ' + $_.Exception.Message) }\n")
		return b.String()
	}

	b.WriteString("try {\n")
	b.WriteString("  qdlog ('running ' + " + psQuote(plan.Target) + ")\n")
	// The launcher's own output is piped through Out-String first: start-pebrel.ps1
	// prints Chinese text, and `*>>` re-encodes it into the log as UTF-16
	// fragments (measured). A decoded string keeps restart.log readable.
	b.WriteString("  $out = & " + psQuote(plan.Target) + " 2>&1 | Out-String\n")
	b.WriteString("  if ($out.Trim()) { qdlog ('launcher output: ' + $out.Trim()) }\n")
	b.WriteString("  qdlog ('launcher exited, exit code ' + $LASTEXITCODE)\n")
	b.WriteString("} catch { qdlog ('launcher failed: ' + $_.Exception.Message) }\n")
	// Safety net: a launcher that stops CPA and then dies (observed when the
	// helper ran inside CPA's job) must not leave the host down.
	b.WriteString("$up = $false\n")
	b.WriteString("for ($i = 0; $i -lt 60; $i++) {\n")
	b.WriteString("  if (Get-NetTCPConnection -LocalPort " + strconv.Itoa(cpaPort) + " -State Listen -ErrorAction SilentlyContinue) { $up = $true; break }\n")
	b.WriteString("  Start-Sleep -Seconds 1\n")
	b.WriteString("}\n")
	b.WriteString("if (-not $up) {\n")
	b.WriteString("  qdlog 'cpa still not listening — starting it directly'\n")
	b.WriteString("  try {\n")
	startDirect()
	b.WriteString("    qdlog 'direct start issued'\n")
	b.WriteString("  } catch { qdlog ('direct start failed: ' + $_.Exception.Message) }\n")
	b.WriteString("}\n")
	return b.String()
}

// scheduleCPARestart writes and launches the helper. The returned map is merged
// into the management response so the panel learns the pid to wait for.
func scheduleCPARestart(reason string) (map[string]any, bool) {
	restartMu.Lock()
	if !restartScheduledAt.IsZero() && time.Since(restartScheduledAt) < restartDebounce {
		at, lastReason := restartScheduledAt, restartReason
		restartMu.Unlock()
		return map[string]any{
			"restart_scheduled": false,
			"restart_reason":    "already scheduled (" + lastReason + " at " + at.Format(time.RFC3339) + ")",
		}, false
	}
	restartMu.Unlock()

	if runtime.GOOS != "windows" {
		return map[string]any{
			"restart_scheduled": false,
			"restart_error":     "automatic restart is implemented for Windows hosts only",
		}, false
	}
	plan, ok := resolveRestartPlan()
	if !ok {
		return map[string]any{
			"restart_scheduled": false,
			"restart_error":     "no launcher found (set restart_script in the plugin config)",
		}, false
	}

	dir := modelIDsDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return map[string]any{"restart_scheduled": false, "restart_error": err.Error()}, false
	}
	helper := restartHelperPath()
	script := buildRestartScript(plan, os.Getpid(), reason, restartSettleDelay)
	if err := os.WriteFile(helper, []byte(script), 0o644); err != nil {
		return map[string]any{"restart_scheduled": false, "restart_error": err.Error()}, false
	}
	if err := spawnRestartHelper(helper, dir); err != nil {
		log.Printf("qoder: restart helper failed to start: %v", err)
		return map[string]any{
			"restart_scheduled": false,
			"restart_error":     err.Error(),
			"restart_script":    helper,
		}, false
	}

	restartMu.Lock()
	restartScheduledAt = time.Now()
	restartReason = reason
	restartMu.Unlock()

	log.Printf("qoder: CPA restart scheduled in %dms via %s (%s) — helper %s, log %s",
		restartSettleDelay/time.Millisecond, plan.Kind, plan.Target, helper, restartLogPath())
	return map[string]any{
		"restart_scheduled": true,
		"restart_in_ms":     int(restartSettleDelay / time.Millisecond),
		"restart_kind":      plan.Kind,
		"restart_target":    plan.Target,
		"restart_log":       restartLogPath(),
		"pid":               os.Getpid(),
		"version":           version,
	}, true
}

// powershellExe returns the PowerShell 5.1 path. It is the one the measured
// spawn works with, and it is on every supported Windows host.
func powershellExe() string {
	if sys := os.Getenv("SystemRoot"); sys != "" {
		p := filepath.Join(sys, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return "powershell.exe"
}

// powershellDoubleQuote renders an argument for a raw CreateProcess command
// line (WMI CommandLine). Single quotes are PowerShell syntax, not Windows
// argument syntax: `-File 'C:\x.ps1'` is passed through literally and the
// helper never starts (measured v0.8.73).
func powershellDoubleQuote(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

// spawnPowerShellDetached starts the helper so it outlives CPA.
//
// WMI is tried first (v0.8.73, measured): Win32_Process.Create hands the
// process to WmiPrvSE, so it is not a child of CPA and survives the job
// object that takes CPA down. A plain exec is the fallback — it works, but a
// helper started that way was observed to die the moment start-pebrel.ps1
// killed CPA, which is why the script also carries a direct-start safety net.
//
// Every spawn is verified: the helper writes its first log line immediately,
// so a missing line means it never ran and the next strategy is tried.
func spawnPowerShellDetached(helper, dir string) error {
	var lastErr error
	if pid, err := spawnViaWMI(helper, dir); err != nil {
		lastErr = err
		log.Printf("qoder: WMI spawn failed (%v), falling back to direct exec", err)
	} else if waitForHelperMarker(helperMarkerTimeout) {
		log.Printf("qoder: restart helper started via WMI (pid %d)", pid)
		return nil
	} else {
		log.Printf("qoder: WMI reported pid %d but the helper never wrote its log — falling back", pid)
	}

	args := []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", helper}
	cmd := exec.Command(powershellExe(), args...)
	cmd.Dir = dir
	cmd.SysProcAttr = detachedSysProcAttr()
	if err := cmd.Start(); err != nil {
		if lastErr != nil {
			return lastErr
		}
		return err
	}
	_ = cmd.Process.Release()
	if !waitForHelperMarker(helperMarkerTimeout) {
		return fmt.Errorf("restart helper did not start (checked %s)", restartLogPath())
	}
	return nil
}

// helperMarkerTimeout is how long a spawned helper gets to write its first log
// line. A cold WMI round trip plus powershell start takes ~1-3s here.
const helperMarkerTimeout = 6 * time.Second

// waitForHelperMarker reports whether the helper logged its start line.
func waitForHelperMarker(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if b, err := os.ReadFile(restartLogPath()); err == nil && len(b) > 0 {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// spawnViaWMI creates the helper through Win32_Process.Create and returns its
// pid.
func spawnViaWMI(helper, dir string) (int, error) {
	cmdline := powershellExe() + " -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File " + powershellDoubleQuote(helper)
	script := "(Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine=" +
		psQuote(cmdline) + "; CurrentDirectory=" + psQuote(dir) + "}).ProcessId"
	cmd := exec.Command(powershellExe(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	cmd.Dir = dir
	cmd.SysProcAttr = detachedSysProcAttr()
	out, err := cmd.Output()
	if err != nil {
		return 0, err
	}
	pid, perr := strconv.Atoi(strings.TrimSpace(string(out)))
	if perr != nil {
		return 0, fmt.Errorf("unexpected WMI output %q", strings.TrimSpace(string(out)))
	}
	return pid, nil
}

// pluginStatus backs GET <base>/status: the panel polls it after a restart and
// waits for a different pid before reloading.
func pluginStatus() map[string]any {
	restartMu.Lock()
	last, lastReason := "", ""
	if !restartScheduledAt.IsZero() {
		last = restartScheduledAt.Format(time.RFC3339)
		lastReason = restartReason
	}
	restartMu.Unlock()

	plan, ok := resolveRestartPlan()
	st := map[string]any{
		"version":                version,
		"pid":                    os.Getpid(),
		"started_at":             processStartAt.Format(time.RFC3339),
		"uptime_seconds":         int(time.Since(processStartAt).Seconds()),
		"restart_on_model_ids":   restartOnSaveEnabled(),
		"restart_launcher_ready": ok,
		"last_restart_request":   last,
		"last_restart_reason":    lastReason,
	}
	if ok {
		st["restart_kind"] = plan.Kind
		st["restart_target"] = plan.Target
	}
	if _, err := os.Stat(restartLogPath()); err == nil {
		st["restart_log"] = restartLogPath()
	}
	return st
}

// resetRestartState clears the debounce window (tests).
func resetRestartState() {
	restartMu.Lock()
	restartScheduledAt = time.Time{}
	restartReason = ""
	restartMu.Unlock()
}
