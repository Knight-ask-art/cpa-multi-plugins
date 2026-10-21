package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// tempPluginState points every state path (model_ids.json, restart-cpa.ps1,
// restart.log) at a throwaway directory.
func tempPluginState(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	prev := umidStateDirOverride
	umidStateDirOverride = func() string { return filepath.Join(dir, "umid") }
	t.Cleanup(func() { umidStateDirOverride = prev })
	return dir
}

func resetRestartConfig(t *testing.T) {
	t.Helper()
	prevSpawn := spawnRestartHelper
	t.Cleanup(func() { spawnRestartHelper = prevSpawn })
	setRestartConfig(true, "")
	resetRestartState()
	t.Cleanup(func() {
		setRestartConfig(true, "")
		resetRestartState()
	})
}

func TestResolveRestartPlanPrefersLauncherScript(t *testing.T) {
	dir := t.TempDir()
	pebrel := filepath.Join(dir, "start-pebrel.ps1")
	if err := os.WriteFile(pebrel, []byte("# stub\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bat := filepath.Join(dir, "start.bat")
	if err := os.WriteFile(bat, []byte("@echo off\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "cli-proxy-api.exe")
	if err := os.WriteFile(exe, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	plan, ok := resolveRestartPlanIn(dir, exe, "")
	if !ok || plan.Kind != "start-pebrel" || plan.Target != pebrel {
		t.Fatalf("plan = %+v ok=%v, want start-pebrel %s", plan, ok, pebrel)
	}

	// A configured script wins over the auto-detected launcher.
	custom := filepath.Join(dir, "restart.cmd")
	if err := os.WriteFile(custom, []byte("@echo off\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	plan, ok = resolveRestartPlanIn(dir, exe, custom)
	if !ok || plan.Kind != "start-bat" || plan.Target != custom {
		t.Fatalf("configured plan = %+v ok=%v, want start-bat %s", plan, ok, custom)
	}

	// A configured path that does not exist must not disable the restart.
	plan, ok = resolveRestartPlanIn(dir, exe, filepath.Join(dir, "nope.ps1"))
	if !ok || plan.Kind != "start-pebrel" {
		t.Fatalf("missing configured script should fall through, got %+v ok=%v", plan, ok)
	}
}

func TestResolveRestartPlanFallsBackToBatThenSelf(t *testing.T) {
	dir := t.TempDir()
	bat := filepath.Join(dir, "start.bat")
	if err := os.WriteFile(bat, []byte("@echo off\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "cli-proxy-api.exe")
	if err := os.WriteFile(exe, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	plan, ok := resolveRestartPlanIn(dir, exe, "")
	if !ok || plan.Kind != "start-bat" || plan.Target != bat {
		t.Fatalf("plan = %+v ok=%v, want start-bat", plan, ok)
	}

	if err := os.Remove(bat); err != nil {
		t.Fatal(err)
	}
	plan, ok = resolveRestartPlanIn(dir, exe, "")
	if !ok || plan.Kind != "self" || plan.Target != exe {
		t.Fatalf("plan = %+v ok=%v, want self %s", plan, ok, exe)
	}

	if _, ok := resolveRestartPlanIn(dir, filepath.Join(dir, "missing.exe"), ""); ok {
		t.Fatal("expected no plan when nothing exists")
	}
}

func TestBuildRestartScriptQuotesPaths(t *testing.T) {
	tempPluginState(t)
	target := `C:\Program Files\it's here\start-pebrel.ps1`
	script := buildRestartScript(restartPlan{Kind: "start-pebrel", Target: target}, 4242, "model-ids", restartSettleDelay)

	if !strings.Contains(script, `C:\Program Files\it''s here\start-pebrel.ps1`) {
		t.Fatalf("single quote not doubled:\n%s", script)
	}
	if !strings.Contains(script, "Start-Sleep -Milliseconds 2500") {
		t.Fatalf("settle delay missing:\n%s", script)
	}
	if !strings.Contains(script, "reason=model-ids") || !strings.Contains(script, "pid=4242") {
		t.Fatalf("request context missing:\n%s", script)
	}
	if !strings.Contains(script, "restart.log") {
		t.Fatalf("log path missing:\n%s", script)
	}
	if strings.Contains(script, "Stop-Process") {
		t.Fatalf("launcher plan must not kill the process itself:\n%s", script)
	}
}

func TestBuildRestartScriptSelfPlanRelaunches(t *testing.T) {
	tempPluginState(t)
	exe := `C:\cpa\cli-proxy-api.exe`
	script := buildRestartScript(restartPlan{Kind: "self", Target: exe}, 99, "model-ids", restartSettleDelay)

	if !strings.Contains(script, "Stop-Process -Id 99") {
		t.Fatalf("self plan must stop this pid:\n%s", script)
	}
	if !strings.Contains(script, "Start-Process -FilePath 'C:\\cpa\\cli-proxy-api.exe'") {
		// v0.8.73: the helper starts the *current* binary (own invocation),
		// not the plan target, so it works for any install path.
		self, _, _ := ownInvocation()
		if !strings.Contains(script, "Start-Process -FilePath "+psQuote(self)) {
			t.Fatalf("self plan must relaunch %s:\n%s", self, script)
		}
	}
	if !strings.Contains(script, "-ArgumentList @(") {
		t.Fatalf("self plan must pass the original arguments:\n%s", script)
	}
}

func TestScheduleRestartWritesHelperAndDebounces(t *testing.T) {
	tempPluginState(t)
	resetRestartConfig(t)

	script := filepath.Join(t.TempDir(), "launcher.ps1")
	if err := os.WriteFile(script, []byte("# launcher\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	setRestartConfig(true, script)

	spawned := 0
	var helperBody string
	spawnRestartHelper = func(helper, dir string) error {
		spawned++
		b, err := os.ReadFile(helper)
		if err != nil {
			t.Fatalf("helper not written: %v", err)
		}
		helperBody = string(b)
		if filepath.Dir(helper) != modelIDsDir() {
			t.Fatalf("helper dir = %s, want %s", filepath.Dir(helper), modelIDsDir())
		}
		return nil
	}

	info, ok := scheduleCPARestart("model-ids")
	if !ok || info["restart_scheduled"] != true {
		t.Fatalf("first schedule = %+v ok=%v", info, ok)
	}
	if spawned != 1 {
		t.Fatalf("spawned = %d, want 1", spawned)
	}
	if !strings.Contains(helperBody, script) {
		t.Fatalf("helper does not run the configured launcher:\n%s", helperBody)
	}
	if got := info["restart_kind"]; got != "start-pebrel" {
		t.Fatalf("restart_kind = %v, want start-pebrel", got)
	}
	if _, hasPID := info["pid"]; !hasPID {
		t.Fatal("response must carry the pre-restart pid for the panel's wait")
	}

	info, ok = scheduleCPARestart("model-ids")
	if ok || info["restart_scheduled"] != false {
		t.Fatalf("debounced schedule = %+v ok=%v", info, ok)
	}
	if reason, _ := info["restart_reason"].(string); !strings.Contains(reason, "already scheduled") {
		t.Fatalf("restart_reason = %v", info["restart_reason"])
	}
	if spawned != 1 {
		t.Fatalf("debounce must not spawn again, spawned=%d", spawned)
	}
}

func TestHandleModelIDsRestartDecision(t *testing.T) {
	tempPluginState(t)
	resetRestartConfig(t)

	// The host RPC bridge is unavailable in tests; empty list keeps the
	// auth-file refresh a no-op.
	prevList := hostAuthListFn
	hostAuthListFn = func() ([]pluginapi.HostAuthFileEntry, error) { return nil, os.ErrNotExist }
	t.Cleanup(func() { hostAuthListFn = prevList })

	spawned := 0
	spawnRestartHelper = func(string, string) error { spawned++; return nil }

	post := func(body string) map[string]any {
		req := pluginapi.ManagementRequest{Method: "POST", Body: []byte(body)}
		return handleModelIDs(req)
	}

	// First save changes the table → restart scheduled.
	resp := post(`{"model_ids":{"qfmodel":"my-flash"},"restart":true}`)
	if resp["restart_scheduled"] != true {
		t.Fatalf("first save should restart: %+v", resp)
	}
	if resp["changed"] != true {
		t.Fatalf("first save changed = %v", resp["changed"])
	}
	if spawned != 1 {
		t.Fatalf("spawned = %d, want 1", spawned)
	}

	// Same table again → nothing to do, no restart.
	resp = post(`{"model_ids":{"qfmodel":"my-flash"},"restart":true}`)
	if resp["restart_scheduled"] != false || resp["restart_reason"] != "unchanged" {
		t.Fatalf("unchanged save must not restart: %+v", resp)
	}
	if spawned != 1 {
		t.Fatalf("spawned = %d, want 1 after unchanged save", spawned)
	}

	// Changed table with restart disabled by the caller.
	resp = post(`{"model_ids":{"qfmodel":"flash-2"},"restart":false}`)
	if resp["restart_scheduled"] != false || resp["restart_reason"] != "disabled" {
		t.Fatalf("restart:false must not restart: %+v", resp)
	}
	if spawned != 1 {
		t.Fatalf("spawned = %d, want 1 after disabled save", spawned)
	}

	// Config switch off + caller silent → still no restart.
	setRestartConfig(false, "")
	resp = post(`{"model_ids":{"qfmodel":"flash-3"}}`)
	if resp["restart_scheduled"] != false || resp["restart_reason"] != "disabled" {
		t.Fatalf("restart_on_model_ids=false must not restart: %+v", resp)
	}

	// The saved table round-trips through the state file.
	var onDisk map[string]string
	b, err := os.ReadFile(modelIDsFile())
	if err != nil {
		t.Fatalf("model_ids.json not written: %v", err)
	}
	if err := json.Unmarshal(b, &onDisk); err != nil {
		t.Fatalf("model_ids.json unreadable: %v", err)
	}
	if onDisk["qfmodel"] != "flash-3" {
		t.Fatalf("persisted table = %+v", onDisk)
	}
}

func TestPluginStatusReportsLauncher(t *testing.T) {
	tempPluginState(t)
	resetRestartConfig(t)

	st := pluginStatus()
	if st["version"] != version {
		t.Fatalf("version = %v, want %s", st["version"], version)
	}
	if pid, _ := st["pid"].(int); pid != os.Getpid() {
		t.Fatalf("pid = %v, want %d", st["pid"], os.Getpid())
	}
	if _, ok := st["uptime_seconds"]; !ok {
		t.Fatal("uptime_seconds missing")
	}
	if _, ok := st["restart_launcher_ready"]; !ok {
		t.Fatal("restart_launcher_ready missing")
	}
}
