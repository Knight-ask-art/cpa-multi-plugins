package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFindVerifiedRuntimeInfoFindsOfficialCopy(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows-only layout")
	}
	home, _ := os.UserHomeDir()
	base := filepath.Join(home, ".qoder-cn", ".bin")
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Skipf("no official qoder-cn bundle on this host: %v", err)
	}
	var bridge string
	var sdk string
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "umid-") {
			bridge = filepath.Join(base, e.Name(), "runtime-info.exe")
			sdk = filepath.Join(base, e.Name(), "sgsdk.dll")
		}
	}
	if bridge == "" || sdk == "" {
		t.Skip("official umid directory not found")
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("QD_UMID_BIN", "")
	// The repair search must locate the companion for a copied bridge that is
	// byte-identical to the official one.
	dir := t.TempDir()
	dst := filepath.Join(dir, "runtime-info.exe")
	if err := copyFileAtomic(bridge, dst); err != nil {
		t.Fatalf("copy bridge: %v", err)
	}
	got, ok := findVerifiedRuntimeInfo(dst)
	if !ok {
		t.Fatal("findVerifiedRuntimeInfo did not locate the official companion")
	}
	if a, _ := fileSha256(got); a == "" {
		t.Fatalf("companion has no content: %s", got)
	}
	_ = sdk
}

func TestFindVerifiedRuntimeInfoRejectsMismatch(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "runtime-info.exe")
	if err := os.WriteFile(exe, []byte("not a bridge"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, ok := findVerifiedRuntimeInfo(exe); ok {
		t.Fatal("an unknown bridge must not be paired with a random DLL")
	}
}

func TestSelectUmidSdkBlobWindowsOnly(t *testing.T) {
	// A PE64 blob in the SDK window is picked for windows/amd64…
	pe := make([]byte, umidSdkBlobMin+16)
	pe[0], pe[1] = 'M', 'Z'
	pe[0x3C] = 0x40
	copy(pe[0x40:], []byte{'P', 'E', 0, 0, 0x64, 0x86})
	small := make([]byte, 1024) // bridge-sized: must not be picked
	if got := selectUmidSdkBlob([][]byte{small, pe}, "windows", "amd64"); len(got) != len(pe) {
		t.Fatalf("windows/amd64 SDK blob not selected: %d bytes", len(got))
	}
	// …and nothing at all on linux (no companion there).
	if got := selectUmidSdkBlob([][]byte{pe}, "linux", "amd64"); got != nil {
		t.Fatal("linux has no sgsdk companion")
	}
}
