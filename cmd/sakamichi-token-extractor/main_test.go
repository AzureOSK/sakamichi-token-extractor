package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/dunhamsteve/plist"
)

func TestDiscoverBackups(t *testing.T) {
	root := t.TempDir()
	deviceDir := filepath.Join(root, "device-id")
	if err := os.Mkdir(deviceDir, 0700); err != nil {
		t.Fatal(err)
	}
	var manifest manifestSummary
	manifest.IsEncrypted = true
	manifest.Lockdown.DeviceName = "Test iPhone"
	manifest.Lockdown.ProductVersion = "26.6"
	encodedManifest, err := plist.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deviceDir, "Manifest.plist"), encodedManifest, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectBackup(deviceDir); err != nil {
		t.Fatalf("inspectBackup failed: %v", err)
	}
	backups, err := discoverBackups(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 1 {
		t.Fatalf("got %d backups, want 1", len(backups))
	}
	if backups[0].DeviceName != "Test iPhone" || backups[0].ProductVersion != "26.6" || !backups[0].Encrypted {
		t.Fatalf("unexpected backup summary: %#v", backups[0])
	}
}

func TestClassifyApp(t *testing.T) {
	tests := map[string]string{
		"ABCDE.jp.co.sonymusic.communication.keyakizaka": "hinatazaka",
		"ABCDE.jp.co.sonymusic.communication.nogizaka":   "nogizaka",
		"ABCDE.jp.co.sonymusic.communication.sakurazaka": "sakurazaka",
		"ABCDE.example.other":                            "unclassified",
	}
	for accessGroup, want := range tests {
		if got := classifyApp(accessGroup); got != want {
			t.Errorf("classifyApp(%q) = %q, want %q", accessGroup, got, want)
		}
	}
}

func TestFindRefreshToken(t *testing.T) {
	var value interface{}
	if err := json.Unmarshal([]byte(`{"accessToken":"access","refresh_token":"refresh"}`), &value); err != nil {
		t.Fatal(err)
	}
	if got := findRefreshToken(value); got != "refresh" {
		t.Fatalf("got %q, want refresh", got)
	}
}

func TestWriteRecoveredTokensUsesRestrictedPermissions(t *testing.T) {
	outputDir := filepath.Join(t.TempDir(), "tokens")
	items := []recoveredToken{{
		App:         "hinatazaka",
		Token:       "test-refresh-token",
		Service:     targetService,
		Account:     targetKeyPrefix + "test",
		AccessGroup: "ABCDE.jp.co.sonymusic.communication.keyakizaka",
	}}
	index, err := writeRecoveredTokens(outputDir, items)
	if err != nil {
		t.Fatal(err)
	}
	if len(index) != 1 {
		t.Fatalf("got %d index entries, want 1", len(index))
	}
	if runtime.GOOS != "windows" {
		dirInfo, err := os.Stat(outputDir)
		if err != nil {
			t.Fatal(err)
		}
		if got := dirInfo.Mode().Perm(); got != 0700 {
			t.Fatalf("directory mode = %o, want 700", got)
		}
		fileInfo, err := os.Stat(index[0].OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		if got := fileInfo.Mode().Perm(); got != 0600 {
			t.Fatalf("token mode = %o, want 600", got)
		}
	}
}

func TestDefaultOutputDirectoryIsExecutableDirectory(t *testing.T) {
	executablePath, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	got, err := defaultOutputDirectory()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Dir(executablePath)
	if got != want {
		t.Fatalf("default output directory = %q, want %q", got, want)
	}
}

func TestEnsureOutputDirectoryPreservesExistingPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix directory permission bits")
	}
	outputDir := filepath.Join(t.TempDir(), "existing")
	if err := os.Mkdir(outputDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := ensureOutputDirectory(outputDir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(outputDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0755 {
		t.Fatalf("existing directory mode = %o, want 755", got)
	}
}
