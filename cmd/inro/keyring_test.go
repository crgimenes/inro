package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestKeyringPersistsMetadata is the round trip that keeps the two stores
// honest: keys as .asc files, nickname and note in keyring.filo, both surviving
// a reopen.
func TestKeyringPersistsMetadata(t *testing.T) {
	dir := t.TempDir()

	kr, err := openKeyring(dir, 0)
	if err != nil {
		t.Fatalf("openKeyring: %v", err)
	}

	imported, err := kr.Import(newTestKey(t, "Bob", "bob@example.com"))
	if err != nil {
		t.Fatalf("Import: %v", err)
	}

	fingerprint := imported[0].Fingerprint

	name := filepath.Join(dir, "keys", fingerprint+".asc")
	_, err = os.Stat(name)
	if err != nil {
		t.Fatalf("key file not written: %v", err)
	}

	err = kr.SetMeta(fingerprint, "bobby", "met at\tthe \"conference\"")
	if err != nil {
		t.Fatalf("SetMeta: %v", err)
	}

	reopened, err := openKeyring(dir, 0)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}

	keys := reopened.List()
	if len(keys) != 1 {
		t.Fatalf("got %d keys after reopen, want 1", len(keys))
	}

	got := keys[0]
	if got.Nickname != "bobby" {
		t.Errorf("nickname = %q, want %q", got.Nickname, "bobby")
	}
	if got.Note != "met at\tthe \"conference\"" {
		t.Errorf("note = %q, want the escaped original back", got.Note)
	}
	if !got.Private {
		t.Error("imported private key came back as public")
	}
	if !strings.Contains(got.Identity, "Bob") {
		t.Errorf("identity = %q, want it to name Bob", got.Identity)
	}
}

// TestKeyringDeleteRemovesFile makes sure Delete does not leave the key file
// behind to be picked up again on the next start.
func TestKeyringDeleteRemovesFile(t *testing.T) {
	dir := t.TempDir()

	kr, err := openKeyring(dir, 0)
	if err != nil {
		t.Fatalf("openKeyring: %v", err)
	}

	imported, err := kr.Import(newTestKey(t, "Bob", "bob@example.com"))
	if err != nil {
		t.Fatalf("Import: %v", err)
	}

	err = kr.Delete(imported[0].Fingerprint)
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}

	reopened, err := openKeyring(dir, 0)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if len(reopened.List()) != 0 {
		t.Fatal("deleted key came back after reopen")
	}
}

// TestExportKeyOmitsPrivateMaterial guards the one mistake in this file that
// would be unrecoverable: handing someone your secret key.
func TestExportKeyOmitsPrivateMaterial(t *testing.T) {
	svc, alice, _ := newTestService(t)

	armored, err := svc.ExportKey(alice.Fingerprint)
	if err != nil {
		t.Fatalf("ExportKey: %v", err)
	}

	if !strings.Contains(armored, "BEGIN PGP PUBLIC KEY BLOCK") {
		t.Errorf("export is not a public key block:\n%s", armored)
	}
	if strings.Contains(armored, "PRIVATE KEY BLOCK") {
		t.Fatal("ExportKey leaked private key material")
	}
}

// TestLoadConfigDefaults checks the config path is not read when absent, so a
// first run works with no files at all.
func TestLoadConfigDefaults(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Chdir(t.TempDir())

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.Width != 1024 || cfg.Height != 720 {
		t.Errorf("window = %dx%d, want 1024x720", cfg.Width, cfg.Height)
	}
}

// TestLoadConfigOverrides checks a Filo config file overrides the defaults.
func TestLoadConfigOverrides(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Chdir(t.TempDir())

	err := os.MkdirAll(filepath.Join(dir, "inro"), 0o700)
	if err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	const src = `(set Width 800)
(set Height 600)
(set Debug #t)
(set DataDir "~/keys-for-inro")
(set DefaultKey "ABCD")
`
	err = os.WriteFile(filepath.Join(dir, "inro", "init.filo"), []byte(src), 0o600)
	if err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.Width != 800 || cfg.Height != 600 {
		t.Errorf("window = %dx%d, want 800x600", cfg.Width, cfg.Height)
	}
	if !cfg.Debug {
		t.Error("Debug not applied from the config file")
	}
	if cfg.DefaultKey != "ABCD" {
		t.Errorf("DefaultKey = %q, want %q", cfg.DefaultKey, "ABCD")
	}

	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home directory: %v", err)
	}
	want := filepath.Join(home, "keys-for-inro")
	if cfg.DataDir != want {
		t.Errorf("DataDir = %q, want %q", cfg.DataDir, want)
	}
}
