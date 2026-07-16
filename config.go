package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/crgimenes/filo"
)

// Config holds the runtime settings, loaded from the Filo config file.
type Config struct {
	Width      int
	Height     int
	Debug      bool
	DataDir    string
	DefaultKey string
}

// configHome returns the base directory for user configuration, honouring
// XDG_CONFIG_HOME and falling back to ~/.config.
func configHome() string {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir != "" {
		return dir
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return filepath.Join(home, ".config")
}

// configPath returns the path to the Filo config file. A local
// "inro_init.filo" in the current directory takes precedence; otherwise
// "$XDG_CONFIG_HOME/inro/init.filo" is used.
func configPath() string {
	const local = "inro_init.filo"
	if fileExists(local) {
		return local
	}
	return filepath.Join(configHome(), "inro", "init.filo")
}

func fileExists(name string) bool {
	info, err := os.Stat(name)
	return err == nil && !info.IsDir()
}

// loadConfig builds the configuration from defaults, overriding them with any
// values set in the Filo config file (if present).
func loadConfig() (*Config, error) {
	cfg := &Config{
		Width:      1024,
		Height:     720,
		Debug:      false,
		DataDir:    filepath.Join(configHome(), "inro"),
		DefaultKey: "",
	}

	name := configPath()
	if !fileExists(name) {
		return cfg, nil
	}

	f := filo.New()
	defer f.Close()

	f.SetGlobal("Width", cfg.Width)
	f.SetGlobal("Height", cfg.Height)
	f.SetGlobal("Debug", cfg.Debug)
	f.SetGlobal("DataDir", cfg.DataDir)
	f.SetGlobal("DefaultKey", cfg.DefaultKey)

	b, err := os.ReadFile(filepath.Clean(name))
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", name, err)
	}

	err = f.DoString(string(b))
	if err != nil {
		return nil, fmt.Errorf("config %q: %w", name, err)
	}

	cfg.Width = f.MustGetInt("Width")
	cfg.Height = f.MustGetInt("Height")
	cfg.Debug = f.MustGetBool("Debug")
	cfg.DataDir = expandHome(f.MustGetString("DataDir"))
	cfg.DefaultKey = f.MustGetString("DefaultKey")

	return cfg, nil
}

// expandHome resolves a leading ~ in a path. Without this a config saying
// "~/keys" would quietly create a directory actually named "~".
func expandHome(path string) string {
	if path != "~" && !strings.HasPrefix(path, "~/") {
		return path
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}

	return filepath.Join(home, strings.TrimPrefix(path, "~"))
}
