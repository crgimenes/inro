// Command inro is a desktop front end for PGP: encrypt, sign, verify and
// decrypt short messages, and keep a list of the keys of people you know.
package main

import (
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/crgimenes/devengine/assets"
	"github.com/crgimenes/glaze"
)

//go:embed ui
var uiFS embed.FS

// startUIServer serves the embedded UI and devengine's assets on loopback.
// The window needs a real origin because devengine's stylesheets are fetched
// from /assets, which a data: or file: page cannot do.
func startUIServer() (string, error) {
	ui, err := fs.Sub(uiFS, "ui")
	if err != nil {
		return "", fmt.Errorf("ui files: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(assets.FS)))
	mux.Handle("/", http.FileServerFS(ui))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("listen: %w", err)
	}

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()

	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		return "", fmt.Errorf("unexpected listener address %v", ln.Addr())
	}

	return fmt.Sprintf("http://127.0.0.1:%d", addr.Port), nil
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}

	kr, err := openKeyring(cfg.DataDir, time.Duration(cfg.KeyCacheSeconds)*time.Second)
	if err != nil {
		log.Fatal(err)
	}

	baseURL, err := startUIServer()
	if err != nil {
		log.Fatal(err)
	}

	w, err := glaze.New(cfg.Debug)
	if err != nil {
		log.Fatal(err)
	}
	defer w.Destroy()

	w.SetTitle("inro")
	w.SetSize(cfg.Width, cfg.Height, glaze.HintNone)

	_, err = glaze.BindMethods(w, "inro", &Service{cfg: cfg, kr: kr, w: w})
	if err != nil {
		log.Fatal(err)
	}

	w.Navigate(baseURL)
	w.Run()
}
