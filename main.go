// Command inro is a desktop front end for PGP: encrypt, sign, verify and
// decrypt short messages, and keep a list of the keys of people you know.
package main

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/crgimenes/devengine/assets"
	"github.com/crgimenes/glaze"
	"github.com/crgimenes/glaze/menu"
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

// installMenu builds the application menu bar. Every action routes to the
// same window.inroMenu(...) entry point the UI exposes, so the menu and the
// on-screen controls stay one implementation. Linux has no menu backend in
// glaze (ErrUnsupported); the UI carries the same actions, so nothing is
// lost, only the bar.
func installMenu(w glaze.WebView) {
	evalAction := func(action string) func() {
		return func() { w.Eval(fmt.Sprintf("inroMenu(%q)", action)) }
	}

	_, err := menu.Set([]menu.Item{
		{Title: "inro", Submenu: []menu.Item{
			{Title: "About inro", OnClick: evalAction("about")},
			{Separator: true},
			{Title: "Quit inro", Shortcut: "cmd+q", OnClick: w.Terminate},
		}},
		{Title: "File", Submenu: []menu.Item{
			{Title: "Open", Shortcut: "cmd+o", OnClick: evalAction("open")},
			{Title: "Save", Shortcut: "cmd+s", OnClick: evalAction("save")},
		}},
		{Title: "View", Submenu: []menu.Item{
			{Title: "Message", Shortcut: "cmd+1", OnClick: evalAction("message")},
			{Title: "Keys", Shortcut: "cmd+2", OnClick: evalAction("keys")},
		}},
		// No Dispatch: main() runs on the UI thread and the run loop has not
		// started yet — glaze's Dispatch only pumps once Run() begins, so
		// passing it makes Set wait forever on a queue nobody drains and the
		// window never appears. Building inline is the documented path for a
		// caller already on the UI thread.
	}, menu.Options{Window: w.Window()})
	if err != nil && !errors.Is(err, menu.ErrUnsupported) {
		log.Printf("menu: %v", err)
	}
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
	// Below this the layout has no room for the field plus its controls.
	w.SetSize(720, 480, glaze.HintMin)

	installMenu(w)

	_, err = glaze.BindMethods(w, "inro", &Service{cfg: cfg, kr: kr, w: w})
	if err != nil {
		log.Fatal(err)
	}

	w.Navigate(baseURL)
	w.Run()
}
