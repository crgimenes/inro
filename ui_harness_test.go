package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/crgimenes/devengine/assets"
)

// TestUIHarness is not a test: it is a development harness. When
// INRO_UI_HARNESS=1 it serves the real UI backed by the real Service over
// loopback HTTP, with the glaze JS bridge replaced by fetch calls, so the
// whole application can be driven from a normal browser. It skips otherwise.
func TestUIHarness(t *testing.T) {
	if os.Getenv("INRO_UI_HARNESS") == "" {
		t.Skip("set INRO_UI_HARNESS=1 to serve the real UI for browser testing")
	}

	dir := os.Getenv("INRO_UI_HARNESS_DIR")
	if dir == "" {
		dir = t.TempDir()
	}

	kr, err := openKeyring(dir, 300*time.Second)
	if err != nil {
		t.Fatalf("openKeyring: %v", err)
	}
	svc := &Service{cfg: &Config{DataDir: dir, KeyCacheSeconds: 300}, kr: kr}

	mux := http.NewServeMux()
	mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(assets.FS)))
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, _ *http.Request) {
		b, err := os.ReadFile("ui/app.js")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/javascript")
		_, _ = w.Write(b)
	})
	mux.HandleFunc("/call/", callHandler(svc))
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		b, err := os.ReadFile("ui/index.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// The fetch bridge must define window.inro_* before app.js runs.
		html := strings.Replace(string(b),
			`<script defer type="module" src="/app.js"></script>`,
			bridgeJS+"\n  "+`<script defer type="module" src="/app.js"></script>`, 1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(html))
	})

	ln, err := net.Listen("tcp", "127.0.0.1:8732")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	t.Logf("UI harness on http://%s (keyring in %s)", ln.Addr(), dir)
	time.Sleep(10 * time.Minute)
}

const bridgeJS = `<script>
  const inroCall = (name) => async (...args) => {
    const r = await fetch("/call/" + name, { method: "POST", body: JSON.stringify(args) });
    const j = await r.json();
    if (!j.ok) throw new Error(j.error);
    return j.result;
  };
  for (const n of ["settings", "list_keys", "import_key", "export_key", "delete_key",
                   "set_key_meta", "who_can_open", "encrypt", "decrypt", "sign",
                   "verify", "generate_key", "open_text_file", "save_text_file"]) {
    window["inro_" + n] = inroCall(n);
  }
</script>`

// callHandler dispatches POST /call/<name> with a JSON array body to the
// matching Service method, mirroring what glaze's Bind does in the real app.
func callHandler(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/call/")

		var args []json.RawMessage
		err := json.NewDecoder(r.Body).Decode(&args)
		if err != nil {
			args = nil
		}

		str := func(i int) string {
			var s string
			if i < len(args) {
				_ = json.Unmarshal(args[i], &s)
			}
			return s
		}

		result, err := func() (any, error) {
			switch name {
			case "settings":
				return svc.Settings()
			case "list_keys":
				return svc.ListKeys()
			case "import_key":
				return svc.ImportKey(str(0))
			case "export_key":
				return svc.ExportKey(str(0))
			case "delete_key":
				return nil, svc.DeleteKey(str(0))
			case "set_key_meta":
				return nil, svc.SetKeyMeta(str(0), str(1), str(2))
			case "who_can_open":
				return svc.WhoCanOpen(str(0))
			case "generate_key":
				return svc.GenerateKey(str(0), str(1), str(2))
			case "verify":
				return svc.Verify(str(0))
			case "encrypt":
				var req EncryptRequest
				_ = json.Unmarshal(args[0], &req)
				return svc.Encrypt(req)
			case "decrypt":
				var req DecryptRequest
				_ = json.Unmarshal(args[0], &req)
				return svc.Decrypt(req)
			case "sign":
				var req SignRequest
				_ = json.Unmarshal(args[0], &req)
				return svc.Sign(req)
			case "open_text_file":
				return svc.OpenTextFile()
			case "save_text_file":
				return svc.SaveTextFile(str(0))
			default:
				return nil, fmt.Errorf("unknown method %q", name)
			}
		}()

		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": result})
	}
}
