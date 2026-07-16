package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/crgimenes/filo"
)

// KeyMeta is the local information about a key that the key material itself
// does not carry, which is why it lives in keyring.filo instead of the .asc.
type KeyMeta struct {
	Nickname string
	Note     string
}

// KeyInfo is how a key is presented to the UI. Everything but Nickname and
// Note is derived from the key itself, so the two stores cannot drift.
type KeyInfo struct {
	Fingerprint string `json:"fingerprint"`
	KeyID       string `json:"keyId"`
	Identity    string `json:"identity"`
	Nickname    string `json:"nickname"`
	Note        string `json:"note"`
	Private     bool   `json:"private"`
	Created     string `json:"created"`
}

// Keyring is the on-disk key collection: one armored file per key under
// <dir>/keys, plus <dir>/keyring.filo with the local metadata.
//
// The cached entities are never unlocked. Operations needing private key
// material re-read the key from disk and unlock that copy, so decrypted
// secrets live only for the duration of a single operation.
type Keyring struct {
	mu       sync.RWMutex
	dir      string
	entities map[string]*openpgp.Entity
	meta     map[string]KeyMeta
}

// openKeyring loads the keyring from dir, creating the directory tree on
// first run.
func openKeyring(dir string) (*Keyring, error) {
	k := &Keyring{
		dir:      dir,
		entities: map[string]*openpgp.Entity{},
		meta:     map[string]KeyMeta{},
	}

	err := os.MkdirAll(k.keysDir(), 0o700)
	if err != nil {
		return nil, fmt.Errorf("create keys directory: %w", err)
	}

	err = k.loadMeta()
	if err != nil {
		return nil, err
	}

	err = k.loadKeys()
	if err != nil {
		return nil, err
	}

	return k, nil
}

func (k *Keyring) keysDir() string {
	return filepath.Join(k.dir, "keys")
}

func (k *Keyring) metaPath() string {
	return filepath.Join(k.dir, "keyring.filo")
}

func (k *Keyring) keyPath(fingerprint string) string {
	return filepath.Join(k.keysDir(), fingerprint+".asc")
}

// loadKeys reads every .asc file in the keys directory. A file that fails to
// parse is reported rather than skipped: silently dropping a key would look
// like the key was never imported.
func (k *Keyring) loadKeys() error {
	entries, err := os.ReadDir(k.keysDir())
	if err != nil {
		return fmt.Errorf("read keys directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".asc") {
			continue
		}

		name := filepath.Join(k.keysDir(), entry.Name())
		b, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			return fmt.Errorf("read key %q: %w", entry.Name(), err)
		}

		el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(b))
		if err != nil {
			return fmt.Errorf("parse key %q: %w", entry.Name(), err)
		}

		for _, e := range el {
			k.entities[fingerprintOf(e)] = e
		}
	}

	return nil
}

// loadMeta reads keyring.filo, whose only form is (key <fingerprint>
// [nickname] [note]) — the ordered-records pattern used by dbv.
func (k *Keyring) loadMeta() error {
	name := k.metaPath()
	if !fileExists(name) {
		return nil
	}

	f := filo.New()
	defer f.Close()

	err := f.RegisterBuiltin("key", func(_ context.Context, args []filo.Value) (filo.Value, error) {
		if len(args) < 1 {
			return filo.VBool(false), fmt.Errorf("key: fingerprint is required")
		}

		fingerprint, err := args[0].AsString()
		if err != nil {
			return filo.VBool(false), fmt.Errorf("key: fingerprint must be a string: %w", err)
		}

		var meta KeyMeta
		meta.Nickname, err = optionalString(args, 1)
		if err != nil {
			return filo.VBool(false), fmt.Errorf("key %s: nickname: %w", fingerprint, err)
		}

		meta.Note, err = optionalString(args, 2)
		if err != nil {
			return filo.VBool(false), fmt.Errorf("key %s: note: %w", fingerprint, err)
		}

		k.meta[strings.ToUpper(fingerprint)] = meta
		return filo.VBool(true), nil
	})
	if err != nil {
		return fmt.Errorf("register key builtin: %w", err)
	}

	b, err := os.ReadFile(filepath.Clean(name))
	if err != nil {
		return fmt.Errorf("read %q: %w", name, err)
	}

	// Filo rejects a script with no forms in it, and a file left with nothing
	// but its header comments is a normal state here.
	if !hasForms(string(b)) {
		return nil
	}

	err = f.DoString(string(b))
	if err != nil {
		return fmt.Errorf("%q: %w", name, err)
	}

	return nil
}

// hasForms reports whether src holds anything Filo would evaluate. Forms start
// with "(", so a line whose first character is ";" is always a comment.
func hasForms(src string) bool {
	for line := range strings.SplitSeq(src, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		return true
	}
	return false
}

func optionalString(args []filo.Value, i int) (string, error) {
	if len(args) <= i {
		return "", nil
	}
	return args[i].AsString()
}

// saveMeta rewrites keyring.filo. Entries are sorted so the file stays stable
// across writes and is reviewable in a diff.
func (k *Keyring) saveMeta() error {
	fingerprints := make([]string, 0, len(k.meta))
	for fp, m := range k.meta {
		if m.Nickname == "" && m.Note == "" {
			continue
		}
		fingerprints = append(fingerprints, fp)
	}
	sort.Strings(fingerprints)

	if len(fingerprints) == 0 {
		err := os.Remove(k.metaPath())
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove %q: %w", k.metaPath(), err)
		}
		return nil
	}

	var b strings.Builder
	b.WriteString("; inro keyring metadata, generated but safe to edit by hand.\n")
	b.WriteString("; (key <fingerprint> <nickname> <note>)\n")

	for _, fp := range fingerprints {
		m := k.meta[fp]
		fmt.Fprintf(&b, "(key %s %s %s)\n",
			filoString(fp), filoString(m.Nickname), filoString(m.Note))
	}

	err := os.WriteFile(k.metaPath(), []byte(b.String()), 0o600)
	if err != nil {
		return fmt.Errorf("write %q: %w", k.metaPath(), err)
	}
	return nil
}

// filoString quotes s as a Filo string literal.
func filoString(s string) string {
	r := strings.NewReplacer(
		`\`, `\\`,
		`"`, `\"`,
		"\n", `\n`,
		"\t", `\t`,
		"\r", `\r`,
	)
	return `"` + r.Replace(s) + `"`
}

// List returns every key, private keys first and then by identity, which is
// the order the UI shows them in.
func (k *Keyring) List() []KeyInfo {
	k.mu.RLock()
	defer k.mu.RUnlock()

	keys := make([]KeyInfo, 0, len(k.entities))
	for fp, e := range k.entities {
		keys = append(keys, KeyInfo{
			Fingerprint: fp,
			KeyID:       e.PrimaryKey.KeyIdString(),
			Identity:    primaryIdentity(e),
			Nickname:    k.meta[fp].Nickname,
			Note:        k.meta[fp].Note,
			Private:     e.PrivateKey != nil,
			Created:     e.PrimaryKey.CreationTime.Format("2006-01-02"),
		})
	}

	slices.SortFunc(keys, func(a, b KeyInfo) int {
		if a.Private != b.Private {
			if a.Private {
				return -1
			}
			return 1
		}
		return strings.Compare(strings.ToLower(a.Identity), strings.ToLower(b.Identity))
	})

	return keys
}

// Import parses one or more armored keys and stores each one as its own file.
// Importing a key that is already present overwrites it, which is how a public
// key gets upgraded to a private one, or refreshed with new signatures.
func (k *Keyring) Import(armored string) ([]KeyInfo, error) {
	el, err := openpgp.ReadArmoredKeyRing(strings.NewReader(armored))
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}
	if len(el) == 0 {
		return nil, fmt.Errorf("no keys found in that text")
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	imported := make([]KeyInfo, 0, len(el))
	for _, e := range el {
		fp := fingerprintOf(e)

		text, err := serializeEntity(e)
		if err != nil {
			return nil, fmt.Errorf("serialize key %s: %w", fp, err)
		}

		err = os.WriteFile(k.keyPath(fp), []byte(text), 0o600)
		if err != nil {
			return nil, fmt.Errorf("write key %s: %w", fp, err)
		}

		k.entities[fp] = e
		imported = append(imported, KeyInfo{
			Fingerprint: fp,
			KeyID:       e.PrimaryKey.KeyIdString(),
			Identity:    primaryIdentity(e),
			Private:     e.PrivateKey != nil,
		})
	}

	return imported, nil
}

// Delete removes a key and its metadata from the keyring.
func (k *Keyring) Delete(fingerprint string) error {
	fingerprint = strings.ToUpper(strings.TrimSpace(fingerprint))

	k.mu.Lock()
	defer k.mu.Unlock()

	_, ok := k.entities[fingerprint]
	if !ok {
		return fmt.Errorf("key %s is not in the keyring", fingerprint)
	}

	err := os.Remove(k.keyPath(fingerprint))
	if err != nil {
		return fmt.Errorf("remove key file: %w", err)
	}

	delete(k.entities, fingerprint)
	delete(k.meta, fingerprint)

	return k.saveMeta()
}

// SetMeta attaches a nickname and a note to a key.
func (k *Keyring) SetMeta(fingerprint, nickname, note string) error {
	fingerprint = strings.ToUpper(strings.TrimSpace(fingerprint))

	k.mu.Lock()
	defer k.mu.Unlock()

	_, ok := k.entities[fingerprint]
	if !ok {
		return fmt.Errorf("key %s is not in the keyring", fingerprint)
	}

	k.meta[fingerprint] = KeyMeta{Nickname: nickname, Note: note}

	return k.saveMeta()
}

// Export returns the armored public key, the form you send to someone else.
// Private key material is never exported.
func (k *Keyring) Export(fingerprint string) (string, error) {
	e, err := k.entity(fingerprint)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	aw, err := armor.Encode(&buf, "PGP PUBLIC KEY BLOCK", nil)
	if err != nil {
		return "", fmt.Errorf("armor: %w", err)
	}

	err = e.Serialize(aw)
	if err != nil {
		return "", fmt.Errorf("serialize key: %w", err)
	}

	err = aw.Close()
	if err != nil {
		return "", fmt.Errorf("finish armor: %w", err)
	}

	return buf.String(), nil
}

// entity returns the cached, locked entity for fingerprint.
func (k *Keyring) entity(fingerprint string) (*openpgp.Entity, error) {
	fingerprint = strings.ToUpper(strings.TrimSpace(fingerprint))

	k.mu.RLock()
	defer k.mu.RUnlock()

	e, ok := k.entities[fingerprint]
	if !ok {
		return nil, fmt.Errorf("key %s is not in the keyring", fingerprint)
	}
	return e, nil
}

// entities resolves a list of fingerprints to cached entities.
func (k *Keyring) entitiesFor(fingerprints []string) ([]*openpgp.Entity, error) {
	out := make([]*openpgp.Entity, 0, len(fingerprints))
	for _, fp := range fingerprints {
		e, err := k.entity(fp)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// publicList returns every cached entity, for signature verification.
func (k *Keyring) publicList() openpgp.EntityList {
	k.mu.RLock()
	defer k.mu.RUnlock()

	el := make(openpgp.EntityList, 0, len(k.entities))
	for _, e := range k.entities {
		el = append(el, e)
	}
	return el
}

// unlocked re-reads the key from disk and unlocks that fresh copy. The
// returned entity is the caller's alone and must be discarded once the
// operation finishes.
func (k *Keyring) unlocked(fingerprint, passphrase string) (*openpgp.Entity, error) {
	fingerprint = strings.ToUpper(strings.TrimSpace(fingerprint))

	b, err := os.ReadFile(filepath.Clean(k.keyPath(fingerprint)))
	if err != nil {
		return nil, fmt.Errorf("key %s is not in the keyring", fingerprint)
	}

	el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("parse key %s: %w", fingerprint, err)
	}
	if len(el) == 0 {
		return nil, fmt.Errorf("key %s is empty", fingerprint)
	}

	e := el[0]
	err = unlock(e, passphrase)
	if err != nil {
		return nil, err
	}

	return e, nil
}

// serializeEntity renders an entity as armored text, keeping the private part
// when there is one.
func serializeEntity(e *openpgp.Entity) (string, error) {
	blockType := "PGP PUBLIC KEY BLOCK"
	if e.PrivateKey != nil {
		blockType = "PGP PRIVATE KEY BLOCK"
	}

	var buf bytes.Buffer
	aw, err := armor.Encode(&buf, blockType, nil)
	if err != nil {
		return "", fmt.Errorf("armor: %w", err)
	}

	err = writeEntity(aw, e)
	if err != nil {
		return "", fmt.Errorf("serialize: %w", err)
	}

	err = aw.Close()
	if err != nil {
		return "", fmt.Errorf("finish armor: %w", err)
	}

	return buf.String(), nil
}

// writeEntity serializes e without re-signing it, so a locked private key
// survives a round trip through the keyring untouched.
func writeEntity(w io.Writer, e *openpgp.Entity) error {
	if e.PrivateKey != nil {
		return e.SerializePrivateWithoutSigning(w, nil)
	}
	return e.Serialize(w)
}
