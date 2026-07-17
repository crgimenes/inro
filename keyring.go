package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

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
	Fingerprint string   `json:"fingerprint"`
	KeyID       string   `json:"keyId"`
	Identity    string   `json:"identity"`
	Nickname    string   `json:"nickname"`
	Note        string   `json:"note"`
	Private     bool     `json:"private"`
	Created     string   `json:"created"`
	Expires     string   `json:"expires"`
	Expired     bool     `json:"expired"`
	CertifiedBy []string `json:"certifiedBy"`
}

// Keyring is the on-disk key collection: one armored file per key under
// <dir>/keys, plus <dir>/keyring.filo with the local metadata.
//
// The entities loaded from disk are never unlocked. Operations needing private
// key material go through unlocked(), which reads a fresh copy and unlocks
// that. A successful unlock is remembered in memory for cacheTTL (the
// KeyCacheSeconds setting) so the next operations skip the passphrase; the
// passphrase itself is never kept anywhere.
type Keyring struct {
	mu           sync.RWMutex
	dir          string
	cacheTTL     time.Duration
	entities     map[string]*openpgp.Entity
	meta         map[string]KeyMeta
	unlockedKeys map[string]unlockedKey
}

type unlockedKey struct {
	e       *openpgp.Entity
	expires time.Time
}

// openKeyring loads the keyring from dir, creating the directory tree on
// first run. cacheTTL is how long an unlocked key stays usable without its
// passphrase; zero disables the cache.
func openKeyring(dir string, cacheTTL time.Duration) (*Keyring, error) {
	k := &Keyring{
		dir:          dir,
		cacheTTL:     cacheTTL,
		entities:     map[string]*openpgp.Entity{},
		meta:         map[string]KeyMeta{},
		unlockedKeys: map[string]unlockedKey{},
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
			return filo.VBool(false), errors.New("key: fingerprint is required")
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
		expires, expired := expiryOf(e)
		keys = append(keys, KeyInfo{
			Fingerprint: fp,
			KeyID:       e.PrimaryKey.KeyIdString(),
			Identity:    primaryIdentity(e),
			Nickname:    k.meta[fp].Nickname,
			Note:        k.meta[fp].Note,
			Private:     e.PrivateKey != nil,
			Created:     e.PrimaryKey.CreationTime.Format("2006-01-02"),
			Expires:     expires,
			Expired:     expired,
			CertifiedBy: k.certifiedByLocked(e),
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
		return nil, errors.New("no keys found in that text")
	}

	imported := make([]KeyInfo, 0, len(el))
	for _, e := range el {
		err = k.store(e)
		if err != nil {
			return nil, err
		}

		imported = append(imported, KeyInfo{
			Fingerprint: fingerprintOf(e),
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
	delete(k.unlockedKeys, fingerprint)

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

// unlocked returns a usable private key: the cached unlocked copy when there
// is a fresh one, otherwise a copy re-read from disk and unlocked with the
// passphrase. The "passphrase required" error text is a contract with the UI,
// which turns it into a passphrase prompt instead of a failure.
func (k *Keyring) unlocked(fingerprint, passphrase string) (*openpgp.Entity, error) {
	fingerprint = strings.ToUpper(strings.TrimSpace(fingerprint))

	e := k.cachedUnlocked(fingerprint)
	if e != nil {
		return e, nil
	}

	e, err := k.loadEntityFile(fingerprint)
	if err != nil {
		return nil, err
	}

	if e.PrivateKey == nil {
		return nil, fmt.Errorf("key %s has no private part", fingerprint)
	}
	if e.PrivateKey.Encrypted && passphrase == "" {
		return nil, fmt.Errorf("passphrase required to unlock %s", primaryIdentity(e))
	}

	err = unlock(e, passphrase)
	if err != nil {
		return nil, err
	}

	k.rememberUnlocked(fingerprint, e)
	return e, nil
}

// cachedUnlocked returns the unlocked entity for fingerprint if the cache
// holds a fresh one. The entity is shared between operations for its lifetime;
// signing and decrypting only read from it, and the UI drives one operation at
// a time.
func (k *Keyring) cachedUnlocked(fingerprint string) *openpgp.Entity {
	k.mu.Lock()
	defer k.mu.Unlock()

	u, ok := k.unlockedKeys[fingerprint]
	if !ok {
		return nil
	}
	if time.Now().After(u.expires) {
		delete(k.unlockedKeys, fingerprint)
		return nil
	}
	return u.e
}

func (k *Keyring) rememberUnlocked(fingerprint string, e *openpgp.Entity) {
	if k.cacheTTL <= 0 {
		return
	}

	k.mu.Lock()
	defer k.mu.Unlock()
	k.unlockedKeys[fingerprint] = unlockedKey{e: e, expires: time.Now().Add(k.cacheTTL)}
}

// isUnlocked reports whether the key currently has a fresh cached unlock, so
// the UI can skip asking for a passphrase it does not need.
func (k *Keyring) isUnlocked(fingerprint string) bool {
	return k.cachedUnlocked(strings.ToUpper(strings.TrimSpace(fingerprint))) != nil
}

// canOpen returns the private keys able to open a message addressed to ids,
// sorted by identity so "pick the first" is deterministic. A wildcard id
// (0, anonymous recipient) matches every private key.
func (k *Keyring) canOpen(ids []uint64) []*openpgp.Entity {
	k.mu.RLock()
	defer k.mu.RUnlock()

	wildcard := slices.Contains(ids, 0)

	var out []*openpgp.Entity
	for _, e := range k.entities {
		if e.PrivateKey == nil {
			continue
		}
		if wildcard || matchesAnyKeyID(e, ids) {
			out = append(out, e)
		}
	}

	slices.SortFunc(out, func(a, b *openpgp.Entity) int {
		return strings.Compare(primaryIdentity(a), primaryIdentity(b))
	})

	return out
}

// expiryOf returns the primary key's expiry date ("" for a key that never
// expires) and whether that date has already passed.
func expiryOf(e *openpgp.Entity) (string, bool) {
	selfSig, _ := e.PrimarySelfSignature()
	if selfSig == nil || selfSig.KeyLifetimeSecs == nil || *selfSig.KeyLifetimeSecs == 0 {
		return "", false
	}
	t := e.PrimaryKey.CreationTime.Add(time.Duration(*selfSig.KeyLifetimeSecs) * time.Second)
	return t.Format("2006-01-02"), time.Now().After(t)
}

// certifiedByLocked lists who vouches for this key: the identities of keyring
// keys whose certification signature on e's primary identity actually
// verifies. Signatures from unknown keys are not shown — an unverifiable
// claim is noise, not assurance. Callers must hold at least a read lock.
func (k *Keyring) certifiedByLocked(e *openpgp.Entity) []string {
	_, ident := e.PrimarySelfSignature()
	if ident == nil {
		return nil
	}

	var out []string
	for _, sig := range ident.Signatures {
		if sig.IssuerKeyId == nil || *sig.IssuerKeyId == e.PrimaryKey.KeyId {
			continue
		}

		for _, issuer := range k.entities {
			if issuer.PrimaryKey.KeyId != *sig.IssuerKeyId {
				continue
			}
			err := issuer.PrimaryKey.VerifyUserIdSignature(ident.Name, e.PrimaryKey, sig)
			if err == nil {
				out = append(out, primaryIdentity(issuer))
			}
			break
		}
	}

	slices.Sort(out)
	return slices.Compact(out)
}

// loadEntityFile reads one key's fresh copy from disk, so callers can unlock
// or extend it without touching the shared cached entity.
func (k *Keyring) loadEntityFile(fingerprint string) (*openpgp.Entity, error) {
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
	return el[0], nil
}

// store persists an entity to its .asc file and makes it the current
// in-memory copy.
func (k *Keyring) store(e *openpgp.Entity) error {
	fp := fingerprintOf(e)

	text, err := serializeEntity(e)
	if err != nil {
		return fmt.Errorf("serialize key %s: %w", fp, err)
	}

	err = os.WriteFile(k.keyPath(fp), []byte(text), 0o600)
	if err != nil {
		return fmt.Errorf("write key %s: %w", fp, err)
	}

	k.mu.Lock()
	k.entities[fp] = e
	k.mu.Unlock()

	return nil
}

func matchesAnyKeyID(e *openpgp.Entity, ids []uint64) bool {
	for _, id := range ids {
		if id == 0 {
			continue
		}
		if e.PrimaryKey.KeyId == id {
			return true
		}
		for _, sub := range e.Subkeys {
			if sub.PublicKey.KeyId == id {
				return true
			}
		}
	}
	return false
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
