package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/crgimenes/glaze"
)

// maxMessageFile bounds what Open reads: this app is for short messages, and
// reading a stray multi-gigabyte file into a textarea helps nobody.
const maxMessageFile = 1 << 20

// Service is the API exposed to the UI. Every exported method is bound as a
// JavaScript function named window.inro_<snake_case_method>.
type Service struct {
	cfg *Config
	kr  *Keyring
	w   glaze.WebView
}

// EncryptRequest asks for text encrypted to Recipients. When SignWith holds a
// fingerprint the message is signed too, which needs Passphrase.
type EncryptRequest struct {
	Text       string   `json:"text"`
	Recipients []string `json:"recipients"`
	SignWith   string   `json:"signWith"`
	Passphrase string   `json:"passphrase"`
}

// DecryptRequest asks for Message to be opened. Key may be empty: the message
// itself names its recipients, so the right private key is found from it.
type DecryptRequest struct {
	Message    string `json:"message"`
	Key        string `json:"key"`
	Passphrase string `json:"passphrase"`
}

// SignRequest asks for Text to be clear-signed with the private key Key.
type SignRequest struct {
	Text       string `json:"text"`
	Key        string `json:"key"`
	Passphrase string `json:"passphrase"`
}

// Settings is the slice of the configuration the UI needs.
type Settings struct {
	DefaultKey string `json:"defaultKey"`
}

// OpenCandidate names a private key that can open a given message. Locked
// tells the UI whether a passphrase will be needed right now.
type OpenCandidate struct {
	Fingerprint string `json:"fingerprint"`
	Locked      bool   `json:"locked"`
}

// MessageInfo describes how an encrypted message can be opened.
type MessageInfo struct {
	Symmetric bool            `json:"symmetric"`
	Keys      []OpenCandidate `json:"keys"`
}

// Settings returns the UI-visible configuration.
func (s *Service) Settings() (Settings, error) {
	return Settings{
		DefaultKey: strings.ToUpper(s.cfg.DefaultKey),
	}, nil
}

// AboutInfo is what the About page shows: where this build came from.
type AboutInfo struct {
	Version   string   `json:"version"`
	GoVersion string   `json:"goVersion"`
	Deps      []string `json:"deps"`
}

// About reports the build's own metadata, read from the binary rather than
// hardcoded so it can never lie about a release.
func (s *Service) About() (AboutInfo, error) {
	info := AboutInfo{Version: "unknown"}

	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return info, nil
	}

	info.GoVersion = bi.GoVersion
	if bi.Main.Version != "" {
		info.Version = bi.Main.Version
	}

	var revision, dirty string
	for _, setting := range bi.Settings {
		if setting.Key == "vcs.revision" {
			revision = setting.Value
		}
		if setting.Key == "vcs.modified" && setting.Value == "true" {
			dirty = " (modified)"
		}
	}
	if info.Version == "(devel)" && revision != "" {
		info.Version = revision[:min(12, len(revision))] + dirty
	}

	// The parts of the machine worth crediting on the About page.
	shown := map[string]bool{
		"github.com/ProtonMail/go-crypto": true,
		"github.com/crgimenes/glaze":      true,
		"github.com/crgimenes/filo":       true,
		"github.com/crgimenes/native":     true,
	}
	for _, dep := range bi.Deps {
		if shown[dep.Path] {
			info.Deps = append(info.Deps, fmt.Sprintf("%s %s", dep.Path, dep.Version))
		}
	}

	return info, nil
}

// ListKeys returns every key in the keyring.
func (s *Service) ListKeys() ([]KeyInfo, error) {
	return s.kr.List(), nil
}

// ImportKey adds one or more armored keys to the keyring.
func (s *Service) ImportKey(armored string) ([]KeyInfo, error) {
	if strings.TrimSpace(armored) == "" {
		return nil, errors.New("paste an armored PGP key first")
	}
	return s.kr.Import(armored)
}

// GenerateKey creates a new key pair (EdDSA/Curve25519) and stores it in the
// keyring. An empty passphrase leaves the private key unprotected on disk.
// expiryDays of zero means the key never expires.
func (s *Service) GenerateKey(name, email, passphrase string, expiryDays int) (KeyInfo, error) {
	name = strings.TrimSpace(name)
	email = strings.TrimSpace(email)
	if name == "" || email == "" {
		return KeyInfo{}, errors.New("name and email are required")
	}
	if expiryDays < 0 || expiryDays > 36500 {
		return KeyInfo{}, errors.New("expiry must be between 0 (never) and 36500 days")
	}

	cfg := &packet.Config{
		Algorithm:       packet.PubKeyAlgoEdDSA,
		KeyLifetimeSecs: uint32(expiryDays) * 86400,
	}

	e, err := openpgp.NewEntity(name, "", email, cfg)
	if err != nil {
		return KeyInfo{}, fmt.Errorf("generate key: %w", err)
	}

	if passphrase != "" {
		err = e.EncryptPrivateKeys([]byte(passphrase), cfg)
		if err != nil {
			return KeyInfo{}, fmt.Errorf("protect key: %w", err)
		}
	}

	armored, err := serializeEntity(e)
	if err != nil {
		return KeyInfo{}, fmt.Errorf("serialize key: %w", err)
	}

	infos, err := s.kr.Import(armored)
	if err != nil {
		return KeyInfo{}, err
	}
	return infos[0], nil
}

// CertifyKey signs the target key's identity with one of the user's own keys
// — the "I checked, this key really belongs to this person" statement of the
// web of trust. The certification is stored on the target key, so exporting
// that key carries it along.
func (s *Service) CertifyKey(fingerprint, signWith, passphrase string) error {
	fingerprint = strings.ToUpper(strings.TrimSpace(fingerprint))
	signWith = strings.ToUpper(strings.TrimSpace(signWith))
	if fingerprint == signWith {
		return errors.New("a key cannot certify itself")
	}

	signer, err := s.kr.unlocked(signWith, passphrase)
	if err != nil {
		return err
	}

	// Work on a fresh copy so a failed signing never leaves a half-mutated
	// entity in the shared cache.
	target, err := s.kr.loadEntityFile(fingerprint)
	if err != nil {
		return err
	}

	err = target.SignIdentity(primaryIdentity(target), signer, nil)
	if err != nil {
		return fmt.Errorf("certify: %w", err)
	}

	return s.kr.store(target)
}

// ExportKey returns the armored public key for a fingerprint.
func (s *Service) ExportKey(fingerprint string) (string, error) {
	return s.kr.Export(fingerprint)
}

// ExportPrivateKey returns the armored private key block as stored on disk,
// still locked by the key's own passphrase. Sensitive either way: the UI only
// offers it behind an explicit action on the key's page.
func (s *Service) ExportPrivateKey(fingerprint string) (string, error) {
	return s.kr.ExportPrivate(fingerprint)
}

// DeleteKey removes a key from the keyring.
func (s *Service) DeleteKey(fingerprint string) error {
	return s.kr.Delete(fingerprint)
}

// SetKeyMeta attaches a nickname and a note to a key.
func (s *Service) SetKeyMeta(fingerprint, nickname, note string) error {
	return s.kr.SetMeta(fingerprint, nickname, note)
}

// WhoCanOpen inspects an encrypted message and reports which of the user's
// private keys can open it, without decrypting anything. The UI uses this to
// pick the key by itself and to only ask for a passphrase when one is needed.
func (s *Service) WhoCanOpen(message string) (MessageInfo, error) {
	ids, symmetric, err := messageRecipients(message)
	if err != nil {
		return MessageInfo{}, err
	}

	// Keys starts non-nil so the UI always receives a JSON array, never null.
	info := MessageInfo{Symmetric: symmetric, Keys: []OpenCandidate{}}
	for _, e := range s.kr.canOpen(ids) {
		fp := fingerprintOf(e)
		info.Keys = append(info.Keys, OpenCandidate{
			Fingerprint: fp,
			Locked:      e.PrivateKey.Encrypted && !s.kr.isUnlocked(fp),
		})
	}

	return info, nil
}

// Encrypt encrypts a message to the requested recipients.
func (s *Service) Encrypt(req EncryptRequest) (string, error) {
	if strings.TrimSpace(req.Text) == "" {
		return "", errors.New("nothing to encrypt")
	}

	to, err := s.kr.entitiesFor(req.Recipients)
	if err != nil {
		return "", err
	}

	if req.SignWith == "" {
		return encryptMessage(req.Text, to, nil)
	}

	signer, err := s.kr.unlocked(req.SignWith, req.Passphrase)
	if err != nil {
		return "", err
	}

	return encryptMessage(req.Text, to, signer)
}

// Decrypt opens an encrypted message and reports on any signature it carries.
// When req.Key is empty the key is chosen from the message's own recipient
// list.
func (s *Service) Decrypt(req DecryptRequest) (Decrypted, error) {
	if strings.TrimSpace(req.Message) == "" {
		return Decrypted{}, errors.New("paste an encrypted message first")
	}

	ids, symmetric, err := messageRecipients(req.Message)
	if err != nil {
		return Decrypted{}, err
	}

	if len(ids) == 0 && symmetric {
		return s.decryptSymmetric(req)
	}

	fp := req.Key
	if fp == "" {
		candidates := s.kr.canOpen(ids)
		if len(candidates) == 0 {
			return Decrypted{}, errors.New("this message is not encrypted to any key in your keyring")
		}
		fp = fingerprintOf(candidates[0])
	}

	e, err := s.kr.unlocked(fp, req.Passphrase)
	if err != nil {
		return Decrypted{}, err
	}

	return decryptMessage(req.Message, s.ringWith(e), nil)
}

// decryptSymmetric opens a message protected by a passphrase instead of a
// key. The keyring is still passed along so an embedded signature can be
// verified.
func (s *Service) decryptSymmetric(req DecryptRequest) (Decrypted, error) {
	if req.Passphrase == "" {
		return Decrypted{}, errors.New("passphrase required: this message is protected by a passphrase, not a key")
	}

	// ReadMessage retries the prompt forever on a wrong passphrase, so the
	// second call reports failure instead of looping.
	attempts := 0
	prompt := func(_ []openpgp.Key, symmetric bool) ([]byte, error) {
		if !symmetric {
			return nil, errors.New("message needs a private key this keyring does not have")
		}
		attempts++
		if attempts > 1 {
			return nil, errors.New("wrong passphrase")
		}
		return []byte(req.Passphrase), nil
	}

	return decryptMessage(req.Message, s.kr.publicList(), prompt)
}

// Sign clear-signs a message, leaving it readable.
func (s *Service) Sign(req SignRequest) (string, error) {
	if strings.TrimSpace(req.Text) == "" {
		return "", errors.New("nothing to sign")
	}

	signer, err := s.kr.unlocked(req.Key, req.Passphrase)
	if err != nil {
		return "", err
	}

	return clearSignMessage(req.Text, signer)
}

// Verify checks a clear-signed message against the keyring.
func (s *Service) Verify(message string) (Decrypted, error) {
	if strings.TrimSpace(message) == "" {
		return Decrypted{}, errors.New("paste a signed message first")
	}
	return verifyMessage(message, s.kr.publicList())
}

// OpenTextFile shows the native open dialog and returns the chosen file's
// content, or "" when the user cancels.
func (s *Service) OpenTextFile() (string, error) {
	if s.w == nil {
		return "", errors.New("no window")
	}

	path, err := s.w.OpenFile(glaze.FileDialogOptions{Title: "Open message"})
	if err != nil || path == "" {
		return "", err
	}

	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("open %q: %w", path, err)
	}
	if info.Size() > maxMessageFile {
		return "", fmt.Errorf("%q is too large to be a message (%d MB)", filepath.Base(path), info.Size()>>20)
	}

	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("read %q: %w", path, err)
	}

	return strings.TrimPrefix(string(b), "\uFEFF"), nil
}

// SaveTextFile shows the native save dialog and writes content to the chosen
// path, suggesting filename. Returns the path, or "" when the user cancels.
func (s *Service) SaveTextFile(content, filename string) (string, error) {
	if s.w == nil {
		return "", errors.New("no window")
	}
	if filename == "" {
		filename = "message.asc"
	}

	path, err := s.w.SaveFile(glaze.FileDialogOptions{
		Title:    "Save",
		Filename: filename,
	})
	if err != nil || path == "" {
		return "", err
	}

	err = os.WriteFile(path, []byte(content), 0o600)
	if err != nil {
		return "", fmt.Errorf("write %q: %w", path, err)
	}

	return path, nil
}

// ringWith puts the unlocked entity in front of the rest of the keyring,
// leaving out the cached locked copy of that same key so that decryption never
// picks the copy it cannot open.
func (s *Service) ringWith(e *openpgp.Entity) openpgp.EntityList {
	fp := fingerprintOf(e)

	ring := openpgp.EntityList{e}
	for _, other := range s.kr.publicList() {
		if fingerprintOf(other) == fp {
			continue
		}
		ring = append(ring, other)
	}

	return ring
}
