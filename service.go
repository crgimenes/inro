package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	DataDir    string `json:"dataDir"`
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
		DataDir:    s.cfg.DataDir,
	}, nil
}

// ListKeys returns every key in the keyring.
func (s *Service) ListKeys() ([]KeyInfo, error) {
	return s.kr.List(), nil
}

// ImportKey adds one or more armored keys to the keyring.
func (s *Service) ImportKey(armored string) ([]KeyInfo, error) {
	if strings.TrimSpace(armored) == "" {
		return nil, fmt.Errorf("paste an armored PGP key first")
	}
	return s.kr.Import(armored)
}

// GenerateKey creates a new key pair (EdDSA/Curve25519) and stores it in the
// keyring. An empty passphrase leaves the private key unprotected on disk.
func (s *Service) GenerateKey(name, email, passphrase string) (KeyInfo, error) {
	name = strings.TrimSpace(name)
	email = strings.TrimSpace(email)
	if name == "" || email == "" {
		return KeyInfo{}, errors.New("name and email are required")
	}

	cfg := &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA}

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

// ExportKey returns the armored public key for a fingerprint.
func (s *Service) ExportKey(fingerprint string) (string, error) {
	return s.kr.Export(fingerprint)
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

	info := MessageInfo{Symmetric: symmetric}
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
		return "", fmt.Errorf("nothing to encrypt")
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
		return Decrypted{}, fmt.Errorf("paste an encrypted message first")
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
		return "", fmt.Errorf("nothing to sign")
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
		return Decrypted{}, fmt.Errorf("paste a signed message first")
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
// path. Returns the path, or "" when the user cancels.
func (s *Service) SaveTextFile(content string) (string, error) {
	if s.w == nil {
		return "", errors.New("no window")
	}

	path, err := s.w.SaveFile(glaze.FileDialogOptions{
		Title:    "Save message",
		Filename: "message.asc",
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
