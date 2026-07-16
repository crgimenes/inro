package main

import (
	"fmt"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
)

// Service is the API exposed to the UI. Every exported method is bound as a
// JavaScript function named window.inro_<snake_case_method>.
type Service struct {
	cfg *Config
	kr  *Keyring
}

// EncryptRequest asks for text encrypted to Recipients. When SignWith holds a
// fingerprint the message is signed too, which needs Passphrase.
type EncryptRequest struct {
	Text       string   `json:"text"`
	Recipients []string `json:"recipients"`
	SignWith   string   `json:"signWith"`
	Passphrase string   `json:"passphrase"`
}

// DecryptRequest asks for Message to be opened with the private key Key.
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
func (s *Service) Decrypt(req DecryptRequest) (Decrypted, error) {
	if strings.TrimSpace(req.Message) == "" {
		return Decrypted{}, fmt.Errorf("paste an encrypted message first")
	}

	e, err := s.kr.unlocked(req.Key, req.Passphrase)
	if err != nil {
		return Decrypted{}, err
	}

	return decryptMessage(req.Message, s.ringWith(e))
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
