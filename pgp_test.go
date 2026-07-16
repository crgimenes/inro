package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

const testPassphrase = "correct horse battery staple"

// newTestKey generates a key and returns it armored and locked with
// testPassphrase, the shape a key has when it arrives from gpg.
func newTestKey(t *testing.T, name, email string) string {
	t.Helper()

	cfg := &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA}

	e, err := openpgp.NewEntity(name, "", email, cfg)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}

	err = e.EncryptPrivateKeys([]byte(testPassphrase), cfg)
	if err != nil {
		t.Fatalf("EncryptPrivateKeys: %v", err)
	}

	armored, err := serializeEntity(e)
	if err != nil {
		t.Fatalf("serializeEntity: %v", err)
	}

	return armored
}

// newTestService builds a service over a keyring in a temporary directory,
// holding the two generated keys.
func newTestService(t *testing.T) (*Service, KeyInfo, KeyInfo) {
	t.Helper()

	dir := t.TempDir()

	kr, err := openKeyring(dir, 0)
	if err != nil {
		t.Fatalf("openKeyring: %v", err)
	}

	svc := &Service{cfg: &Config{DataDir: dir}, kr: kr}

	alice, err := svc.ImportKey(newTestKey(t, "Alice", "alice@example.com"))
	if err != nil {
		t.Fatalf("import alice: %v", err)
	}

	bob, err := svc.ImportKey(newTestKey(t, "Bob", "bob@example.com"))
	if err != nil {
		t.Fatalf("import bob: %v", err)
	}

	return svc, alice[0], bob[0]
}

// TestEncryptDecryptRoundTrip covers the main flow: Alice encrypts to Bob and
// signs, Bob opens it and sees a verified signature.
func TestEncryptDecryptRoundTrip(t *testing.T) {
	svc, alice, bob := newTestService(t)

	const message = "meet me at the usual place — açaí, ¥500, 🍣"

	armored, err := svc.Encrypt(EncryptRequest{
		Text:       message,
		Recipients: []string{bob.Fingerprint},
		SignWith:   alice.Fingerprint,
		Passphrase: testPassphrase,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if !strings.Contains(armored, "BEGIN PGP MESSAGE") {
		t.Fatalf("output is not an armored message:\n%s", armored)
	}
	if strings.Contains(armored, message) {
		t.Fatal("plaintext leaked into the encrypted output")
	}

	got, err := svc.Decrypt(DecryptRequest{
		Message:    armored,
		Key:        bob.Fingerprint,
		Passphrase: testPassphrase,
	})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got.Text != message {
		t.Errorf("text = %q, want %q", got.Text, message)
	}
	if !got.Signature.Verified {
		t.Errorf("signature not verified: %+v", got.Signature)
	}
	if !strings.Contains(got.Signature.SignedBy, "Alice") {
		t.Errorf("signedBy = %q, want it to name Alice", got.Signature.SignedBy)
	}
}

// TestDecryptWrongPassphrase makes sure a bad passphrase fails loudly rather
// than returning empty text.
func TestDecryptWrongPassphrase(t *testing.T) {
	svc, _, bob := newTestService(t)

	armored, err := svc.Encrypt(EncryptRequest{
		Text:       "hello",
		Recipients: []string{bob.Fingerprint},
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, err = svc.Decrypt(DecryptRequest{
		Message:    armored,
		Key:        bob.Fingerprint,
		Passphrase: "wrong",
	})
	if err == nil {
		t.Fatal("Decrypt with a wrong passphrase returned no error")
	}
}

// TestSignVerifyRoundTrip covers clear-signing and verification.
func TestSignVerifyRoundTrip(t *testing.T) {
	svc, alice, _ := newTestService(t)

	const message = "I really said this."

	signed, err := svc.Sign(SignRequest{
		Text:       message,
		Key:        alice.Fingerprint,
		Passphrase: testPassphrase,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !strings.Contains(signed, message) {
		t.Fatalf("clear-signed message should stay readable:\n%s", signed)
	}

	got, err := svc.Verify(signed)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !got.Signature.Verified {
		t.Fatalf("signature not verified: %+v", got.Signature)
	}
	if got.Text != message {
		t.Errorf("text = %q, want %q", got.Text, message)
	}
}

// TestVerifyRejectsTamperedMessage is the test that matters: an edited message
// must not come back verified.
func TestVerifyRejectsTamperedMessage(t *testing.T) {
	svc, alice, _ := newTestService(t)

	signed, err := svc.Sign(SignRequest{
		Text:       "pay Alice 100",
		Key:        alice.Fingerprint,
		Passphrase: testPassphrase,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	tampered := strings.Replace(signed, "pay Alice 100", "pay Mallory 900", 1)
	if tampered == signed {
		t.Fatal("test setup failed to tamper with the message")
	}

	got, err := svc.Verify(tampered)
	if err != nil {
		return // rejecting outright is a fine outcome too
	}
	if got.Signature.Verified {
		t.Fatal("a tampered message was reported as verified")
	}
}

// TestVerifyUnknownSigner checks the case where the signature is good but the
// signer is a stranger: it must not be reported as verified.
func TestVerifyUnknownSigner(t *testing.T) {
	svc, alice, _ := newTestService(t)

	signed, err := svc.Sign(SignRequest{
		Text:       "hello",
		Key:        alice.Fingerprint,
		Passphrase: testPassphrase,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	err = svc.DeleteKey(alice.Fingerprint)
	if err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}

	got, err := svc.Verify(signed)
	if err != nil {
		return
	}
	if got.Signature.Verified {
		t.Fatal("a message from an unknown signer was reported as verified")
	}
}

// TestMessageRecipients checks the packet-level recipient listing that drives
// automatic key selection.
func TestMessageRecipients(t *testing.T) {
	svc, _, bob := newTestService(t)

	armored, err := svc.Encrypt(EncryptRequest{
		Text:       "hello",
		Recipients: []string{bob.Fingerprint},
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	ids, symmetric, err := messageRecipients(armored)
	if err != nil {
		t.Fatalf("messageRecipients: %v", err)
	}
	if symmetric {
		t.Error("key-encrypted message reported as symmetric")
	}
	if len(ids) == 0 {
		t.Fatal("no recipient key IDs found")
	}

	// The IDs must map back to Bob and to nobody else.
	candidates := svc.kr.canOpen(ids)
	if len(candidates) != 1 {
		t.Fatalf("canOpen returned %d keys, want 1", len(candidates))
	}
	if fingerprintOf(candidates[0]) != bob.Fingerprint {
		t.Errorf("canOpen picked %s, want Bob %s", fingerprintOf(candidates[0]), bob.Fingerprint)
	}
}

// TestDecryptAutoKey checks that Decrypt finds the right key from the message
// itself when none is named.
func TestDecryptAutoKey(t *testing.T) {
	svc, _, bob := newTestService(t)

	armored, err := svc.Encrypt(EncryptRequest{
		Text:       "auto",
		Recipients: []string{bob.Fingerprint},
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	got, err := svc.Decrypt(DecryptRequest{
		Message:    armored,
		Passphrase: testPassphrase,
	})
	if err != nil {
		t.Fatalf("Decrypt without explicit key: %v", err)
	}
	if got.Text != "auto" {
		t.Errorf("text = %q, want %q", got.Text, "auto")
	}
}

// TestDecryptPassphraseRequired checks the error contract the UI relies on to
// turn a missing passphrase into a prompt instead of a failure.
func TestDecryptPassphraseRequired(t *testing.T) {
	svc, _, bob := newTestService(t)

	armored, err := svc.Encrypt(EncryptRequest{
		Text:       "hello",
		Recipients: []string{bob.Fingerprint},
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, err = svc.Decrypt(DecryptRequest{Message: armored})
	if err == nil {
		t.Fatal("Decrypt of a locked key with no passphrase succeeded")
	}
	if !strings.Contains(err.Error(), "passphrase required") {
		t.Errorf("error = %q, want it to contain %q", err, "passphrase required")
	}
}

// TestKeyCache checks the unlocked-key cache: with a TTL a second operation
// needs no passphrase, without one it does.
func TestKeyCache(t *testing.T) {
	svc, _, bob := newTestService(t)
	svc.kr.cacheTTL = time.Minute

	armored, err := svc.Encrypt(EncryptRequest{
		Text:       "cached",
		Recipients: []string{bob.Fingerprint},
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, err = svc.Decrypt(DecryptRequest{Message: armored, Passphrase: testPassphrase})
	if err != nil {
		t.Fatalf("first Decrypt: %v", err)
	}

	if !svc.kr.isUnlocked(bob.Fingerprint) {
		t.Fatal("key not cached after a successful unlock")
	}

	got, err := svc.Decrypt(DecryptRequest{Message: armored})
	if err != nil {
		t.Fatalf("second Decrypt should use the cache: %v", err)
	}
	if got.Text != "cached" {
		t.Errorf("text = %q, want %q", got.Text, "cached")
	}

	// Expire the entry and the passphrase is needed again.
	svc.kr.mu.Lock()
	u := svc.kr.unlockedKeys[bob.Fingerprint]
	u.expires = time.Now().Add(-time.Second)
	svc.kr.unlockedKeys[bob.Fingerprint] = u
	svc.kr.mu.Unlock()

	_, err = svc.Decrypt(DecryptRequest{Message: armored})
	if err == nil || !strings.Contains(err.Error(), "passphrase required") {
		t.Errorf("after expiry, error = %v, want passphrase required", err)
	}
}

// TestGenerateKey checks the in-app key generation round trip.
func TestGenerateKey(t *testing.T) {
	svc, _, _ := newTestService(t)

	info, err := svc.GenerateKey("Carol", "carol@example.com", "s3cret")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if !info.Private {
		t.Error("generated key is not private")
	}
	if !strings.Contains(info.Identity, "Carol") {
		t.Errorf("identity = %q, want it to name Carol", info.Identity)
	}

	armored, err := svc.Encrypt(EncryptRequest{
		Text:       "to carol",
		Recipients: []string{info.Fingerprint},
	})
	if err != nil {
		t.Fatalf("Encrypt to generated key: %v", err)
	}

	got, err := svc.Decrypt(DecryptRequest{Message: armored, Passphrase: "s3cret"})
	if err != nil {
		t.Fatalf("Decrypt with generated key: %v", err)
	}
	if got.Text != "to carol" {
		t.Errorf("text = %q, want %q", got.Text, "to carol")
	}

	_, err = svc.GenerateKey("", "", "")
	if err == nil {
		t.Error("GenerateKey with empty name and email should fail")
	}
}

// TestDecryptSymmetric checks passphrase-protected messages, which have no
// recipient keys at all.
func TestDecryptSymmetric(t *testing.T) {
	svc, _, _ := newTestService(t)

	var buf bytes.Buffer
	aw, err := armor.Encode(&buf, "PGP MESSAGE", nil)
	if err != nil {
		t.Fatalf("armor: %v", err)
	}
	w, err := openpgp.SymmetricallyEncrypt(aw, []byte("shared secret"), nil, nil)
	if err != nil {
		t.Fatalf("SymmetricallyEncrypt: %v", err)
	}
	_, err = io.WriteString(w, "symmetric hello")
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	err = w.Close()
	if err != nil {
		t.Fatalf("close: %v", err)
	}
	err = aw.Close()
	if err != nil {
		t.Fatalf("close armor: %v", err)
	}
	message := buf.String()

	ids, symmetric, err := messageRecipients(message)
	if err != nil {
		t.Fatalf("messageRecipients: %v", err)
	}
	if !symmetric || len(ids) != 0 {
		t.Fatalf("ids=%v symmetric=%v, want none and true", ids, symmetric)
	}

	got, err := svc.Decrypt(DecryptRequest{Message: message, Passphrase: "shared secret"})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got.Text != "symmetric hello" {
		t.Errorf("text = %q, want %q", got.Text, "symmetric hello")
	}

	_, err = svc.Decrypt(DecryptRequest{Message: message, Passphrase: "wrong"})
	if err == nil {
		t.Error("symmetric decrypt with wrong passphrase succeeded")
	}

	_, err = svc.Decrypt(DecryptRequest{Message: message})
	if err == nil || !strings.Contains(err.Error(), "passphrase required") {
		t.Errorf("no passphrase: error = %v, want passphrase required", err)
	}
}

// TestWhoCanOpen checks the inspection the UI uses to pick keys and decide
// whether to prompt.
func TestWhoCanOpen(t *testing.T) {
	svc, alice, bob := newTestService(t)

	armored, err := svc.Encrypt(EncryptRequest{
		Text:       "x",
		Recipients: []string{bob.Fingerprint},
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	info, err := svc.WhoCanOpen(armored)
	if err != nil {
		t.Fatalf("WhoCanOpen: %v", err)
	}
	if info.Symmetric {
		t.Error("reported symmetric for a key-encrypted message")
	}
	if len(info.Keys) != 1 || info.Keys[0].Fingerprint != bob.Fingerprint {
		t.Fatalf("keys = %+v, want only Bob", info.Keys)
	}
	if !info.Keys[0].Locked {
		t.Error("Bob's key is passphrase-protected and not cached; want Locked=true")
	}
	_ = alice
}
