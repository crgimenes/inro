package main

import (
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
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

	kr, err := openKeyring(dir)
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
