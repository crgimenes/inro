package main

import (
	"bytes"
	"encoding/json"
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

	info, err := svc.GenerateKey("Carol", "carol@example.com", "s3cret", 0)
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

	_, err = svc.GenerateKey("", "", "", 0)
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

// TestGenerateKeyExpiry checks that an expiry lands on the self-signature and
// surfaces in the key listing.
func TestGenerateKeyExpiry(t *testing.T) {
	svc, _, _ := newTestService(t)

	info, err := svc.GenerateKey("Dave", "dave@example.com", "", 365)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if info.Fingerprint == "" {
		t.Fatal("no fingerprint returned")
	}

	var listed KeyInfo
	for _, k := range svc.kr.List() {
		if k.Fingerprint == info.Fingerprint {
			listed = k
		}
	}
	if listed.Expires == "" {
		t.Fatal("key generated with expiry lists no expiry date")
	}
	want := time.Now().AddDate(0, 0, 365).Format("2006-01-02")
	if listed.Expires != want {
		t.Errorf("expires = %q, want %q", listed.Expires, want)
	}

	forever, err := svc.GenerateKey("Eve", "eve@example.com", "", 0)
	if err != nil {
		t.Fatalf("GenerateKey without expiry: %v", err)
	}
	for _, k := range svc.kr.List() {
		if k.Fingerprint == forever.Fingerprint && k.Expires != "" {
			t.Errorf("key without expiry lists %q", k.Expires)
		}
	}

	_, err = svc.GenerateKey("F", "f@example.com", "", -1)
	if err == nil {
		t.Error("negative expiry accepted")
	}
}

// TestCertifyKey covers the web-of-trust flow: Alice certifies Bob's key, the
// certification is listed, survives a reopen, and travels with the export.
func TestCertifyKey(t *testing.T) {
	svc, alice, bob := newTestService(t)

	err := svc.CertifyKey(bob.Fingerprint, alice.Fingerprint, testPassphrase)
	if err != nil {
		t.Fatalf("CertifyKey: %v", err)
	}

	certifiers := func(list []KeyInfo, fp string) []string {
		for _, k := range list {
			if k.Fingerprint == fp {
				return k.CertifiedBy
			}
		}
		return nil
	}

	got := certifiers(svc.kr.List(), bob.Fingerprint)
	if len(got) != 1 || !strings.Contains(got[0], "Alice") {
		t.Fatalf("CertifiedBy = %v, want Alice", got)
	}

	// The certification must be on disk, not only in memory.
	reopened, err := openKeyring(svc.cfg.DataDir, 0)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got = certifiers(reopened.List(), bob.Fingerprint)
	if len(got) != 1 || !strings.Contains(got[0], "Alice") {
		t.Fatalf("after reopen, CertifiedBy = %v, want Alice", got)
	}

	// And it travels with the exported public key.
	exported, err := svc.ExportKey(bob.Fingerprint)
	if err != nil {
		t.Fatalf("ExportKey: %v", err)
	}
	other, err := openKeyring(t.TempDir(), 0)
	if err != nil {
		t.Fatalf("second keyring: %v", err)
	}
	_, err = other.Import(exported)
	if err != nil {
		t.Fatalf("import exported bob: %v", err)
	}
	_, err = other.Import(newTestKey(t, "Alice", "alice@example.com"))
	if err != nil {
		t.Fatalf("import fresh alice: %v", err)
	}
	// The second keyring has a DIFFERENT Alice key, so the certification must
	// NOT verify there: vouching is per key, not per name.
	got = certifiers(other.List(), bob.Fingerprint)
	if len(got) != 0 {
		t.Errorf("certification verified against an unrelated key: %v", got)
	}

	err = svc.CertifyKey(bob.Fingerprint, bob.Fingerprint, testPassphrase)
	if err == nil {
		t.Error("a key certified itself")
	}

	err = svc.CertifyKey(bob.Fingerprint, alice.Fingerprint, "wrong")
	if err == nil {
		t.Error("certify with wrong passphrase succeeded")
	}
}

// TestServiceSurface covers the thin UI-facing service methods: the settings
// slice, the listing, the metadata write path and the About metadata.
func TestServiceSurface(t *testing.T) {
	svc, alice, _ := newTestService(t)
	svc.cfg.DefaultKey = strings.ToLower(alice.Fingerprint)

	settings, err := svc.Settings()
	if err != nil {
		t.Fatalf("Settings: %v", err)
	}
	if settings.DefaultKey != alice.Fingerprint {
		t.Errorf("DefaultKey = %q, want %q upper-cased", settings.DefaultKey, alice.Fingerprint)
	}

	err = svc.SetKeyMeta(alice.Fingerprint, "me", "my own key")
	if err != nil {
		t.Fatalf("SetKeyMeta: %v", err)
	}

	list, err := svc.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("got %d keys, want 2", len(list))
	}
	found := false
	for _, k := range list {
		if k.Fingerprint == alice.Fingerprint && k.Nickname == "me" {
			found = true
		}
	}
	if !found {
		t.Error("nickname set through the service did not surface in the listing")
	}

	about, err := svc.About()
	if err != nil {
		t.Fatalf("About: %v", err)
	}
	if about.Version == "" || about.GoVersion == "" {
		t.Errorf("about = %+v, want version and go version filled", about)
	}
	foundDep := false
	for _, dep := range about.Deps {
		if strings.Contains(dep, "go-crypto") {
			foundDep = true
		}
	}
	if !foundDep {
		t.Errorf("deps = %v, want go-crypto listed", about.Deps)
	}
}

// TestExpiredKeyIsFlagged checks that an expired key is reported as such in
// the listing, since the UI marks it and blocks selecting it.
func TestExpiredKeyIsFlagged(t *testing.T) {
	svc, alice, _ := newTestService(t)

	past := time.Now().Add(-48 * time.Hour)
	cfg := &packet.Config{
		Algorithm:       packet.PubKeyAlgoEdDSA,
		Time:            func() time.Time { return past },
		KeyLifetimeSecs: 86400, // one day: expired yesterday
	}

	e, err := openpgp.NewEntity("Old", "", "old@example.com", cfg)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	armored, err := serializeEntity(e)
	if err != nil {
		t.Fatalf("serializeEntity: %v", err)
	}
	imported, err := svc.ImportKey(armored)
	if err != nil {
		t.Fatalf("ImportKey: %v", err)
	}

	var old, fresh KeyInfo
	for _, k := range svc.kr.List() {
		if k.Fingerprint == imported[0].Fingerprint {
			old = k
		}
		if k.Fingerprint == alice.Fingerprint {
			fresh = k
		}
	}

	if !old.Expired {
		t.Errorf("key that expired yesterday is not flagged: %+v", old)
	}
	if old.Expires == "" {
		t.Error("expired key lists no expiry date")
	}
	if fresh.Expired {
		t.Errorf("key without expiry is flagged as expired: %+v", fresh)
	}
}

// TestImportDoesNotDowngradePrivate reproduces the gpg migration sequence
// that bit in practice: import your own private key, then a contacts file
// that also carries your public key. The private part must survive, and a
// certification arriving on the public copy must still land.
func TestImportDoesNotDowngradePrivate(t *testing.T) {
	svc, alice, bob := newTestService(t)

	err := svc.CertifyKey(bob.Fingerprint, alice.Fingerprint, testPassphrase)
	if err != nil {
		t.Fatalf("CertifyKey: %v", err)
	}

	// The public export carries the certification; importing it back over the
	// private copy is the contacts.asc scenario.
	pub, err := svc.ExportKey(bob.Fingerprint)
	if err != nil {
		t.Fatalf("ExportKey: %v", err)
	}
	_, err = svc.ImportKey(pub)
	if err != nil {
		t.Fatalf("re-import public copy: %v", err)
	}

	var got KeyInfo
	for _, k := range svc.kr.List() {
		if k.Fingerprint == bob.Fingerprint {
			got = k
		}
	}
	if !got.Private {
		t.Fatal("importing the public copy downgraded the stored private key")
	}
	if len(got.CertifiedBy) == 0 {
		t.Error("certification lost after re-importing the public copy")
	}

	// The key must still decrypt, proving the private material on disk.
	armored, err := svc.Encrypt(EncryptRequest{Text: "still private", Recipients: []string{bob.Fingerprint}})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	dec, err := svc.Decrypt(DecryptRequest{Message: armored, Passphrase: testPassphrase})
	if err != nil {
		t.Fatalf("Decrypt after re-import: %v", err)
	}
	if dec.Text != "still private" {
		t.Errorf("text = %q", dec.Text)
	}
}

// TestExportPrivateKey covers the private-key export and its refusal for
// keys that have no private part.
func TestExportPrivateKey(t *testing.T) {
	svc, alice, _ := newTestService(t)

	armored, err := svc.ExportPrivateKey(alice.Fingerprint)
	if err != nil {
		t.Fatalf("ExportPrivateKey: %v", err)
	}
	if !strings.Contains(armored, "BEGIN PGP PRIVATE KEY BLOCK") {
		t.Errorf("export is not a private key block:\n%.80s", armored)
	}

	// A public-only key must refuse: generate, export public, delete, re-import.
	carol, err := svc.GenerateKey("Carol", "carol@example.com", "", 0)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub, err := svc.ExportKey(carol.Fingerprint)
	if err != nil {
		t.Fatalf("ExportKey: %v", err)
	}
	err = svc.DeleteKey(carol.Fingerprint)
	if err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}
	_, err = svc.ImportKey(pub)
	if err != nil {
		t.Fatalf("ImportKey: %v", err)
	}
	_, err = svc.ExportPrivateKey(carol.Fingerprint)
	if err == nil {
		t.Fatal("exported a private block for a public-only key")
	}
}

// TestWhoCanOpenEmitsEmptyKeysArray pins the JSON contract with the UI: a
// message no key of ours can open must serialize keys as [], never null,
// which crashed the front end in the field.
func TestWhoCanOpenEmitsEmptyKeysArray(t *testing.T) {
	svc, _, _ := newTestService(t)

	stranger, err := openpgp.NewEntity("Stranger", "", "s@example.com",
		&packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}

	var buf bytes.Buffer
	aw, err := armor.Encode(&buf, "PGP MESSAGE", nil)
	if err != nil {
		t.Fatalf("armor: %v", err)
	}
	w, err := openpgp.Encrypt(aw, []*openpgp.Entity{stranger}, nil, nil, nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	_, _ = io.WriteString(w, "not for us")
	_ = w.Close()
	_ = aw.Close()

	info, err := svc.WhoCanOpen(buf.String())
	if err != nil {
		t.Fatalf("WhoCanOpen: %v", err)
	}

	b, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"keys":[]`) {
		t.Errorf("json = %s, want keys serialized as an empty array", b)
	}
}
