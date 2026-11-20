package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// Signature reports what could be established about the signature carried by a
// message. Verified is only true when the signature checks out against a key
// present in the keyring.
type Signature struct {
	Signed   bool   `json:"signed"`
	Verified bool   `json:"verified"`
	SignedBy string `json:"signedBy"`
	KeyID    string `json:"keyId"`
	Reason   string `json:"reason"`
}

// Decrypted is the result of opening an encrypted message.
type Decrypted struct {
	Text      string    `json:"text"`
	Signature Signature `json:"signature"`
}

// encryptMessage encrypts text to the given recipients, signing it with signer
// when signer is not nil. The result is an ASCII-armored PGP message.
func encryptMessage(text string, to []*openpgp.Entity, signer *openpgp.Entity) (string, error) {
	if len(to) == 0 {
		return "", errors.New("no recipients selected")
	}

	var buf bytes.Buffer
	aw, err := armor.Encode(&buf, "PGP MESSAGE", nil)
	if err != nil {
		return "", fmt.Errorf("armor: %w", err)
	}

	w, err := openpgp.Encrypt(aw, to, signer, nil, nil)
	if err != nil {
		return "", fmt.Errorf("encrypt: %w", err)
	}

	_, err = io.WriteString(w, text)
	if err != nil {
		return "", fmt.Errorf("write plaintext: %w", err)
	}

	err = w.Close()
	if err != nil {
		return "", fmt.Errorf("finish message: %w", err)
	}

	err = aw.Close()
	if err != nil {
		return "", fmt.Errorf("finish armor: %w", err)
	}

	return buf.String(), nil
}

// messageRecipients lists the key IDs an armored encrypted message is
// addressed to, and whether it can also (or only) be opened with a passphrase.
// It reads the session-key packets at the head of the message, so no key
// material is needed. An ID of 0 means an anonymous recipient.
func messageRecipients(message string) (ids []uint64, symmetric bool, err error) {
	block, err := armor.Decode(strings.NewReader(message))
	if err != nil {
		return nil, false, fmt.Errorf("not an armored PGP message: %w", err)
	}

	packets := packet.NewReader(block.Body)
	for {
		p, err := packets.Next()
		if err != nil {
			// EOF or a packet we cannot parse; the session-key packets a valid
			// message starts with have been consumed by now either way.
			return ids, symmetric, nil
		}

		switch pkt := p.(type) {
		case *packet.EncryptedKey:
			ids = append(ids, pkt.KeyId)
		case *packet.SymmetricKeyEncrypted:
			symmetric = true
		default:
			// First non-session-key packet: the encrypted payload itself.
			return ids, symmetric, nil
		}
	}
}

// decryptMessage opens an armored PGP message. The keyring must hold the
// unlocked private key the message was encrypted to; any public keys it also
// holds are used to verify an embedded signature. prompt is only consulted for
// passphrase-protected (symmetric) messages and may be nil.
func decryptMessage(message string, keyring openpgp.EntityList, prompt openpgp.PromptFunction) (Decrypted, error) {
	block, err := armor.Decode(strings.NewReader(message))
	if err != nil {
		return Decrypted{}, fmt.Errorf("not an armored PGP message: %w", err)
	}

	md, err := openpgp.ReadMessage(block.Body, keyring, prompt, nil)
	if err != nil {
		return Decrypted{}, fmt.Errorf("decrypt: %w", err)
	}

	// The signature (and the AEAD authentication tag) can only be checked once
	// the body has been read to EOF, so the plaintext is not trustworthy before
	// this call returns.
	body, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return Decrypted{}, fmt.Errorf("read message body: %w", err)
	}

	return Decrypted{
		Text:      string(body),
		Signature: signatureOf(md),
	}, nil
}

// signatureOf describes the signature state of a message whose body has
// already been consumed to EOF.
func signatureOf(md *openpgp.MessageDetails) Signature {
	if !md.IsSigned {
		return Signature{}
	}

	sig := Signature{
		Signed: true,
		KeyID:  fmt.Sprintf("%016X", md.SignedByKeyId),
	}

	if md.SignedBy == nil {
		sig.Reason = "signer key is not in your keyring"
		return sig
	}

	sig.SignedBy = primaryIdentity(md.SignedBy.Entity)

	if md.SignatureError != nil {
		sig.Reason = md.SignatureError.Error()
		return sig
	}

	sig.Verified = true
	return sig
}

// clearSignMessage wraps text in a clear-signed PGP block: the message stays
// readable and carries its own signature, which suits short messages meant to
// be pasted somewhere. signer must be unlocked.
func clearSignMessage(text string, signer *openpgp.Entity) (string, error) {
	key, ok := signer.SigningKey(time.Now())
	if !ok {
		return "", errors.New("key has no usable signing key")
	}
	if key.PrivateKey == nil {
		return "", errors.New("key has no private part")
	}

	var buf bytes.Buffer
	w, err := clearsign.Encode(&buf, key.PrivateKey, nil)
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}

	_, err = io.WriteString(w, text)
	if err != nil {
		return "", fmt.Errorf("write message: %w", err)
	}

	err = w.Close()
	if err != nil {
		return "", fmt.Errorf("finish signature: %w", err)
	}

	return buf.String(), nil
}

// verifyMessage checks a clear-signed message against the keyring and returns
// the signed text alongside the outcome.
func verifyMessage(message string, keyring openpgp.EntityList) (Decrypted, error) {
	block, _ := clearsign.Decode([]byte(message))
	if block == nil {
		return Decrypted{}, errors.New("not a clear-signed PGP message")
	}

	text := string(block.Plaintext)

	signer, err := openpgp.CheckDetachedSignature(
		keyring,
		bytes.NewReader(block.Bytes),
		block.ArmoredSignature.Body,
		nil,
	)
	if err != nil {
		return Decrypted{
			Text: text,
			Signature: Signature{
				Signed: true,
				Reason: err.Error(),
			},
		}, nil
	}

	return Decrypted{
		Text: text,
		Signature: Signature{
			Signed:   true,
			Verified: true,
			SignedBy: primaryIdentity(signer),
			KeyID:    signer.PrimaryKey.KeyIdString(),
		},
	}, nil
}

// unlock decrypts the private key material of e in place, so e must be a copy
// that is discarded after use rather than one shared with the cached keyring.
func unlock(e *openpgp.Entity, passphrase string) error {
	if e.PrivateKey == nil {
		return errors.New("key has no private part")
	}

	pass := []byte(passphrase)

	if e.PrivateKey.Encrypted {
		err := e.PrivateKey.Decrypt(pass)
		if err != nil {
			return fmt.Errorf("unlock key: %w", err)
		}
	}

	for _, sub := range e.Subkeys {
		if sub.PrivateKey == nil || !sub.PrivateKey.Encrypted {
			continue
		}
		err := sub.PrivateKey.Decrypt(pass)
		if err != nil {
			return fmt.Errorf("unlock subkey: %w", err)
		}
	}

	return nil
}

// primaryIdentity returns the user ID of the entity's primary identity,
// typically "Full Name <email@example.com>".
func primaryIdentity(e *openpgp.Entity) string {
	_, ident := e.PrimarySelfSignature()
	if ident != nil {
		return ident.Name
	}

	for name := range e.Identities {
		return name
	}

	return "(no identity)"
}

// fingerprintOf returns the entity fingerprint as uppercase hex, the form used
// to address keys everywhere in inro.
func fingerprintOf(e *openpgp.Entity) string {
	return fmt.Sprintf("%X", e.PrimaryKey.Fingerprint)
}
