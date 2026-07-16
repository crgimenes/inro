# inro

A desktop front end for PGP: encrypt, sign, verify and decrypt short messages,
and keep a list of the keys of the people you write to.

An *inro* (印籠) is the small case that used to hang from an obi to carry a
personal seal and its ink. This one carries yours.

Go, cgo-free. The window is [glaze](https://github.com/crgimenes/glaze) (the
platform webview via purego), the UI is embedded HTML, the crypto is
[ProtonMail/go-crypto](https://github.com/ProtonMail/go-crypto), and the
configuration is [Filo](https://github.com/crgimenes/filo). One binary, no
files alongside it, no gpg required.

## Install

```sh
go install github.com/crgimenes/inro@latest
```

## Use

Import a key on the **Keys** tab: paste an armored public key a friend sent
you, or your own private key exported from gpg.

```sh
gpg --armor --export-secret-keys you@example.com   # your key, to sign and decrypt
gpg --armor --export friend@example.com            # a friend's key, to encrypt to them
```

Then work on the **Message** screen: input on the left, result on the right.
There is no mode to choose, because what you put in the input already decides
what can be done with it.

- **An encrypted message** can only be opened, so the button says *Decrypt* and
  asks which of your keys opens it.
- **A signed message** can only be checked, so the button says *Verify* and asks
  for nothing at all.
- **Plain text** can only go out. Pick recipients to *Encrypt*, turn on *Sign as*
  to sign, or do both. Signing on its own clear-signs the message: it stays
  readable and carries its signature, which is what you want for something
  pasted into an email.

Any signature found while decrypting or verifying is reported above the result.
A signature only reports as valid when the signer's key is in your keyring.
"Valid" here means the message was not altered and it was signed by that key —
whether the key really belongs to who it claims to is still on you.

Your passphrase is asked per operation and never stored. Private keys are held
locked in memory; each sign or decrypt unlocks a throwaway copy read from disk.

## Files

```
~/.config/inro/
  init.filo        ; configuration (optional)
  keyring.filo     ; nicknames and notes
  keys/
    <FINGERPRINT>.asc
```

Keys are stored in PGP's own armored format, one file per key, so
`gpg --import ~/.config/inro/keys/*.asc` works and nothing is locked inside
this app. `keyring.filo` holds only what the key material cannot carry — the
nickname and note you attach to a key — so the two can never disagree about a
fingerprint or a user ID.

`$XDG_CONFIG_HOME` is honoured. An `inro_init.filo` in the working directory
takes precedence over `~/.config/inro/init.filo`.

## Configuration

Every setting is optional; the defaults are shown.

```lisp
(set Width 1024)
(set Height 720)
(set Debug #f)                       ; open the webview developer tools
(set DataDir "~/.config/inro")       ; where keys and metadata live
(set DefaultKey "")                  ; fingerprint pre-selected in the UI
```

## Status

Early. Encrypt, decrypt, sign, verify, and key import/export/delete work.
Key generation is not implemented yet — bring a key from gpg.
