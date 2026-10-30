 GPG Keychain Provisioner
=============================
This script provides an easy interface for generating a full GPG keychain (Master CA key + 3 subkeys), generating backup files, revocation certifications, public ssh keys, and provisoning yubikeys/smart cards with these keys (one yubikey/smartcard for the CA master key to enable expiration bumping and signing others public keys, and another yubikey/smartcard to hold the 3-subkeys for day-today usage such as signing, authorizing, and decryption).

This script automates [lrvick's](https://github.com/lrvick) GPG ["advanced setup"](https://github.com/lrvick/security-token-docs/blob/master/Use_Cases/GPG/Advanced_Setup.md) documentation (which can also be found maintained actively on [hashbang.sh](https://book.hashbang.sh/docs/security/key-management/gnupg/)), but with the addition of also including support for generating secp256k1 GPG keys as well.


## Requirements ##

* gpg
* pcscd
* python3-ykman (yubikit, YubiKey Manager's Python library, version 5.x)
* python3-cryptography

The script is a single self-contained file. GnuPG builds the keychain (certificate, UID, sub-key bindings, backups) inside a throwaway `GNUPGHOME`. The yubikeys/smartcards are provisioned by talking to their OpenPGP applet directly (factory reset, PINs, cardholder name, touch policy, key import, fingerprints, turning off OTP mode).


## Installation ##

`sudo apt-get install gpg pcscd python3-ykman python3-cryptography`

## How to use ##

`./gpg-provision.py`

You are asked for your first and last name, e-mail, key type (RSA or secp256k1), a password for the backup files, an expiration in years (just press enter for no expiration), and the user and admin PINs for the cards (what you type is visible while typing, then masked once you press enter). Progress messages tell you which step is running.

The last question is whether to use a separate certifying key/yubikey, which is recommended for the highest security: press enter for yes. The master CA key then goes on its own yubikey/smartcard, to be inserted only when bumping expirations and certifying other keys, and the signing, encryption and authorization sub-keys go on a second one. Insert the card for the master CA key first, then, when asked, the card for the three sub-keys.

Type "no" (and "no" again when asked to confirm) to have one yubikey/smartcard perform all operations. The keychain then has three keys: a master key that can both certify and sign, an encryption key and an authorization key, and a single yubikey holds all of them.

Files are written to the `keys` sub-directory (`<fingerprint>` is the master key's), split into two directories so that each can be copied to a disk/microSD card of its own.

`keys/private/` is kept offline:

* `<fingerprint>.private.keychain.asc`: password protected backup of the whole keychain
* `<fingerprint>.private.subkeys.asc` (with a separate certifying key): password protected backup of the sub-keys without the master key
* `<fingerprint>.private.revoke.cert.asc`: revocation certificate

`keys/public/` holds the only files that should ever touch an internet connected computer:

* `<fingerprint>.public.asc`: public key
* `<fingerprint>.public.ssh.key`: public SSH key


## Notes ##

Never run this on a non-airgapped system.  I recommend [airgap](https://github.com/Logicwax/airgap) OS on a laptop with its radios removed.

For those wanting to deterministically generate their GPG keychains from BIP39 seeds, please see [my gpg-hd project](https://github.com/Logicwax/gpg-hd)
