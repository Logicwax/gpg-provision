 GPG Keychain Provisioner
=============================
This script provides an easy interface for generating a full GPG keychain (Master CA key + 3 subkeys), generating backup files, revocation certifications, public ssh keys, and provisoning yubikeys/smart cards with these keys (one yubikey/smartcard for the CA master key to enable expiration bumping and signing others public keys, and another yubikey/smartcard to hold the 3-subkeys for day-today usage such as signing, authorizing, and decryption).

This script is an exact automation of [lrvick's](https://github.com/lrvick) GPG ["advanced setup"](https://github.com/lrvick/security-token-docs/blob/master/Use_Cases/GPG/Advanced_Setup.md) documentation (which can also be found maintained actively on [hashbang.sh](https://book.hashbang.sh/docs/security/key-management/gnupg/)), but with the addition of also including support for generating secp256k1 GPG keys as well.


## Requirements ##

* gpg
* python-is-python2
* python-ptyprocess
* scdaemon
* pcscd
* ykman (YubiKey Manager CLI)


## Installation ##

### Debian Packages ###
`sudo apt-get install gpg scdaemon pcscd python-is-python2 python-ptyprocess`

### YubiKey Manager ###

` sudo apt-add-repository ppa:yubico/stable && sudo apt-get update && sudo apt install yubikey-manager`

## How to use ##

`./gpg-provision`


## Notes ##

Never run this on a non-airgapped system.  I recommend [airgap](https://github.com/Logicwax/airgap) OS on a laptop with its radios removed.

For those wanting to deterministically generate their GPG keychains from BIP39 seeds, please see [my gpg-hd project](https://github.com/Logicwax/gpg-hd)
