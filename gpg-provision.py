#!/usr/bin/env python3

# GPG Keychain Provisioner: generates a full GPG keychain (master CA key + sign, encryption and authorization
# sub-keys; RSA or secp256k1), its backup files, revocation certificate and public/SSH keys, and provisions
# two yubikeys/smartcards with them: one holding the CA master key, one holding the three sub-keys.
#
# Self-contained: GnuPG builds the keychain inside a throwaway GNUPGHOME (certificate, UID, sub-key bindings,
# backups); the cards are provisioned by talking to their OpenPGP applet directly through yubikit (reset, PINs,
# name, touch policy, key import, fingerprints), instead of scripting gpg's --card-edit / --edit-key menus.
#
# Requires: gpg, pcscd, python3-ykman (yubikit), python3-cryptography.

import hashlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from ykman.device import list_all_devices
from yubikit.core.smartcard import SmartCardConnection
from yubikit.management import USB_INTERFACE, ManagementSession, Mode
from yubikit.openpgp import DO, KEY_REF, UIF, OpenPgpSession

DEFAULT_USER_PIN = "123456"
DEFAULT_ADMIN_PIN = "12345678"

SLOT = {"sig": KEY_REF.SIG, "enc": KEY_REF.DEC, "aut": KEY_REF.AUT}
SLOT_NAME = {KEY_REF.SIG: "signature", KEY_REF.DEC: "encryption", KEY_REF.AUT: "authentication"}

# OpenPGP public-key algorithm ids
ALGO_RSA, ALGO_ECDH, ALGO_ECDSA, ALGO_EDDSA = 1, 18, 19, 22


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

def ask(prompt, mask=False):
  """input() that, with `mask`, redraws the answered line as asterisks once enter is pressed.

  What is typed stays visible while typing (so typos can be spotted); only the line left on screen
  afterwards is masked.  Without a terminal (piped input) nothing is redrawn.
  """
  value = input(prompt)
  if mask and sys.stdin.isatty() and sys.stdout.isatty():
    columns = shutil.get_terminal_size().columns
    rows = (len(prompt) + len(value)) // columns + 1   # the typed line may have wrapped
    sys.stdout.write("\033[%dF\033[J%s%s\n" % (rows, prompt, "*" * len(value)))
    sys.stdout.flush()
  return value


def say(message):
  """Progress line for the operator, shown immediately."""
  print(message, flush=True)


def ask_nonempty(prompt):
  """Ask until something other than blank is entered (first and last name)."""
  value = ""
  while value == "":
    value = input(prompt).strip()
  return value


# ---------------------------------------------------------------------------
# Smartcard (yubikit)
# ---------------------------------------------------------------------------

def kill_daemons():
  """Stop any gpg-agent, scdaemon or ssh-agent a previous script left behind.

  A stale scdaemon holds the card exclusively and a hung agent blocks every later gpg call, so this runs
  before each card access and at the start and end of the scripts.
  """
  subprocess.run(["killall", "gpg-agent", "scdaemon", "ssh-agent"],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _single_device():
  """The one attached YubiKey, asking again until exactly one is present.

  Several keys are refused so a factory reset can never hit the wrong one; none (or several) just means the
  user has to insert (or remove) a card and press enter, as many times as it takes.
  """
  while True:
    devices = list_all_devices()
    if len(devices) == 1:
      return devices[0][0]
    if devices:
      input("Found %d YubiKeys, expected exactly one. Please remove the others, then press enter " \
        % len(devices))
    else:
      input("No YubiKey found. Please insert a Yubikey/smartcard, then press enter ")


def _smartcard_device():
  """The one attached YubiKey, once its smartcard interface is visible through pcscd.

  If a gpg scdaemon grabs a card the moment it is inserted, pcscd fails to claim it (LIBUSB_ERROR_BUSY)
  and keeps no reader for it until it is restarted; the key then only shows up on its HID side and
  yubikit reports "Unsupported Connection type".  A fresh pcscd rescans the bus, so restart it (as the
  old scripts did with `sudo killall pcscd`) and look again.
  """
  kill_daemons()
  for attempt in range(3):
    device = _single_device()
    if device.supports_connection(SmartCardConnection):
      return device
    if attempt == 0:
      subprocess.run(["sudo", "killall", "pcscd"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
      input("Please run 'sudo systemctl restart pcscd' in another terminal, then press enter ")
    time.sleep(2)
    kill_daemons()
  raise SystemExit("The YubiKey's smartcard interface is still not available through pcscd.")


@contextmanager
def card():
  """Open the OpenPGP applet of the one and only attached YubiKey."""
  with _smartcard_device().open_connection(SmartCardConnection) as connection:
    yield OpenPgpSession(connection)


def card_disable_otp():
  """Turn off HOTP/OTP: USB interfaces FIDO+CCID only (what `ykman config mode f+c` does)."""
  say("Turning off HOTP/OTP mode ...")
  with _smartcard_device().open_connection(SmartCardConnection) as connection:
    ManagementSession(connection).set_mode(Mode(USB_INTERFACE.FIDO | USB_INTERFACE.CCID))


def card_version(session):
  """OpenPGP applet version as a float, same value `gpg --card-status` reports as 'Version'."""
  aid = session.aid
  major, minor = aid.version
  return float("%d.%d" % (major, minor))


def card_factory_reset(session):
  say("Resetting card to factory settings ...")
  session.reset()


def card_set_pins(session, user_pin, admin_pin):
  say("Setting user and admin PINs ...")
  session.change_pin(DEFAULT_USER_PIN, user_pin)
  session.change_admin(DEFAULT_ADMIN_PIN, admin_pin)


def card_set_name(session, admin_pin, firstname, lastname):
  # Same encoding gpg's `name` command writes: lastname<<Givenname, spaces as '<'.
  say("Setting cardholder name ...")
  session.verify_admin(admin_pin)
  name = lastname.replace(" ", "<") + "<<" + firstname.replace(" ", "<")
  session.put_data(DO.NAME, name.encode("ascii"))


def card_set_touch(session, admin_pin):
  say("Requiring touch for signing, encryption and authentication ...")
  session.verify_admin(admin_pin)
  for slot in (KEY_REF.SIG, KEY_REF.DEC, KEY_REF.AUT):
    session.set_uif(slot, UIF.FIXED)


def card_write_key(session, slot, key, creation_time, fingerprint):
  """Import `key` into `slot` and record the metadata gpg needs to match card and certificate."""
  say("Writing %s key to card ..." % SLOT_NAME[slot])
  session.put_key(slot, key)
  session.set_generation_time(slot, creation_time)
  session.set_fingerprint(slot, fingerprint)


def _public_bytes(public_key):
  if isinstance(public_key, rsa.RSAPublicKey):
    n = public_key.public_numbers()
    return b"rsa" + n.n.to_bytes(512, "big") + n.e.to_bytes(4, "big")
  if isinstance(public_key, ed25519.Ed25519PublicKey):
    return public_key.public_bytes_raw()
  return public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def card_verify(session, slots):
  """Read the card back: for each {slot: parsed key} the fingerprint, generation time and public key must match."""
  say("Verifying card contents ...")
  fingerprints = session.get_fingerprints()
  times = session.get_generation_times()
  for slot, key in slots.items():
    if fingerprints[slot] != bytes.fromhex(key["fpr"]):
      raise SystemExit("Card verification failed: %s fingerprint mismatch" % slot.name)
    if times[slot] != key["created"]:
      raise SystemExit("Card verification failed: %s generation time mismatch" % slot.name)
    if _public_bytes(session.get_public_key(slot)) != _public_bytes(key["key"].public_key()):
      raise SystemExit("Card verification failed: %s public key mismatch" % slot.name)


# ---------------------------------------------------------------------------
# GnuPG, confined to a throwaway homedir with no smartcard daemon
# ---------------------------------------------------------------------------

class Gpg:
  def __init__(self):
    """Throwaway GNUPGHOME whose agent has no smartcard daemon, so it can never touch the card."""
    base = "/dev/shm" if os.path.isdir("/dev/shm") else None
    self.home = tempfile.mkdtemp(prefix="gpg-", dir=base)
    os.chmod(self.home, 0o700)
    with open(os.path.join(self.home, "gpg-agent.conf"), "w") as f:
      f.write("allow-loopback-pinentry\ndisable-scdaemon\n")
    self.base = ["gpg", "--homedir", self.home, "--keyring", "trustedkeys.gpg",
      "--no-default-keyring", "--batch", "--pinentry-mode", "loopback", "--expert"]



  def run(self, args, passphrase=None, stdin=None, batch=True):
    cmd = list(self.base)
    if not batch:  # --gen-revoke only works interactively (answers come in on --command-fd)
      cmd.remove("--batch")
    fds = ()
    r = w = None
    try:
      if passphrase is not None:
        # passphrase travels over a pipe, never on a command line
        r, w = os.pipe()
        os.write(w, passphrase.encode() + b"\n")
        os.close(w)
        w = None
        cmd += ["--passphrase-fd", str(r)]
        fds = (r,)
      p = subprocess.run(cmd + args, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        pass_fds=fds)
    finally:
      for fd in (r, w):
        if fd is not None:
          os.close(fd)
    if p.returncode != 0:
      raise RuntimeError("gpg %s failed: %s" % (" ".join(args[:2]), p.stderr.decode(errors="replace")))
    return p.stdout

  def drive(self, args, answers, passphrase=None, scdaemon_env=None):
    """Run an interactive gpg command, answering each prompt by its --status-fd tag.

    `answers` maps a tag (e.g. keygen.flags) to the list of lines to send for successive prompts of
    that tag. A prompt with no answer left aborts, so an unexpected gpg menu can never be answered by
    accident.
    """
    pending = {tag: list(lines) for tag, lines in answers.items()}
    cmd = list(self.base)
    cmd.remove("--batch")
    sr, sw = os.pipe()
    pr = pw = None
    fds = [sw]
    if passphrase is not None:
      pr, pw = os.pipe()
      os.write(pw, passphrase.encode() + b"\n")
      os.close(pw)
      cmd += ["--passphrase-fd", str(pr)]
      fds.append(pr)
    cmd += ["--no-tty", "--command-fd", "0", "--status-fd", str(sw)]
    p = subprocess.Popen(cmd + args, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
      stderr=subprocess.PIPE, pass_fds=fds)
    os.close(sw)
    if pr is not None:
      os.close(pr)
    try:
      with os.fdopen(sr) as status:
        for line in status:
          f = line.split()
          if len(f) >= 3 and f[1] in ("GET_LINE", "GET_BOOL", "GET_HIDDEN"):
            tag = f[2]
            if not pending.get(tag):
              p.kill()
              raise RuntimeError("unexpected gpg prompt '%s' while running %s" % (tag, " ".join(args)))
            p.stdin.write((pending[tag].pop(0) + "\n").encode())
            p.stdin.flush()
    finally:
      p.stdin.close()
      err = p.stderr.read().decode(errors="replace")
      rc = p.wait()
    if rc != 0:
      raise RuntimeError("gpg %s failed: %s" % (" ".join(args[:2]), err))

  def close(self):
    subprocess.run(["gpgconf", "--homedir", self.home, "--kill", "all"],
      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    shutil.rmtree(self.home, ignore_errors=True)

  # -- keychain creation -----------------------------------------------------

  def generate(self, uid, primary, usage, subkeys, passphrase, expire):
    """Create a primary key plus subkeys. `expire` is in years, 0 meaning never.

    primary/subkey algos are gpg --quick-* names (e.g. secp256k1, ed25519, rsa4096) and usages are
    the --quick-* usage list (cert, sign, encr, auth). Returns the primary fingerprint.
    """
    exp = "0" if str(expire) == "0" else "%sy" % expire
    self.run(["--quick-gen-key", uid, primary, usage, exp], passphrase)
    fpr = self.primary_fingerprint()
    for algo, use in subkeys:
      if use == "sign" and algo.startswith(("secp", "nistp", "brainpool")):
        self.add_ecdsa_sign_subkey(fpr, algo, exp, passphrase)
      else:
        self.run(["--quick-add-key", fpr, algo, use, exp], passphrase)
    return fpr

  def add_ecdsa_sign_subkey(self, fpr, curve, exp, passphrase):
    """ECDSA signing subkey on a Weierstrass curve (e.g. secp256k1).

    gpg 2.4.7 (the airgap image) rejects these with --quick-add-key ("Wrong key usage"), because the curve
    name alone resolves to ECDH there; the addkey menu entry "ECC (sign only)" always works, so answer it
    by prompt tag.
    """
    self.drive(["--edit-key", fpr], {
      "keyedit.prompt": ["addkey", "save"], "keygen.algo": ["10"],
      "keygen.curve": [curve], "keygen.valid": [exp]}, passphrase)

  def primary_fingerprint(self):
    for rec in self.list_keys():
      if rec["type"] == "pub":
        return rec["fpr"]
    raise RuntimeError("no key in keyring")

  def list_keys(self):
    """[{type: pub|sub, fpr, created, caps}] from --with-colons output."""
    out = self.run(["--list-keys", "--with-colons"]).decode()
    keys = []
    for line in out.splitlines():
      f = line.split(":")
      if f[0] in ("pub", "sub"):
        keys.append({"type": f[0], "created": int(f[5]), "caps": f[11].lower()})
      elif f[0] == "fpr" and keys and "fpr" not in keys[-1]:
        keys[-1]["fpr"] = f[9]
    return keys

  # -- exports -----------------------------------------------------------------

  def export_public(self, fpr):
    return self.run(["--armor", "--export", fpr]).decode()

  def export_ssh(self, fpr):
    return self.run(["--export-ssh-key", fpr]).decode()

  def export_secret(self, fpr, passphrase, subkeys_only=False):
    opt = "--export-secret-subkeys" if subkeys_only else "--export-secret-keys"
    return self.run(["--armor", opt, fpr], passphrase).decode()

  def revoke_cert(self, fpr, passphrase):
    # Answers, by prompt tag, what the old --gen-revoke menu got: confirm, reason 0 (none), no text, confirm.
    out = os.path.join(self.home, "revoke.asc")
    self.drive(["--armor", "--output", out, "--gen-revoke", fpr], {
      "gen_revoke.okay": ["y"], "ask_revocation_reason.code": ["0"],
      "ask_revocation_reason.text": [""], "ask_revocation_reason.okay": ["y"]}, passphrase)
    with open(out) as f:
      return f.read()

  def secret_keys(self, passphrase):
    """Decrypt every secret (sub)key in the keyring.

    Returns [{fpr, created, algo, key}] where `key` is a cryptography private key, checked against
    the public part of the same packet and against the fingerprint gpg itself reports.
    """
    raw = self.run(["--export-secret-keys"], passphrase)
    keys = [parse_secret_packet(tag, body, passphrase) for tag, body in iter_packets(raw) if tag in (5, 7)]
    known = {k["fpr"] for k in self.list_keys()}
    for k in keys:
      if k["fpr"] not in known:
        raise RuntimeError("parsed secret key %s does not match any key gpg lists" % k["fpr"])
    return keys


# ---------------------------------------------------------------------------
# Minimal OpenPGP secret-key reader, enough to move gpg-generated keys onto a card
# ---------------------------------------------------------------------------

def iter_packets(data):
  i = 0
  while i < len(data):
    ctb = data[i]
    i += 1
    if not ctb & 0x80:
      raise ValueError("bad OpenPGP packet header")
    if ctb & 0x40:  # new format
      tag = ctb & 0x3F
      l = data[i]
      if l < 192:
        i += 1
      elif l < 224:
        l = ((l - 192) << 8) + data[i + 1] + 192
        i += 2
      elif l == 255:
        l = struct.unpack(">I", data[i + 1:i + 5])[0]
        i += 5
      else:
        raise ValueError("partial-length packets are not supported")
    else:  # old format
      tag = (ctb >> 2) & 0x0F
      lt = ctb & 0x03
      if lt == 3:
        raise ValueError("indeterminate-length packets are not supported")
      n = (1, 2, 4)[lt]
      l = int.from_bytes(data[i:i + n], "big")
      i += n
    yield tag, data[i:i + l]
    i += l


def _mpi(buf, off):
  bits = struct.unpack(">H", buf[off:off + 2])[0]
  n = (bits + 7) // 8
  return int.from_bytes(buf[off + 2:off + 2 + n], "big"), buf[off + 2:off + 2 + n], off + 2 + n


def _s2k_iterated(hash_name, passphrase, salt, coded_count, keylen):
  count = (16 + (coded_count & 15)) << ((coded_count >> 4) + 6)
  data = salt + passphrase.encode()
  stream = (data * (count // len(data) + 1))[:max(count, len(data))]
  return hashlib.new(hash_name, stream).digest()[:keylen]


_HASH = {2: "sha1", 8: "sha256", 9: "sha384", 10: "sha512", 11: "sha224"}
_SYM_KEYLEN = {7: 16, 8: 24, 9: 32}


def parse_secret_packet(tag, body, passphrase):
  if body[0] != 4:
    raise ValueError("only v4 keys are supported")
  created = struct.unpack(">I", body[1:5])[0]
  algo = body[5]
  off = 6
  if algo in (ALGO_ECDSA, ALGO_EDDSA, ALGO_ECDH):
    oid_len = body[off]
    oid = body[off + 1:off + 1 + oid_len]
    off += 1 + oid_len
    _, point, off = _mpi(body, off)
    if algo == ALGO_ECDH:
      off += 1 + body[off]
  elif algo == ALGO_RSA:
    n, _, off = _mpi(body, off)
    e, _, off = _mpi(body, off)
  else:
    raise ValueError("unsupported public-key algorithm %d" % algo)
  pub_end = off
  fpr = hashlib.sha1(b"\x99" + struct.pack(">H", pub_end) + body[:pub_end]).hexdigest().upper()

  usage = body[off]
  off += 1
  if usage in (254, 255):
    sym = body[off]
    if body[off + 1] != 3:
      raise ValueError("only iterated+salted S2K is supported")
    hash_name = _HASH[body[off + 2]]
    salt = body[off + 3:off + 11]
    coded = body[off + 11]
    iv = body[off + 12:off + 28]
    cipher = body[off + 28:]
    key = _s2k_iterated(hash_name, passphrase, salt, coded, _SYM_KEYLEN[sym])
    dec = Cipher(algorithms.AES(key), modes.CFB(iv)).decryptor()
    plain = dec.update(cipher) + dec.finalize()
    if usage == 254:
      plain, check = plain[:-20], plain[-20:]
      if hashlib.sha1(plain).digest() != check:
        raise ValueError("wrong passphrase for key %s" % fpr)
    else:
      plain, check = plain[:-2], plain[-2:]
      if sum(plain) & 0xFFFF != int.from_bytes(check, "big"):
        raise ValueError("wrong passphrase for key %s" % fpr)
  elif usage == 0:
    plain = body[off:-2]
  else:
    raise ValueError("unsupported secret-key protection %d" % usage)

  if algo in (ALGO_ECDSA, ALGO_ECDH):
    d, _, _ = _mpi(plain, 0)
    curve = {"2b8104000a": ec.SECP256K1()}[oid.hex()]
    key = ec.derive_private_key(d, curve)
    pub = key.public_key().public_numbers()
    if point != b"\x04" + pub.x.to_bytes(32, "big") + pub.y.to_bytes(32, "big"):
      raise ValueError("secret key does not match public key for %s" % fpr)
  elif algo == ALGO_EDDSA:
    _, seed, _ = _mpi(plain, 0)
    key = ed25519.Ed25519PrivateKey.from_private_bytes(seed.rjust(32, b"\x00"))
    raw = key.public_key().public_bytes_raw()
    if point != b"\x40" + raw:
      raise ValueError("secret key does not match public key for %s" % fpr)
  else:
    d, _, o = _mpi(plain, 0)
    p, _, o = _mpi(plain, o)
    q, _, o = _mpi(plain, o)
    key = rsa.RSAPrivateNumbers(p, q, d, rsa.rsa_crt_dmp1(d, p), rsa.rsa_crt_dmq1(d, q),
      rsa.rsa_crt_iqmp(p, q), rsa.RSAPublicNumbers(e, n)).private_key()
  return {"fpr": fpr, "created": created, "algo": algo, "key": key}


# ---------------------------------------------------------------------------
# gpg-provision
# ---------------------------------------------------------------------------

def check_yubikey_version():
  kill_daemons()
  with card() as session:
    version = card_version(session)
  if version < 3.4:
    print("The inserted yubikey has too old of firmware version to support secp256k1 keys.  " \
      + "Please insert a yubikey with PGP applet version 3.4 or newer.")
    input("\n\nPress any key to try again.")
    check_yubikey_version()


def ask_separate_certifying_key():
  """True for a separate certifying key/yubikey (the default); False for one yubikey that does everything."""
  while True:
    answer = input('Would you like to provision your keychain with a separate certifying key/yubikey (recommended for ' \
      + 'highest security).   Press enter for yes, or type "no" to have one yubikey perform all operations: ').strip().lower()
    if answer in ("", "y", "yes"):
      return True
    if answer in ("n", "no"):
      answer = input('Are you sure?  A separate key/yubikey is recommended to insert only when bumping expirations and ' \
        + 'certifying other keys.   Press enter again, or type "no" to have all keys on one yubikey ' \
        + '(same key can certify AND sign): ').strip().lower()
      if answer in ("n", "no"):
        return False
      if answer in ("", "y", "yes"):
        return True


def gpg_generate(gpg, name, email, password, expire, keyType, separate_certifying):
  """Separate certifying key: certify-only master CA key plus sign, encryption and authorization sub-keys.
  One yubikey: a master key that certifies AND signs, plus encryption and authorization sub-keys."""
  uid = name + " <" + email + ">"
  say("Generating keychain (RSA keys can take a few minutes) ..." if keyType == "rsa" else "Generating keychain ...")
  algo = "rsa4096" if keyType == "rsa" else "secp256k1"
  auth = "rsa4096" if keyType == "rsa" else "ed25519"
  if separate_certifying:
    return gpg.generate(uid, algo, "cert", [(algo, "sign"), (algo, "encr"), (auth, "auth")], password, expire)
  return gpg.generate(uid, algo, "cert,sign", [(algo, "encr"), (auth, "auth")], password, expire)


def gpg_export_keychain(gpg, keyID, password, separate_certifying):
  say("Exporting backups, revocation certificate, public and SSH keys ...")
  keys_path = os.path.join(os.path.abspath(os.getcwd()), "keys")
  # keys/private and keys/public, so each can be copied to its own disk/microSD card
  files = [
    ("private", ".private.keychain.asc", gpg.export_secret(keyID, password)),
    ("public", ".public.asc", gpg.export_public(keyID)),
    ("public", ".public.ssh.key", gpg.export_ssh(keyID)),
    ("private", ".private.revoke.cert.asc", gpg.revoke_cert(keyID, password)),
  ]
  if separate_certifying:
    # the sub-keys without the master key, for an everyday machine that must not hold the master
    files.insert(1, ("private", ".private.subkeys.asc", gpg.export_secret(keyID, password, subkeys_only=True)))
  for subdir, suffix, content in files:
    with open(os.path.join(keys_path, subdir, str(keyID) + suffix), "w") as f:
      f.write(content)


def card_keys(gpg, password, separate_certifying):
  """The keys for each card.

  Separate certifying key: the CA key (sig slot of the CA card) and the sub-keys (sig/enc/aut of the other card).
  One yubikey: no CA card, and the master key (certifies and signs) takes the sig slot next to enc and aut."""
  info = {k["fpr"]: k for k in gpg.list_keys()}
  master, subkeys = None, {}
  for key in gpg.secret_keys(password):
    k = info[key["fpr"]]
    if k["type"] == "pub":
      master = key
    else:
      subkeys[{"s": "sig", "e": "enc", "a": "aut"}[k["caps"]]] = key
  if separate_certifying:
    return {"sig": master}, subkeys
  subkeys["sig"] = master
  return None, subkeys


def card_provision(slots, userPin, adminPin, firstname, lastname):
  kill_daemons()
  with card() as session:
    card_factory_reset(session)
    card_set_pins(session, userPin, adminPin)
    session.verify_admin(adminPin)
    for role, key in slots.items():
      card_write_key(session, SLOT[role], key["key"], key["created"], bytes.fromhex(key["fpr"]))
    card_set_name(session, adminPin, firstname, lastname)
    card_set_touch(session, adminPin)
    card_verify(session, {SLOT[r]: k for r, k in slots.items()})


if __name__ == '__main__':
  os.system("rm -rf *.asc keys > /dev/null 2>&1")
  os.system("mkdir -p keys/private keys/public")
  kill_daemons()
  print("\n")
  firstname = ask_nonempty('First name: ')
  lastname = ask_nonempty('Last name: ')
  name = firstname + " " + lastname
  email = input('Email: ')
  print("Please choose a key type:")
  if input('RSA (1) or secp256k1 (2): ') == '1':
    keyType = "rsa"
  else:
    keyType = "secp256k1"
  password = ask('Desired GPG back-up file password: ', mask=True)
  expire = "?"
  while (expire != "" and not expire.isdigit()):
    expire = input('Expire time (in years, as an integer, or press enter for no expiration): ').strip()
  if expire == "":
    expire = "0"
  userPin = ""
  while (len(userPin) < 6):
    userPin = ask('Desired Yubikey/smartcard user pin# (minimum of 6 chars): ', mask=True)
  adminPin = ""
  while (len(adminPin) < 8 or userPin == adminPin):
    adminPin = ask('Desired Yubikey/smartcard admin pin# (minimum of 8 chars): ', mask=True)
    if userPin == adminPin:
      print("\nError: Smartcard user pin and admin pin should not be the same!\n")
  separate_certifying = ask_separate_certifying_key()

  print("\n\n" \
    +  "*************************************************************************\n" \
    + "*   WARNING: THIS WILL FACTORY RESET ANY INSERTED YUBIKEY/SMARTCARDS!   *\n" \
    + "*   Please remove any Yubikeys/smartcards that you do not want reset    *\n" \
    + "*************************************************************************\n")
  if separate_certifying:
    input("Press insert a Yubikey/smartcard that you intend to act as your master CA key. " \
      + "\nThis card will be used for activities such as bumping expiration time and signing " \
      + "others public GPG keys.\n\n\nPress enter when ready")
  else:
    input("Press insert the Yubikey/smartcard that will hold all of your keys (certifying, signing, " \
      + "authorizing, and decryption).\n\n\nPress enter when ready")
  if keyType == "secp256k1":
    check_yubikey_version()

  gpg = Gpg()
  try:
    masterkeyID = gpg_generate(gpg, name, email, password, expire, keyType, separate_certifying)
    gpg_export_keychain(gpg, masterkeyID, password, separate_certifying)
    ca, subkeys = card_keys(gpg, password, separate_certifying)
  finally:
    gpg.close()

  if separate_certifying:
    card_provision(ca, userPin, adminPin, firstname, lastname)
    card_disable_otp() # Turn off HOTP mode
    os.system("reset")
    print("Your CA masterkey yubikey/smartcard is now setup.  Please remove it and store " \
      + "it in a safe location\n\nNow, please insert your yubikey/smartcard to be used for subkeys " \
      + "(everyday tasks such as signing, authorizing, and decryption)\n\n")
    while input("Type \"yes\" when ready: ").strip() != "yes": pass
  card_provision(subkeys, userPin, adminPin, firstname, lastname)
  card_disable_otp()
  # just for show...
  os.system("reset")
  if separate_certifying:
    print("Master key " + masterkeyID + " on CA card; sign, encryption and authorization sub-keys on sub-key card.")
  else:
    print("Master key " + masterkeyID + " (certifying and signing), encryption and authorization keys on the card.")
  path_str = os.path.join(os.path.abspath(os.getcwd()), "keys") + "/"
  print(path_str)
  # -C: tree only colors its output by itself when LS_COLORS is set, which the shell here does not do
  if os.system("tree" + (" -C" if sys.stdout.isatty() else "") + " keys 2>/dev/null") != 0:   # tree is not installed
    os.system("ls -alh keys/private keys/public")
  if separate_certifying:
    print("\n\n\nYour yubikey/smartcard is now provisioned with three subkeys (Signing, Authorization, and Decryption)\n")
  else:
    print("\n\n\nYour yubikey/smartcard is now provisioned with three keys (Certifying and Signing, Authorization, and Decryption)\n")
  print("The private keys are in " + path_str + "private/ : please back them up onto a disk/microSD card that is kept in a safe" \
    + " location offline.  This disk should never touch an internet connected machine.\n\nThe public keys are in " \
    + path_str + "public/ : these are the only files that should ever touch an internet connected computer (use a separate microSD card for them).\n\n")
  kill_daemons()
