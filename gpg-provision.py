#!/usr/bin/env python3

import os
import subprocess
import sys
import ptyprocess

gpg_cmdline = "GNUPGHOME=\"temp\" gpg " \
  + "--homedir temp " \
  + "--keyring trustedkeys.gpg " \
  + "--no-default-keyring " \
  + "--pinentry-mode=loopback " \
  + "--command-fd=0 " \
  + "--expert "

def gpg_get_masterkey():
  gpg = subprocess.Popen(gpg_cmdline + "--list-keys | " \
    "tail -n +3 | awk \'{ print $1 }\' | grep -v \"pub\" | grep -v \"uid\" | tr -s \'\\n\' \'\\n\'", \
    stdout=subprocess.PIPE, \
    shell=True \
    )
  return gpg.communicate()[0].decode().strip()


def gpg_add_auth_subkey(keyID, password, expire, keyType):
  if keyType == "rsa":
    cmd_seq = "echo 8; echo S; echo E; echo A; echo Q; echo 4096; echo " + str(expire) + "y; echo '" \
    + password + "'; echo save;"
  else:
    cmd_seq = "echo 11; echo A; echo S; echo Q; echo 9; echo " + str(expire) + "y; echo '" + password \
    + "'; echo 'save';"
  gpg = subprocess.Popen( \
    "bash -c \"{ echo addkey; " + cmd_seq + " } | " + gpg_cmdline + " --edit-key " + str(keyID) + "\"", \
    shell=True \
    )
  gpg.communicate()[0]


def gpg_add_enc_subkey(keyID, password, expire, keyType):
  if keyType == "rsa":
    cmd_seq = "echo 6; echo 4096; echo " + str(expire) + "y; echo '" + password + "'; echo save;"
  else:
    cmd_seq = "echo 12; echo 9; echo " + str(expire) + "y; echo '" + password + "'; echo 'save';"
  gpg = subprocess.Popen( \
    "bash -c \"{ echo addkey; " + cmd_seq + " } | " + gpg_cmdline + " --edit-key " + str(keyID) + "\"", \
    shell=True \
    )
  gpg.communicate()[0]


def gpg_add_sig_subkey(keyID, password, expire, keyType):
  if keyType == "rsa":
    cmd_seq = "echo 4; echo 4096; echo " + str(expire) + "y; echo '"+ password + "'; echo save;"
  else:
    cmd_seq = "echo 10; echo 9; echo " + str(expire) + "y; echo '" + password + "'; echo 'save';"
  gpg = subprocess.Popen( \
    "bash -c \"{ echo addkey; " + cmd_seq + " } | " \
    + gpg_cmdline + " --edit-key " + str(keyID) + "\"", \
    shell=True \
    )
  gpg.communicate()[0]


def gpg_create_key(name, email, password, expire, keyType):
  if keyType == "rsa":
    cmd_seq = "echo 8; echo S; echo E; echo Q; echo 4096; echo " + str(expire) + "y; echo y; echo '" \
    + name + "'; echo '" + email + "'; echo ''; echo '" + password + "'; echo save;"
  else:
    cmd_seq = "echo 11; echo S; echo Q; echo 9; echo " + str(expire) + "y; echo y; echo '" \
    + name + "'; echo '" + email + "'; echo ''; echo '" + password + "'; echo save;"
  gpg = subprocess.Popen( \
    "bash -c \"{ " + cmd_seq + " } | " + gpg_cmdline + " --full-generate-key \"", \
  stdout=subprocess.PIPE, shell=True)
  gpg.communicate()[0]


def gpg_gen_revoke_cert(keyID, password):
  # Generate revoke certificate
  keys_path = os.path.join(os.path.dirname(__file__) , "keys")
  cmd_seq = "echo y; echo 0; echo ' '; echo y; echo '" + password + "';"
  gpg = subprocess.Popen( \
    "bash -c \"{ " + cmd_seq + " } | " + gpg_cmdline + " --gen-revoke " + str(keyID) + "\"", \
    stdout=subprocess.PIPE, \
    shell=True)
  revoke_cert = gpg.communicate()[0]
  certFile = open(os.path.join(os.path.abspath(os.getcwd()), "keys", str(keyID) + ".private.revoke.cert.asc"), "w")
  certFile.write(revoke_cert.decode())
  certFile.close()


def gpg_export_keychain(keyID, password, keyType):
  keys_path = os.path.join(os.path.dirname(__file__) , "keys")
  # Export private master CA key to file
  gpg = subprocess.Popen("bash -c \"{ echo '" + password + "'; } | " + gpg_cmdline \
    + "--armor --export-secret-keys " + str(keyID) + "\"", \
    stdout=subprocess.PIPE, \
    shell=True)
  privateMasterCAKey = gpg.communicate()[0]
  keyFile = open(os.path.join(os.path.abspath(os.getcwd()), "keys", str(keyID) + ".private.master.asc"), "w")
  keyFile.write(privateMasterCAKey.decode())
  keyFile.close()
  # Export private subkeys to file
  gpg = subprocess.Popen("bash -c \"{ echo '" + password + "'; } | " + gpg_cmdline \
    + "--armor --export-secret-subkeys " + str(keyID) + "\"", \
    stdout=subprocess.PIPE, \
    shell=True)
  privateSubKeys = gpg.communicate()[0]
  keyFile = open(os.path.join(os.path.abspath(os.getcwd()), "keys", str(keyID) + ".private.subkeys.asc"), "w")
  keyFile.write(privateSubKeys.decode())
  keyFile.close()
  # Export public key to file
  gpg = subprocess.Popen(gpg_cmdline + "--armor --export " + str(keyID), stdout=subprocess.PIPE, shell=True)
  publicKey = gpg.communicate()[0]
  keyFile = open(os.path.join(os.path.abspath(os.getcwd()), "keys", str(keyID) + ".public.asc"), "w")
  keyFile.write(publicKey.decode())
  keyFile.close()
  # Export SSH public key to file
  if (keyType == "rsa"):
    gpg = subprocess.Popen("bash -c \"{ echo '" + password + "'; } | " + gpg_cmdline
      + " --export-ssh-key " + str(keyID) + "\"", \
      stdout=subprocess.PIPE, shell=True)
    sshPub = gpg.communicate()[0]
    keyFile = open(os.path.join(os.path.abspath(os.getcwd()), "keys", str(keyID) +  ".public.ssh.asc"), "w")
    keyFile.write(sshPub.decode())
    keyFile.close()


def gpg_card_factory_reset():
  gpg_card_wakeup()
  gpg = subprocess.Popen( \
    "bash -c \"{ echo admin; echo factory-reset; echo y; echo yes; echo q;} | " \
    + gpg_cmdline + " --card-edit\"", \
    shell=True \
    )
  gpg.communicate()[0]
  os.system("killall gpg-agent scdaemon ssh-agent > /dev/null 2>&1")


def gpg_card_configure_userpin(userpin):
  gpg_card_wakeup()
  gpg = subprocess.Popen( \
    "bash -c \"{ echo admin; echo passwd; echo 1; echo '123456'; echo '" + userpin + "'; echo '" \
    + userpin + "'; echo q; echo q;} | " + gpg_cmdline + " --card-edit\"", \
    shell=True \
    )
  gpg.communicate()[0]
  os.system("killall gpg-agent scdaemon ssh-agent > /dev/null 2>&1")


def gpg_card_configure_adminpin(userpin):
  gpg_card_wakeup()
  gpg = subprocess.Popen( \
    "bash -c \"{ echo admin; echo passwd; echo 3; echo '12345678'; echo '" + adminpin + "'; echo '" + adminpin \
    + "'; echo q; echo q;} | " + gpg_cmdline + " --card-edit\"", \
    shell=True \
    )
  gpg.communicate()[0]
  os.system("killall gpg-agent scdaemon ssh-agent > /dev/null 2>&1")


def gpg_ca_card_write(keyID, password, adminpin):
  gpg_card_wakeup()
  gpg = subprocess.Popen( \
    "bash -c \"{ echo keytocard; echo y; echo 1; echo '" + password + "'; echo '" + adminpin + "'; echo '" \
    + adminpin + "'; echo 'save'; echo q;} | " + gpg_cmdline + " --edit-key " + str(keyID) + "\"", \
    shell=True \
    )
  gpg.communicate()[0]


def gpg_subkey_card_write(keyID, password, adminpin):
  gpg_card_wakeup()
  # Write Sig key to card
  gpg = subprocess.Popen( \
    "bash -c \"{ echo key 1; echo keytocard; echo 1; echo '" \
    + password + "'; echo '" + adminpin + "'; echo '" + adminpin + "'; echo 'key 1'; echo 'save'; echo q; } | " \
    + gpg_cmdline + " --edit-key " + str(keyID) + "\"", \
    shell=True \
    )
  gpg.communicate()[0]
  # Write Enc key to card
  gpg = subprocess.Popen( \
    "bash -c \"{ echo key 2; echo keytocard; echo 2; echo '" \
    + password + "'; echo '" + adminpin + "'; echo 'key 2'; echo 'save'; echo q;} | " \
    + gpg_cmdline + " --edit-key " + str(keyID) + "\"", \
    shell=True \
    )
  gpg.communicate()[0]
  # Write Auth key to card
  gpg = subprocess.Popen( \
    "bash -c \"{ echo key 3; echo keytocard; echo 3; echo '" \
    + password + "'; echo '" + adminpin + "'; echo 'key 3'; echo 'save'; echo q;} | " \
    + gpg_cmdline + " --edit-key " + str(keyID) + "\"", \
    shell=True \
    )
  gpg.communicate()[0]


def gpg_card_wakeup():
  # Stupid hack because GPG is dumb
  gpg = subprocess.Popen( \
    gpg_cmdline + " --card-status", \
    shell=True \
    )
  gpg.communicate()[0]

def yk_config_touch(adminpin):
  os.system("sudo killall gpg-agent pcscd > /dev/null 2>&1")
  ykman = subprocess.Popen("ykman -v | grep version | awk -F' ' '{print $5}'", \
    stdout=subprocess.PIPE, \
    shell=True)
  version = ykman.communicate()[0].decode()
  # Debian has ancient version of ykman
  if version.strip() == "2.1.0":
    os.system("ykman openpgp touch --admin-pin " + adminpin + " --force sig fixed")
    os.system("ykman openpgp touch --admin-pin " + adminpin + " --force enc fixed")
    os.system("ykman openpgp touch --admin-pin " + adminpin + " --force aut fixed")
  else:
    os.system("ykman openpgp keys set-touch --admin-pin " + adminpin + " --force sig FIXED")
    os.system("ykman openpgp keys set-touch --admin-pin " + adminpin + " --force enc FIXED")
    os.system("ykman openpgp keys set-touch --admin-pin " + adminpin + " --force aut FIXED")
  os.system("ykman config mode -f \"f+c\"")


if __name__ == '__main__':
  os.system("rm -rf temp *.asc keys > /dev/null 2>&1")
  os.system("mkdir -p temp keys && chmod -R 700 temp")
  os.system("killall gpg-agent scdaemon ssh-agent > /dev/null 2>&1")
  print("\n")
  name = input('Name: ')
  email = input('Email: ')
  print("Please choose a key type:")
  if input('RSA (1) or secp256k1 (2): ') == '1':
    keyType = "rsa"
  else:
    keyType = "secp256k1"
  password = input('Desired GPG back-up file password: ')
  expire = input('Expire time in years (integer): ')
  userpin = input('Desired Yubikey/smartcard user pin#: ')
  adminpin = input('Desired Yubikey/smartcard admin pin#: ')
  if userpin == adminpin:
    print("\nError: Smartcard user pin and admin pin cannot be the same\n")
    exit()

  print("\n\n" \
    +  "*************************************************************************\n" \
    + "*   WARNING: THIS WILL FACTORY RESET ANY INSERTED YUBIKEY/SMARTCARDS!   *\n" \
    + "*   Please remove any Yubikeys/smartcards that you do not want reset    *\n" \
    + "*************************************************************************\n")
  input("Press insert a Yubikey/smartcard that you intend to act as your master CA key. " \
    + "\nThis card will be used for activities such as bumping expiration time and signing " \
    + "others public GPG keys.\n\n\nPress enter when ready")

  # Create master CA key
  gpg_create_key(name, email, password, expire, keyType)
  masterkeyID = gpg_get_masterkey()
  gpg_add_sig_subkey(masterkeyID, password, expire, keyType)
  gpg_add_enc_subkey(masterkeyID, password, expire, keyType)
  gpg_add_auth_subkey(masterkeyID, password, expire, keyType)
  gpg_export_keychain(masterkeyID, password, keyType)
  gpg_gen_revoke_cert(masterkeyID, password)
  gpg_card_factory_reset()
  gpg_card_configure_userpin(userpin)
  gpg_card_configure_adminpin(adminpin)
  gpg_ca_card_write(masterkeyID, password, adminpin)
  yk_config_touch(adminpin)
  os.system("reset")
  print("Your CA masterkey yubikey/smartcard is now setup.  Please remove it and store " \
    + "it in a safe location\n\nNow, please insert your yubikey/smartcard to be used for subkeys " \
    + "(everyday tasks such as signing, authorizing, and decryption)\n\n")
  while input("Type \"yes\" when ready: ").strip() != "yes": pass
  os.system("killall gpg-agent scdaemon ssh-agent > /dev/null 2>&1")
  gpg_card_factory_reset()
  gpg_card_configure_userpin(userpin)
  gpg_card_configure_adminpin(adminpin)
  gpg_subkey_card_write(masterkeyID, password, adminpin)
  yk_config_touch(adminpin)
  # just for show...
  os.system("reset")
  gpg_list = subprocess.Popen(gpg_cmdline + "--list-keys " + masterkeyID, shell=True)
  gpg_list.communicate()
  os.system("rm -rf temp")
  os.system("ls -alh keys")
  print("\n\n\nYour yubikey/smartcard is now provisioned with three subkeys (Signing, Authorization, and Decryption\n")
  print("All key files are located in the \"keys\" sub-directory of wherever you ran this script, please back them up" \
    + " onto a disk that is kept in a safe location offline.  \nThe files with \".public\" suffix are safe to be transfered" \
    + " onto an internet connected machine\n\n")
