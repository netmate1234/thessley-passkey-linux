# Thessley Passkey for Linux

Approve **Thessley Passkey** logins from an Ubuntu (or other GTK) desktop, the same
protocol the Android app speaks. It works with any site running the Thessley Passkey
module (WordPress plugin or the Drupal module), unchanged.

Press **Open on this device** on a site's login or profile page and this app opens
(`thessleypasskey://` link handler). It shows which site is asking and from where, you
choose **Approve** or **Deny**, then unlock with your **PIN** and/or **FIDO2 security key**.

## Install

```
sudo apt install python3-gi gir1.2-adw-1 python3-cryptography python3-requests python3-fido2
./install.sh          # installs for your user and registers the link handler
./uninstall.sh        # removes it (add --purge to also delete enrolled keys)
```

Needs Python 3.10+, GTK 4 and libadwaita 1.5+ (Ubuntu 24.04 or newer), and
python-fido2 1.2+ for security keys (Ubuntu 26.04 ships 2.0; older: `pip install fido2`).

### Using a security key
The key needs to be reachable by your user (`/dev/hidraw*`). On most desktops that is
automatic; if not, install `libfido2-1` (it ships the udev rules) and re-plug the key.
The key must support **hmac-secret** (YubiKey 5, Nitrokey 3, SoloKeys, most FIDO2 keys).
Verified on hardware with a YubiKey 5 (OTP+FIDO+CCID): `tests/hardware_fido2_check.py` passes.
Creating the credential needs the key's own PIN once (YubiKeys require it when a PIN is set); after
that, approving only needs a touch.

## Enrol this computer
1. On the site, log in, open your profile page, press **Add a device**, then **Open on this device**.
2. In the window choose a name and how to protect the key: **PIN**, **Security key**, or both.
3. Done. The site now lists this computer under *Thessley Passkey devices* (you can revoke it there).

## How the key is protected
* The signing key is a software EC P-256 key (not hardware attested: the site shows it as
  "Unverified", unlike a phone's TEE/StrongBox).
* It is stored only **encrypted** (AES-256-GCM) in `~/.local/share/thessley-passkey/devices.json`
  (file mode 600). The wrapping key comes from:
  * **PIN**: scrypt (64 MiB) of the PIN. At least 6 characters. 5 wrong PINs in a row lock
    the device for a growing delay.
  * **Security key**: the key's hmac-secret output for a random per-device salt. It needs the physical
    key and a touch (plus the key's own PIN only if the key demands it).
  * **Both**: the two secrets are combined, so each alone is useless.
* Every approval asks again; nothing stays unlocked.
* A login request is only answered for a site this computer was enrolled with. A link for any
  other site (for example a relayed QR) gets a warning and no Approve button.
* Redirects are never followed and TLS is always verified. `http://` is refused (a development
  switch for localhost exists only for tests).

**Limits to know about:** the PIN lock-out counter lives in the same file, so someone who copies
the file can try PINs offline (scrypt makes that slow, so use a long PIN, or protect with a security
key). A key that is the only protection can be used by anyone who holds it and can touch it. For
the strongest setup choose **PIN and security key**.

## Terminal mode
```
thessley-passkey list
thessley-passkey enroll 'thessleypasskey://auth?type=enroll&...' --protect pin
thessley-passkey respond 'thessleypasskey://auth?type=login&...' --approve
thessley-passkey remove DEVICE_ID
```

## Tests
```
python3 -m unittest discover -s tests -p 'test_*.py'        # 24 unit tests, no network
python3 tests/hardware_fido2_check.py                          # YOU run this with your security key
# against a Drupal sandbox running thessley_passkey (never a live site):
THESSLEY_PASSKEY_DEV=1 BASE=http://127.0.0.1:10190 SSH_HOST=<host> DRUPAL_DIR=~/drupal-sandbox python3 tests/integration_drupal.py
THESSLEY_PASSKEY_DEV=1 BASE=http://127.0.0.1:10190 SSH_HOST=<host> DRUPAL_DIR=~/drupal-sandbox xvfb-run -a python3 tests/gui_smoke.py
```

Protocol details: see `PROTOCOL.md` in the thessley-passkey-server repository.
