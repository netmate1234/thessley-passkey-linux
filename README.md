# Thessley Passkey for Linux (and Windows 11)

Approve **Thessley Passkey** logins from an Ubuntu (or other GTK) desktop, or from **Windows 11** (see [WINDOWS.md](WINDOWS.md)), the same
protocol the Android app speaks. It works with any site running the Thessley Passkey
module (WordPress plugin or the Drupal module), unchanged.

Press **Open on this device** on a site's login or profile page and this app opens
(`thessleypasskey://` link handler). It shows which site is asking and from where, you
choose **Approve** or **Deny**, then unlock with your **PIN** and/or **FIDO2 security key**.

## Install

```
sudo apt install python3-gi gir1.2-adw-1 python3-cryptography python3-requests python3-fido2 \
                 python3-asn1crypto                          # the last one only for the TPM option
./install.sh          # installs for your user and registers the link handler
./uninstall.sh        # removes it (add --purge to also delete enrolled keys)
```

Needs Python 3.10+, GTK 4 and libadwaita 1.5+ (Ubuntu 24.04 or newer), and
python-fido2 1.2+ for security keys (Ubuntu 26.04 ships 2.0; older: `pip install fido2`).


## Enrol this computer
1. On the site, log in, open your profile page, press **Add a device**, then **Open on this device**.
2. In the window choose a name and how to protect the key (the TPM option is first when your computer has a usable TPM).
3. Done. The site now lists this computer under *Thessley Passkey devices* (you can revoke it there).

## How the key is protected

Choose one when you enrol:

| Option | Where the signing key lives | What unlocks it |
|---|---|---|
| **TPM chip + PIN** (recommended where available) | Inside this computer's TPM 2.0 chip; it cannot be copied off the machine | Your PIN, checked by the chip itself |
| **TPM chip + PIN + security key** | Same | PIN and a touch of your FIDO2 key |
| **PIN** | Software key, stored encrypted | scrypt of the PIN (at least 6 characters) |
| **Security key** | Software key, stored encrypted | The key's hmac-secret, needs a touch |
| **PIN and security key** | Software key, stored encrypted | Both |

Every approval asks again; nothing stays unlocked. Encrypted data is in
`~/.local/share/thessley-passkey/devices.json` (mode 600).

**Software keys:** 5 wrong PINs in a row lock the device for a growing delay, but that counter is in the
same file, so someone who copies the file can guess PINs offline (scrypt makes that slow). Prefer the TPM
option or add a security key.

**TPM keys:** the chip counts wrong PINs and locks out by itself, and the key never leaves it. The app
counts attempts too and stops after 5, so a guesser cannot use up the chip's lockout, which is shared with
everything else that uses the TPM (disk unlock, for example). Anyone who can use the TPM device can still
lock it out on purpose; that is true of every TPM tool.

### TPM option: setup and what the site learns
Your user needs access to the TPM device: `sudo usermod -aG tss $USER`, then log in again. Without it the
window explains why the TPM choices are missing.

When you enrol with a TPM key the app also proves to the site that the key really is inside a genuine TPM:
1. it sends the chip's **endorsement key certificate chain** (stored in the chip; missing links are fetched
   from the maker's published URLs, https only);
2. the site checks the chain against its trusted TPM maker roots and sends back a secret that **only that
   chip** can open (credential activation);
3. a fresh attestation key in the chip **certifies the signing key**, bound to this enrolment.

If the site accepts, the device shows **TPM 2.0 hardware** in its device list. If anything fails (no TPM
certificate, a maker the site does not trust yet, an older site), enrolment still succeeds, shown as
"Unverified", and the window says why.

**What it proves:** the key is non-exportable and lives in a TPM from the maker named in its certificate.
**What it does not:** revocation (certificate revocation lists are not checked) or anything about the
chip's firmware. Tested with Intel PTT (Core / N-series; the site ships Intel's On-Die CA root). Other makers
need their root certificate added to the site's `tpm-roots` folder; only ECC P-256 endorsement keys are
supported.

### Using a security key
The key needs to be reachable by your user (`/dev/hidraw*`); on most desktops that is automatic (install
`libfido2-1` for the udev rules otherwise). It must support **hmac-secret** (YubiKey 5, Nitrokey 3, most
FIDO2 keys). Creating the credential needs the key's own PIN once if one is set; approving only needs a touch.
Verified on hardware with a YubiKey 5.

## Terminal mode
```
thessley-passkey list
thessley-passkey enroll 'thessleypasskey://auth?type=enroll&...' --protect pin
thessley-passkey respond 'thessleypasskey://auth?type=login&...' --approve
thessley-passkey remove DEVICE_ID
```

## Tests
```
python3 -m unittest discover -s tests -p 'test_*.py'        # 40 unit tests, no network
python3 tests/hardware_fido2_check.py                          # YOU run this with your security key
IMPL=drupal|wp THESSLEY_TPM_TCTI=swtpm:host=127.0.0.1,port=2321 python3 tests/tpm_interop.py   # vs. a software TPM (swtpm)
sudo setfacl -m u:$USER:rw /dev/tpmrm0; python3 tests/real_tpm_check.py   # this computer's real TPM (read-only + short-lived objects); remove the ACL afterwards
# against a Drupal sandbox running thessley_passkey (never a live site):
THESSLEY_PASSKEY_DEV=1 BASE=http://127.0.0.1:10190 SSH_HOST=<host> DRUPAL_DIR=~/drupal-sandbox python3 tests/integration_drupal.py
THESSLEY_PASSKEY_DEV=1 BASE=http://127.0.0.1:10190 SSH_HOST=<host> DRUPAL_DIR=~/drupal-sandbox xvfb-run -a python3 tests/gui_smoke.py
```

Protocol details: see `PROTOCOL.md` in the thessley-passkey-server repository.
