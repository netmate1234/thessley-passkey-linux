# Thessley Passkey on Windows 11

Same app, same sites, same protocol. Differences from Linux: the window is Qt, the link handler is a
registry entry (per user, no administrator rights), the key store is `%LOCALAPPDATA%\ThessleyPasskey`, a
security key is reached through **Windows' own passkey dialog**, and the TPM through **Windows TPM Base
Services**. Windows 11 requires a TPM 2.0, so the TPM option is normally available.

> Status: written and checked on Linux (the shared code, the window, the packaging recipe and the TPM
> client against a real chip and an emulator). The Windows-only parts (registry handler, TPM Base Services
> connection, Windows' security-key dialog) have **not** been run on Windows yet. Start with the
> diagnostics report below.

## 1. Try it from source (fastest)

You need Python 3.10+ 64-bit (`winget install Python.Python.3.12`) and the project folder (download the
zip from GitLab, or `git clone`). In PowerShell, inside the folder:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r packaging\windows\requirements.txt
.\.venv\Scripts\python.exe -m pip install -e .

# 1) what works on this computer (writes %TEMP%\thessley-passkey-diagnose.txt and shows where)
.\.venv\Scripts\python.exe -m thessley_passkey --diagnose

# 2) make "Open on this device" links open the app (this user only)
.\.venv\Scripts\python.exe -m thessley_passkey --register-handler

# 3) open the window
.\.venv\Scripts\pythonw.exe -m thessley_passkey
```

Then on a site's profile page press **Add a device**, then **Open on this device**. Your browser asks once
whether to open Thessley Passkey. To undo the link handler: `... -m thessley_passkey --unregister-handler`.

## 2. Build and install a real program

```powershell
.\packaging\windows\build.ps1      # makes dist\ThessleyPasskey\ (ThessleyPasskey.exe + thessley-passkey-cli.exe)
.\packaging\windows\install.ps1    # copies it to %LOCALAPPDATA%\Programs, adds a Start menu entry and the link handler
.\packaging\windows\uninstall.ps1  # removes it again (-Purge also deletes the enrolled keys)
```

`ThessleyPasskey.exe` is the window; `thessley-passkey-cli.exe` prints to a console (`list`, `enroll`,
`respond`, `--diagnose`). The programs are not code-signed, so SmartScreen may warn when you first run
them from a downloaded zip; building them yourself avoids that.

## 3. What the diagnostics tell us

`--diagnose` checks, step by step, what an ordinary (non-administrator) program can do here, without
touching your keys or sending anything anywhere:

* **TPM:** can it open TPM Base Services, read the maker and the chip's certificates, create a storage key
  (owner hierarchy, or the endorsement hierarchy if Windows keeps the owner password), create the
  endorsement key, sign, and run a policy session. A step that fails shows the TPM's error code.
* **Security key:** whether Windows' WebAuthn API is present and its version. The security-key secret
  needs version 6 or newer (a current Windows 11); otherwise the security-key options explain that.
* **Link handler** and storage location.

Please send the report back if anything is marked FAILED; it tells us exactly what to fix.

## Notes
* **TPM and Windows:** Windows may restrict some TPM commands for ordinary programs. The app does not need
  administrator rights and never changes the TPM's owner, lockout or hierarchy settings. If the TPM option
  cannot work on a particular machine the window says why and PIN / security-key protection still work.
* **Security key:** creating the credential asks for the key's PIN in Windows' dialog (once); approving
  only needs a touch. Windows may offer "security key" and "this device"; choose **security key**.
* **Wrong PINs and the TPM:** the chip counts wrong tries and locks out for a long time (hours). The
  app stops after 5 itself so a mistake does not lock the chip for everything else that uses it, such as
  BitLocker.
