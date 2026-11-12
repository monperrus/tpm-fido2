# tpm-fido2

A FIDO2 security key for Linux whose private keys live in the TPM, with full
passkey support. It is the FIDO2/CTAP2 successor of
[tpm-fido](https://github.com/psanford/tpm-fido) (which is U2F only): like it,
it uses Linux `uhid` to appear as a USB HID security key, so browsers,
libfido2 (OpenSSH, systemd-cryptenroll, pam-u2f) and python-fido2 use it
without any special support.

Features:

- CTAP 2.1 (`FIDO_2_0`, `FIDO_2_1`) and CTAP1/U2F (`U2F_V2`) over CTAPHID
- passkeys (discoverable / resident credentials), account selection, `getNextAssertion`
- user verification through a client PIN (PIN/UV auth protocols 1 and 2,
  `pinUvAuthToken` with permissions and RP binding, retry counter)
- credential management (list, rename, delete passkeys)
- extensions: `credProtect`, `hmac-secret` (WebAuthn `prf`)
- ES256 (P-256) keys created and used inside the TPM; nothing secret is ever on disk
- user presence: a pinentry Allow/Deny dialog stands in for the touch sensor
- `authenticatorReset` really invalidates every credential, discoverable or not

## Install

```
go build -o tpm-fido2 .
```

Requirements:

- read/write access to `/dev/tpmrm0` (Debian/Ubuntu/Arch: be in the `tss` group);
- read/write access to `/dev/uhid`, e.g. with a udev rule
  `/etc/udev/rules.d/92-uhid.rules`:

  ```
  KERNEL=="uhid", SUBSYSTEM=="misc", GROUP="tss", MODE="0660"
  ```

  and `uhid` in `/etc/modules-load.d/uhid.conf` so the module is loaded at boot;
- access to the created `/dev/hidrawN`: systemd's `60-fido-id.rules` recognises
  the FIDO report descriptor and grants the logged-in user access, as for a
  hardware key;
- a pinentry program (`pinentry-gnome3`, `-qt`, `-gtk-2`, ... are auto-detected).

Do not run it as root.

## Usage

```
tpm-fido2 [-tpm /dev/tpmrm0] [-state ~/.local/share/tpm-fido2/state] [-pinentry PATH]
```

It runs in the foreground until interrupted and prints the hidraw node once
ready. Only one instance can use a state file (it is locked); `-debug` logs
every CTAP request and its status code, which is what to attach to a bug
report. As a systemd user service:

```
install -D tpm-fido2 ~/.local/bin/tpm-fido2
install -D -m644 contrib/tpm-fido2.service ~/.config/systemd/user/tpm-fido2.service
systemctl --user daemon-reload
systemctl --user enable --now tpm-fido2
```

The service needs `DISPLAY`/`WAYLAND_DISPLAY` in the user manager
environment for the pinentry dialog (GNOME and KDE import them).

Manage it like any security key, e.g. `fido2-token -I /dev/hidrawN`,
`fido2-token -S /dev/hidrawN` (set PIN), `fido2-token -L -r /dev/hidrawN`
(list passkeys), or the browser's security key settings
(`chrome://settings/securityKeys`).

## Troubleshooting

- Registering on a site where this key already holds a credential fails
  (CTAP status `0x19`, credential excluded): the site lists its known
  credentials and the authenticator refuses a duplicate, as a hardware key
  does. Signing in with the existing passkey works in any browser.

## Design

- **Credential keys.** Per credential, a random 16-byte seed; a storage primary
  key is derived in the owner hierarchy from a template whose unique field is
  `HKDF(seed, flags || binding)`, and a P-256 signing child key is created under
  it (the scheme of tpm-fido). `binding = SHA-256(epoch || rpIdHash)`. The
  credential ID is `version || flags || seed || TPM private || TPM public || tag`
  (252 bytes: short enough to double as a U2F key handle). Loading it for another RP,
  after a reset (new epoch), with altered flags (credProtect level), or on
  another TPM fails. `tag` is an HMAC keyed from the TPM that rejects foreign
  IDs without a TPM round trip (each TPM operation takes ~0.4 s).
- **TPM secret.** A keyed-hash primary with a fixed template is a non-exportable
  HMAC key fixed by the TPM owner seed; it derives the ID-tag key, the
  hmac-secret key and the state encryption key.
- **State** (`~/.local/share/tpm-fido2/state`, AES-256-GCM, mode 0600): passkey
  metadata (RP, user handle, names), PIN hash and retry counter, signature
  counter, reset epoch. It cannot be decrypted on another machine.
- **Attestation.** `packed` self-attestation (U2F: a per-credential self-signed
  certificate), so registrations are not linkable across sites.
- **CTAPHID**: channels, fragmentation, busy/cancel, 100 ms keepalives
  (`UPNEEDED` while the dialog is open), transaction timeouts.

## Security notes

- Keys cannot be exported or backed up. Clearing the TPM (`tpm2_clear`, BIOS
  "clear TPM") or losing the state file destroys all credentials: always
  register a second authenticator.
- Like any software confirmation dialog, the pinentry prompt can be clicked by
  malware running as your user (on X11 in particular). The TPM protects against
  key theft, not against a compromised session.
- The PIN retry counter is in the state file; an attacker who can write your
  files can roll it back to keep guessing online. Use a strong PIN.
- `--insecure-auto-presence` approves every request without asking. It exists
  for the end-to-end tests only.

## Tests

```
go test ./...         # unit tests, TPM simulator (cgo)
tests/e2e/run.sh      # real TPM + uhid, python-fido2 RP flows and libfido2 tools
```

`TPMFIDO2_REAL_TPM=1 go test ./tpmkey` also exercises `/dev/tpmrm0`.

## License

MIT
