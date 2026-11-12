"""End-to-end test of a running tpm-fido2 daemon through python-fido2.

Exercises the real path: hidraw -> uhid -> CTAPHID -> CTAP2 -> TPM, with a
WebAuthn relying party (fido2.server) verifying every response. The daemon
must run with --insecure-auto-presence and a throwaway --state file: this
script sets a PIN and finally resets the authenticator.

Only the device named tpm-fido2-e2e (VID/PID and serial) is touched.
"""

from __future__ import annotations

import hashlib
import os
import sys
import time

from fido2.client import DefaultClientDataCollector, Fido2Client, UserInteraction
from fido2.ctap import CtapError
from fido2.ctap1 import Ctap1
from fido2.ctap2 import Ctap2
from fido2.ctap2.credman import CredentialManagement
from fido2.ctap2.pin import ClientPin
from fido2.hid import CtapHidDevice
from fido2.server import Fido2Server
from fido2.utils import websafe_decode
from fido2.webauthn import (
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialType,
    PublicKeyCredentialUserEntity,
)

VID, PID = 0x1209, 0x0001
# Unique HID name/serial given by run.sh: never touch a real tpm-fido2 instance.
NAME = "tpm-fido2-e2e"
PIN = "246813"
RP = PublicKeyCredentialRpEntity(id="example.com", name="Example")
ORIGIN = "https://example.com"

failures: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(("PASS " if cond else "FAIL ") + name + (f" ({detail})" if detail and not cond else ""))
    if not cond:
        failures.append(name)


def find_device() -> CtapHidDevice:
    for _ in range(50):
        for d in CtapHidDevice.list_devices():
            if (d.descriptor.vid, d.descriptor.pid, d.descriptor.serial_number) == (VID, PID, NAME):
                return d
        time.sleep(0.1)
    sys.exit("tpm-fido2 device not found")


class Pin(UserInteraction):
    def request_pin(self, permissions, rp_id):
        return PIN

    def request_uv(self, permissions, rp_id):
        return True


def main() -> None:
    dev = find_device()
    ctap = Ctap2(dev)
    info = ctap.get_info()
    check("getInfo FIDO_2_1", "FIDO_2_1" in info.versions)
    if info.options.get("clientPin"):
        sys.exit("refusing to run: a PIN is already set (use a fresh --state)")

    server = Fido2Server(RP)
    client = Fido2Client(dev, DefaultClientDataCollector(ORIGIN), Pin())

    # 1. second-factor credential, no PIN
    opts, state = server.register_begin(
        PublicKeyCredentialUserEntity(id=b"u2f-user", name="sf"), user_verification="discouraged"
    )
    reg = client.make_credential(opts.public_key)
    auth_data = server.register_complete(state, reg)
    sf_cred = auth_data.credential_data
    check("non-resident register verified by RP", sf_cred is not None)
    opts, state = server.authenticate_begin([sf_cred], user_verification="discouraged")
    res = client.get_assertion(opts.public_key).get_response(0)
    server.authenticate_complete(state, [sf_cred], res)
    check("non-resident login verified by RP", True)

    # 2. set PIN, then passkeys with UV
    ClientPin(ctap).set_pin(PIN)
    check("setPIN", ctap.get_info().options.get("clientPin") is True)

    creds = []
    for name in ("alice", "bob"):
        opts, state = server.register_begin(
            PublicKeyCredentialUserEntity(id=name.encode(), name=name, display_name=name.title()),
            resident_key_requirement="required",
            user_verification="required",
            extensions={"credProps": True, "credentialProtectionPolicy": "userVerificationRequired", "prf": {}},
        )
        reg = client.make_credential(opts.public_key)
        ad = server.register_complete(state, reg)
        creds.append(ad.credential_data)
        ext = reg.client_extension_results
        check(f"passkey {name}: UV flag", ad.is_user_verified())
        check(f"passkey {name}: credProps.rk", bool(ext.get("credProps", {}).get("rk")), str(ext))
        check(f"passkey {name}: prf enabled", bool(ext.get("prf", {}).get("enabled")), str(ext))

    # discoverable login (no allowList), RP verifies
    opts, state = server.authenticate_begin(user_verification="required")
    sel = client.get_assertion(opts.public_key)
    responses = sel.get_assertions()
    check("discoverable login returns both accounts", len(responses) == 2, str(len(responses)))
    users = {r.user.get("name") for r in responses if r.user}
    check("account chooser gets user names (UV done)", users == {"alice", "bob"}, str(users))
    for i in range(len(responses)):
        server.authenticate_complete(state, creds, sel.get_response(i))
    check("discoverable assertions verified by RP", True)

    # PRF (hmac-secret): deterministic per credential and salt
    def prf(salt: bytes) -> bytes:
        opts, _ = server.authenticate_begin([creds[0]], user_verification="required", extensions={"prf": {"eval": {"first": salt}}})
        r = client.get_assertion(opts.public_key).get_response(0)
        return websafe_decode(r.client_extension_results["prf"]["results"]["first"])

    a, b, c = prf(b"s" * 32), prf(b"s" * 32), prf(b"t" * 32)
    check("prf deterministic", a == b and len(a) == 32)
    check("prf depends on salt", a != c)

    # wrong origin/RP must not find the credential
    other = Fido2Client(dev, DefaultClientDataCollector("https://evil.example.org"), Pin())
    evil = Fido2Server(PublicKeyCredentialRpEntity(id="evil.example.org", name="Evil"))
    opts, _ = evil.authenticate_begin([creds[0]], user_verification="required")
    try:
        other.get_assertion(opts.public_key)
        check("credential bound to RP", False)
    except Exception:  # noqa: BLE001 - any failure is the expected outcome
        check("credential bound to RP", True)

    # 3. credential management
    pin = ClientPin(ctap)
    token = pin.get_pin_token(PIN, ClientPin.PERMISSION.CREDENTIAL_MGMT)
    cm = CredentialManagement(ctap, pin.protocol, token)
    meta = cm.get_metadata()
    check("credMgmt metadata count", meta[CredentialManagement.RESULT.EXISTING_CRED_COUNT] == 2, str(meta))
    rps = cm.enumerate_rps()
    check("credMgmt rps", [r[CredentialManagement.RESULT.RP]["id"] for r in rps] == ["example.com"])
    rp_hash = hashlib.sha256(b"example.com").digest()
    listed = cm.enumerate_creds(rp_hash)
    check("credMgmt creds", len(listed) == 2)
    victim = next(c for c in listed if c[CredentialManagement.RESULT.USER]["name"] == "bob")
    cm.update_user_info(victim[CredentialManagement.RESULT.CREDENTIAL_ID], {"id": b"bob", "name": "robert"})
    names = {c[CredentialManagement.RESULT.USER]["name"] for c in cm.enumerate_creds(rp_hash)}
    check("credMgmt update user", names == {"alice", "robert"}, str(names))
    cm.delete_cred(victim[CredentialManagement.RESULT.CREDENTIAL_ID])
    check("credMgmt delete", cm.get_metadata()[CredentialManagement.RESULT.EXISTING_CRED_COUNT] == 1)

    # wrong PIN decrements retries
    try:
        ClientPin(ctap).get_pin_token("000000")
        check("wrong PIN rejected", False)
    except CtapError as e:
        check("wrong PIN rejected", e.code == CtapError.ERR.PIN_INVALID, str(e))
    check("PIN retries decremented", ClientPin(ctap).get_pin_retries()[0] == 7)
    ClientPin(ctap).get_pin_token(PIN)  # resets retries
    check("PIN retries restored", ClientPin(ctap).get_pin_retries()[0] == 8)

    # 4. U2F / CTAP1
    u2f = Ctap1(dev)
    app = hashlib.sha256(b"https://u2f.example.com").digest()
    chal = os.urandom(32)
    regdata = None
    for _ in range(100):
        try:
            regdata = u2f.register(chal, app)
            break
        except Exception:  # noqa: BLE001 - 0x6985 until presence confirmed
            time.sleep(0.1)
    check("U2F register", regdata is not None)
    if regdata is not None:
        regdata.verify(app, chal)
        check("U2F attestation verifies", True)
        sig = None
        for _ in range(100):
            try:
                sig = u2f.authenticate(chal, app, regdata.key_handle)
                break
            except Exception:  # noqa: BLE001
                time.sleep(0.1)
        check("U2F authenticate", sig is not None)
        if sig is not None:
            sig.verify(app, chal, regdata.public_key)
            check("U2F signature verifies", True)

    # 5. reset wipes passkeys and invalidates non-resident credentials
    ctap.reset()
    check("reset clears PIN", not ctap.get_info().options.get("clientPin"))
    client = Fido2Client(dev, DefaultClientDataCollector(ORIGIN), Pin())
    opts, _ = server.authenticate_begin([sf_cred], user_verification="discouraged")
    try:
        client.get_assertion(opts.public_key)
        check("reset invalidates old credentials", False)
    except Exception:  # noqa: BLE001
        check("reset invalidates old credentials", True)

    if failures:
        print(f"FAILED: {len(failures)} check(s): {', '.join(failures)}")
        sys.exit(1)
    print("ALL PASS")


if __name__ == "__main__":
    main()
