#!/bin/sh
# Build tpm-fido2, run it on the real TPM with a throwaway state file and
# auto-approved presence, and drive it with python-fido2 (tests/e2e/e2e.py).
# Needs: /dev/tpmrm0 and /dev/uhid access, python3.
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
trap 'kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; rm -rf "$work"' EXIT

cd "$root"
go build -o "$work/tpm-fido2" .
if [ ! -x .venv/bin/python ]; then
	python3 -m venv .venv
	.venv/bin/pip install -q fido2
fi

"$work/tpm-fido2" --state "$work/state" --insecure-auto-presence --name tpm-fido2-e2e >"$work/daemon.log" 2>&1 &
pid=$!
sleep 1
fail() {
	echo "FAIL $1" >&2
	echo "--- daemon log" >&2
	cat "$work/daemon.log" >&2
	exit 1
}
.venv/bin/python -I tests/e2e/e2e.py || fail python-fido2

# Independent client: libfido2 tools (used by OpenSSH and systemd-cryptenroll).
if command -v fido2-cred >/dev/null; then
	dev=$(fido2-token -L | grep 'vendor=0x1209, product=0x0001' | cut -d: -f1)
	cd "$work"
	head -c32 /dev/urandom | base64 >cdh
	{ cat cdh; echo example.org; echo alice; head -c16 /dev/urandom | base64; } >cred_in
	fido2-cred -M -r -h -i cred_in -o cred_out "$dev" es256 || fail "libfido2 make credential"
	fido2-cred -V -h -i cred_out -o cred_pub es256 || fail "libfido2 verify credential"
	{ cat cdh; echo example.org; sed -n 5p cred_out; head -c32 /dev/urandom | base64; } >as_in
	fido2-assert -G -h -i as_in -o as_out "$dev" || fail "libfido2 get assertion"
	fido2-assert -V -h -i as_out cred_pub es256 || fail "libfido2 verify assertion"
	echo "PASS libfido2 resident credential + hmac-secret"
fi
