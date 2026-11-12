package ctap2

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-tpm/tpm2/transport/simulator"

	"github.com/monperrus/tpm-fido2/store"
	"github.com/monperrus/tpm-fido2/tpmkey"
)

type fakePresence struct {
	answer  bool
	prompts []string
}

func (f *fakePresence) Confirm(ctx context.Context, prompt string) (bool, error) {
	f.prompts = append(f.prompts, prompt)
	return f.answer, nil
}

type env struct {
	t    *testing.T
	a    *Authenticator
	pres *fakePresence
	tpm  *tpmkey.TPM
	path string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	k := tpmkey.New(sim)
	t.Cleanup(func() { k.Close() })
	key, err := StateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "state")
	st, err := store.Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	pres := &fakePresence{answer: true}
	a, err := New(k, st, pres)
	if err != nil {
		t.Fatal(err)
	}
	return &env{t: t, a: a, pres: pres, tpm: k, path: path}
}

// call sends a CTAP2 command and decodes the response map.
func (e *env) call(cmd byte, req any) (Status, map[int]cbor.RawMessage) {
	e.t.Helper()
	msg := []byte{cmd}
	if req != nil {
		b, err := encMode.Marshal(req)
		if err != nil {
			e.t.Fatal(err)
		}
		msg = append(msg, b...)
	}
	resp := e.a.CBOR(context.Background(), msg, func(byte) {})
	if resp[0] != 0 || len(resp) == 1 {
		return Status(resp[0]), nil
	}
	var m map[int]cbor.RawMessage
	if err := cbor.Unmarshal(resp[1:], &m); err != nil {
		e.t.Fatalf("decode response: %v", err)
	}
	return 0, m
}

func (e *env) must(cmd byte, req any) map[int]cbor.RawMessage {
	e.t.Helper()
	st, m := e.call(cmd, req)
	if st != 0 {
		e.t.Fatalf("cmd 0x%02x: status 0x%02x", cmd, byte(st))
	}
	return m
}

func get[T any](t *testing.T, m map[int]cbor.RawMessage, k int) T {
	t.Helper()
	var v T
	if err := cbor.Unmarshal(m[k], &v); err != nil {
		t.Fatalf("field %d: %v", k, err)
	}
	return v
}

type authData struct {
	rpIDHash []byte
	flags    byte
	counter  uint32
	credID   []byte
	pub      *ecdsa.PublicKey
	ext      map[string]cbor.RawMessage
}

func parseAuthData(t *testing.T, b []byte) authData {
	t.Helper()
	ad := authData{rpIDHash: b[:32], flags: b[32], counter: binary.BigEndian.Uint32(b[33:37])}
	rest := b[37:]
	if ad.flags&flagAT != 0 {
		rest = rest[16:]
		n := int(binary.BigEndian.Uint16(rest))
		ad.credID = rest[2 : 2+n]
		rest = rest[2+n:]
		var k coseKey
		dec := cbor.NewDecoder(bytes.NewReader(rest))
		if err := dec.Decode(&k); err != nil {
			t.Fatal(err)
		}
		rest = rest[dec.NumBytesRead():]
		ad.pub = &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(k.X), Y: new(big.Int).SetBytes(k.Y)}
	}
	if ad.flags&flagED != 0 {
		if err := cbor.Unmarshal(rest, &ad.ext); err != nil {
			t.Fatal(err)
		}
	}
	return ad
}

func cdh() []byte { b := make([]byte, 32); _, _ = rand.Read(b); return b }

type mcOpts struct {
	rp, user string
	rk       bool
	exclude  [][]byte
	ext      map[string]any
	token    []byte
	proto    int
}

func (e *env) makeCredential(o mcOpts) (Status, authData, []byte) {
	e.t.Helper()
	c := cdh()
	req := map[int]any{
		1: c,
		2: map[string]any{"id": o.rp, "name": o.rp},
		3: map[string]any{"id": []byte(o.user), "name": o.user, "displayName": "User " + o.user},
		4: []map[string]any{{"type": "public-key", "alg": -7}},
	}
	if o.rk {
		req[7] = map[string]bool{"rk": true}
	}
	if len(o.exclude) > 0 {
		var l []map[string]any
		for _, id := range o.exclude {
			l = append(l, map[string]any{"type": "public-key", "id": id})
		}
		req[5] = l
	}
	if o.ext != nil {
		req[6] = o.ext
	}
	if o.token != nil {
		req[8] = pinProtocols[o.proto].authenticate(o.token, c)
		req[9] = o.proto
	}
	st, m := e.call(cmdMakeCredential, req)
	if st != 0 {
		return st, authData{}, nil
	}
	if get[string](e.t, m, 1) != "packed" {
		e.t.Fatal("fmt not packed")
	}
	raw := get[[]byte](e.t, m, 2)
	ad := parseAuthData(e.t, raw)
	att := get[map[string]cbor.RawMessage](e.t, m, 3)
	var sig []byte
	_ = cbor.Unmarshal(att["sig"], &sig)
	d := sha256.Sum256(append(bytes.Clone(raw), c...))
	if !ecdsa.VerifyASN1(ad.pub, d[:], sig) {
		e.t.Fatal("attestation signature invalid")
	}
	h := sha256.Sum256([]byte(o.rp))
	if !bytes.Equal(ad.rpIDHash, h[:]) {
		e.t.Fatal("rpIdHash mismatch")
	}
	return 0, ad, raw
}

type gaOpts struct {
	rp    string
	allow [][]byte
	up    *bool
	token []byte
	proto int
	ext   map[string]any
}

type assertion struct {
	credID []byte
	ad     authData
	user   map[string]cbor.RawMessage
	n      int
}

func (e *env) verifyAssertion(m map[int]cbor.RawMessage, c []byte, pub *ecdsa.PublicKey) assertion {
	e.t.Helper()
	cred := get[map[string]cbor.RawMessage](e.t, m, 1)
	var id []byte
	_ = cbor.Unmarshal(cred["id"], &id)
	raw := get[[]byte](e.t, m, 2)
	sig := get[[]byte](e.t, m, 3)
	if pub == nil {
		var err error
		pub, err = tpmkey.PublicKey(id[:len(id)-tagLen])
		if err != nil {
			e.t.Fatal(err)
		}
	}
	d := sha256.Sum256(append(bytes.Clone(raw), c...))
	if !ecdsa.VerifyASN1(pub, d[:], sig) {
		e.t.Fatal("assertion signature invalid")
	}
	as := assertion{credID: id, ad: parseAuthData(e.t, raw)}
	if m[4] != nil {
		as.user = get[map[string]cbor.RawMessage](e.t, m, 4)
	}
	if m[5] != nil {
		as.n = get[int](e.t, m, 5)
	}
	return as
}

func (e *env) getAssertion(o gaOpts, pub *ecdsa.PublicKey) (Status, assertion, []byte) {
	e.t.Helper()
	c := cdh()
	req := map[int]any{1: o.rp, 2: c}
	if len(o.allow) > 0 {
		var l []map[string]any
		for _, id := range o.allow {
			l = append(l, map[string]any{"type": "public-key", "id": id})
		}
		req[3] = l
	}
	if o.ext != nil {
		req[4] = o.ext
	}
	if o.up != nil {
		req[5] = map[string]bool{"up": *o.up}
	}
	if o.token != nil {
		req[6] = pinProtocols[o.proto].authenticate(o.token, c)
		req[7] = o.proto
	}
	st, m := e.call(cmdGetAssertion, req)
	if st != 0 {
		return st, assertion{}, c
	}
	return 0, e.verifyAssertion(m, c, pub), c
}

// pinClient is the platform side of a PIN/UV auth protocol.
type pinClient struct {
	proto  int
	p      pinProtocol
	shared []byte
	ka     map[int]any
}

func (e *env) pinClient(proto int) *pinClient {
	m := e.must(cmdClientPIN, map[int]any{1: proto, 2: 2})
	var k coseKey
	if err := cbor.Unmarshal(m[1], &k); err != nil {
		e.t.Fatal(err)
	}
	if k.Alg != -25 {
		e.t.Fatalf("keyAgreement alg %d", k.Alg)
	}
	priv, _ := ecdh.P256().GenerateKey(rand.Reader)
	pub, err := ecdh.P256().NewPublicKey(append(append([]byte{4}, k.X...), k.Y...))
	if err != nil {
		e.t.Fatal(err)
	}
	z, _ := priv.ECDH(pub)
	b := priv.PublicKey().Bytes()
	p := pinProtocols[proto]
	return &pinClient{proto: proto, p: p, shared: p.kdf(z), ka: map[int]any{1: 2, 3: -25, -1: 1, -2: b[1:33], -3: b[33:]}}
}

func (pc *pinClient) enc(t *testing.T, pt []byte) []byte {
	ct, err := pc.p.encrypt(pc.shared, pt)
	if err != nil {
		t.Fatal(err)
	}
	return ct
}

func padPIN(pin string) []byte  { b := make([]byte, 64); copy(b, pin); return b }
func pinHash(pin string) []byte { h := sha256.Sum256([]byte(pin)); return h[:16] }

func (e *env) setPIN(proto int, pin string) Status {
	pc := e.pinClient(proto)
	ne := pc.enc(e.t, padPIN(pin))
	st, _ := e.call(cmdClientPIN, map[int]any{1: proto, 2: 3, 3: pc.ka, 4: pc.p.authenticate(pc.shared, ne), 5: ne})
	return st
}

func (e *env) token(proto int, pin string, perms int, rpID string) (Status, []byte) {
	pc := e.pinClient(proto)
	req := map[int]any{1: proto, 2: 9, 3: pc.ka, 6: pc.enc(e.t, pinHash(pin)), 9: perms}
	if rpID != "" {
		req[10] = rpID
	}
	st, m := e.call(cmdClientPIN, req)
	if st != 0 {
		return st, nil
	}
	tok, err := pc.p.decrypt(pc.shared, get[[]byte](e.t, m, 2))
	if err != nil {
		e.t.Fatal(err)
	}
	return 0, tok
}

func TestGetInfo(t *testing.T) {
	e := newEnv(t)
	m := e.must(cmdGetInfo, nil)
	vers := get[[]string](t, m, 1)
	if !contains(vers, "FIDO_2_1") || !contains(vers, "U2F_V2") {
		t.Fatalf("versions %v", vers)
	}
	opts := get[map[string]bool](t, m, 4)
	if !opts["rk"] || !opts["credMgmt"] || opts["clientPin"] {
		t.Fatalf("options %v", opts)
	}
	if !bytes.Equal(get[[]byte](t, m, 3), AAGUID[:]) {
		t.Fatal("aaguid")
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func TestNonResidentRoundTrip(t *testing.T) {
	e := newEnv(t)
	st, ad, _ := e.makeCredential(mcOpts{rp: "example.com", user: "alice"})
	if st != 0 {
		t.Fatalf("mc: %x", byte(st))
	}
	if ad.flags&flagUP == 0 || ad.flags&flagUV != 0 {
		t.Fatalf("flags %x", ad.flags)
	}
	st, as, _ := e.getAssertion(gaOpts{rp: "example.com", allow: [][]byte{{1, 2, 3}, ad.credID}}, ad.pub)
	if st != 0 {
		t.Fatalf("ga: %x", byte(st))
	}
	if !bytes.Equal(as.credID, ad.credID) || as.ad.counter <= ad.counter {
		t.Fatalf("bad assertion %+v", as.ad)
	}
	// negative: other RP
	if st, _, _ := e.getAssertion(gaOpts{rp: "evil.com", allow: [][]byte{ad.credID}}, nil); st != ErrNoCredentials {
		t.Fatalf("other rp: %x", byte(st))
	}
	// negative: no allowList and not resident
	if st, _, _ := e.getAssertion(gaOpts{rp: "example.com"}, nil); st != ErrNoCredentials {
		t.Fatalf("no rk: %x", byte(st))
	}
	// silent probe
	f := false
	n := len(e.pres.prompts)
	st, as, _ = e.getAssertion(gaOpts{rp: "example.com", allow: [][]byte{ad.credID}, up: &f}, ad.pub)
	if st != 0 || as.ad.flags&flagUP != 0 || len(e.pres.prompts) != n {
		t.Fatalf("silent: st=%x flags=%x", byte(st), as.ad.flags)
	}
	// exclude list
	if st, _, _ := e.makeCredential(mcOpts{rp: "example.com", user: "alice", exclude: [][]byte{ad.credID}}); st != ErrCredentialExcluded {
		t.Fatalf("exclude: %x", byte(st))
	}
	// presence denied
	e.pres.answer = false
	if st, _, _ := e.getAssertion(gaOpts{rp: "example.com", allow: [][]byte{ad.credID}}, nil); st != ErrOperationDenied {
		t.Fatalf("denied: %x", byte(st))
	}
}

func TestResidentAndNext(t *testing.T) {
	e := newEnv(t)
	_, a1, _ := e.makeCredential(mcOpts{rp: "example.com", user: "alice", rk: true})
	time.Sleep(10 * time.Millisecond)
	_, a2, _ := e.makeCredential(mcOpts{rp: "example.com", user: "bob", rk: true})
	_, _, _ = e.makeCredential(mcOpts{rp: "other.org", user: "carol", rk: true})
	st, as, _ := e.getAssertion(gaOpts{rp: "example.com"}, nil)
	if st != 0 || as.n != 2 || !bytes.Equal(as.credID, a2.credID) {
		t.Fatalf("ga rk: st=%x n=%d", byte(st), as.n)
	}
	var uid []byte
	_ = cbor.Unmarshal(as.user["id"], &uid)
	if string(uid) != "bob" || as.user["name"] != nil {
		t.Fatalf("user %v (no uv => no name)", as.user)
	}
	m := e.must(cmdGetNextAssertion, nil)
	// gna signs over the same clientDataHash; verify against key only
	cred := get[map[string]cbor.RawMessage](t, m, 1)
	var id []byte
	_ = cbor.Unmarshal(cred["id"], &id)
	if !bytes.Equal(id, a1.credID) {
		t.Fatal("next credential mismatch")
	}
	if st, _ := e.call(cmdGetNextAssertion, nil); st != ErrNotAllowed {
		t.Fatalf("gna exhausted: %x", byte(st))
	}
	// re-registering same user replaces the credential
	_, a3, _ := e.makeCredential(mcOpts{rp: "example.com", user: "alice", rk: true})
	if len(e.a.store.State.Credentials) != 3 || e.a.store.Find(a1.credID) >= 0 || e.a.store.Find(a3.credID) < 0 {
		t.Fatal("replacement failed")
	}
}

func TestPINAndUV(t *testing.T) {
	for _, proto := range []int{1, 2} {
		t.Run(fmt.Sprint("proto", proto), func(t *testing.T) { testPINAndUV(t, proto) })
	}
}

func testPINAndUV(t *testing.T, proto int) {
	{
		e := newEnv(t)
		if st := e.setPIN(proto, "12"); st != ErrPINPolicyViolation {
			t.Fatalf("short pin: %x", byte(st))
		}
		if st := e.setPIN(proto, "1234"); st != 0 {
			t.Fatalf("setPIN: %x", byte(st))
		}
		if st := e.setPIN(proto, "5678"); st != ErrNotAllowed {
			t.Fatalf("setPIN twice: %x", byte(st))
		}
		if !get[map[string]bool](t, e.must(cmdGetInfo, nil), 4)["clientPin"] {
			t.Fatal("clientPin not reported")
		}
		// rk without UV when PIN set
		if st, _, _ := e.makeCredential(mcOpts{rp: "example.com", user: "alice", rk: true}); st != ErrPUATRequired {
			t.Fatalf("rk no uv: %x", byte(st))
		}
		// non-rk without UV is fine (makeCredUvNotRqd)
		if st, _, _ := e.makeCredential(mcOpts{rp: "example.com", user: "x"}); st != 0 {
			t.Fatalf("non-rk: %x", byte(st))
		}
		st, tok := e.token(proto, "1234", permMC|permGA, "example.com")
		if st != 0 {
			t.Fatalf("token: %x", byte(st))
		}
		st, ad, _ := e.makeCredential(mcOpts{rp: "example.com", user: "alice", rk: true, token: tok, proto: proto})
		if st != 0 || ad.flags&flagUV == 0 {
			t.Fatalf("mc uv: st=%x flags=%x", byte(st), ad.flags)
		}
		st, as, _ := e.getAssertion(gaOpts{rp: "example.com", token: tok, proto: proto}, ad.pub)
		if st != 0 || as.ad.flags&flagUV == 0 || as.user["name"] == nil {
			t.Fatalf("ga uv: st=%x flags=%x user=%v", byte(st), as.ad.flags, as.user)
		}
		// token bound to example.com
		if st, _, _ := e.getAssertion(gaOpts{rp: "other.org", token: tok, proto: proto}, nil); st != ErrPINAuthInvalid {
			t.Fatalf("rp binding: %x", byte(st))
		}
		// wrong pin: retries decrement, then auth blocked after 3
		for i, want := range []Status{ErrPINInvalid, ErrPINInvalid, ErrPINAuthBlocked, ErrPINAuthBlocked} {
			if st, _ := e.token(proto, "0000", permGA, "example.com"); st != want {
				t.Fatalf("wrong pin #%d: %x want %x", i, byte(st), byte(want))
			}
		}
		r := e.must(cmdClientPIN, map[int]any{2: 1})
		if get[int](t, r, 3) != store.MaxPINRetries-3 {
			t.Fatalf("retries %d", get[int](t, r, 3))
		}
	}
}

func TestChangePIN(t *testing.T) {
	e := newEnv(t)
	e.setPIN(2, "1234")
	pc := e.pinClient(2)
	ne := pc.enc(t, padPIN("abcdef"))
	phe := pc.enc(t, pinHash("1234"))
	st, _ := e.call(cmdClientPIN, map[int]any{1: 2, 2: 4, 3: pc.ka, 4: pc.p.authenticate(pc.shared, append(bytes.Clone(ne), phe...)), 5: ne, 6: phe})
	if st != 0 {
		t.Fatalf("changePIN: %x", byte(st))
	}
	if st, _ := e.token(2, "1234", permGA, "a"); st != ErrPINInvalid {
		t.Fatalf("old pin: %x", byte(st))
	}
	if st, _ := e.token(2, "abcdef", permGA, "a"); st != 0 {
		t.Fatalf("new pin: %x", byte(st))
	}
}

func TestCredProtectAndHMACSecret(t *testing.T) {
	e := newEnv(t)
	st, ad, _ := e.makeCredential(mcOpts{rp: "example.com", user: "a", rk: true, ext: map[string]any{"credProtect": 3, "hmac-secret": true}})
	if st != 0 {
		t.Fatal(byte(st))
	}
	var cp int
	_ = cbor.Unmarshal(ad.ext["credProtect"], &cp)
	var hs bool
	_ = cbor.Unmarshal(ad.ext["hmac-secret"], &hs)
	if cp != 3 || !hs {
		t.Fatalf("ext %v", ad.ext)
	}
	// level 3 requires UV, even with allowList
	if st, _, _ := e.getAssertion(gaOpts{rp: "example.com", allow: [][]byte{ad.credID}}, nil); st != ErrNoCredentials {
		t.Fatalf("credProtect 3 without uv: %x", byte(st))
	}
	if st, _, _ := e.getAssertion(gaOpts{rp: "example.com"}, nil); st != ErrNoCredentials {
		t.Fatalf("credProtect 3 discoverable without uv: %x", byte(st))
	}
	// tampering the flag byte is rejected (tag and TPM binding)
	bad := bytes.Clone(ad.credID)
	bad[1] = 1
	if st, _, _ := e.getAssertion(gaOpts{rp: "example.com", allow: [][]byte{bad}}, nil); st != ErrNoCredentials {
		t.Fatalf("tampered: %x", byte(st))
	}

	// hmac-secret on a level-1 credential
	_, ad2, _ := e.makeCredential(mcOpts{rp: "example.com", user: "b", ext: map[string]any{"hmac-secret": true}})
	for _, proto := range []int{1, 2} {
		salt := bytes.Repeat([]byte{7}, 32)
		eval := func() []byte {
			pc := e.pinClient(proto)
			se := pc.enc(t, salt)
			ext := map[string]any{"hmac-secret": map[int]any{1: pc.ka, 2: se, 3: pc.p.authenticate(pc.shared, se), 4: proto}}
			st, as, _ := e.getAssertion(gaOpts{rp: "example.com", allow: [][]byte{ad2.credID}, ext: ext}, ad2.pub)
			if st != 0 {
				t.Fatalf("hmac-secret ga: %x", byte(st))
			}
			var enc []byte
			_ = cbor.Unmarshal(as.ad.ext["hmac-secret"], &enc)
			out, err := pc.p.decrypt(pc.shared, enc)
			if err != nil || len(out) != 32 {
				t.Fatalf("decrypt output: %v len %d", err, len(out))
			}
			return out
		}
		o1, o2 := eval(), eval()
		if !bytes.Equal(o1, o2) {
			t.Fatal("hmac-secret not deterministic")
		}
		salt = bytes.Repeat([]byte{8}, 32)
		if bytes.Equal(eval(), o1) {
			t.Fatal("hmac-secret ignores salt")
		}
	}
}

func TestCredentialManagement(t *testing.T) {
	e := newEnv(t)
	e.setPIN(2, "1234")
	_, tok := e.token(2, "1234", permMC, "example.com")
	_, a1, _ := e.makeCredential(mcOpts{rp: "example.com", user: "alice", rk: true, token: tok, proto: 2})
	_, tok = e.token(2, "1234", permMC, "other.org")
	_, _, _ = e.makeCredential(mcOpts{rp: "other.org", user: "bob", rk: true, token: tok, proto: 2})

	_, tok = e.token(2, "1234", permCM, "")
	cm := func(sub int, sp map[int]any) (Status, map[int]cbor.RawMessage) {
		msg := []byte{byte(sub)}
		req := map[int]any{1: sub}
		if sp != nil {
			b, _ := encMode.Marshal(sp)
			msg = append(msg, b...)
			req[2] = cbor.RawMessage(b)
		}
		if sub != 3 && sub != 5 {
			req[3] = 2
			req[4] = pinV2{}.authenticate(tok, msg)
		}
		return e.call(cmdCredentialMgmt, req)
	}
	_, m := cm(1, nil)
	if get[int](t, m, 1) != 2 {
		t.Fatal("metadata count")
	}
	_, m = cm(2, nil)
	if get[int](t, m, 5) != 2 {
		t.Fatal("rp total")
	}
	rp := get[map[string]string](t, m, 3)
	if rp["id"] != "example.com" {
		t.Fatalf("first rp %v", rp)
	}
	_, m = cm(3, nil)
	if get[map[string]string](t, m, 3)["id"] != "other.org" {
		t.Fatal("second rp")
	}
	h := sha256.Sum256([]byte("example.com"))
	st, m := cm(4, map[int]any{1: h[:]})
	if st != 0 || get[int](t, m, 9) != 1 {
		t.Fatalf("enumerate creds: %x", byte(st))
	}
	var pk coseKey
	_ = cbor.Unmarshal(m[8], &pk)
	if new(big.Int).SetBytes(pk.X).Cmp(a1.pub.X) != 0 {
		t.Fatal("public key mismatch")
	}
	// update user info
	if st, _ := cm(7, map[int]any{2: map[string]any{"id": a1.credID, "type": "public-key"}, 3: map[string]any{"id": []byte("alice"), "name": "alice2"}}); st != 0 {
		t.Fatalf("update: %x", byte(st))
	}
	if e.a.store.State.Credentials[e.a.store.Find(a1.credID)].UserName != "alice2" {
		t.Fatal("update not applied")
	}
	// bad auth
	req := map[int]any{1: 1, 3: 2, 4: bytes.Repeat([]byte{0}, 32)}
	if st, _ := e.call(cmdCredentialMgmt, req); st != ErrPINAuthInvalid {
		t.Fatalf("bad auth: %x", byte(st))
	}
	if st, _ := cm(6, map[int]any{2: map[string]any{"id": a1.credID, "type": "public-key"}}); st != 0 {
		t.Fatalf("delete: %x", byte(st))
	}
	_, m = cm(1, nil)
	if get[int](t, m, 1) != 1 {
		t.Fatal("delete not applied")
	}
}

func TestResetInvalidatesEverything(t *testing.T) {
	e := newEnv(t)
	_, ad, _ := e.makeCredential(mcOpts{rp: "example.com", user: "a"})
	e.setPIN(2, "1234")
	if st, _ := e.call(cmdReset, nil); st != 0 {
		t.Fatalf("reset: %x", byte(st))
	}
	if st, _, _ := e.getAssertion(gaOpts{rp: "example.com", allow: [][]byte{ad.credID}}, nil); st != ErrNoCredentials {
		t.Fatalf("old cred after reset: %x", byte(st))
	}
	if e.a.store.State.PINHash != nil {
		t.Fatal("pin survived reset")
	}
}

func TestStatePersistsAcrossRestart(t *testing.T) {
	e := newEnv(t)
	_, ad, _ := e.makeCredential(mcOpts{rp: "example.com", user: "a", rk: true})
	key, _ := StateKey(e.tpm)
	st, err := store.Open(e.path, key)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := New(e.tpm, st, e.pres)
	if err != nil {
		t.Fatal(err)
	}
	e.a = a2
	if st, as, _ := e.getAssertion(gaOpts{rp: "example.com"}, ad.pub); st != 0 || !bytes.Equal(as.credID, ad.credID) {
		t.Fatalf("after restart: %x", byte(st))
	}
}

func TestU2F(t *testing.T) {
	e := newEnv(t)
	chal := bytes.Repeat([]byte{1}, 32)
	app := sha256.Sum256([]byte("https://u2f.example"))
	apdu := func(ins, p1 byte, data []byte) []byte {
		b := []byte{0, ins, p1, 0, 0, byte(len(data) >> 8), byte(len(data))}
		return append(append(b, data...), 0, 0)
	}
	poll := func(req []byte) []byte {
		for i := 0; i < 50; i++ {
			r := e.a.Msg(context.Background(), req)
			if !bytes.Equal(r[len(r)-2:], []byte{0x69, 0x85}) {
				return r
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("presence never satisfied")
		return nil
	}
	if r := e.a.Msg(context.Background(), apdu(3, 0, nil)); string(r[:6]) != "U2F_V2" {
		t.Fatalf("version %x", r)
	}
	r := poll(apdu(1, 0, append(bytes.Clone(chal), app[:]...)))
	if r[0] != 5 || !bytes.Equal(r[len(r)-2:], []byte{0x90, 0}) {
		t.Fatalf("register %x", r)
	}
	pubRaw := r[1:66]
	khLen := int(r[66])
	kh := r[67 : 67+khLen]
	rest := r[67+khLen : len(r)-2]
	cert, err := x509.ParseCertificate(rest[:len(rest)-certSigLen(rest)])
	if err != nil {
		t.Fatal(err)
	}
	certPub := cert.PublicKey.(*ecdsa.PublicKey)
	x, y := elliptic.Unmarshal(elliptic.P256(), pubRaw) //nolint:staticcheck
	if certPub.X.Cmp(x) != 0 || certPub.Y.Cmp(y) != 0 {
		t.Fatal("cert key != credential key")
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		t.Fatalf("self-signed cert: %v", err)
	}

	auth := append(append(append(bytes.Clone(chal), app[:]...), byte(len(kh))), kh...)
	if r := e.a.Msg(context.Background(), apdu(2, 7, auth)); !bytes.Equal(r, []byte{0x69, 0x85}) {
		t.Fatalf("check-only %x", r)
	}
	r = poll(apdu(2, 3, auth))
	if r[0] != 1 {
		t.Fatalf("auth flags %x", r)
	}
	msg := append(append(app[:], r[:5]...), chal...)
	d := sha256.Sum256(msg)
	if !ecdsa.VerifyASN1(certPub, d[:], r[5:len(r)-2]) {
		t.Fatal("u2f signature invalid")
	}
	// wrong app
	other := sha256.Sum256([]byte("https://evil"))
	bad := append(append(append(bytes.Clone(chal), other[:]...), byte(len(kh))), kh...)
	if r := e.a.Msg(context.Background(), apdu(2, 7, bad)); !bytes.Equal(r, []byte{0x6a, 0x80}) {
		t.Fatalf("wrong app %x", r)
	}
	// U2F credentials are usable through CTAP2 with rpId = appid
	h := sha256.Sum256([]byte("https://u2f.example"))
	_ = h
	if st, _, _ := e.getAssertion(gaOpts{rp: "https://u2f.example", allow: [][]byte{kh}}, certPub); st != 0 {
		t.Fatalf("ctap2 over u2f credential: %x", byte(st))
	}
}

// certSigLen returns the length of the trailing DER ECDSA signature.
func certSigLen(b []byte) int {
	// cert is a DER SEQUENCE; its total length tells where the signature starts
	if b[1]&0x80 == 0 {
		return len(b) - 2 - int(b[1])
	}
	n := int(b[1] & 0x7f)
	l := 0
	for i := 0; i < n; i++ {
		l = l<<8 | int(b[2+i])
	}
	return len(b) - 2 - n - l
}

func TestCredentialIDLength(t *testing.T) {
	e := newEnv(t)
	_, ad, _ := e.makeCredential(mcOpts{rp: "example.com", user: "a"})
	if len(ad.credID) != 252 {
		t.Fatalf("credential ID length %d, README says 252", len(ad.credID))
	}
}
