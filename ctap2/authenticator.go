// Package ctap2 implements a FIDO2 authenticator (CTAP 2.1) and its CTAP1/U2F
// compatibility layer on top of TPM-held keys.
package ctap2

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/monperrus/tpm-fido2/ctaphid"
	"github.com/monperrus/tpm-fido2/store"
	"github.com/monperrus/tpm-fido2/tpmkey"
)

// AAGUID identifies this authenticator model.
var AAGUID = [16]byte{0x74, 0x70, 0x6d, 0x2d, 0x66, 0x69, 0x64, 0x6f, 0x32, 0x00, 0x8a, 0x3c, 0x51, 0x0e, 0x4b, 0x21}

// Keys is the TPM key service.
type Keys interface {
	NewKey(binding []byte, flags byte) ([]byte, *ecdsa.PublicKey, error)
	Sign(id, binding, digest []byte) ([]byte, error)
	HMAC(data []byte) ([]byte, error)
}

// ErrPresenceTimeout is returned by Presence when the user did not answer.
var ErrPresenceTimeout = errors.New("user presence timeout")

// Presence asks the user to confirm an operation.
type Presence interface {
	// Confirm returns true if the user approved, false if they declined,
	// ErrPresenceTimeout on timeout, or ctx.Err() when cancelled.
	Confirm(ctx context.Context, prompt string) (bool, error)
}

// Authenticator is a CTAP2 authenticator. It implements ctaphid.Handler.
type Authenticator struct {
	mu       sync.Mutex
	keys     Keys
	store    *store.Store
	presence Presence

	macKey        []byte // credential ID tags
	hmacSecretKey []byte // hmac-secret CredRandom derivation

	keyAgreement        *ecdh.PrivateKey
	token               []byte
	tokenValid          bool
	tokenPerms          byte
	tokenRPID           string
	tokenExpiry         time.Time
	pinConsecutiveFails int

	next     *pendingAssertions
	rpEnum   []string
	credEnum []store.Credential

	u2f u2fPresence

	// Debug logs every request (CBOR diagnostic notation) and its status.
	Debug bool
}

// New creates an Authenticator. It derives its software keys from the TPM's
// HMAC secret.
func New(keys Keys, st *store.Store, presence Presence) (*Authenticator, error) {
	a := &Authenticator{keys: keys, store: st, presence: presence}
	var err error
	if a.macKey, err = keys.HMAC([]byte("tpm-fido2 credential id mac v1")); err != nil {
		return nil, err
	}
	if a.hmacSecretKey, err = keys.HMAC([]byte("tpm-fido2 hmac-secret v1")); err != nil {
		return nil, err
	}
	a.regenKeyAgreement()
	a.resetToken()
	return a, nil
}

// StateKey derives the state-file encryption key from the TPM.
func StateKey(keys Keys) ([]byte, error) {
	return keys.HMAC([]byte("tpm-fido2 state key v1"))
}

// Command codes.
const (
	cmdMakeCredential     = 0x01
	cmdGetAssertion       = 0x02
	cmdGetInfo            = 0x04
	cmdClientPIN          = 0x06
	cmdReset              = 0x07
	cmdGetNextAssertion   = 0x08
	cmdCredentialMgmt     = 0x0a
	cmdSelection          = 0x0b
	cmdCredentialMgmtPrev = 0x41
)

var encMode, _ = cbor.CTAP2EncOptions().EncMode()

// CBOR implements ctaphid.Handler.
func (a *Authenticator) CBOR(ctx context.Context, req []byte, setStatus func(byte)) []byte {
	resp := a.handleCBOR(ctx, req, setStatus)
	if a.Debug && len(req) > 0 {
		diag := ""
		if len(req) > 1 {
			diag, _ = cbor.Diagnose(req[1:])
		}
		log.Printf("debug: ctap2 cmd=0x%02x status=0x%02x req=%s", req[0], resp[0], diag)
	}
	return resp
}

func (a *Authenticator) handleCBOR(ctx context.Context, req []byte, setStatus func(byte)) []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(req) == 0 {
		return []byte{byte(ErrInvalidLength)}
	}
	cmd := req[0]
	p, err := parseParams(req[1:])
	if err != nil {
		return []byte{byte(statusOf(err))}
	}
	if cmd != cmdGetNextAssertion {
		a.next = nil
	}
	if cmd != cmdCredentialMgmt && cmd != cmdCredentialMgmtPrev {
		a.rpEnum, a.credEnum = nil, nil
	}
	var resp any
	switch cmd {
	case cmdGetInfo:
		resp, err = a.getInfo(), nil
	case cmdMakeCredential:
		resp, err = a.makeCredential(ctx, p, setStatus)
	case cmdGetAssertion:
		resp, err = a.getAssertion(ctx, p, setStatus)
	case cmdGetNextAssertion:
		resp, err = a.getNextAssertion()
	case cmdClientPIN:
		resp, err = a.clientPIN(p)
	case cmdReset:
		err = a.reset(ctx, setStatus)
	case cmdCredentialMgmt, cmdCredentialMgmtPrev:
		resp, err = a.credentialManagement(p)
	case cmdSelection:
		err = a.userPresence(ctx, setStatus, "Select this tpm-fido2 security key?")
	default:
		err = ErrInvalidCommand
	}
	if err != nil {
		var s Status
		if !errors.As(err, &s) {
			log.Printf("ctap2: command 0x%02x: %v", cmd, err)
		}
		return []byte{byte(statusOf(err))}
	}
	if resp == nil {
		return []byte{0}
	}
	b, err := encMode.Marshal(resp)
	if err != nil {
		log.Printf("ctap2: encode: %v", err)
		return []byte{byte(ErrOther)}
	}
	return append([]byte{0}, b...)
}

func statusOf(err error) Status {
	var s Status
	if errors.As(err, &s) {
		return s
	}
	return ErrOther
}

// params is a CTAP2 request map with integer keys, values kept raw so that
// authenticated sub-structures can be MACed exactly as sent.
type params map[int]cbor.RawMessage

func parseParams(b []byte) (params, error) {
	p := params{}
	if len(b) == 0 {
		return p, nil
	}
	if err := cbor.Unmarshal(b, (*map[int]cbor.RawMessage)(&p)); err != nil {
		return nil, ErrInvalidCBOR
	}
	return p, nil
}

func (p params) decode(k int, v any, required bool) (bool, error) {
	raw, ok := p[k]
	if !ok {
		if required {
			return false, ErrMissingParameter
		}
		return false, nil
	}
	if err := cbor.Unmarshal(raw, v); err != nil {
		return false, ErrCBORUnexpectedType
	}
	return true, nil
}

func (p params) int(k int, required bool) (int, error) {
	var v int
	_, err := p.decode(k, &v, required)
	return v, err
}

func (p params) str(k int, required bool) (string, error) {
	var v string
	_, err := p.decode(k, &v, required)
	return v, err
}

func (p params) bytes(k int, required bool) ([]byte, error) {
	var v []byte
	_, err := p.decode(k, &v, required)
	return v, err
}

func (a *Authenticator) getInfo() map[int]any {
	return map[int]any{
		1: []string{"U2F_V2", "FIDO_2_0", "FIDO_2_1"},
		2: []string{"credProtect", "hmac-secret"},
		3: AAGUID[:],
		4: map[string]bool{
			"rk":               true,
			"up":               true,
			"plat":             false,
			"clientPin":        a.store.State.PINHash != nil,
			"credMgmt":         true,
			"pinUvAuthToken":   true,
			"makeCredUvNotRqd": true,
		},
		5:    1200,
		6:    []int{2, 1},
		7:    8,
		8:    256,
		9:    []string{"usb"},
		10:   []map[string]any{{"alg": -7, "type": "public-key"}},
		0x0c: false,
		0x0d: minPINLength,
		0x0e: 1,
	}
}

// userPresence asks for a touch-equivalent confirmation.
func (a *Authenticator) userPresence(ctx context.Context, setStatus func(byte), prompt string) error {
	setStatus(ctaphid.StatusUPNeeded)
	defer setStatus(ctaphid.StatusProcessing)
	ok, err := a.presence.Confirm(ctx, prompt)
	switch {
	case ctx.Err() != nil:
		return ErrKeepaliveCancel
	case errors.Is(err, ErrPresenceTimeout):
		return ErrUserActionTimeout
	case err != nil:
		log.Printf("presence: %v", err)
		return ErrOperationDenied
	case !ok:
		return ErrOperationDenied
	}
	return nil
}

// binding ties a credential to the RP and the current reset epoch.
func (a *Authenticator) binding(rpIDHash []byte) []byte {
	h := sha256.New()
	h.Write([]byte("tpm-fido2 binding v1"))
	h.Write(a.store.State.Epoch)
	h.Write(rpIDHash)
	return h.Sum(nil)
}

const tagLen = 16

func (a *Authenticator) tag(binding, tpmID []byte) []byte {
	m := hmac.New(sha256.New, a.macKey)
	m.Write(binding)
	m.Write(tpmID)
	return m.Sum(nil)[:tagLen]
}

// wrapID appends an authentication tag to a TPM credential blob.
func (a *Authenticator) wrapID(binding, tpmID []byte) []byte {
	return append(bytes.Clone(tpmID), a.tag(binding, tpmID)...)
}

// unwrapID checks the tag of a credential ID for this RP and returns the TPM
// blob, or nil if the ID is not ours.
func (a *Authenticator) unwrapID(binding, id []byte) []byte {
	if len(id) <= tagLen {
		return nil
	}
	tpmID, tag := id[:len(id)-tagLen], id[len(id)-tagLen:]
	if !hmac.Equal(tag, a.tag(binding, tpmID)) {
		return nil
	}
	return tpmID
}

func credProtectOf(tpmID []byte) int {
	f, err := tpmkey.Flags(tpmID)
	if err != nil || f < 1 || f > 3 {
		return 1
	}
	return int(f)
}

func coseES256(pub *ecdsa.PublicKey) map[int]any {
	x := pub.X.FillBytes(make([]byte, 32))
	y := pub.Y.FillBytes(make([]byte, 32))
	return map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y}
}

const (
	flagUP = 0x01
	flagUV = 0x04
	flagAT = 0x40
	flagED = 0x80
)

type rpEntity struct {
	ID   string `cbor:"id"`
	Name string `cbor:"name,omitempty"`
}

type userEntity struct {
	ID          []byte `cbor:"id"`
	Name        string `cbor:"name,omitempty"`
	DisplayName string `cbor:"displayName,omitempty"`
}

type credDescriptor struct {
	ID   []byte `cbor:"id"`
	Type string `cbor:"type"`
}

// checkPinUvAuthParam handles the common pinUvAuthParam preamble of
// makeCredential / getAssertion. It returns uv=true when a valid token was
// presented.
func (a *Authenticator) checkPinUvAuthParam(ctx context.Context, setStatus func(byte), p params, kParam, kProto int, cdh []byte, perm byte, rpID string) (bool, error) {
	raw, present := p[kParam]
	if !present {
		return false, nil
	}
	var param []byte
	if err := cbor.Unmarshal(raw, &param); err != nil {
		return false, ErrCBORUnexpectedType
	}
	if len(param) == 0 {
		// Platform probing for a touch (authenticator selection).
		if err := a.userPresence(ctx, setStatus, "Use this tpm-fido2 security key?"); err != nil {
			return false, err
		}
		if a.store.State.PINHash == nil {
			return false, ErrPINNotSet
		}
		return false, ErrPINInvalid
	}
	proto, err := p.int(kProto, true)
	if err != nil {
		return false, err
	}
	if _, ok := pinProtocols[proto]; !ok {
		return false, ErrInvalidParameter
	}
	if err := a.verifyToken(proto, cdh, param, perm, rpID); err != nil {
		return false, err
	}
	return true, nil
}

func (a *Authenticator) makeCredential(ctx context.Context, p params, setStatus func(byte)) (any, error) {
	cdh, err := p.bytes(1, true)
	if err != nil {
		return nil, err
	}
	var rp rpEntity
	if _, err := p.decode(2, &rp, true); err != nil {
		return nil, err
	}
	var user userEntity
	if _, err := p.decode(3, &user, true); err != nil {
		return nil, err
	}
	var algs []struct {
		Alg  int    `cbor:"alg"`
		Type string `cbor:"type"`
	}
	if _, err := p.decode(4, &algs, true); err != nil {
		return nil, err
	}
	var exclude []credDescriptor
	if _, err := p.decode(5, &exclude, false); err != nil {
		return nil, err
	}
	var exts map[string]cbor.RawMessage
	if _, err := p.decode(6, &exts, false); err != nil {
		return nil, err
	}
	var opts map[string]bool
	if _, err := p.decode(7, &opts, false); err != nil {
		return nil, err
	}
	if p[0x0a] != nil {
		return nil, ErrInvalidParameter // enterprise attestation unsupported
	}

	uv, err := a.checkPinUvAuthParam(ctx, setStatus, p, 8, 9, cdh, permMC, rp.ID)
	if err != nil {
		return nil, err
	}
	es256 := false
	for _, al := range algs {
		if al.Type == "public-key" && al.Alg == -7 {
			es256 = true
		}
	}
	if !es256 {
		return nil, ErrUnsupportedAlgorithm
	}
	rk := opts["rk"]
	if v, ok := opts["up"]; ok && !v {
		return nil, ErrInvalidOption
	}
	if opts["uv"] && !uv {
		return nil, ErrInvalidOption // no built-in user verification
	}
	if !uv && a.store.State.PINHash != nil && rk {
		return nil, ErrPUATRequired
	}

	credProtect := 0
	if raw, ok := exts["credProtect"]; ok {
		if err := cbor.Unmarshal(raw, &credProtect); err != nil || credProtect < 1 || credProtect > 3 {
			return nil, ErrInvalidParameter
		}
	}
	hmacSecret := false
	if raw, ok := exts["hmac-secret"]; ok {
		if err := cbor.Unmarshal(raw, &hmacSecret); err != nil {
			return nil, ErrCBORUnexpectedType
		}
	}

	rpIDHash := sha256.Sum256([]byte(rp.ID))
	bind := a.binding(rpIDHash[:])
	for _, c := range exclude {
		tpmID := a.unwrapID(bind, c.ID)
		if tpmID == nil {
			continue
		}
		if credProtectOf(tpmID) == 3 && !uv {
			continue
		}
		if err := a.userPresence(ctx, setStatus, fmt.Sprintf("Confirm: %s, this security key is already registered", rp.ID)); err != nil {
			return nil, err
		}
		return nil, ErrCredentialExcluded
	}

	if !rk && rp.ID == ".dummy" {
		// Chrome's "touch any key" probe.
		if err := a.userPresence(ctx, setStatus, "Use this tpm-fido2 security key?"); err != nil {
			return nil, err
		}
	} else {
		who := user.Name
		if who == "" {
			who = user.DisplayName
		}
		kind := "a security key credential"
		if rk {
			kind = "a passkey"
		}
		if err := a.userPresence(ctx, setStatus, fmt.Sprintf("Create %s for %s (%s)?", kind, rp.ID, who)); err != nil {
			return nil, err
		}
	}

	level := credProtect
	if level == 0 {
		level = 1
	}
	tpmID, pub, err := a.keys.NewKey(bind, byte(level))
	if err != nil {
		return nil, err
	}
	credID := a.wrapID(bind, tpmID)
	if rk {
		if err := a.store.Put(store.Credential{
			ID: credID, RPID: rp.ID, RPName: rp.Name, UserID: user.ID,
			UserName: user.Name, DisplayName: user.DisplayName,
			CredProtect: level, Created: time.Now().UTC(),
		}); err != nil {
			return nil, err
		}
	}

	extOut := map[string]any{}
	if credProtect != 0 {
		extOut["credProtect"] = credProtect
	}
	if hmacSecret {
		extOut["hmac-secret"] = true
	}
	counter, err := a.store.NextCounter()
	if err != nil {
		return nil, err
	}
	flags := byte(flagUP | flagAT)
	if uv {
		flags |= flagUV
	}
	var ad bytes.Buffer
	ad.Write(rpIDHash[:])
	if len(extOut) > 0 {
		flags |= flagED
	}
	ad.WriteByte(flags)
	_ = binary.Write(&ad, binary.BigEndian, counter)
	ad.Write(AAGUID[:])
	_ = binary.Write(&ad, binary.BigEndian, uint16(len(credID)))
	ad.Write(credID)
	pk, _ := encMode.Marshal(coseES256(pub))
	ad.Write(pk)
	if len(extOut) > 0 {
		e, _ := encMode.Marshal(extOut)
		ad.Write(e)
	}
	authData := ad.Bytes()

	digest := sha256.Sum256(append(bytes.Clone(authData), cdh...))
	sig, err := a.keys.Sign(tpmID, bind, digest[:])
	if err != nil {
		return nil, err
	}
	return map[int]any{
		1: "packed",
		2: authData,
		3: map[string]any{"alg": -7, "sig": sig},
	}, nil
}

type assertionCred struct {
	id    []byte // full credential ID
	tpmID []byte
	user  *store.Credential
}

type pendingAssertions struct {
	creds    []assertionCred
	rpIDHash []byte
	bind     []byte
	cdh      []byte
	flags    byte
	uv       bool
	hmacExt  *hmacSecretInput
	expires  time.Time
}

type hmacSecretInput struct {
	shared  []byte
	proto   pinProtocol
	saltEnc []byte
}

func (a *Authenticator) getAssertion(ctx context.Context, p params, setStatus func(byte)) (any, error) {
	rpID, err := p.str(1, true)
	if err != nil {
		return nil, err
	}
	cdh, err := p.bytes(2, true)
	if err != nil {
		return nil, err
	}
	var allow []credDescriptor
	if _, err := p.decode(3, &allow, false); err != nil {
		return nil, err
	}
	var exts map[string]cbor.RawMessage
	if _, err := p.decode(4, &exts, false); err != nil {
		return nil, err
	}
	var opts map[string]bool
	if _, err := p.decode(5, &opts, false); err != nil {
		return nil, err
	}
	uv, err := a.checkPinUvAuthParam(ctx, setStatus, p, 6, 7, cdh, permGA, rpID)
	if err != nil {
		return nil, err
	}
	if opts["uv"] && !uv {
		return nil, ErrUnsupportedOption
	}
	if _, ok := opts["rk"]; ok {
		return nil, ErrUnsupportedOption
	}
	up := true
	if v, ok := opts["up"]; ok {
		up = v
	}

	var hmacIn *hmacSecretInput
	if raw, ok := exts["hmac-secret"]; ok {
		hmacIn, err = a.parseHMACSecret(raw)
		if err != nil {
			return nil, err
		}
	}

	rpIDHash := sha256.Sum256([]byte(rpID))
	bind := a.binding(rpIDHash[:])
	var creds []assertionCred
	if len(allow) > 0 {
		for _, c := range allow {
			tpmID := a.unwrapID(bind, c.ID)
			if tpmID == nil {
				continue
			}
			if credProtectOf(tpmID) == 3 && !uv {
				continue
			}
			ac := assertionCred{id: c.ID, tpmID: tpmID}
			if i := a.store.Find(c.ID); i >= 0 {
				u := a.store.State.Credentials[i]
				ac.user = &u
			}
			creds = append(creds, ac)
			break
		}
	} else {
		var found []store.Credential
		for _, c := range a.store.State.Credentials {
			if c.RPID != rpID {
				continue
			}
			if c.CredProtect >= 2 && !uv {
				continue
			}
			found = append(found, c)
		}
		sort.SliceStable(found, func(i, j int) bool { return found[i].Created.After(found[j].Created) })
		for i := range found {
			tpmID := a.unwrapID(bind, found[i].ID)
			if tpmID == nil {
				continue // stale entry from a previous epoch
			}
			creds = append(creds, assertionCred{id: found[i].ID, tpmID: tpmID, user: &found[i]})
		}
	}
	if len(creds) == 0 {
		return nil, ErrNoCredentials
	}

	if up {
		prompt := "Sign in to " + rpID + "?"
		if len(creds) == 1 && creds[0].user != nil && creds[0].user.UserName != "" {
			prompt = fmt.Sprintf("Sign in to %s as %s?", rpID, creds[0].user.UserName)
		}
		if err := a.userPresence(ctx, setStatus, prompt); err != nil {
			return nil, err
		}
	}
	var flags byte
	if up {
		flags |= flagUP
	}
	if uv {
		flags |= flagUV
	}
	pa := &pendingAssertions{
		creds: creds, rpIDHash: rpIDHash[:], bind: bind, cdh: cdh,
		flags: flags, uv: uv, hmacExt: hmacIn, expires: time.Now().Add(30 * time.Second),
	}
	resp, err := a.assert(pa, 0, len(allow) == 0)
	if err != nil {
		return nil, err
	}
	if len(allow) == 0 {
		resp[5] = len(creds)
		if len(creds) > 1 {
			a.next = pa
			pa.creds = pa.creds[1:]
		}
	}
	return resp, nil
}

func (a *Authenticator) getNextAssertion() (any, error) {
	pa := a.next
	if pa == nil || len(pa.creds) == 0 || time.Now().After(pa.expires) {
		a.next = nil
		return nil, ErrNotAllowed
	}
	resp, err := a.assert(pa, 0, true)
	if err != nil {
		return nil, err
	}
	pa.creds = pa.creds[1:]
	pa.expires = time.Now().Add(30 * time.Second)
	if len(pa.creds) == 0 {
		a.next = nil
	}
	return resp, nil
}

// assert signs an assertion for pa.creds[i].
func (a *Authenticator) assert(pa *pendingAssertions, i int, discoverable bool) (map[int]any, error) {
	c := pa.creds[i]
	extOut := map[string]any{}
	if pa.hmacExt != nil {
		out, err := a.hmacSecret(pa.hmacExt, c.id, pa.uv)
		if err != nil {
			return nil, err
		}
		extOut["hmac-secret"] = out
	}
	counter, err := a.store.NextCounter()
	if err != nil {
		return nil, err
	}
	flags := pa.flags
	if len(extOut) > 0 {
		flags |= flagED
	}
	var ad bytes.Buffer
	ad.Write(pa.rpIDHash)
	ad.WriteByte(flags)
	_ = binary.Write(&ad, binary.BigEndian, counter)
	if len(extOut) > 0 {
		e, _ := encMode.Marshal(extOut)
		ad.Write(e)
	}
	authData := ad.Bytes()
	digest := sha256.Sum256(append(bytes.Clone(authData), pa.cdh...))
	sig, err := a.keys.Sign(c.tpmID, pa.bind, digest[:])
	if errors.Is(err, tpmkey.ErrInvalidCredential) {
		return nil, ErrInvalidCredential
	}
	if err != nil {
		return nil, err
	}
	resp := map[int]any{
		1: map[string]any{"id": c.id, "type": "public-key"},
		2: authData,
		3: sig,
	}
	if c.user != nil {
		u := map[string]any{"id": c.user.UserID}
		if discoverable && pa.uv {
			if c.user.UserName != "" {
				u["name"] = c.user.UserName
			}
			if c.user.DisplayName != "" {
				u["displayName"] = c.user.DisplayName
			}
		}
		resp[4] = u
	}
	return resp, nil
}

func (a *Authenticator) parseHMACSecret(raw cbor.RawMessage) (*hmacSecretInput, error) {
	var m map[int]cbor.RawMessage
	if err := cbor.Unmarshal(raw, &m); err != nil {
		return nil, ErrCBORUnexpectedType
	}
	p := params(m)
	protoID := 1
	if _, ok := p[4]; ok {
		var err error
		if protoID, err = p.int(4, true); err != nil {
			return nil, err
		}
	}
	proto, ok := pinProtocols[protoID]
	if !ok {
		return nil, ErrInvalidParameter
	}
	shared, err := a.sharedSecret(proto, p[1])
	if err != nil {
		return nil, err
	}
	saltEnc, err := p.bytes(2, true)
	if err != nil {
		return nil, err
	}
	saltAuth, err := p.bytes(3, true)
	if err != nil {
		return nil, err
	}
	if !proto.verify(shared, saltEnc, saltAuth) {
		return nil, ErrPINAuthInvalid // CTAP2_ERR_EXTENSION_FIRST in some versions
	}
	return &hmacSecretInput{shared: shared, proto: proto, saltEnc: saltEnc}, nil
}

func (a *Authenticator) hmacSecret(in *hmacSecretInput, credID []byte, uv bool) ([]byte, error) {
	salts, err := in.proto.decrypt(in.shared, in.saltEnc)
	if err != nil {
		return nil, err
	}
	if len(salts) != 32 && len(salts) != 64 {
		return nil, ErrInvalidLength
	}
	m := hmac.New(sha256.New, a.hmacSecretKey)
	if uv {
		m.Write([]byte{1})
	} else {
		m.Write([]byte{0})
	}
	m.Write(credID)
	credRandom := m.Sum(nil)
	var out []byte
	for i := 0; i < len(salts); i += 32 {
		h := hmac.New(sha256.New, credRandom)
		h.Write(salts[i : i+32])
		out = append(out, h.Sum(nil)...)
	}
	return in.proto.encrypt(in.shared, out)
}

func (a *Authenticator) reset(ctx context.Context, setStatus func(byte)) error {
	if err := a.userPresence(ctx, setStatus, "RESET tpm-fido2? This deletes ALL passkeys and invalidates ALL credentials of this key."); err != nil {
		return err
	}
	if err := a.store.Reset(); err != nil {
		return err
	}
	a.regenKeyAgreement()
	a.resetToken()
	a.pinConsecutiveFails = 0
	return nil
}
