package ctap2

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"io"
	"time"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/hkdf"

	"github.com/monperrus/tpm-fido2/store"
)

// pinProtocol is a PIN/UV auth protocol (CTAP 2.1 §6.5.6, §6.5.7).
type pinProtocol interface {
	kdf(z []byte) []byte
	encrypt(key, pt []byte) ([]byte, error)
	decrypt(key, ct []byte) ([]byte, error)
	authenticate(key, msg []byte) []byte
	verify(key, msg, sig []byte) bool
}

type pinV1 struct{}

func (pinV1) kdf(z []byte) []byte { h := sha256.Sum256(z); return h[:] }
func (pinV1) encrypt(key, pt []byte) ([]byte, error) {
	return cbcEncrypt(key, make([]byte, 16), pt)
}
func (pinV1) decrypt(key, ct []byte) ([]byte, error) {
	return cbcDecrypt(key, make([]byte, 16), ct)
}
func (pinV1) authenticate(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)[:16]
}
func (p pinV1) verify(key, msg, sig []byte) bool {
	return len(sig) == 16 && subtle.ConstantTimeCompare(p.authenticate(key, msg), sig) == 1
}

type pinV2 struct{}

func (pinV2) kdf(z []byte) []byte {
	salt := make([]byte, 32)
	out := make([]byte, 64)
	_, _ = io.ReadFull(hkdf.New(sha256.New, z, salt, []byte("CTAP2 HMAC key")), out[:32])
	_, _ = io.ReadFull(hkdf.New(sha256.New, z, salt, []byte("CTAP2 AES key")), out[32:])
	return out
}
func aesKeyV2(key []byte) []byte {
	if len(key) == 64 {
		return key[32:]
	}
	return key
}
func hmacKeyV2(key []byte) []byte {
	if len(key) == 64 {
		return key[:32]
	}
	return key
}
func (pinV2) encrypt(key, pt []byte) ([]byte, error) {
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	ct, err := cbcEncrypt(aesKeyV2(key), iv, pt)
	if err != nil {
		return nil, err
	}
	return append(iv, ct...), nil
}
func (pinV2) decrypt(key, ct []byte) ([]byte, error) {
	if len(ct) < 16 {
		return nil, ErrInvalidParameter
	}
	return cbcDecrypt(aesKeyV2(key), ct[:16], ct[16:])
}
func (pinV2) authenticate(key, msg []byte) []byte {
	m := hmac.New(sha256.New, hmacKeyV2(key))
	m.Write(msg)
	return m.Sum(nil)
}
func (p pinV2) verify(key, msg, sig []byte) bool {
	return len(sig) == 32 && subtle.ConstantTimeCompare(p.authenticate(key, msg), sig) == 1
}

func cbcEncrypt(key, iv, pt []byte) ([]byte, error) {
	if len(pt)%16 != 0 {
		return nil, ErrInvalidParameter
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(pt))
	cipher.NewCBCEncrypter(b, iv).CryptBlocks(out, pt)
	return out, nil
}

func cbcDecrypt(key, iv, ct []byte) ([]byte, error) {
	if len(ct) == 0 || len(ct)%16 != 0 {
		return nil, ErrInvalidParameter
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(ct))
	cipher.NewCBCDecrypter(b, iv).CryptBlocks(out, ct)
	return out, nil
}

var pinProtocols = map[int]pinProtocol{1: pinV1{}, 2: pinV2{}}

// Permissions of a pinUvAuthToken.
const (
	permMC  = 0x01
	permGA  = 0x02
	permCM  = 0x04
	permBE  = 0x08
	permLBW = 0x10
	permACF = 0x20

	supportedPerms = permMC | permGA | permCM

	tokenLifetime = 10 * time.Minute
)

// coseKey is an EC2 P-256 COSE_Key.
type coseKey struct {
	Kty int    `cbor:"1,keyasint"`
	Alg int    `cbor:"3,keyasint"`
	Crv int    `cbor:"-1,keyasint"`
	X   []byte `cbor:"-2,keyasint"`
	Y   []byte `cbor:"-3,keyasint"`
}

func (a *Authenticator) regenKeyAgreement() {
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	a.keyAgreement = k
}

func (a *Authenticator) resetToken() {
	a.token = make([]byte, 32)
	if _, err := rand.Read(a.token); err != nil {
		panic(err)
	}
	a.tokenValid = false
	a.tokenPerms = 0
	a.tokenRPID = ""
}

// sharedSecret performs ECDH with the platform key and applies the protocol KDF.
func (a *Authenticator) sharedSecret(p pinProtocol, raw cbor.RawMessage) ([]byte, error) {
	if raw == nil {
		return nil, ErrMissingParameter
	}
	var k coseKey
	if err := cbor.Unmarshal(raw, &k); err != nil {
		return nil, ErrInvalidCBOR
	}
	if k.Kty != 2 || k.Crv != 1 || len(k.X) != 32 || len(k.Y) != 32 {
		return nil, ErrInvalidParameter
	}
	pub, err := ecdh.P256().NewPublicKey(append(append([]byte{4}, k.X...), k.Y...))
	if err != nil {
		return nil, ErrInvalidParameter
	}
	z, err := a.keyAgreement.ECDH(pub)
	if err != nil {
		return nil, ErrInvalidParameter
	}
	return p.kdf(z), nil
}

func (a *Authenticator) keyAgreementCOSE() map[int]any {
	b := a.keyAgreement.PublicKey().Bytes() // 0x04 || X || Y
	return map[int]any{1: 2, 3: -25, -1: 1, -2: b[1:33], -3: b[33:65]}
}

// ClientPIN parameter keys.
const (
	cpProtocol     = 1
	cpSubCommand   = 2
	cpKeyAgreement = 3
	cpPinUvAuth    = 4
	cpNewPinEnc    = 5
	cpPinHashEnc   = 6
	cpPermissions  = 9
	cpRPID         = 10
)

func (a *Authenticator) clientPIN(p params) (any, error) {
	sub, err := p.int(cpSubCommand, true)
	if err != nil {
		return nil, err
	}
	var proto pinProtocol
	if sub != 1 { // getPINRetries does not need a protocol
		v, err := p.int(cpProtocol, true)
		if err != nil {
			return nil, err
		}
		var ok bool
		if proto, ok = pinProtocols[v]; !ok {
			return nil, ErrInvalidParameter
		}
	}
	st := &a.store.State
	switch sub {
	case 1: // getPINRetries
		return map[int]any{3: st.PINRetries}, nil
	case 2: // getKeyAgreement
		return map[int]any{1: a.keyAgreementCOSE()}, nil
	case 3: // setPIN
		if st.PINHash != nil {
			return nil, ErrNotAllowed
		}
		shared, err := a.sharedSecret(proto, p[cpKeyAgreement])
		if err != nil {
			return nil, err
		}
		newPinEnc, err := p.bytes(cpNewPinEnc, true)
		if err != nil {
			return nil, err
		}
		auth, err := p.bytes(cpPinUvAuth, true)
		if err != nil {
			return nil, err
		}
		if !proto.verify(shared, newPinEnc, auth) {
			return nil, ErrPINAuthInvalid
		}
		pin, err := decryptNewPIN(proto, shared, newPinEnc)
		if err != nil {
			return nil, err
		}
		h := sha256.Sum256(pin)
		st.PINHash = h[:16]
		st.PINRetries = store.MaxPINRetries
		return nil, a.store.Save()
	case 4: // changePIN
		if st.PINHash == nil {
			return nil, ErrPINNotSet
		}
		shared, err := a.sharedSecret(proto, p[cpKeyAgreement])
		if err != nil {
			return nil, err
		}
		newPinEnc, err := p.bytes(cpNewPinEnc, true)
		if err != nil {
			return nil, err
		}
		pinHashEnc, err := p.bytes(cpPinHashEnc, true)
		if err != nil {
			return nil, err
		}
		auth, err := p.bytes(cpPinUvAuth, true)
		if err != nil {
			return nil, err
		}
		if !proto.verify(shared, append(bytes.Clone(newPinEnc), pinHashEnc...), auth) {
			return nil, ErrPINAuthInvalid
		}
		if err := a.checkPIN(proto, shared, pinHashEnc); err != nil {
			return nil, err
		}
		pin, err := decryptNewPIN(proto, shared, newPinEnc)
		if err != nil {
			return nil, err
		}
		h := sha256.Sum256(pin)
		st.PINHash = h[:16]
		a.resetToken()
		return nil, a.store.Save()
	case 5, 9: // getPinToken, getPinUvAuthTokenUsingPinWithPermissions
		perms := permMC | permGA
		rpID := ""
		if sub == 9 {
			perms, err = p.int(cpPermissions, true)
			if err != nil {
				return nil, err
			}
			if perms == 0 {
				return nil, ErrInvalidParameter
			}
			if perms&^supportedPerms != 0 {
				return nil, ErrUnauthorizedPermission
			}
			rpID, err = p.str(cpRPID, perms&(permMC|permGA) != 0)
			if err != nil {
				return nil, err
			}
		} else if p[cpPermissions] != nil || p[cpRPID] != nil {
			return nil, ErrInvalidParameter
		}
		if st.PINHash == nil {
			return nil, ErrPINNotSet
		}
		shared, err := a.sharedSecret(proto, p[cpKeyAgreement])
		if err != nil {
			return nil, err
		}
		pinHashEnc, err := p.bytes(cpPinHashEnc, true)
		if err != nil {
			return nil, err
		}
		if err := a.checkPIN(proto, shared, pinHashEnc); err != nil {
			return nil, err
		}
		a.resetToken()
		a.tokenValid = true
		a.tokenPerms = byte(perms)
		a.tokenRPID = rpID
		a.tokenExpiry = time.Now().Add(tokenLifetime)
		enc, err := proto.encrypt(shared, a.token)
		if err != nil {
			return nil, err
		}
		return map[int]any{2: enc}, nil
	default:
		return nil, ErrInvalidSubcommand
	}
}

// ErrInvalidSubcommand is CTAP2_ERR_INVALID_SUBCOMMAND.
const ErrInvalidSubcommand Status = 0x3e

func decryptNewPIN(proto pinProtocol, shared, enc []byte) ([]byte, error) {
	padded, err := proto.decrypt(shared, enc)
	if err != nil {
		return nil, err
	}
	if len(padded) < 64 {
		return nil, ErrInvalidParameter
	}
	pin := bytes.TrimRight(padded, "\x00")
	if len(pin) > 63 || !utf8.Valid(pin) || utf8.RuneCount(pin) < minPINLength {
		return nil, ErrPINPolicyViolation
	}
	return pin, nil
}

const minPINLength = 4

// checkPIN verifies an encrypted PIN hash, maintaining the retry counters.
func (a *Authenticator) checkPIN(proto pinProtocol, shared, pinHashEnc []byte) error {
	st := &a.store.State
	if st.PINRetries <= 0 {
		return ErrPINBlocked
	}
	if a.pinConsecutiveFails >= 3 {
		return ErrPINAuthBlocked
	}
	st.PINRetries--
	if err := a.store.Save(); err != nil {
		return err
	}
	ph, err := proto.decrypt(shared, pinHashEnc)
	if err != nil {
		return err
	}
	if len(ph) < 16 || subtle.ConstantTimeCompare(ph[:16], st.PINHash) != 1 {
		a.regenKeyAgreement()
		a.pinConsecutiveFails++
		if st.PINRetries <= 0 {
			return ErrPINBlocked
		}
		if a.pinConsecutiveFails >= 3 {
			return ErrPINAuthBlocked
		}
		return ErrPINInvalid
	}
	st.PINRetries = store.MaxPINRetries
	a.pinConsecutiveFails = 0
	return a.store.Save()
}

// verifyToken checks a pinUvAuthParam against the current pinUvAuthToken,
// its permissions and its RP binding. An unbound token is bound to rpID.
func (a *Authenticator) verifyToken(protoID int, msg, param []byte, perm byte, rpID string) error {
	proto, ok := pinProtocols[protoID]
	if !ok {
		return ErrInvalidParameter
	}
	if !a.tokenValid || time.Now().After(a.tokenExpiry) {
		a.tokenValid = false
		return ErrPINAuthInvalid
	}
	if !proto.verify(a.token, msg, param) {
		return ErrPINAuthInvalid
	}
	if a.tokenPerms&perm == 0 {
		return ErrPINAuthInvalid
	}
	if rpID != "" {
		if a.tokenRPID != "" && a.tokenRPID != rpID {
			return ErrPINAuthInvalid
		}
		if a.tokenRPID == "" && perm&(permMC|permGA) != 0 {
			a.tokenRPID = rpID
		}
	}
	return nil
}
