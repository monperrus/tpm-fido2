package ctap2

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"io"
	"log"
	"math/big"
	"sync"
	"time"
)

// U2F status words.
const (
	swNoError          = 0x9000
	swConditionsNotMet = 0x6985
	swWrongData        = 0x6a80
	swWrongLength      = 0x6700
	swClaNotSupported  = 0x6e00
	swInsNotSupported  = 0x6d00
)

// u2fPresence implements the U2F polling model: the first request starts a
// confirmation prompt and gets "conditions not satisfied"; the browser keeps
// retrying and gets the result once the user answered.
type u2fPresence struct {
	mu         sync.Mutex
	key        [64]byte
	pending    bool
	approved   bool
	answeredAt time.Time
}

func (a *Authenticator) u2fCheckPresence(key [64]byte, prompt string) bool {
	u := &a.u2f
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.key == key && !u.pending && time.Since(u.answeredAt) < 10*time.Second {
		ok := u.approved
		u.answeredAt = time.Time{}
		u.key = [64]byte{}
		return ok
	}
	if u.pending {
		return false
	}
	u.pending = true
	u.key = key
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		ok, err := a.presence.Confirm(ctx, prompt)
		if err != nil {
			log.Printf("u2f presence: %v", err)
		}
		u.mu.Lock()
		u.pending = false
		u.approved = ok && err == nil
		u.answeredAt = time.Now()
		u.mu.Unlock()
	}()
	return false
}

func sw(data []byte, status uint16) []byte {
	return binary.BigEndian.AppendUint16(data, status)
}

// Msg implements ctaphid.Handler for CTAP1/U2F APDUs.
func (a *Authenticator) Msg(ctx context.Context, req []byte) []byte {
	resp := a.handleMsg(req)
	if a.Debug && len(req) >= 4 {
		log.Printf("debug: u2f ins=0x%02x p1=0x%02x sw=%x", req[1], req[2], resp[len(resp)-2:])
	}
	return resp
}

func (a *Authenticator) handleMsg(req []byte) []byte {
	if len(req) < 4 {
		return sw(nil, swWrongLength)
	}
	cla, ins, p1 := req[0], req[1], req[2]
	if cla != 0 {
		return sw(nil, swClaNotSupported)
	}
	var data []byte
	switch {
	case len(req) == 4:
	case req[4] == 0 && len(req) >= 7: // extended length
		n := int(binary.BigEndian.Uint16(req[5:7]))
		if len(req) < 7+n {
			return sw(nil, swWrongLength)
		}
		data = req[7 : 7+n]
	default:
		n := int(req[4])
		if len(req) < 5+n {
			return sw(nil, swWrongLength)
		}
		data = req[5 : 5+n]
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	switch ins {
	case 0x01:
		return a.u2fRegister(data)
	case 0x02:
		return a.u2fAuthenticate(p1, data)
	case 0x03:
		return sw([]byte("U2F_V2"), swNoError)
	default:
		return sw(nil, swInsNotSupported)
	}
}

func (a *Authenticator) u2fRegister(data []byte) []byte {
	if len(data) != 64 {
		return sw(nil, swWrongLength)
	}
	chal, app := data[:32], data[32:]
	var key [64]byte
	copy(key[:], data)
	if !a.u2fCheckPresence(key, "Register this security key with a U2F site (app "+hex.EncodeToString(app[:4])+"…)?") {
		return sw(nil, swConditionsNotMet)
	}
	bind := a.binding(app)
	tpmID, pub, err := a.keys.NewKey(bind, 1)
	if err != nil {
		log.Printf("u2f register: %v", err)
		return sw(nil, swWrongData)
	}
	kh := a.wrapID(bind, tpmID)
	if len(kh) > 255 {
		log.Printf("u2f register: key handle too long (%d)", len(kh))
		return sw(nil, swWrongData)
	}
	signer := &tpmSigner{a: a, tpmID: tpmID, bind: bind, pub: pub}
	cert, err := selfSignedCert(signer)
	if err != nil {
		log.Printf("u2f register cert: %v", err)
		return sw(nil, swWrongData)
	}
	pubRaw := elliptic.Marshal(elliptic.P256(), pub.X, pub.Y) //nolint:staticcheck // uncompressed point is the U2F wire format
	var msg bytes.Buffer
	msg.WriteByte(0)
	msg.Write(app)
	msg.Write(chal)
	msg.Write(kh)
	msg.Write(pubRaw)
	digest := sha256.Sum256(msg.Bytes())
	sig, err := a.keys.Sign(tpmID, bind, digest[:])
	if err != nil {
		log.Printf("u2f register sign: %v", err)
		return sw(nil, swWrongData)
	}
	var out bytes.Buffer
	out.WriteByte(0x05)
	out.Write(pubRaw)
	out.WriteByte(byte(len(kh)))
	out.Write(kh)
	out.Write(cert)
	out.Write(sig)
	return sw(out.Bytes(), swNoError)
}

func (a *Authenticator) u2fAuthenticate(p1 byte, data []byte) []byte {
	if len(data) < 65 || len(data) != 65+int(data[64]) {
		return sw(nil, swWrongLength)
	}
	chal, app, kh := data[:32], data[32:64], data[65:]
	bind := a.binding(app)
	tpmID := a.unwrapID(bind, kh)
	if tpmID == nil {
		return sw(nil, swWrongData)
	}
	var flags byte
	switch p1 {
	case 0x07: // check-only
		return sw(nil, swConditionsNotMet)
	case 0x03: // enforce-user-presence-and-sign
		var key [64]byte
		copy(key[:], data[:64])
		if !a.u2fCheckPresence(key, "Sign in to a U2F site (app "+hex.EncodeToString(app[:4])+"…)?") {
			return sw(nil, swConditionsNotMet)
		}
		flags = flagUP
	case 0x08: // dont-enforce-user-presence-and-sign
	default:
		return sw(nil, swWrongData)
	}
	counter, err := a.store.NextCounter()
	if err != nil {
		log.Printf("u2f counter: %v", err)
		return sw(nil, swWrongData)
	}
	var msg bytes.Buffer
	msg.Write(app)
	msg.WriteByte(flags)
	_ = binary.Write(&msg, binary.BigEndian, counter)
	msg.Write(chal)
	digest := sha256.Sum256(msg.Bytes())
	sig, err := a.keys.Sign(tpmID, bind, digest[:])
	if err != nil {
		log.Printf("u2f sign: %v", err)
		return sw(nil, swWrongData)
	}
	out := []byte{flags}
	out = binary.BigEndian.AppendUint32(out, counter)
	return sw(append(out, sig...), swNoError)
}

// tpmSigner is a crypto.Signer backed by a TPM credential key.
type tpmSigner struct {
	a     *Authenticator
	tpmID []byte
	bind  []byte
	pub   *ecdsa.PublicKey
}

func (s *tpmSigner) Public() crypto.PublicKey { return s.pub }
func (s *tpmSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	return s.a.keys.Sign(s.tpmID, s.bind, digest)
}

// selfSignedCert makes a per-credential self-signed attestation certificate,
// so U2F registrations reveal nothing shared across sites.
func selfSignedCert(s crypto.Signer) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:       serial,
		Subject:            pkix.Name{CommonName: "tpm-fido2"},
		NotBefore:          time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:           time.Date(2050, 1, 1, 0, 0, 0, 0, time.UTC),
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	return x509.CreateCertificate(rand.Reader, tmpl, tmpl, s.Public(), s)
}
