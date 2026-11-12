// Package tpmkey keeps FIDO credential private keys inside a TPM 2.0.
//
// Each credential gets a random seed. A storage primary key is derived in the
// owner hierarchy from a template whose unique field is HKDF(seed, binding,
// flags), and a P-256 signing key is created under it. The credential ID
// carries the seed, the flags and the TPM-wrapped child key. Loading it under a
// different binding (relying party, reset epoch), with altered flags, or on
// another TPM fails, so a credential ID is useless anywhere else.
//
// A keyed-hash primary with a fixed template gives a TPM-resident HMAC secret,
// used for hmac-secret and for the state encryption key.
package tpmkey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/hkdf"
)

const (
	idVersion = 0x01
	seedLen   = 16
)

// ErrInvalidCredential means the credential ID was not issued by this TPM
// for this binding.
var ErrInvalidCredential = errors.New("invalid credential")

// TPM is a handle on a TPM device. It serialises all TPM commands.
type TPM struct {
	mu sync.Mutex
	t  transport.TPM
	c  io.Closer
}

// Open opens a TPM character device such as /dev/tpmrm0.
func Open(path string) (*TPM, error) {
	t, err := linuxtpm.Open(path)
	if err != nil {
		return nil, err
	}
	return &TPM{t: t, c: t}, nil
}

// New wraps an existing transport (used with the simulator in tests).
func New(t transport.TPMCloser) *TPM { return &TPM{t: t, c: t} }

// Close closes the TPM connection.
func (k *TPM) Close() error { return k.c.Close() }

func parentTemplate(seed, binding []byte, flags byte) tpm2.TPMTPublic {
	info := append([]byte("tpm-fido2 credential v1"), flags)
	info = append(info, binding...)
	r := hkdf.New(sha256.New, seed, nil, info)
	x, y := make([]byte, 32), make([]byte, 32)
	if _, err := io.ReadFull(r, x); err != nil {
		panic(err)
	}
	if _, err := io.ReadFull(r, y); err != nil {
		panic(err)
	}
	t := tpm2.ECCSRKTemplate
	t.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{Buffer: x},
		Y: tpm2.TPM2BECCParameter{Buffer: y},
	})
	return t
}

var childTemplate = tpm2.TPMTPublic{
	Type:    tpm2.TPMAlgECC,
	NameAlg: tpm2.TPMAlgSHA256,
	ObjectAttributes: tpm2.TPMAObject{
		FixedTPM:            true,
		FixedParent:         true,
		SensitiveDataOrigin: true,
		UserWithAuth:        true,
		NoDA:                true,
		SignEncrypt:         true,
	},
	Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
		Scheme: tpm2.TPMTECCScheme{
			Scheme:  tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
		},
		CurveID: tpm2.TPMECCNistP256,
	}),
	Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
		Y: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
	}),
}

var hmacTemplate = tpm2.TPMTPublic{
	Type:    tpm2.TPMAlgKeyedHash,
	NameAlg: tpm2.TPMAlgSHA256,
	ObjectAttributes: tpm2.TPMAObject{
		SignEncrypt:         true,
		FixedTPM:            true,
		FixedParent:         true,
		SensitiveDataOrigin: true,
		UserWithAuth:        true,
		NoDA:                true,
	},
	Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash, &tpm2.TPMSKeyedHashParms{
		Scheme: tpm2.TPMTKeyedHashScheme{
			Scheme:  tpm2.TPMAlgHMAC,
			Details: tpm2.NewTPMUSchemeKeyedHash(tpm2.TPMAlgHMAC, &tpm2.TPMSSchemeHMAC{HashAlg: tpm2.TPMAlgSHA256}),
		},
	}),
	Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgKeyedHash, &tpm2.TPM2BDigest{Buffer: []byte("tpm-fido2 hmac master v1")}),
}

func (k *TPM) flush(h tpm2.TPMHandle) {
	_, _ = tpm2.FlushContext{FlushHandle: h}.Execute(k.t)
}

// cred is a parsed credential ID.
type cred struct {
	flags   byte
	seed    []byte
	private []byte
	public  []byte
}

func (c *cred) marshal() []byte {
	var b bytes.Buffer
	b.WriteByte(idVersion)
	b.WriteByte(c.flags)
	b.Write(c.seed)
	_ = binary.Write(&b, binary.BigEndian, uint16(len(c.private)))
	b.Write(c.private)
	_ = binary.Write(&b, binary.BigEndian, uint16(len(c.public)))
	b.Write(c.public)
	return b.Bytes()
}

func parseCred(id []byte) (*cred, error) {
	r := bytes.NewReader(id)
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil || hdr[0] != idVersion {
		return nil, ErrInvalidCredential
	}
	c := &cred{flags: hdr[1], seed: make([]byte, seedLen)}
	if _, err := io.ReadFull(r, c.seed); err != nil {
		return nil, ErrInvalidCredential
	}
	readLV := func() ([]byte, error) {
		var n uint16
		if err := binary.Read(r, binary.BigEndian, &n); err != nil {
			return nil, err
		}
		b := make([]byte, n)
		_, err := io.ReadFull(r, b)
		return b, err
	}
	var err error
	if c.private, err = readLV(); err != nil {
		return nil, ErrInvalidCredential
	}
	if c.public, err = readLV(); err != nil {
		return nil, ErrInvalidCredential
	}
	if r.Len() != 0 {
		return nil, ErrInvalidCredential
	}
	return c, nil
}

// Flags returns the flags byte embedded in a credential ID (authenticated by
// the TPM at signing time, not here).
func Flags(id []byte) (byte, error) {
	c, err := parseCred(id)
	if err != nil {
		return 0, err
	}
	return c.flags, nil
}

// PublicKey extracts the public key from a credential ID without the TPM.
func PublicKey(id []byte) (*ecdsa.PublicKey, error) {
	c, err := parseCred(id)
	if err != nil {
		return nil, err
	}
	return publicFromBytes(c.public)
}

func publicFromBytes(b []byte) (*ecdsa.PublicKey, error) {
	pub, err := tpm2.Unmarshal[tpm2.TPMTPublic](b)
	if err != nil {
		return nil, ErrInvalidCredential
	}
	parms, err := pub.Parameters.ECCDetail()
	if err != nil {
		return nil, ErrInvalidCredential
	}
	pt, err := pub.Unique.ECC()
	if err != nil {
		return nil, ErrInvalidCredential
	}
	key, err := tpm2.ECDSAPub(parms, pt)
	if err != nil {
		return nil, ErrInvalidCredential
	}
	return key, nil
}

func (k *TPM) createParent(seed, binding []byte, flags byte) (*tpm2.CreatePrimaryResponse, error) {
	return tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(parentTemplate(seed, binding, flags)),
	}.Execute(k.t)
}

// NewKey creates a P-256 credential bound to binding and flags.
func (k *TPM) NewKey(binding []byte, flags byte) ([]byte, *ecdsa.PublicKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	seed := make([]byte, seedLen)
	if _, err := rand.Read(seed); err != nil {
		return nil, nil, err
	}
	parent, err := k.createParent(seed, binding, flags)
	if err != nil {
		return nil, nil, fmt.Errorf("CreatePrimary: %w", err)
	}
	defer k.flush(parent.ObjectHandle)

	rsp, err := tpm2.Create{
		ParentHandle: tpm2.NamedHandle{Handle: parent.ObjectHandle, Name: parent.Name},
		InPublic:     tpm2.New2B(childTemplate),
	}.Execute(k.t)
	if err != nil {
		return nil, nil, fmt.Errorf("Create: %w", err)
	}
	c := &cred{flags: flags, seed: seed, private: rsp.OutPrivate.Buffer, public: rsp.OutPublic.Bytes()}
	pub, err := publicFromBytes(c.public)
	if err != nil {
		return nil, nil, err
	}
	return c.marshal(), pub, nil
}

// Check reports whether the credential ID loads under binding on this TPM.
func (k *TPM) Check(id, binding []byte) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	h, err := k.load(id, binding)
	if err != nil {
		return false
	}
	k.flush(h.Handle)
	return true
}

func (k *TPM) load(id, binding []byte) (*tpm2.NamedHandle, error) {
	c, err := parseCred(id)
	if err != nil {
		return nil, err
	}
	parent, err := k.createParent(c.seed, binding, c.flags)
	if err != nil {
		return nil, fmt.Errorf("CreatePrimary: %w", err)
	}
	defer k.flush(parent.ObjectHandle)
	rsp, err := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{Handle: parent.ObjectHandle, Name: parent.Name},
		InPrivate:    tpm2.TPM2BPrivate{Buffer: c.private},
		InPublic:     tpm2.BytesAs2B[tpm2.TPMTPublic](c.public),
	}.Execute(k.t)
	if err != nil {
		var tpmErr tpm2.TPMRC
		if errors.As(err, &tpmErr) {
			return nil, ErrInvalidCredential
		}
		var fmtErr tpm2.TPMFmt1Error
		if errors.As(err, &fmtErr) {
			return nil, ErrInvalidCredential
		}
		return nil, fmt.Errorf("Load: %w", err)
	}
	return &tpm2.NamedHandle{Handle: rsp.ObjectHandle, Name: rsp.Name}, nil
}

// Sign signs a SHA-256 digest with the credential key and returns an ASN.1
// DER ECDSA signature. It returns ErrInvalidCredential when the ID does not
// belong to this TPM and binding.
func (k *TPM) Sign(id, binding, digest []byte) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	h, err := k.load(id, binding)
	if err != nil {
		return nil, err
	}
	defer k.flush(h.Handle)
	rsp, err := tpm2.Sign{
		KeyHandle: *h,
		Digest:    tpm2.TPM2BDigest{Buffer: digest},
		InScheme: tpm2.TPMTSigScheme{
			Scheme:  tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256}),
		},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck, Hierarchy: tpm2.TPMRHNull},
	}.Execute(k.t)
	if err != nil {
		return nil, fmt.Errorf("Sign: %w", err)
	}
	sig, err := rsp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(new(big.Int).SetBytes(sig.SignatureR.Buffer))
		b.AddASN1BigInt(new(big.Int).SetBytes(sig.SignatureS.Buffer))
	})
	return b.Bytes()
}

// HMAC computes HMAC-SHA256 of data with the TPM-resident master secret,
// which is fixed for a given TPM owner seed.
func (k *TPM) HMAC(data []byte) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	p, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(hmacTemplate),
	}.Execute(k.t)
	if err != nil {
		return nil, fmt.Errorf("CreatePrimary hmac: %w", err)
	}
	defer k.flush(p.ObjectHandle)
	rsp, err := tpm2.Hmac{
		Handle:  tpm2.AuthHandle{Handle: p.ObjectHandle, Name: p.Name, Auth: tpm2.PasswordAuth(nil)},
		Buffer:  tpm2.TPM2BMaxBuffer{Buffer: data},
		HashAlg: tpm2.TPMAlgSHA256,
	}.Execute(k.t)
	if err != nil {
		return nil, fmt.Errorf("HMAC: %w", err)
	}
	return rsp.OutHMAC.Buffer, nil
}
