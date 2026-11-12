package tpmkey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func newSim(t *testing.T) *TPM {
	t.Helper()
	s, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	k := New(s)
	t.Cleanup(func() { k.Close() })
	return k
}

func TestKeyLifecycle(t *testing.T) {
	k := newSim(t)
	bind := sha256.Sum256([]byte("example.com"))
	other := sha256.Sum256([]byte("evil.com"))

	id, pub, err := k.NewKey(bind[:], 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(id) > 255 {
		t.Errorf("credential id too long for U2F: %d", len(id))
	}
	if f, _ := Flags(id); f != 2 {
		t.Errorf("flags = %d", f)
	}
	pub2, err := PublicKey(id)
	if err != nil || !pub.Equal(pub2) {
		t.Fatalf("PublicKey mismatch: %v", err)
	}

	digest := sha256.Sum256([]byte("hello"))
	sig, err := k.Sign(id, bind[:], digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatal("signature does not verify")
	}
	if !k.Check(id, bind[:]) {
		t.Fatal("Check failed on valid credential")
	}

	// negative: wrong binding
	if _, err := k.Sign(id, other[:], digest[:]); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("wrong binding: got %v", err)
	}
	if k.Check(id, other[:]) {
		t.Fatal("Check accepted wrong binding")
	}
	// negative: tampered flags
	bad := bytes.Clone(id)
	bad[1] = 1
	if _, err := k.Sign(bad, bind[:], digest[:]); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("tampered flags: got %v", err)
	}
	// boundary: garbage / truncated
	for _, g := range [][]byte{nil, {1}, id[:len(id)-1], append(bytes.Clone(id), 0)} {
		if _, err := k.Sign(g, bind[:], digest[:]); !errors.Is(err, ErrInvalidCredential) {
			t.Fatalf("garbage %x: got %v", g, err)
		}
	}
}

func TestHMACDeterministic(t *testing.T) {
	k := newSim(t)
	a, err := k.HMAC([]byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := k.HMAC([]byte("x"))
	c, _ := k.HMAC([]byte("y"))
	if !bytes.Equal(a, b) || bytes.Equal(a, c) || len(a) != 32 {
		t.Fatalf("hmac a=%x b=%x c=%x", a, b, c)
	}
}

// TestRealTPM runs against /dev/tpmrm0 when TPMFIDO2_REAL_TPM=1.
func TestRealTPM(t *testing.T) {
	if os.Getenv("TPMFIDO2_REAL_TPM") != "1" {
		t.Skip("set TPMFIDO2_REAL_TPM=1")
	}
	k, err := Open("/dev/tpmrm0")
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	bind := sha256.Sum256([]byte("example.com"))
	start := time.Now()
	id, pub, err := k.NewKey(bind[:], 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("NewKey %v, id len %d", time.Since(start), len(id))
	digest := sha256.Sum256([]byte("hello"))
	start = time.Now()
	sig, err := k.Sign(id, bind[:], digest[:])
	if err != nil || !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatalf("sign: %v", err)
	}
	t.Logf("Sign %v", time.Since(start))
	if _, err := k.HMAC([]byte("x")); err != nil {
		t.Fatal(err)
	}
}
