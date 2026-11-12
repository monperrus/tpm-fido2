// Package store persists authenticator state: discoverable credential
// metadata, the PIN hash and retry counter, the signature counter and the
// reset epoch. The file is encrypted with AES-256-GCM under a key that the
// caller derives from the TPM, so it is unreadable on any other machine.
package store

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

var magic = []byte("TPMFIDO2\x01")

// Credential is a discoverable credential (passkey). The private key is in
// the TPM; ID is the TPM-wrapped credential ID.
type Credential struct {
	ID          []byte    `json:"id"`
	RPID        string    `json:"rp_id"`
	RPName      string    `json:"rp_name,omitempty"`
	UserID      []byte    `json:"user_id"`
	UserName    string    `json:"user_name,omitempty"`
	DisplayName string    `json:"display_name,omitempty"`
	CredProtect int       `json:"cred_protect"`
	Created     time.Time `json:"created"`
}

// State is the whole persisted state.
type State struct {
	// Epoch is mixed into every credential binding; Reset replaces it,
	// invalidating all credentials, discoverable or not.
	Epoch       []byte       `json:"epoch"`
	PINHash     []byte       `json:"pin_hash,omitempty"` // LEFT(SHA-256(PIN), 16)
	PINRetries  int          `json:"pin_retries"`
	Counter     uint32       `json:"counter"`
	Credentials []Credential `json:"credentials"`
}

// Store is an encrypted state file.
type Store struct {
	path  string
	aead  cipher.AEAD
	State State
}

// MaxPINRetries is the PIN retry budget.
const MaxPINRetries = 8

// Lock takes an exclusive lock next to the state file, so that two daemons
// never share (and overwrite) one state. Release by closing the file.
func Lock(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path+".lock", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("%s is in use by another tpm-fido2 process", path)
	}
	return f, nil
}

// Open loads the state at path, creating a fresh one if the file is missing.
func Open(path string, key []byte) (*Store, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	s := &Store{path: path, aead: aead}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		s.State = fresh()
		return s, s.Save()
	}
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(b, magic) || len(b) < len(magic)+aead.NonceSize() {
		return nil, fmt.Errorf("%s: not a tpm-fido2 state file", path)
	}
	b = b[len(magic):]
	pt, err := aead.Open(nil, b[:aead.NonceSize()], b[aead.NonceSize():], magic)
	if err != nil {
		return nil, fmt.Errorf("%s: cannot decrypt (different TPM or TPM cleared?): %w", path, err)
	}
	if err := json.Unmarshal(pt, &s.State); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(s.State.Epoch) == 0 {
		return nil, fmt.Errorf("%s: missing epoch", path)
	}
	return s, nil
}

func fresh() State {
	e := make([]byte, 32)
	if _, err := rand.Read(e); err != nil {
		panic(err)
	}
	return State{Epoch: e, PINRetries: MaxPINRetries}
}

// Reset wipes everything and starts a new epoch.
func (s *Store) Reset() error {
	s.State = fresh()
	return s.Save()
}

// Save writes the state atomically.
func (s *Store) Save() error {
	pt, err := json.Marshal(&s.State)
	if err != nil {
		return err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	out := append(append(bytes.Clone(magic), nonce...), s.aead.Seal(nil, nonce, pt, magic)...)
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(out); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

// NextCounter increments and persists the signature counter.
func (s *Store) NextCounter() (uint32, error) {
	s.State.Counter++
	return s.State.Counter, s.Save()
}

// Find returns the index of the credential with the given ID, or -1.
func (s *Store) Find(id []byte) int {
	for i, c := range s.State.Credentials {
		if bytes.Equal(c.ID, id) {
			return i
		}
	}
	return -1
}

// Put adds a credential, replacing any for the same RP and user handle.
func (s *Store) Put(c Credential) error {
	kept := s.State.Credentials[:0]
	for _, o := range s.State.Credentials {
		if o.RPID == c.RPID && bytes.Equal(o.UserID, c.UserID) {
			continue
		}
		kept = append(kept, o)
	}
	s.State.Credentials = append(kept, c)
	return s.Save()
}

// Delete removes the credential with the given ID.
func (s *Store) Delete(id []byte) (bool, error) {
	i := s.Find(id)
	if i < 0 {
		return false, nil
	}
	s.State.Credentials = append(s.State.Credentials[:i], s.State.Credentials[i+1:]...)
	return true, s.Save()
}
