package store

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRoundTripAndWrongKey(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "state")
	key := bytes.Repeat([]byte{1}, 32)
	s, err := Open(p, key)
	if err != nil {
		t.Fatal(err)
	}
	if s.State.PINRetries != MaxPINRetries || len(s.State.Epoch) != 32 {
		t.Fatalf("fresh state wrong: %+v", s.State)
	}
	if err := s.Put(Credential{ID: []byte{1}, RPID: "a", UserID: []byte{9}, UserName: "old"}); err != nil {
		t.Fatal(err)
	}
	// same rp+user replaces
	if err := s.Put(Credential{ID: []byte{2}, RPID: "a", UserID: []byte{9}, UserName: "new"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.NextCounter(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(p, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(s2.State.Credentials) != 1 || s2.State.Credentials[0].UserName != "new" || s2.State.Counter != 1 {
		t.Fatalf("reloaded state wrong: %+v", s2.State)
	}
	if !bytes.Equal(s.State.Epoch, s2.State.Epoch) {
		t.Fatal("epoch changed")
	}
	raw, _ := os.ReadFile(p)
	if bytes.Contains(raw, []byte("new")) {
		t.Fatal("state not encrypted")
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if _, err := Open(p, bytes.Repeat([]byte{2}, 32)); err == nil {
		t.Fatal("wrong key accepted")
	}
	ok, _ := s2.Delete([]byte{2})
	if !ok || len(s2.State.Credentials) != 0 {
		t.Fatal("delete failed")
	}
	old := s2.State.Epoch
	_ = s2.Reset()
	if bytes.Equal(old, s2.State.Epoch) {
		t.Fatal("reset kept epoch")
	}
}
