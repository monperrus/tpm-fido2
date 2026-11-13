package ctap2

import (
	"fmt"
	"github.com/monperrus/tpm-fido2/store"
	"testing"
)

func TestMalformedPINPreservesRetries(t *testing.T) {
	for _, version := range []int{1, 2} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			e := newEnv(t)
			if st := e.setPIN(version, "1234"); st != 0 {
				t.Fatal(st)
			}
			pc := e.pinClient(version)
			for _, ct := range [][]byte{nil, {0}, pc.enc(t, make([]byte, 32))} {
				for i := 0; i < 9; i++ {
					st, _ := e.call(cmdClientPIN, map[int]any{1: version, 2: 5, 3: pc.ka, 6: ct})
					if st != ErrInvalidParameter {
						t.Fatalf("protocol %d: %v", version, st)
					}
				}
			}
			if e.a.store.State.PINRetries != store.MaxPINRetries {
				t.Fatal("retries consumed")
			}
			if st, _ := e.token(version, "1234", permGA, "example.com"); st != 0 {
				t.Fatal(st)
			}
			if st, _ := e.token(version, "9999", permGA, "example.com"); st != ErrPINInvalid {
				t.Fatal(st)
			}
		})
	}
}
