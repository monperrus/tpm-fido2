package presence

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/monperrus/tpm-fido2/ctap2"
)

// fakePinentry writes a shell script speaking just enough Assuan.
func fakePinentry(t *testing.T, confirmReply string, delay string) string {
	p := filepath.Join(t.TempDir(), "pinentry")
	script := `#!/bin/sh
echo "OK Pleased to meet you"
while read -r cmd rest; do
  case "$cmd" in
    CONFIRM) sleep ` + delay + `; echo "` + confirmReply + `";;
    BYE) echo OK; exit 0;;
    SETDESC) echo "$rest" > "$0.desc"; echo OK;;
    *) echo OK;;
  esac
done
`
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestConfirm(t *testing.T) {
	ok, err := (&Pinentry{Path: fakePinentry(t, "OK", "0")}).Confirm(context.Background(), "Sign in to a.com?\n100%")
	if err != nil || !ok {
		t.Fatalf("approve: %v %v", ok, err)
	}
	ok, err = (&Pinentry{Path: fakePinentry(t, "ERR 83886179 Operation cancelled <Pinentry>", "0")}).Confirm(context.Background(), "x")
	if err != nil || ok {
		t.Fatalf("deny: %v %v", ok, err)
	}
	ok, err = (&Pinentry{Path: fakePinentry(t, "ERR 83886142 Timeout <Pinentry>", "0")}).Confirm(context.Background(), "x")
	if !errors.Is(err, ctap2.ErrPresenceTimeout) || ok {
		t.Fatalf("timeout: %v %v", ok, err)
	}
}

func TestConfirmCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(100 * time.Millisecond); cancel() }()
	start := time.Now()
	ok, err := (&Pinentry{Path: fakePinentry(t, "OK", "5")}).Confirm(ctx, "x")
	if ok || !errors.Is(err, context.Canceled) || time.Since(start) > 2*time.Second {
		t.Fatalf("cancel: %v %v after %v", ok, err, time.Since(start))
	}
}

func TestEscape(t *testing.T) {
	if got := escape("a%\nb"); got != "a%25%0Ab" {
		t.Fatal(got)
	}
}
