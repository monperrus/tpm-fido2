// Package presence asks the user to confirm FIDO operations, standing in for
// the touch sensor of a hardware security key.
package presence

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/monperrus/tpm-fido2/ctap2"
)

// Timeout is how long a prompt waits for an answer.
const Timeout = 30 * time.Second

// Pinentry confirms presence with a pinentry CONFIRM dialog (Assuan protocol).
type Pinentry struct {
	// Path of the pinentry program; empty means auto-detect.
	Path string
}

// FindPinentry returns the first GUI pinentry found, falling back to "pinentry".
func FindPinentry() string {
	for _, c := range []string{"pinentry-gnome3", "pinentry-qt", "pinentry-qt5", "pinentry-gtk-2", "pinentry-x11", "pinentry-fltk", "pinentry"} {
		if p, err := exec.LookPath(c); err == nil {
			return p
		}
	}
	return "pinentry"
}

func escape(s string) string {
	r := strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A")
	return r.Replace(s)
}

// Confirm implements ctap2.Presence.
func (p *Pinentry) Confirm(ctx context.Context, prompt string) (bool, error) {
	path := p.Path
	if path == "" {
		path = FindPinentry()
	}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path)
	cmd.WaitDelay = 500 * time.Millisecond
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return false, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return false, err
	}
	if err := cmd.Start(); err != nil {
		return false, fmt.Errorf("start %s: %w", path, err)
	}
	defer func() {
		stdin.Close()
		_ = cmd.Wait()
	}()

	type result struct {
		ok  bool
		err error
	}
	done := make(chan result, 1)
	go func() {
		ok, err := converse(stdin, bufio.NewReader(stdout), prompt)
		done <- result{ok, err}
	}()
	select {
	case r := <-done:
		return r.ok, r.err
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return false, ctap2.ErrPresenceTimeout
		}
		return false, ctx.Err()
	}
}

func converse(w io.Writer, r *bufio.Reader, prompt string) (bool, error) {
	readOK := func() (bool, string, error) {
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return false, "", err
			}
			line = strings.TrimRight(line, "\r\n")
			switch {
			case line == "OK" || strings.HasPrefix(line, "OK "):
				return true, line, nil
			case strings.HasPrefix(line, "ERR"):
				return false, line, nil
			}
			// status/comment lines: keep reading
		}
	}
	if ok, line, err := readOK(); err != nil || !ok {
		return false, fmt.Errorf("pinentry greeting: %q %v", line, err)
	}
	for _, c := range []string{
		"SETTITLE tpm-fido2",
		"SETDESC " + escape(prompt),
		"SETOK Allow",
		"SETCANCEL Deny",
		fmt.Sprintf("SETTIMEOUT %d", int(Timeout.Seconds())),
	} {
		if _, err := fmt.Fprintf(w, "%s\n", c); err != nil {
			return false, err
		}
		if _, _, err := readOK(); err != nil {
			return false, err
		}
	}
	if _, err := io.WriteString(w, "CONFIRM\n"); err != nil {
		return false, err
	}
	ok, line, err := readOK()
	if err != nil {
		return false, err
	}
	if !ok && strings.Contains(line, "Timeout") {
		return false, ctap2.ErrPresenceTimeout
	}
	_, _ = io.WriteString(w, "BYE\n")
	return ok, nil
}

// Auto approves everything. For automated testing only: it removes the user
// presence guarantee, so any local process can use the credentials.
type Auto struct{}

// Confirm implements ctap2.Presence.
func (Auto) Confirm(_ context.Context, prompt string) (bool, error) {
	log.Printf("INSECURE auto-presence approved: %s", prompt)
	return true, nil
}
