// Command tpm-fido2 is a FIDO2/CTAP2.1 security key (with passkeys) whose
// private keys live in the TPM. It appears to the system as a USB HID device
// through Linux uhid, so browsers and libfido2 use it like a hardware key.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/monperrus/tpm-fido2/ctap2"
	"github.com/monperrus/tpm-fido2/ctaphid"
	"github.com/monperrus/tpm-fido2/hiddev"
	"github.com/monperrus/tpm-fido2/presence"
	"github.com/monperrus/tpm-fido2/store"
	"github.com/monperrus/tpm-fido2/tpmkey"
)

func defaultStatePath() string {
	dir := os.Getenv("XDG_DATA_HOME")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(dir, "tpm-fido2", "state")
}

func main() {
	tpmPath := flag.String("tpm", "/dev/tpmrm0", "TPM device")
	statePath := flag.String("state", defaultStatePath(), "encrypted state file (passkeys, PIN, counter)")
	pinentry := flag.String("pinentry", "", "pinentry program for presence prompts (default: auto-detect a GUI pinentry)")
	name := flag.String("name", "tpm-fido2", "HID device name")
	autoPresence := flag.Bool("insecure-auto-presence", false, "approve every request without asking (TESTING ONLY)")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [flags]\n\nRuns a TPM-backed FIDO2 security key as a virtual USB HID device until interrupted.\n\nFlags:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	log.SetFlags(0)

	if err := run(*tpmPath, *statePath, *pinentry, *name, *autoPresence); err != nil {
		log.Fatalf("tpm-fido2: %v", err)
	}
}

func run(tpmPath, statePath, pinentryPath, name string, autoPresence bool) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	tpm, err := tpmkey.Open(tpmPath)
	if err != nil {
		return fmt.Errorf("open TPM: %w", err)
	}
	defer tpm.Close()
	key, err := ctap2.StateKey(tpm)
	if err != nil {
		return fmt.Errorf("derive state key: %w", err)
	}
	st, err := store.Open(statePath, key)
	if err != nil {
		return err
	}

	var pres ctap2.Presence = &presence.Pinentry{Path: pinentryPath}
	if autoPresence {
		log.Printf("WARNING: --insecure-auto-presence: every request is approved without asking")
		pres = presence.Auto{}
	}
	auth, err := ctap2.New(tpm, st, pres)
	if err != nil {
		return err
	}

	dev, err := hiddev.Open(ctx, name)
	if err != nil {
		return fmt.Errorf("create uhid device: %w", err)
	}
	defer dev.Close()

	nctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	node, err := dev.HidrawNode(nctx)
	cancel()
	if err == nil {
		log.Printf("tpm-fido2: ready on %s", node)
	}

	err = ctaphid.NewServer(dev, auth).Run(ctx)
	if ctx.Err() != nil {
		return nil
	}
	return err
}
