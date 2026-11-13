package ctap2

import (
	"context"
	"encoding/binary"
	"github.com/monperrus/tpm-fido2/ctaphid"
	"github.com/monperrus/tpm-fido2/store"
	"testing"
	"time"
)

type channelDevice struct{ in, out chan []byte }

func (d *channelDevice) ReadReport() ([]byte, error) { return <-d.in, nil }
func (d *channelDevice) WriteReport(b []byte) error  { d.out <- b; return nil }

func TestContinuationChannelIsolation(t *testing.T) {
	e := newEnv(t)
	d := &channelDevice{make(chan []byte, 20), make(chan []byte, 20)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ctaphid.NewServer(d, e.a).Run(ctx)
	send := func(cid uint32, cmd byte, p []byte) {
		for _, f := range ctaphid.Frames(cid, cmd, p) {
			d.in <- f
		}
	}
	receive := func() []byte {
		select {
		case b := <-d.out:
			return b
		case <-time.After(time.Second):
			t.Fatal("timeout")
			return nil
		}
	}
	init := func() uint32 {
		send(0xffffffff, ctaphid.CmdInit, make([]byte, 8))
		return binary.BigEndian.Uint32(receive()[15:19])
	}
	a, b := init(), init()
	call := func(cid uint32) byte {
		send(cid, ctaphid.CmdCBOR, []byte{cmdCredentialMgmt, 0xa1, 1, 3})
		return receive()[7]
	}
	if call(a) != byte(ErrNotAllowed) {
		t.Fatal("empty continuation accepted")
	}
	seed := func() { e.a.mu.Lock(); e.a.rpEnum = []string{"one.example", "two.example"}; e.a.mu.Unlock() }
	seed()
	if call(a) != 0 {
		t.Fatal("same channel rejected")
	}
	e.a.mu.Lock()
	e.a.next = &pendingAssertions{}
	e.a.credEnum = []store.Credential{{RPID: "private.example"}}
	e.a.mu.Unlock()
	if call(b) != byte(ErrNotAllowed) {
		t.Fatal("cross-channel continuation accepted")
	}
	e.a.mu.Lock()
	retained := e.a.next != nil || len(e.a.credEnum) != 0
	e.a.mu.Unlock()
	if retained {
		t.Fatal("other continuation state retained")
	}
	seed()
	send(b, ctaphid.CmdInit, make([]byte, 8))
	receive()
	if call(b) != byte(ErrNotAllowed) {
		t.Fatal("INIT retained continuation")
	}
	seed()
	send(b, ctaphid.CmdCancel, nil)
	if call(b) != byte(ErrNotAllowed) {
		t.Fatal("CANCEL retained continuation")
	}
}
