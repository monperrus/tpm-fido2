package ctaphid

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"
)

type fakeDev struct {
	in  chan []byte
	out chan []byte
}

func (d *fakeDev) ReadReport() ([]byte, error) { return <-d.in, nil }
func (d *fakeDev) WriteReport(b []byte) error  { d.out <- b; return nil }

type echoHandler struct{ block chan struct{} }

func (h *echoHandler) CBOR(ctx context.Context, req []byte, setStatus func(byte)) []byte {
	if h.block != nil {
		setStatus(StatusUPNeeded)
		select {
		case <-ctx.Done():
			return []byte{0x2d}
		case <-h.block:
		}
	}
	return append([]byte{0}, req...)
}
func (h *echoHandler) Msg(ctx context.Context, req []byte) []byte { return append(req, 0x90, 0x00) }

func setup(t *testing.T, h Handler) (*fakeDev, context.CancelFunc) {
	d := &fakeDev{in: make(chan []byte, 200), out: make(chan []byte, 200)}
	ctx, cancel := context.WithCancel(context.Background())
	go NewServer(d, h).Run(ctx)
	t.Cleanup(cancel)
	return d, cancel
}

func send(d *fakeDev, cid uint32, cmd byte, data []byte) {
	for _, f := range Frames(cid, cmd, data) {
		d.in <- f
	}
}

// recv reads one message, skipping keepalives unless wantKeepalive.
func recv(t *testing.T, d *fakeDev, skipKeepalive bool) (uint32, byte, []byte) {
	t.Helper()
	for {
		var frames [][]byte
		select {
		case f := <-d.out:
			frames = append(frames, f)
		case <-time.After(2 * time.Second):
			t.Fatal("timeout")
		}
		total := int(binary.BigEndian.Uint16(frames[0][5:7]))
		for got := initDataLen; got < total; got += contDataLen {
			frames = append(frames, <-d.out)
		}
		cid, cmd, data, err := Reassemble(frames)
		if err != nil {
			t.Fatal(err)
		}
		if skipKeepalive && cmd == CmdKeepalive {
			continue
		}
		return cid, cmd, data
	}
}

func initChannel(t *testing.T, d *fakeDev) uint32 {
	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	send(d, broadcastCID, CmdInit, nonce)
	cid, cmd, data := recv(t, d, true)
	if cid != broadcastCID || cmd != CmdInit || !bytes.Equal(data[:8], nonce) || len(data) != 17 {
		t.Fatalf("bad init resp cid=%x cmd=%x data=%x", cid, cmd, data)
	}
	if data[16]&capCBOR == 0 {
		t.Fatal("CBOR capability missing")
	}
	return binary.BigEndian.Uint32(data[8:12])
}

func TestInitPingCBORLarge(t *testing.T) {
	d, _ := setup(t, &echoHandler{})
	cid := initChannel(t, d)
	big := bytes.Repeat([]byte{0xab}, 1000)
	send(d, cid, CmdPing, big)
	if _, cmd, data := recv(t, d, true); cmd != CmdPing || !bytes.Equal(data, big) {
		t.Fatalf("ping mismatch")
	}
	send(d, cid, CmdCBOR, big)
	if _, cmd, data := recv(t, d, true); cmd != CmdCBOR || data[0] != 0 || !bytes.Equal(data[1:], big) {
		t.Fatalf("cbor mismatch")
	}
	// back to back requests must not hit CHANNEL_BUSY
	for i := 0; i < 50; i++ {
		send(d, cid, CmdMsg, []byte{byte(i)})
		if _, cmd, data := recv(t, d, true); cmd != CmdMsg || data[0] != byte(i) {
			t.Fatalf("msg %d: cmd=%x data=%x", i, cmd, data)
		}
	}
}

func TestErrors(t *testing.T) {
	d, _ := setup(t, &echoHandler{})
	cid := initChannel(t, d)
	// unknown channel
	send(d, 0x12345678, CmdPing, []byte{1})
	if _, cmd, data := recv(t, d, true); cmd != CmdError || data[0] != ErrInvalidChannel {
		t.Fatalf("got %x %x", cmd, data)
	}
	// unknown command
	send(d, cid, 0x55, nil)
	if _, cmd, data := recv(t, d, true); cmd != CmdError || data[0] != ErrInvalidCmd {
		t.Fatalf("got %x %x", cmd, data)
	}
	// bad sequence
	fr := Frames(cid, CmdPing, bytes.Repeat([]byte{1}, 200))
	fr[1][4] = 5
	for _, f := range fr {
		d.in <- f
	}
	if _, cmd, data := recv(t, d, true); cmd != CmdError || data[0] != ErrInvalidSeq {
		t.Fatalf("got %x %x", cmd, data)
	}
	// timeout on incomplete message
	d.in <- Frames(cid, CmdPing, bytes.Repeat([]byte{1}, 200))[0]
	if _, cmd, data := recv(t, d, true); cmd != CmdError || data[0] != ErrMsgTimeout {
		t.Fatalf("got %x %x", cmd, data)
	}
}

func TestBusyKeepaliveCancel(t *testing.T) {
	h := &echoHandler{block: make(chan struct{})}
	d, _ := setup(t, h)
	cid := initChannel(t, d)
	cid2 := initChannel(t, d)
	send(d, cid, CmdCBOR, []byte{4})
	// keepalive with UPNEEDED
	_, cmd, data := recv(t, d, false)
	if cmd != CmdKeepalive || data[0] != StatusUPNeeded {
		t.Fatalf("expected keepalive, got %x %x", cmd, data)
	}
	send(d, cid2, CmdPing, []byte{1})
	for {
		c, cmd, data := recv(t, d, true)
		if c == cid2 {
			if cmd != CmdError || data[0] != ErrChannelBusy {
				t.Fatalf("expected busy, got %x %x", cmd, data)
			}
			break
		}
	}
	send(d, cid, CmdCancel, nil)
	_, cmd, data = recv(t, d, true)
	if cmd != CmdCBOR || data[0] != 0x2d {
		t.Fatalf("expected KEEPALIVE_CANCEL, got %x %x", cmd, data)
	}
}
