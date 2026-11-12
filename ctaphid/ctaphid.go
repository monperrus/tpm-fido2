// Package ctaphid implements the CTAPHID transport (FIDO CTAP 2.1 §11.2):
// framing of 64-byte HID reports, channel allocation, busy/cancel handling and
// keepalives. The authenticator logic is behind the Handler interface.
package ctaphid

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"log"
	"sync"
	"time"
)

// ReportLen is the HID report size.
const ReportLen = 64

// Commands.
const (
	CmdPing      = 0x01
	CmdMsg       = 0x03
	CmdLock      = 0x04
	CmdInit      = 0x06
	CmdWink      = 0x08
	CmdCBOR      = 0x10
	CmdCancel    = 0x11
	CmdKeepalive = 0x3b
	CmdError     = 0x3f
)

// Error codes.
const (
	ErrInvalidCmd     = 0x01
	ErrInvalidPar     = 0x02
	ErrInvalidLen     = 0x03
	ErrInvalidSeq     = 0x04
	ErrMsgTimeout     = 0x05
	ErrChannelBusy    = 0x06
	ErrInvalidChannel = 0x0b
	ErrOther          = 0x7f
)

// Keepalive status values.
const (
	StatusProcessing = 1
	StatusUPNeeded   = 2
)

const (
	broadcastCID = 0xffffffff
	initDataLen  = ReportLen - 7
	contDataLen  = ReportLen - 5
	maxMsgSize   = initDataLen + 128*contDataLen // 7609

	capWink = 0x01
	capCBOR = 0x04

	msgTimeout = 500 * time.Millisecond
)

// Device reads and writes raw 64-byte HID reports.
type Device interface {
	// ReadReport blocks until the host sends a report.
	ReadReport() ([]byte, error)
	WriteReport([]byte) error
}

// Handler processes complete messages. Implementations must return promptly
// once ctx is cancelled (CTAPHID_CANCEL or channel re-init).
type Handler interface {
	// CBOR handles a CTAPHID_CBOR request. setStatus changes the keepalive
	// status sent while the request is in progress.
	CBOR(ctx context.Context, req []byte, setStatus func(byte)) []byte
	// Msg handles a CTAPHID_MSG (CTAP1/U2F APDU) request.
	Msg(ctx context.Context, req []byte) []byte
}

// Server runs the CTAPHID protocol over a Device.
type Server struct {
	dev Device
	h   Handler

	wmu sync.Mutex // serialises frame writes

	// Version reported in INIT responses.
	Major, Minor, Build byte
}

// NewServer returns a Server.
func NewServer(dev Device, h Handler) *Server {
	return &Server{dev: dev, h: h, Major: 1}
}

type assembly struct {
	cid   uint32
	cmd   byte
	total int
	data  []byte
	seq   byte
	last  time.Time
}

type job struct {
	cid    uint32
	cancel context.CancelFunc
}

type done struct{ cid uint32 }

// Run serves until ctx is cancelled or the device fails.
func (s *Server) Run(ctx context.Context) error {
	reports := make(chan []byte)
	readErr := make(chan error, 1)
	go func() {
		for {
			r, err := s.dev.ReadReport()
			if err != nil {
				readErr <- err
				return
			}
			select {
			case reports <- r:
			case <-ctx.Done():
				return
			}
		}
	}()

	channels := map[uint32]bool{}
	var asm *assembly
	var busy *job
	finished := make(chan done, 1)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	defer func() {
		if busy != nil {
			busy.cancel()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-readErr:
			return err
		case d := <-finished:
			if busy != nil && busy.cid == d.cid {
				busy = nil
			}
		case <-tick.C:
			if asm != nil && time.Since(asm.last) > msgTimeout {
				s.writeError(asm.cid, ErrMsgTimeout)
				asm = nil
			}
		case r := <-reports:
			// A job may have finished just before this report arrived.
			select {
			case d := <-finished:
				if busy != nil && busy.cid == d.cid {
					busy = nil
				}
			default:
			}
			if len(r) < 7 {
				continue
			}
			cid := binary.BigEndian.Uint32(r[0:4])
			if r[4]&0x80 == 0 {
				// continuation frame
				if asm == nil || asm.cid != cid {
					continue // spurious, ignore
				}
				if r[4] != asm.seq {
					s.writeError(cid, ErrInvalidSeq)
					asm = nil
					continue
				}
				asm.seq++
				asm.last = time.Now()
				asm.data = append(asm.data, r[5:]...)
				if len(asm.data) >= asm.total {
					a := asm
					asm = nil
					busy = s.dispatch(ctx, a.cid, a.cmd, a.data[:a.total], busy, finished)
				}
				continue
			}

			cmd := r[4] & 0x7f
			bcnt := int(binary.BigEndian.Uint16(r[5:7]))
			if cid == 0 {
				s.writeError(cid, ErrInvalidChannel)
				continue
			}
			if cmd == CmdInit {
				if bcnt != 8 {
					s.writeError(cid, ErrInvalidLen)
					continue
				}
				if asm != nil && asm.cid == cid {
					asm = nil
				}
				if busy != nil && busy.cid == cid {
					busy.cancel()
				}
				newCID := cid
				if cid == broadcastCID {
					newCID = allocCID(channels)
				} else if !channels[cid] {
					s.writeError(cid, ErrInvalidChannel)
					continue
				}
				resp := make([]byte, 17)
				copy(resp[0:8], r[7:15])
				binary.BigEndian.PutUint32(resp[8:12], newCID)
				resp[12] = 2 // CTAPHID protocol version
				resp[13], resp[14], resp[15] = s.Major, s.Minor, s.Build
				resp[16] = capWink | capCBOR
				s.write(cid, CmdInit, resp)
				continue
			}
			if cid == broadcastCID || !channels[cid] {
				s.writeError(cid, ErrInvalidChannel)
				continue
			}
			if cmd == CmdCancel {
				if busy != nil && busy.cid == cid {
					busy.cancel()
				}
				continue
			}
			if busy != nil || (asm != nil && asm.cid != cid) {
				s.writeError(cid, ErrChannelBusy)
				continue
			}
			if bcnt > maxMsgSize {
				s.writeError(cid, ErrInvalidLen)
				continue
			}
			a := &assembly{cid: cid, cmd: cmd, total: bcnt, last: time.Now()}
			a.data = append(a.data, r[7:]...)
			if len(a.data) >= a.total {
				busy = s.dispatch(ctx, cid, cmd, a.data[:a.total], busy, finished)
			} else {
				asm = a
			}
		}
	}
}

func allocCID(channels map[uint32]bool) uint32 {
	for {
		var b [4]byte
		_, _ = rand.Read(b[:])
		c := binary.BigEndian.Uint32(b[:])
		if c != 0 && c != broadcastCID && !channels[c] {
			channels[c] = true
			return c
		}
	}
}

// dispatch handles a complete message. Long-running commands run in a
// goroutine and the returned job marks the authenticator busy.
func (s *Server) dispatch(ctx context.Context, cid uint32, cmd byte, data []byte, busy *job, finished chan done) *job {
	switch cmd {
	case CmdPing:
		s.write(cid, CmdPing, data)
		return busy
	case CmdWink:
		s.write(cid, CmdWink, nil)
		return busy
	case CmdMsg, CmdCBOR:
		jctx, cancel := context.WithCancel(ctx)
		j := &job{cid: cid, cancel: cancel}
		go func() {
			defer cancel()
			var resp []byte
			if cmd == CmdCBOR {
				resp = s.runCBOR(jctx, cid, data)
			} else {
				resp = s.h.Msg(jctx, data)
			}
			finished <- done{cid}
			s.write(cid, cmd, resp)
		}()
		return j
	default:
		s.writeError(cid, ErrInvalidCmd)
		return busy
	}
}

func (s *Server) runCBOR(ctx context.Context, cid uint32, data []byte) []byte {
	var mu sync.Mutex
	status := byte(StatusProcessing)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(100 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				mu.Lock()
				st := status
				mu.Unlock()
				s.write(cid, CmdKeepalive, []byte{st})
			}
		}
	}()
	resp := s.h.CBOR(ctx, data, func(b byte) {
		mu.Lock()
		status = b
		mu.Unlock()
	})
	close(stop)
	wg.Wait()
	return resp
}

func (s *Server) writeError(cid uint32, code byte) {
	s.write(cid, CmdError, []byte{code})
}

// write splits a message into frames and sends them atomically with respect
// to other writes.
func (s *Server) write(cid uint32, cmd byte, data []byte) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	for _, f := range Frames(cid, cmd, data) {
		if err := s.dev.WriteReport(f); err != nil {
			log.Printf("ctaphid: write: %v", err)
			return
		}
	}
}

// Frames splits a message into 64-byte CTAPHID frames.
func Frames(cid uint32, cmd byte, data []byte) [][]byte {
	var out [][]byte
	f := make([]byte, ReportLen)
	binary.BigEndian.PutUint32(f[0:4], cid)
	f[4] = cmd | 0x80
	binary.BigEndian.PutUint16(f[5:7], uint16(len(data)))
	n := copy(f[7:], data)
	out = append(out, f)
	data = data[n:]
	for seq := byte(0); len(data) > 0; seq++ {
		f := make([]byte, ReportLen)
		binary.BigEndian.PutUint32(f[0:4], cid)
		f[4] = seq
		n := copy(f[5:], data)
		out = append(out, f)
		data = data[n:]
	}
	return out
}

// Reassemble parses a sequence of frames for one message (used by tests and
// clients). It returns the command and payload.
func Reassemble(frames [][]byte) (cid uint32, cmd byte, data []byte, err error) {
	if len(frames) == 0 || frames[0][4]&0x80 == 0 {
		return 0, 0, nil, errors.New("no init frame")
	}
	f := frames[0]
	cid = binary.BigEndian.Uint32(f[0:4])
	cmd = f[4] & 0x7f
	total := int(binary.BigEndian.Uint16(f[5:7]))
	data = append(data, f[7:]...)
	for i, c := range frames[1:] {
		if c[4] != byte(i) {
			return 0, 0, nil, errors.New("bad sequence")
		}
		data = append(data, c[5:]...)
	}
	if len(data) < total {
		return 0, 0, nil, errors.New("short message")
	}
	return cid, cmd, data[:total], nil
}
