// Package hiddev creates the virtual FIDO HID device through Linux uhid.
package hiddev

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/psanford/uhid"
)

// pid.codes test VID/PID.
const (
	busUSB    = 0x03
	vendorID  = 0x1209
	productID = 0x0001
)

// reportDescriptor declares a FIDO Alliance (usage page 0xF1D0) device with
// 64-byte input and output reports; udev's fido_id recognises it as a
// security token and grants the seat user access to the hidraw node.
var reportDescriptor = []byte{
	0x06, 0xd0, 0xf1, // USAGE_PAGE (FIDO Alliance)
	0x09, 0x01, // USAGE (CTAPHID)
	0xa1, 0x01, // COLLECTION (Application)
	0x09, 0x20, //   USAGE (Input Report Data)
	0x15, 0x00, //   LOGICAL_MINIMUM (0)
	0x26, 0xff, 0x00, //   LOGICAL_MAXIMUM (255)
	0x75, 0x08, //   REPORT_SIZE (8)
	0x95, 0x40, //   REPORT_COUNT (64)
	0x81, 0x02, //   INPUT (Data,Var,Abs)
	0x09, 0x21, //   USAGE (Output Report Data)
	0x15, 0x00, //   LOGICAL_MINIMUM (0)
	0x26, 0xff, 0x00, //   LOGICAL_MAXIMUM (255)
	0x75, 0x08, //   REPORT_SIZE (8)
	0x95, 0x40, //   REPORT_COUNT (64)
	0x91, 0x02, //   OUTPUT (Data,Var,Abs)
	0xc0, // END_COLLECTION
}

// uhid_output_req: data[4096], size u16, rtype u8.
const uhidDataMax = 4096

// Device is a uhid-backed HID device implementing ctaphid.Device.
type Device struct {
	d      *uhid.Device
	events chan uhid.Event
}

// Open creates the virtual device.
func Open(ctx context.Context, name string) (*Device, error) {
	d, err := uhid.NewDevice(name, reportDescriptor)
	if err != nil {
		return nil, err
	}
	d.Data.Bus = busUSB
	d.Data.VendorID = vendorID
	d.Data.ProductID = productID
	// The library default is 64 random bytes, which is not valid UTF-8 and
	// makes some FIDO clients (python-fido2) skip the device.
	if err := d.SetUniq(name); err != nil {
		return nil, err
	}
	ev, err := d.Open(ctx)
	if err != nil {
		return nil, err
	}
	return &Device{d: d, events: ev}, nil
}

// HidrawNode waits for the kernel to create the hidraw node of this device
// and returns its path. Devices are matched by HID_UNIQ, set to the name.
func (d *Device) HidrawNode(ctx context.Context) (string, error) {
	want := "HID_UNIQ=" + strings.TrimRight(d.d.Uniq(), "\x00")
	for {
		paths, _ := filepath.Glob("/sys/class/hidraw/hidraw*/device/uevent")
		for _, p := range paths {
			b, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(b), "\n") {
				if line == want {
					return "/dev/" + filepath.Base(filepath.Dir(filepath.Dir(p))), nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// Close destroys the device.
func (d *Device) Close() error { return d.d.Close() }

// ReadReport returns the next 64-byte output report sent by the host.
func (d *Device) ReadReport() ([]byte, error) {
	for ev := range d.events {
		if ev.Err != nil {
			return nil, ev.Err
		}
		if ev.Type != uhid.Output {
			continue
		}
		data := ev.Data
		if len(data) < uhidDataMax+2 {
			return nil, fmt.Errorf("short uhid output event (%d bytes)", len(data))
		}
		size := int(binary.LittleEndian.Uint16(data[uhidDataMax:]))
		data = data[:size]
		// Without numbered reports the host prefixes a 0 report ID.
		if len(data) == 65 {
			data = data[1:]
		}
		if len(data) != 64 {
			continue
		}
		return data, nil
	}
	return nil, errors.New("uhid event channel closed")
}

// WriteReport sends a 64-byte input report to the host.
func (d *Device) WriteReport(b []byte) error {
	req := uhid.Input2Request{RequestType: uhid.Input2, DataSize: uint16(len(b))}
	copy(req.Data[:], b)
	return d.d.WriteEvent(req)
}
