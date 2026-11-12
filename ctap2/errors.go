package ctap2

import "fmt"

// Status is a CTAP2 status code (CTAP 2.1 §8.2).
type Status byte

// CTAP2 status codes.
const (
	StatusOK                  Status = 0x00
	ErrInvalidCommand         Status = 0x01
	ErrInvalidParameter       Status = 0x02
	ErrInvalidLength          Status = 0x03
	ErrCBORUnexpectedType     Status = 0x11
	ErrInvalidCBOR            Status = 0x12
	ErrMissingParameter       Status = 0x14
	ErrLimitExceeded          Status = 0x15
	ErrCredentialExcluded     Status = 0x19
	ErrInvalidCredential      Status = 0x22
	ErrUnsupportedAlgorithm   Status = 0x26
	ErrOperationDenied        Status = 0x27
	ErrKeyStoreFull           Status = 0x28
	ErrUnsupportedOption      Status = 0x2b
	ErrInvalidOption          Status = 0x2c
	ErrKeepaliveCancel        Status = 0x2d
	ErrNoCredentials          Status = 0x2e
	ErrUserActionTimeout      Status = 0x2f
	ErrNotAllowed             Status = 0x30
	ErrPINInvalid             Status = 0x31
	ErrPINBlocked             Status = 0x32
	ErrPINAuthInvalid         Status = 0x33
	ErrPINAuthBlocked         Status = 0x34
	ErrPINNotSet              Status = 0x35
	ErrPUATRequired           Status = 0x36
	ErrPINPolicyViolation     Status = 0x37
	ErrRequestTooLarge        Status = 0x39
	ErrUnauthorizedPermission Status = 0x40
	ErrOther                  Status = 0x7f
)

func (s Status) Error() string { return fmt.Sprintf("CTAP2 status 0x%02x", byte(s)) }
