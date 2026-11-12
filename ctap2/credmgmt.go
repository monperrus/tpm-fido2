package ctap2

import (
	"bytes"
	"crypto/sha256"
	"sort"

	"github.com/fxamacker/cbor/v2"

	"github.com/monperrus/tpm-fido2/store"
	"github.com/monperrus/tpm-fido2/tpmkey"
)

// maxResident bounds the passkey count (reported as remaining capacity).
const maxResident = 1000

// credentialManagement implements authenticatorCredentialManagement (§6.8).
func (a *Authenticator) credentialManagement(p params) (any, error) {
	sub, err := p.int(1, true)
	if err != nil {
		return nil, err
	}
	// Subcommands that start an operation require a pinUvAuthParam over
	// subCommand || subCommandParams (raw CBOR as sent).
	if sub != 3 && sub != 5 {
		proto, err := p.int(3, true)
		if err != nil {
			return nil, err
		}
		param, err := p.bytes(4, true)
		if err != nil {
			return nil, err
		}
		msg := append([]byte{byte(sub)}, p[2]...)
		// A token bound to an RP only manages that RP (checked per subcommand).
		if err := a.verifyToken(proto, msg, param, permCM, ""); err != nil {
			return nil, err
		}
		if a.tokenRPID != "" && (sub == 1 || sub == 2) {
			return nil, ErrPINAuthInvalid
		}
	}
	var sp params
	if raw, ok := p[2]; ok {
		var m map[int]cbor.RawMessage
		if err := cbor.Unmarshal(raw, &m); err != nil {
			return nil, ErrInvalidCBOR
		}
		sp = params(m)
	}
	creds := a.store.State.Credentials
	switch sub {
	case 1: // getCredsMetadata
		return map[int]any{1: len(creds), 2: max(0, maxResident-len(creds))}, nil
	case 2: // enumerateRPsBegin
		seen := map[string]bool{}
		var rps []string
		for _, c := range creds {
			if !seen[c.RPID] {
				seen[c.RPID] = true
				rps = append(rps, c.RPID)
			}
		}
		if len(rps) == 0 {
			return nil, ErrNoCredentials
		}
		sort.Strings(rps)
		resp := a.rpEntry(rps[0])
		resp[5] = len(rps)
		a.rpEnum = rps[1:]
		return resp, nil
	case 3: // enumerateRPsGetNextRP
		if len(a.rpEnum) == 0 {
			return nil, ErrNotAllowed
		}
		resp := a.rpEntry(a.rpEnum[0])
		a.rpEnum = a.rpEnum[1:]
		return resp, nil
	case 4: // enumerateCredentialsBegin
		h, err := sp.bytes(1, true)
		if err != nil {
			return nil, err
		}
		var list []store.Credential
		for _, c := range creds {
			hh := sha256.Sum256([]byte(c.RPID))
			if bytes.Equal(hh[:], h) {
				if a.tokenRPID != "" && a.tokenRPID != c.RPID {
					return nil, ErrPINAuthInvalid
				}
				list = append(list, c)
			}
		}
		if len(list) == 0 {
			return nil, ErrNoCredentials
		}
		resp, err := credEntry(list[0])
		if err != nil {
			return nil, err
		}
		resp[9] = len(list)
		a.credEnum = list[1:]
		return resp, nil
	case 5: // enumerateCredentialsGetNextCredential
		if len(a.credEnum) == 0 {
			return nil, ErrNotAllowed
		}
		resp, err := credEntry(a.credEnum[0])
		a.credEnum = a.credEnum[1:]
		return resp, err
	case 6, 7: // deleteCredential, updateUserInformation
		var d credDescriptor
		if _, err := sp.decode(2, &d, true); err != nil {
			return nil, err
		}
		i := a.store.Find(d.ID)
		if i < 0 {
			return nil, ErrNoCredentials
		}
		if a.tokenRPID != "" && a.tokenRPID != creds[i].RPID {
			return nil, ErrPINAuthInvalid
		}
		if sub == 6 {
			_, err := a.store.Delete(d.ID)
			return nil, err
		}
		var u userEntity
		if _, err := sp.decode(3, &u, true); err != nil {
			return nil, err
		}
		if !bytes.Equal(u.ID, creds[i].UserID) {
			return nil, ErrInvalidParameter
		}
		creds[i].UserName = u.Name
		creds[i].DisplayName = u.DisplayName
		return nil, a.store.Save()
	default:
		return nil, ErrInvalidSubcommand
	}
}

func (a *Authenticator) rpEntry(rpID string) map[int]any {
	rp := map[string]any{"id": rpID}
	for _, c := range a.store.State.Credentials {
		if c.RPID == rpID && c.RPName != "" {
			rp["name"] = c.RPName
			break
		}
	}
	h := sha256.Sum256([]byte(rpID))
	return map[int]any{3: rp, 4: h[:]}
}

func credEntry(c store.Credential) (map[int]any, error) {
	if len(c.ID) <= tagLen {
		return nil, ErrOther
	}
	pub, err := tpmkey.PublicKey(c.ID[:len(c.ID)-tagLen])
	if err != nil {
		return nil, err
	}
	u := map[string]any{"id": c.UserID}
	if c.UserName != "" {
		u["name"] = c.UserName
	}
	if c.DisplayName != "" {
		u["displayName"] = c.DisplayName
	}
	return map[int]any{
		6:    u,
		7:    map[string]any{"id": c.ID, "type": "public-key"},
		8:    coseES256(pub),
		0x0a: c.CredProtect,
	}, nil
}
