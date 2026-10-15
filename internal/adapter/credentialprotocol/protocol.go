package credentialprotocol

import (
	"bytes"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/binary"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	d "iwut-auth-center/internal/credentialmanagement/domain"
	"math/big"
)

type Protocol struct{ *deviceprotocol.Protocol }

func New(serviceID string) (*Protocol, error) {
	p, err := deviceprotocol.New(serviceID)
	if err != nil {
		return nil, err
	}
	return &Protocol{p}, nil
}
func (p *Protocol) SigningPayload(op d.Operation) ([]byte, error) {
	if op.Purpose != d.Purpose || op.ApplicationID != "iwut-client" || !d.ValidID(op.OperationID) || !d.ValidID(op.SessionID) || !d.ValidID(op.CallerCredentialID) || !d.ValidID(op.TargetCredentialID) || len(op.Challenge) != 32 || op.ExpiresAt.UnixMilli() < 0 {
		return nil, d.ErrInvalid
	}
	if _, err := deviceprotocol.New(op.ServiceID); err != nil {
		return nil, d.ErrInvalid
	}
	var stamp [8]byte
	binary.BigEndian.PutUint64(stamp[:], uint64(op.ExpiresAt.UnixMilli()))
	fields := [][]byte{[]byte("iwut-credential-revocation-proof-v1"), []byte(d.Purpose), []byte(op.ServiceID), []byte(op.ApplicationID), []byte(op.OperationID), []byte(op.SessionID), []byte(op.CallerCredentialID), []byte(op.TargetCredentialID), op.Challenge, stamp[:]}
	var out []byte
	for _, field := range fields {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(field)))
		out = append(out, size[:]...)
		out = append(out, field...)
	}
	if len(out) > 1024 {
		return nil, d.ErrInvalid
	}
	return out, nil
}
func (p *Protocol) ValidSignature(raw []byte) bool {
	var v struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(raw, &v)
	if err != nil || len(rest) != 0 || v.R == nil || v.S == nil || v.R.Sign() <= 0 || v.S.Sign() <= 0 || v.R.Cmp(elliptic.P256().Params().N) >= 0 || v.S.Cmp(elliptic.P256().Params().N) >= 0 {
		return false
	}
	canonical, err := asn1.Marshal(v)
	return err == nil && len(raw) <= 72 && bytes.Equal(raw, canonical)
}
