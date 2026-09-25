package emailprotocol

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	auth "iwut-auth-center/internal/authentication/domain"
	"iwut-auth-center/internal/emailbinding/domain"
	emailport "iwut-auth-center/internal/emailbinding/port"
	"math/big"
)

type Protocol struct {
	key     []byte
	service string
}

func New(key []byte, service string) (*Protocol, error) {
	if len(key) != 32 {
		return nil, domain.ErrUnavailable
	}
	if _, e := deviceprotocol.New(service); e != nil {
		return nil, e
	}
	return &Protocol{append([]byte(nil), key...), service}, nil
}
func (p *Protocol) KeyID() string {
	sum := sha256.Sum256(deviceprotocol.Frame([]byte("iwut-email-key-id-v1"), p.key))
	return hex.EncodeToString(sum[:])
}
func (*Protocol) ValidID(s string) bool { return deviceprotocol.ValidID(s) }
func u64(n int64) []byte                { b := make([]byte, 8); binary.BigEndian.PutUint64(b, uint64(n)); return b }
func (p *Protocol) mac(fields ...[]byte) []byte {
	h := hmac.New(sha256.New, p.key)
	b := deviceprotocol.Frame(fields...)
	defer clear(b)
	h.Write(b)
	return h.Sum(nil)
}
func (p *Protocol) RequestMAC(b domain.Begin, authID string) []byte {
	f := [][]byte{[]byte("iwut-email-request-v1"), []byte(b.Mode), []byte(b.RequestID), []byte(b.Email), []byte(p.service), []byte(auth.ApplicationID)}
	if b.Mode == domain.Register {
		f = append(f, []byte(b.ProtocolVersion), b.PublicKey, []byte(b.Scheme), b.Token)
	} else {
		f = append(f, []byte(authID), u64(*b.Revision))
	}
	return p.mac(f...)
}
func (p *Protocol) CodeMAC(o emailport.Operation, code string) []byte {
	return p.mac([]byte("iwut-email-code-v1"), []byte(o.Proof.Purpose), []byte(o.Proof.OperationID), u64(o.Proof.ExpiresAt.UnixMilli()), o.RequestMAC, []byte(code))
}
func (p *Protocol) Payload(o emailport.Operation, digest []byte) ([]byte, error) {
	a := o.Proof
	if o.Mode != domain.Register || a.Purpose != domain.RegistrationPurpose || a.ProtocolVersion != auth.ProtocolVersion || a.ServiceID != p.service || a.ApplicationID != auth.ApplicationID || !deviceprotocol.ValidID(a.OperationID) || len(a.Challenge) != 32 || len(digest) != 32 || a.ExpiresAt.UnixMilli() < 0 {
		return nil, domain.ErrInvalid
	}
	d, _ := deviceprotocol.New(p.service)
	if d.ValidatePublicKey(a.PublicKey) != nil {
		return nil, domain.ErrInvalid
	}
	email, e := domain.NormalizeEmail(o.Email)
	if e != nil || email != o.Email {
		return nil, domain.ErrInvalid
	}
	payload := deviceprotocol.Frame([]byte("iwut-email-registration-proof-v1"), []byte(domain.ProtocolVersion), []byte(domain.RegistrationPurpose), []byte(p.service), []byte(auth.ApplicationID), []byte(a.OperationID), a.Challenge, u64(a.ExpiresAt.UnixMilli()), a.PublicKey, digest, []byte(email))
	if len(payload) > 1024 {
		return nil, domain.ErrInvalid
	}
	return payload, nil
}
func (*Protocol) NewCode() (string, error) {
	n, e := rand.Int(rand.Reader, big.NewInt(100000000))
	if e != nil {
		return "", e
	}
	return fmt.Sprintf("%08d", n.Int64()), nil
}
