package emailaccountprotocol

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"

	"iwut-auth-center/internal/adapter/deviceprotocol"
	auth "iwut-auth-center/internal/authentication/domain"
	"iwut-auth-center/internal/emailaccount/domain"
	"iwut-auth-center/internal/emailaccount/port"
	email "iwut-auth-center/internal/emailbinding/domain"
)

type Protocol struct {
	emailKey, passwordKey []byte
	service               string
	device                *deviceprotocol.Protocol
}

func New(emailKey, passwordKey []byte, service string) (*Protocol, error) {
	d, err := deviceprotocol.New(service)
	if err != nil || len(emailKey) != 32 || len(passwordKey) != 32 || hmac.Equal(emailKey, passwordKey) {
		return nil, domain.ErrUnavailable
	}
	return &Protocol{append([]byte(nil), emailKey...), append([]byte(nil), passwordKey...), service, d}, nil
}
func (*Protocol) ValidID(v string) bool { return deviceprotocol.ValidID(v) }
func (p *Protocol) KeyID() string {
	sum := sha256.Sum256(deviceprotocol.Frame([]byte("iwut-email-key-id-v1"), p.emailKey))
	return hex.EncodeToString(sum[:])
}
func (p *Protocol) MutationKeyID(purpose string) string {
	if purpose != domain.Switch {
		return p.KeyID()
	}
	sum := sha256.Sum256(deviceprotocol.Frame([]byte("iwut-password-operation-key-id-v1"), p.passwordKey))
	return hex.EncodeToString(sum[:])
}

func u64(v int64) []byte { var b [8]byte; binary.BigEndian.PutUint64(b[:], uint64(v)); return b[:] }
func mac(key []byte, fields ...[]byte) []byte {
	data := deviceprotocol.Frame(fields...)
	defer clear(data)
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
func (p *Protocol) RequestMAC(o port.Operation) ([]byte, error) {
	address, err := email.NormalizeEmail(o.Email)
	if err != nil || address != o.Email || !p.ValidID(o.RequestID) || o.ServiceID != p.service {
		return nil, domain.ErrInvalid
	}
	f := [][]byte{[]byte("iwut-email-request-v3"), []byte(o.Purpose), []byte(o.RequestID), []byte(o.Email), []byte(p.service), []byte(auth.ApplicationID)}
	switch o.Purpose {
	case domain.Register:
		if p.device.ValidatePublicKey(o.PublicKey) != nil {
			return nil, domain.ErrInvalid
		}
		f = append(f, []byte(auth.ProtocolVersion), o.PublicKey)
	case domain.Add:
		if o.AuthID == "" || o.AccountRevision <= 0 || o.DirectoryRevision <= 0 {
			return nil, domain.ErrInvalid
		}
		f = append(f, []byte(o.AuthID), u64(o.AccountRevision), u64(o.DirectoryRevision))
	default:
		return nil, domain.ErrInvalid
	}
	return mac(p.emailKey, f...), nil
}
func (p *Protocol) CodeMAC(o port.Operation, code string) ([]byte, error) {
	if !p.ValidID(o.OperationID) || !email.ValidCode(code) || len(o.RequestMAC) != 32 || o.ExpiresAt.UnixMilli() < 0 || (o.Purpose != domain.Register && o.Purpose != domain.Add) {
		return nil, domain.ErrInvalid
	}
	return mac(p.emailKey, []byte("iwut-email-code-v3"), []byte(o.Purpose), []byte(o.OperationID), u64(o.ExpiresAt.UnixMilli()), o.RequestMAC, []byte(code)), nil
}
func (p *Protocol) Payload(o port.Operation) ([]byte, error) {
	address, err := email.NormalizeEmail(o.Email)
	if err != nil || address != o.Email || o.Purpose != domain.Register || o.ServiceID != p.service || !p.ValidID(o.OperationID) || len(o.Challenge) != 32 || o.ExpiresAt.UnixMilli() < 0 || p.device.ValidatePublicKey(o.PublicKey) != nil {
		return nil, domain.ErrInvalid
	}
	b := deviceprotocol.Frame([]byte("iwut-email-registration-proof-v3"), []byte(domain.ProtocolVersion), []byte(domain.Register), []byte(p.service), []byte(auth.ApplicationID), []byte(o.OperationID), o.Challenge, u64(o.ExpiresAt.UnixMilli()), o.PublicKey, []byte(o.Email))
	if len(b) > 1024 {
		return nil, domain.ErrInvalid
	}
	return b, nil
}
func (p *Protocol) MutationMAC(o port.Mutation, password string) ([]byte, error) {
	if o.AuthID == "" || !p.ValidID(o.RequestID) || !p.ValidID(o.BindingID) || o.DirectoryRevision <= 0 || o.AccountRevision <= 0 || (o.Purpose != domain.Switch && o.Purpose != domain.Remove) {
		return nil, domain.ErrInvalid
	}
	f := [][]byte{[]byte("iwut-email-mutation-request-v3"), []byte(o.Purpose), []byte(o.AuthID), []byte(o.RequestID), []byte(o.BindingID), u64(o.DirectoryRevision), u64(o.RoleRevision), u64(o.PasswordRevision), u64(o.AccountRevision)}
	if o.Purpose == domain.Switch {
		if o.RoleRevision <= 0 || o.PasswordRevision <= 0 || password == "" {
			return nil, domain.ErrInvalid
		}
		f = append(f, []byte(password))
		return mac(p.passwordKey, f...), nil
	}
	if password != "" {
		return nil, domain.ErrInvalid
	}
	return mac(p.emailKey, f...), nil
}
func (*Protocol) AddressQuotaKey(address string) string {
	sum := sha256.Sum256([]byte("email:" + address))
	return "mail-index:" + hex.EncodeToString(sum[:])
}
func (*Protocol) NewCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(100000000))
	if err != nil {
		return "", domain.ErrUnavailable
	}
	return fmt.Sprintf("%08d", n.Int64()), nil
}
