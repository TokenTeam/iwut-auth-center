package campusprotocol

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	auth "iwut-auth-center/internal/authentication/domain"
	d "iwut-auth-center/internal/campuscertification/domain"
	"iwut-auth-center/internal/campuscertification/port"
	"math/big"
)

type Protocol struct {
	key       []byte
	serviceID string
}

func New(key []byte, serviceID string) (*Protocol, error) {
	if len(key) != 32 {
		return nil, d.ErrUnavailable
	}
	if _, err := deviceprotocol.New(serviceID); err != nil {
		return nil, d.ErrUnavailable
	}
	return &Protocol{append([]byte(nil), key...), serviceID}, nil
}
func (p *Protocol) KeyID() string {
	sum := sha256.Sum256(deviceprotocol.Frame([]byte("iwut-campus-key-id-v1"), p.key))
	return hex.EncodeToString(sum[:])
}
func (*Protocol) ValidID(id string) bool { return deviceprotocol.ValidID(id) }
func u64(n int64) []byte                 { b := make([]byte, 8); binary.BigEndian.PutUint64(b, uint64(n)); return b }
func (p *Protocol) mac(fields ...[]byte) []byte {
	h := hmac.New(sha256.New, p.key)
	b := deviceprotocol.Frame(fields...)
	defer clear(b)
	h.Write(b)
	return h.Sum(nil)
}
func (p *Protocol) RequestMAC(b d.Begin, authID string, revision int64) []byte {
	return p.mac([]byte("iwut-campus-request-v1"), []byte(b.RequestID), []byte(authID), u64(revision), []byte(b.Email), []byte(p.serviceID), []byte(auth.ApplicationID))
}
func (p *Protocol) CodeMAC(op port.Operation, code string) []byte {
	return p.mac([]byte("iwut-campus-code-v1"), []byte(d.Purpose), []byte(op.Proof.OperationID), u64(op.Proof.ExpiresAt.UnixMilli()), op.RequestMAC, []byte(code))
}
func (*Protocol) NewCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(100000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%08d", n.Int64()), nil
}
