// Package emailloginprotocol implements the independent iwut-email-login-v1 proof.
package emailloginprotocol

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"
	"unicode/utf8"

	"iwut-auth-center/internal/adapter/deviceprotocol"
	auth "iwut-auth-center/internal/authentication/domain"
	"iwut-auth-center/internal/emaillogin/domain"
	"iwut-auth-center/internal/emaillogin/port"
)

type Protocol struct {
	device    *deviceprotocol.Protocol
	serviceID string
	key       []byte
	keyID     string
	normalize func(string) (string, error)
}

// normalize is UC011's authoritative address normalization, supplied by composition.
func New(serviceID string, key []byte, normalize func(string) (string, error)) (*Protocol, error) {
	device, err := deviceprotocol.New(serviceID)
	if err != nil || len(key) != 32 || normalize == nil {
		return nil, domain.ErrUnavailable
	}
	key = bytes.Clone(key)
	id := sha256.Sum256(deviceprotocol.Frame([]byte("iwut-email-login-key-id-v1"), key))
	return &Protocol{device: device, serviceID: serviceID, key: key, keyID: hex.EncodeToString(id[:]), normalize: normalize}, nil
}
func (*Protocol) ValidSignature(signature []byte) bool {
	return deviceprotocol.ValidSignature(signature)
}
func (p *Protocol) KeyID() string                           { return p.keyID }
func (*Protocol) ValidID(id string) bool                    { return deviceprotocol.ValidID(id) }
func (p *Protocol) NormalizeEmail(s string) (string, error) { return p.normalize(s) }
func (*Protocol) ValidCode(s string) bool {
	if len(s) != 8 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
func (p *Protocol) mac(fields ...[]byte) []byte {
	h := hmac.New(sha256.New, p.key)
	h.Write(deviceprotocol.Frame(fields...))
	return h.Sum(nil)
}
func (p *Protocol) RequestMAC(b domain.Begin) []byte {
	return p.mac([]byte("iwut-email-login-request-v1"), []byte(b.RequestID), []byte(b.Email), []byte(p.serviceID), []byte(auth.ApplicationID), []byte(b.ProtocolVersion), b.PublicKey)
}
func (p *Protocol) CodeMAC(op domain.Operation, code string) []byte {
	var expiry [8]byte
	binary.BigEndian.PutUint64(expiry[:], uint64(op.ExpiresAt.UnixMilli()))
	return p.mac([]byte("iwut-email-login-code-v1"), []byte(domain.Purpose), []byte(op.OperationID), expiry[:], op.RequestMAC, []byte(code))
}
func (*Protocol) NewCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(100000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%08d", n.Int64()), nil
}
func (p *Protocol) Payload(op domain.Operation) ([]byte, error) {
	email, err := p.normalize(op.Email)
	if err != nil || email != op.Email || !utf8.ValidString(op.Email) || op.Purpose != domain.Purpose || op.ProtocolVersion != domain.ProtocolVersion || op.ServiceID != p.serviceID || op.ApplicationID != auth.ApplicationID || !p.ValidID(op.OperationID) || len(op.Challenge) != 32 || op.ExpiresAt.UnixMilli() < 0 || p.device.ValidatePublicKey(op.PublicKey) != nil {
		return nil, domain.ErrInvalid
	}
	var expiry [8]byte
	binary.BigEndian.PutUint64(expiry[:], uint64(op.ExpiresAt.UnixMilli()))
	payload := deviceprotocol.Frame([]byte("iwut-email-login-proof-v1"), []byte(op.ProtocolVersion), []byte(op.Purpose), []byte(op.ServiceID), []byte(op.ApplicationID), []byte(op.OperationID), op.Challenge, expiry[:], op.PublicKey, []byte(op.Email))
	if len(payload) > 1024 {
		return nil, domain.ErrInvalid
	}
	return payload, nil
}

// ParsePayload is strict and reconstructs the payload to check every contextual
// field. The caller must additionally compare the parsed values to its intent.
func (p *Protocol) ParsePayload(payload []byte) (domain.Operation, error) {
	f, err := deviceprotocol.ParseFrame(payload, 10)
	if err != nil || string(f[0]) != "iwut-email-login-proof-v1" || len(f[7]) != 8 {
		return domain.Operation{}, domain.ErrInvalid
	}
	for _, i := range []int{0, 1, 2, 3, 4, 5, 9} {
		if !utf8.Valid(f[i]) {
			return domain.Operation{}, domain.ErrInvalid
		}
	}
	ms := binary.BigEndian.Uint64(f[7])
	if ms > uint64(1<<63-1) {
		return domain.Operation{}, domain.ErrInvalid
	}
	op := domain.Operation{ProtocolVersion: string(f[1]), Purpose: string(f[2]), ServiceID: string(f[3]), ApplicationID: string(f[4]), OperationID: string(f[5]), Challenge: f[6], ExpiresAt: time.UnixMilli(int64(ms)), PublicKey: f[8], Email: string(f[9])}
	canonical, err := p.Payload(op)
	if err != nil || !bytes.Equal(canonical, payload) {
		return domain.Operation{}, domain.ErrInvalid
	}
	return op, nil
}
func (p *Protocol) Verify(publicKey, payload, signature []byte) bool {
	op, err := p.ParsePayload(payload)
	return err == nil && bytes.Equal(op.PublicKey, publicKey) && p.device.Verify(publicKey, payload, signature)
}

var _ port.Protocol = (*Protocol)(nil)
