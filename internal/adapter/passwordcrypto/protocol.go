package passwordcrypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"time"

	"iwut-auth-center/internal/adapter/deviceprotocol"
	email "iwut-auth-center/internal/emailbinding/domain"
	"iwut-auth-center/internal/password/domain"
)

type Protocol struct {
	key     []byte
	service string
	device  *deviceprotocol.Protocol
}

func NewProtocol(key []byte, service string) (*Protocol, error) {
	d, err := deviceprotocol.New(service)
	if err != nil || len(key) != 32 {
		return nil, domain.ErrUnavailable
	}
	return &Protocol{append([]byte(nil), key...), service, d}, nil
}

func u64(value int64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(value))
	return b[:]
}
func (p *Protocol) mac(fields ...[]byte) []byte {
	b := deviceprotocol.Frame(fields...)
	defer clear(b)
	h := hmac.New(sha256.New, p.key)
	h.Write(b)
	return h.Sum(nil)
}
func (p *Protocol) KeyID() string {
	sum := sha256.Sum256(deviceprotocol.Frame([]byte("iwut-password-operation-key-id-v1"), p.key))
	return hex.EncodeToString(sum[:])
}
func (p *Protocol) ChangeMAC(authID, requestID, sessionID string, accountRevision, passwordRevision int64, current, next string) ([]byte, error) {
	if authID == "" || !deviceprotocol.ValidID(requestID) || !deviceprotocol.ValidID(sessionID) || accountRevision <= 0 || passwordRevision <= 0 {
		return nil, domain.ErrInvalidInput
	}
	return p.mac([]byte("iwut-password-change-request-v1"), []byte(authID), []byte(requestID), []byte(sessionID), u64(accountRevision), u64(passwordRevision), []byte(current), []byte(next)), nil
}
func (p *Protocol) ResetRequestMAC(requestID, address string) ([]byte, error) {
	normalized, err := email.NormalizeEmail(address)
	if err != nil || normalized != address || !deviceprotocol.ValidID(requestID) {
		return nil, domain.ErrInvalidInput
	}
	return p.mac([]byte("iwut-password-reset-request-v1"), []byte(requestID), []byte(address), []byte(p.service), []byte("iwut-client")), nil
}
func (p *Protocol) ResetCodeMAC(operationID, authID string, roleRevision, passwordRevision, accountRevision int64, expires time.Time, requestMAC []byte, code string) ([]byte, error) {
	if !deviceprotocol.ValidID(operationID) || authID == "" || roleRevision <= 0 || passwordRevision <= 0 || accountRevision <= 0 || expires.UnixMilli() < 0 || len(requestMAC) != 32 || !validCode(code) {
		return nil, domain.ErrInvalidInput
	}
	return p.mac([]byte("iwut-password-reset-code-v1"), []byte("RESET_PASSWORD"), []byte(operationID), []byte(authID), u64(roleRevision), u64(passwordRevision), u64(accountRevision), u64(expires.UnixMilli()), requestMAC, []byte(code)), nil
}
func (p *Protocol) ResetCompletionMAC(operationID string, codeMAC []byte, next string) ([]byte, error) {
	if !deviceprotocol.ValidID(operationID) || len(codeMAC) != 32 {
		return nil, domain.ErrInvalidInput
	}
	return p.mac([]byte("iwut-password-reset-completion-v1"), []byte(operationID), codeMAC, []byte(next)), nil
}
func validCode(code string) bool {
	if len(code) != 8 {
		return false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func (p *Protocol) LoginPayload(operationID, address string, key, challenge []byte, expires time.Time) ([]byte, error) {
	normalized, err := email.NormalizeEmail(address)
	if err != nil || normalized != address || !deviceprotocol.ValidID(operationID) || p.device.ValidatePublicKey(key) != nil || len(challenge) != 32 || expires.UnixMilli() < 0 {
		return nil, domain.ErrInvalidInput
	}
	payload := deviceprotocol.Frame([]byte("iwut-password-login-proof-v1"), []byte("iwut-password-login-v1"), []byte("LOGIN_WITH_PASSWORD"), []byte(p.service), []byte("iwut-client"), []byte(operationID), challenge, u64(expires.UnixMilli()), key, []byte(address))
	if len(payload) > 1024 {
		return nil, domain.ErrInvalidInput
	}
	return payload, nil
}
