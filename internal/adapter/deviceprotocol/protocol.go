// Package deviceprotocol implements the fixed app-device-session-v1 wire contract.
package deviceprotocol

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math/big"
	"regexp"

	"github.com/google/uuid"
	"iwut-auth-center/internal/authentication/domain"
	"iwut-auth-center/internal/authentication/port"
)

var servicePattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
var idPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var errEncoding = errors.New("invalid device protocol encoding")

type Protocol struct{ serviceID string }

func New(serviceID string) (*Protocol, error) {
	if !servicePattern.MatchString(serviceID) {
		return nil, errEncoding
	}
	return &Protocol{serviceID: serviceID}, nil
}

func ValidID(id string) bool { return idPattern.MatchString(id) }

func Frame(fields ...[]byte) []byte {
	var out []byte
	for _, field := range fields {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(field)))
		out = append(out, size[:]...)
		out = append(out, field...)
	}
	return out
}

func ParseFrame(payload []byte, count int) ([][]byte, error) {
	if len(payload) > 1024 || count < 0 || count > 32 {
		return nil, errEncoding
	}
	fields := make([][]byte, 0, count)
	for i := 0; i < count; i++ {
		if len(payload) < 4 {
			return nil, errEncoding
		}
		n := binary.BigEndian.Uint32(payload[:4])
		payload = payload[4:]
		if uint64(n) > uint64(len(payload)) {
			return nil, errEncoding
		}
		fields = append(fields, bytes.Clone(payload[:n]))
		payload = payload[n:]
	}
	if len(payload) != 0 {
		return nil, errEncoding
	}
	return fields, nil
}

func (*Protocol) ValidatePublicKey(publicKey []byte) error {
	if len(publicKey) != 65 || publicKey[0] != 4 {
		return errEncoding
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), publicKey)
	if x == nil || y == nil {
		return errEncoding
	}
	return nil
}

func (p *Protocol) Fingerprint(publicKey []byte) ([]byte, error) {
	if err := p.ValidatePublicKey(publicKey); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(Frame([]byte("iwut-device-public-key-v1"), publicKey))
	return digest[:], nil
}

func (p *Protocol) SigningPayload(op domain.Operation, associationDigest []byte) ([]byte, error) {
	if op.ProtocolVersion != domain.ProtocolVersion || op.ServiceID != p.serviceID || op.ApplicationID != domain.ApplicationID || !ValidID(op.OperationID) || len(op.Challenge) != 32 || op.ExpiresAt.UnixMilli() < 0 {
		return nil, errEncoding
	}
	switch op.Purpose {
	case domain.Register:
		if op.LocatorKind != domain.FingerprintLocator || len(op.LocatorValue) != 32 || len(associationDigest) != 32 {
			return nil, errEncoding
		}
	case domain.Login:
		if len(associationDigest) != 0 {
			return nil, errEncoding
		}
		if (op.LocatorKind != domain.CredentialIDLocator || !ValidID(string(op.LocatorValue))) && (op.LocatorKind != domain.FingerprintLocator || len(op.LocatorValue) != 32) {
			return nil, errEncoding
		}
	default:
		return nil, errEncoding
	}
	var expiry [8]byte
	binary.BigEndian.PutUint64(expiry[:], uint64(op.ExpiresAt.UnixMilli()))
	payload := Frame([]byte("iwut-device-proof-v1"), []byte(op.ProtocolVersion), []byte(op.Purpose), []byte(op.ServiceID), []byte(op.ApplicationID), []byte(op.OperationID), op.Challenge, expiry[:], []byte(op.LocatorKind), op.LocatorValue, associationDigest)
	if len(payload) > 1024 {
		return nil, errEncoding
	}
	return payload, nil
}

func (p *Protocol) Verify(publicKey, payload, signature []byte) bool {
	if p.ValidatePublicKey(publicKey) != nil || len(payload) == 0 || len(payload) > 1024 || len(signature) == 0 || len(signature) > 72 {
		return false
	}
	var rs struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(signature, &rs)
	if err != nil || len(rest) != 0 || rs.R == nil || rs.S == nil || rs.R.Sign() <= 0 || rs.S.Sign() <= 0 || rs.R.Cmp(elliptic.P256().Params().N) >= 0 || rs.S.Cmp(elliptic.P256().Params().N) >= 0 {
		return false
	}
	canonical, err := asn1.Marshal(rs)
	if err != nil || !bytes.Equal(canonical, signature) {
		return false
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), publicKey)
	digest := sha256.Sum256(payload)
	return ecdsa.Verify(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, digest[:], rs.R, rs.S)
}

func (*Protocol) NewID() (string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}
	return id.String(), nil
}
func (*Protocol) RandomBytes(n int) ([]byte, error) {
	if n < 1 || n > 1024 {
		return nil, errEncoding
	}
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}
func (p *Protocol) NewSessionToken() (string, []byte, error) {
	raw, err := p.RandomBytes(32)
	if err != nil {
		return "", nil, err
	}
	digest := sha256.Sum256(raw)
	return base64.RawURLEncoding.EncodeToString(raw), digest[:], nil
}
func (*Protocol) TokenDigest(token string) ([]byte, error) {
	if len(token) != 43 {
		return nil, errEncoding
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != token {
		return nil, errEncoding
	}
	digest := sha256.Sum256(raw)
	return digest[:], nil
}

var _ port.DeviceProtocol = (*Protocol)(nil)
