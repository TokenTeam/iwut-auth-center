package closureprotocol

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"

	closure "iwut-auth-center/internal/accountclosure/domain"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	auth "iwut-auth-center/internal/authentication/domain"
)

var errEncoding = errors.New("invalid account closure proof encoding")

type Protocol struct {
	*deviceprotocol.Protocol
	serviceID string
}

func New(serviceID string) (*Protocol, error) {
	p, err := deviceprotocol.New(serviceID)
	if err != nil {
		return nil, err
	}
	return &Protocol{Protocol: p, serviceID: serviceID}, nil
}

func (p *Protocol) SigningPayload(proof closure.Proof) ([]byte, error) {
	if proof.ServiceID != p.serviceID || proof.ApplicationID != auth.ApplicationID || !deviceprotocol.ValidID(proof.OperationID) ||
		len(proof.Challenge) != 32 || proof.ExpiresAt.UnixMilli() < 0 || proof.PolicyVersion != closure.PolicyVersion {
		return nil, errEncoding
	}
	if (proof.LocatorKind != string(auth.CredentialIDLocator) || !deviceprotocol.ValidID(string(proof.LocatorValue))) &&
		(proof.LocatorKind != string(auth.FingerprintLocator) || len(proof.LocatorValue) != 32) {
		return nil, errEncoding
	}
	var expiry [8]byte
	binary.BigEndian.PutUint64(expiry[:], uint64(proof.ExpiresAt.UnixMilli()))
	return deviceprotocol.Frame([]byte("iwut-account-closure-proof-v1"), []byte(closure.ProofPurpose),
		[]byte(proof.ServiceID), []byte(proof.ApplicationID), []byte(proof.OperationID), proof.Challenge,
		expiry[:], []byte(proof.LocatorKind), proof.LocatorValue, []byte(proof.PolicyVersion)), nil
}

func (*Protocol) TokenDigest(purpose closure.TokenPurpose, token string) ([]byte, error) {
	if purpose != closure.ConfirmationToken && purpose != closure.ReceiptToken || len(token) != 43 {
		return nil, errEncoding
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != token {
		return nil, errEncoding
	}
	digest := sha256.Sum256(deviceprotocol.Frame([]byte("iwut-closure-"+string(purpose)+"-v1"), raw))
	return digest[:], nil
}

func (p *Protocol) NewToken(purpose closure.TokenPurpose) (string, []byte, error) {
	if purpose != closure.ConfirmationToken && purpose != closure.ReceiptToken {
		return "", nil, errEncoding
	}
	raw, err := p.RandomBytes(32)
	if err != nil {
		return "", nil, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	digest, err := p.TokenDigest(purpose, token)
	return token, digest, err
}
