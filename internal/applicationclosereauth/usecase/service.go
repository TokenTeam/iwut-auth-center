package usecase

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
	d "iwut-auth-center/internal/applicationclosereauth/domain"
	p "iwut-auth-center/internal/applicationclosereauth/port"
	pd "iwut-auth-center/internal/password/domain"
	pp "iwut-auth-center/internal/password/port"
)

const (
	proofAudience = "iwut-app-center"
	proofPurpose  = "app.close"
	proofType     = "APP_CLOSE_REAUTH"
)

type Service struct {
	password   pp.PasswordVerifier
	repository p.Repository
	protocol   p.Protocol
	signer     p.Signer
	issuer     string
	clock      func() time.Time
	newJTI     func() (uuid.UUID, error)
}

func New(repository p.Repository, protocol p.Protocol, signer p.Signer, issuer string, password pp.PasswordVerifier) (*Service, error) {
	if password == nil || repository == nil || protocol == nil || signer == nil || strings.TrimSpace(issuer) == "" {
		return nil, d.ErrUnavailable
	}
	return &Service{password: password, repository: repository, protocol: protocol, signer: signer, issuer: issuer, clock: time.Now, newJTI: uuid.NewV7}, nil
}

func canonicalID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && strings.ToLower(id.String()) == value
}

func (s *Service) Begin(ctx context.Context, sessionDigest []byte, applicationID string) (d.Challenge, error) {
	if len(sessionDigest) != 32 || !canonicalID(applicationID) {
		return d.Challenge{}, d.ErrInvalid
	}
	id, err := s.protocol.NewID()
	if err != nil {
		return d.Challenge{}, d.ErrUnavailable
	}
	challenge, err := s.protocol.RandomBytes(32)
	if err != nil {
		return d.Challenge{}, d.ErrUnavailable
	}
	now := s.clock().UTC().Truncate(time.Millisecond)
	op, err := s.repository.Begin(ctx, sessionDigest, applicationID, id, challenge, now, now.Add(5*time.Minute))
	if err != nil {
		return d.Challenge{}, err
	}
	return d.Challenge{OperationID: op.OperationID, Challenge: append([]byte(nil), op.Challenge...), ExpiresAt: op.ExpiresAt}, nil
}

func SigningPayload(operationID, applicationID string, challenge []byte) ([]byte, error) {
	op, e1 := uuid.Parse(operationID)
	app, e2 := uuid.Parse(applicationID)
	if e1 != nil || e2 != nil || strings.ToLower(op.String()) != operationID || strings.ToLower(app.String()) != applicationID || len(challenge) != 32 {
		return nil, d.ErrInvalid
	}
	return frame([]byte("iwut-application-close-reauth-v1"), []byte("COMPLETE_APPLICATION_CLOSE_REAUTH"), op[:], app[:], challenge), nil
}

func frame(fields ...[]byte) []byte {
	var out []byte
	for _, field := range fields {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(field)))
		out = append(out, size[:]...)
		out = append(out, field...)
	}
	return out
}

func validSignature(signature []byte) bool {
	type scalars struct{ R, S *big.Int }
	var value scalars
	rest, err := asn1.Unmarshal(signature, &value)
	if err != nil || len(rest) != 0 || value.R == nil || value.S == nil || value.R.Sign() <= 0 || value.S.Sign() <= 0 || value.R.Cmp(elliptic.P256().Params().N) >= 0 || value.S.Cmp(elliptic.P256().Params().N) >= 0 {
		return false
	}
	canonical, err := asn1.Marshal(value)
	return err == nil && bytes.Equal(canonical, signature) && len(signature) <= 72
}

func (s *Service) Complete(ctx context.Context, sessionDigest []byte, operationID, applicationID string, signature []byte, password, source string) (d.Proof, error) {
	if password == "" || len(password) > 1024 || len(sessionDigest) != 32 || !canonicalID(operationID) || !canonicalID(applicationID) || !validSignature(signature) {
		return d.Proof{}, d.ErrInvalid
	}
	now := s.clock().UTC().Truncate(time.Millisecond)
	op, err := s.repository.ReadForComplete(ctx, sessionDigest, operationID, applicationID, now)
	if err != nil {
		return d.Proof{}, err
	}
	digest := sha256.Sum256(signature)
	payload, err := SigningPayload(op.OperationID, op.ApplicationID, op.Challenge)
	if err != nil || !s.protocol.Verify(op.PublicKey, payload, signature) || op.State == d.Completed && !equal(op.SignatureDigest, digest[:]) {
		return d.Proof{}, s.reject(ctx, op, now)
	}
	revision, err := s.password.VerifyPassword(ctx, pp.ReauthRequest{AuthID: op.AuthID, CredentialID: op.CredentialID, AccountRevision: op.AccountRevision, Password: password, Source: source})
	if err != nil {
		switch {
		case errors.Is(err, pd.ErrAuthentication), errors.Is(err, pd.ErrSessionInvalid):
			return d.Proof{}, s.reject(ctx, op, now)
		case errors.Is(err, pd.ErrInvalidInput):
			return d.Proof{}, d.ErrInvalid
		case errors.Is(err, pd.ErrLimited):
			return d.Proof{}, d.ErrRate
		default:
			return d.Proof{}, d.ErrUnavailable
		}
	}
	if revision <= 0 || revision != op.PasswordRevision {
		return d.Proof{}, d.ErrFailed
	}
	// auth_time represents successful dual verification, not request arrival or
	// the Session timestamp; the repository rechecks expiry at this final time.
	now = s.clock().UTC().Truncate(time.Millisecond)
	if op.State == d.Completed {
		// Even retries cross the final authentication fence after verifying the password.
		op, err = s.repository.Complete(ctx, sessionDigest, operationID, applicationID, digest[:], revision, operationClaims(op, s.issuer), now)
		if err != nil {
			return d.Proof{}, err
		}
		return s.proof(ctx, op)
	}
	jti, err := s.newJTI()
	if err != nil {
		return d.Proof{}, d.ErrUnavailable
	}
	issued := time.Unix(now.Unix(), 0).UTC()
	claims := d.Claims{Issuer: s.issuer, Subject: op.AuthID, Audience: proofAudience, TokenType: proofType, Purpose: proofPurpose, ApplicationID: applicationID, JTI: jti.String(), AuthTime: issued, IssuedAt: issued, NotBefore: issued.Add(-30 * time.Second), ExpiresAt: issued.Add(5 * time.Minute)}
	op, err = s.repository.Complete(ctx, sessionDigest, operationID, applicationID, digest[:], revision, claims, now)
	if err != nil {
		return d.Proof{}, err
	}
	return s.proof(ctx, op)
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func operationClaims(op d.Operation, issuer string) d.Claims {
	return d.Claims{Issuer: issuer, Subject: op.AuthID, Audience: proofAudience, TokenType: proofType, Purpose: proofPurpose, ApplicationID: op.ApplicationID, JTI: op.JTI, AuthTime: op.AuthTime, IssuedAt: op.IssuedAt, NotBefore: op.NotBefore, ExpiresAt: op.ProofExpiresAt}
}

func (s *Service) proof(ctx context.Context, op d.Operation) (d.Proof, error) {
	if op.State != d.Completed || op.JTI == "" || op.ProofExpiresAt.IsZero() {
		return d.Proof{}, d.ErrInconsistent
	}
	proof, err := s.signer.Sign(ctx, operationClaims(op, s.issuer))
	if err != nil {
		return d.Proof{}, d.ErrUnavailable
	}
	return d.Proof{JWS: proof, ExpiresAt: op.ProofExpiresAt}, nil
}

func (s *Service) reject(ctx context.Context, op d.Operation, now time.Time) error {
	if op.State == d.Pending {
		if err := s.repository.Fail(ctx, op.OperationID, now); err != nil {
			return err
		}
	}
	return d.ErrFailed
}
