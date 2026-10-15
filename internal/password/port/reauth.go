package port

import (
	"context"
	"iwut-auth-center/internal/password/domain"
	"time"
)

// The caller must first prove its registered device. This is a private
// attestation to be rechecked by that command's final Auth transaction, never
// a reusable public unlock token or a replacement for business authorization.
type ReauthRequest struct {
	AuthID, CredentialID, Password, Source string
	AccountRevision                        int64
	AllowDisabled                          bool
}
type ReauthRepository interface {
	ReadReauth(context.Context, ReauthRequest, time.Time) (domain.Record, error)
}
type PasswordVerifier interface {
	VerifyPassword(context.Context, ReauthRequest) (int64, error)
}
