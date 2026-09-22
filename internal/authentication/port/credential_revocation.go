package port

import (
	"context"
	"time"

	"iwut-auth-center/internal/authentication/domain"
)

// CredentialRevocationRepository must revalidate the authorizing session and
// ownership in the same transaction that permanently revokes the target.
type CredentialRevocationRepository interface {
	RevokeOwnCredential(context.Context, domain.Session, string, time.Time) error
}
