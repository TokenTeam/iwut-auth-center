package port

import (
	"context"
	"iwut-auth-center/internal/password/domain"
)

// Engine never logs or persists its plaintext inputs. Shared quota reservation
// belongs to the use case, before any expensive calls, not transaction retries.
type Engine interface {
	Normalize(string) (string, error)
	ValidateNew(string) (string, error)
	Hash(context.Context, string) (domain.Material, error)
	Verify(context.Context, string, domain.Material) (bool, error)
	NeedsUpgrade(domain.Material) bool
}
