package mongo

import (
	"context"
	"go.mongodb.org/mongo-driver/v2/mongo"
	d "iwut-auth-center/internal/campuscertification/domain"
	"time"
)

// Only current verified bindings authorize certification. The historical
// permanent collection is not consulted, repaired or migrated.
func ReadCurrentCampusBasisTx(ctx context.Context, db *mongo.Database, authID string) (d.Certification, error) {
	directory, err := ReadEmailDirectoryTx(ctx, db, authID)
	if err != nil {
		return d.Certification{}, d.ErrUnavailable
	}
	var earliest time.Time
	for _, binding := range directory.Bindings {
		if d.IsWHUTEmail(binding.Email) && (earliest.IsZero() || binding.VerifiedAt.Before(earliest)) {
			earliest = binding.VerifiedAt
		}
	}
	if earliest.IsZero() {
		return d.Certification{}, d.ErrNotFound
	}
	return d.Certification{Institution: "WHUT", CertifiedAt: earliest}, nil
}
