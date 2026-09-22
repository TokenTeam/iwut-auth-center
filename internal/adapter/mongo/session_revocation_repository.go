package mongo

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"iwut-auth-center/internal/authentication/port"
)

// RevokeCurrentSession shares the durable authentication fence with online
// checks and login. The conditional update preserves the first revokedAt,
// regardless of expiration or the principal/credential's current state.
func (r *AuthenticationRepository) RevokeCurrentSession(ctx context.Context, digest []byte, now time.Time) error {
	if len(digest) != 32 {
		return port.ErrInvalidSessionToken
	}
	return r.WithAuthTransaction(ctx, func(tx context.Context) error {
		_, err := r.database.Collection(SessionCollection).UpdateOne(tx,
			bson.M{"tokenDigest": digest, "revokedAt": nil},
			bson.M{"$set": bson.M{"revokedAt": r.currentTime(now)}})
		return err
	})
}

var _ port.SessionRevocationRepository = (*AuthenticationRepository)(nil)
