package mongo

import (
	"context"
	"errors"
	m "go.mongodb.org/mongo-driver/v2/mongo"
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
		var session SessionDocument
		err := r.database.Collection(SessionCollection).FindOne(tx, bson.M{"tokenDigest": digest}).Decode(&session)
		if errors.Is(err, m.ErrNoDocuments) {
			return nil
		}
		if err != nil {
			return err
		}
		// Revocation does not require an active owner, unexpired Session or usable
		// credential, but a corrupt/unknown authentication method is never trusted.
		if !validSessionMethod(session) {
			return port.ErrUnavailable
		}

		_, err = r.database.Collection(SessionCollection).UpdateOne(tx,
			bson.M{"tokenDigest": digest, "revokedAt": nil},
			bson.M{"$set": bson.M{"revokedAt": r.currentTime(now)}})
		return err
	})
}

var _ port.SessionRevocationRepository = (*AuthenticationRepository)(nil)
