package mongo

import (
	"context"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	drivermongo "go.mongodb.org/mongo-driver/v2/mongo"
	"iwut-auth-center/internal/authentication/domain"
	"iwut-auth-center/internal/authentication/port"
)

func (r *AuthenticationRepository) RevokeOwnCredential(ctx context.Context, caller domain.Session, credentialID string, now time.Time) error {
	return r.WithAuthTransaction(ctx, func(tx context.Context) error {
		now := r.currentTime(now)
		// The middleware's earlier authorization is not sufficient: both revocation
		// and login share this transaction fence, including retries and expiry checks.
		var session SessionDocument
		err := r.database.Collection(SessionCollection).FindOne(tx, bson.M{"sessionId": caller.SessionID, "authId": caller.AuthID, "credentialId": caller.CredentialID, "tokenDigest": caller.TokenDigest, "revokedAt": nil, "expiresAt": bson.M{"$gt": now}}).Decode(&session)
		if errors.Is(err, drivermongo.ErrNoDocuments) {
			return port.ErrSessionInvalid
		}
		if err != nil {
			return err
		}
		if !validSession(session) {
			return port.ErrSessionInvalid
		}
		var credential CredentialDocument
		err = r.database.Collection(CredentialCollection).FindOne(tx, bson.M{"credentialId": session.CredentialID, "authId": session.AuthID, "revokedAt": nil}).Decode(&credential)
		if errors.Is(err, drivermongo.ErrNoDocuments) {
			return port.ErrSessionInvalid
		}
		if err != nil {
			return err
		}
		if !validCredential(credential) {
			return port.ErrSessionInvalid
		}
		if err := r.ConfirmAccountTx(tx, session.AuthID, session.AccountRevision); errors.Is(err, port.ErrAuthenticationFailed) {
			return port.ErrSessionInvalid
		} else if err != nil {
			return err
		}
		if err := r.ConfirmPrincipalCredentialTx(tx, session.AuthID, session.CredentialID, now); errors.Is(err, port.ErrAuthenticationFailed) {
			return port.ErrSessionInvalid
		} else if err != nil {
			return err
		}
		// Other targets receive the same response without an ownership lookup.
		if credentialID != session.CredentialID {
			return port.ErrCredentialReauthRequired
		}
		// This write makes concurrent direct session revocation conflict too, rather
		// than trusting a snapshot whose authorizing Session was already revoked.
		updated, err := r.database.Collection(SessionCollection).UpdateOne(tx, bson.M{"sessionId": session.SessionID, "revokedAt": nil, "expiresAt": bson.M{"$gt": now}}, bson.M{"$max": bson.M{"lastUsedAt": now}, "$inc": bson.M{"authenticationFence": int64(1)}})
		if err != nil {
			return err
		}
		if updated.MatchedCount != 1 {
			return port.ErrSessionInvalid
		}
		return r.revokeCredentialTargetTx(tx, session.AuthID, credentialID, now)
	})
}

// Private target-state primitive, called only inside a final authorizing Auth
// transaction. It cannot grant authority or become a second public endpoint.
func (r *AuthenticationRepository) revokeCredentialTargetTx(tx context.Context, owner, credentialID string, now time.Time) error {
	var target CredentialDocument
	err := r.database.Collection(CredentialCollection).FindOne(tx, bson.M{"credentialId": credentialID, "authId": owner}).Decode(&target)
	if errors.Is(err, drivermongo.ErrNoDocuments) {
		return port.ErrNotFound
	}
	if err != nil {
		return err
	}
	if target.RevokedAt != nil {
		return nil
	}
	result, err := r.database.Collection(CredentialCollection).UpdateOne(tx, bson.M{"credentialId": credentialID, "authId": owner, "revokedAt": nil}, bson.M{"$set": bson.M{"revokedAt": now}})
	if err != nil {
		return err
	}
	if result.MatchedCount != 1 {
		return port.ErrUnavailable
	}
	return nil
}

var _ port.CredentialRevocationRepository = (*AuthenticationRepository)(nil)
