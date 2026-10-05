package mongo

import (
	"context"
	"errors"
	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	account "iwut-auth-center/internal/account/domain"
	"iwut-auth-center/internal/authentication/port"
)

// AccountRevisionTx reads authoritative account state in the caller's transaction.
func (r *AuthenticationRepository) AccountRevisionTx(ctx context.Context, authID string) (int64, error) {
	var raw bson.Raw
	err := r.database.Collection(PrincipalCollection).FindOne(ctx, bson.M{"authId": authID}).Decode(&raw)
	if errors.Is(err, m.ErrNoDocuments) {
		return 0, port.ErrAuthenticationFailed
	}
	if err != nil {
		return 0, err
	}
	if v := raw.Lookup("principalType"); v.Type == bson.TypeString && v.StringValue() == "SYSTEM" {
		return 0, port.ErrAuthenticationFailed
	}
	if !identityFields(raw, map[string]bson.Type{"principalType": bson.TypeString, "accountStatus": bson.TypeString, "accountRevision": bson.TypeInt64}) {
		return 0, port.ErrUnavailable
	}
	revision := raw.Lookup("accountRevision").Int64()
	if revision <= 0 {
		return 0, port.ErrUnavailable
	}
	if raw.Lookup("principalType").StringValue() != "USER" || raw.Lookup("accountStatus").StringValue() != "ACTIVE" {
		return 0, port.ErrAuthenticationFailed
	}
	return revision, nil
}
func (r *AuthenticationRepository) ConfirmAccountTx(ctx context.Context, authID string, revision int64) error {
	current, err := r.AccountRevisionTx(ctx, authID)
	if err != nil {
		return err
	}
	if revision <= 0 || revision != current {
		return port.ErrAuthenticationFailed
	}
	result, err := r.database.Collection(PrincipalCollection).UpdateOne(ctx, bson.M{"authId": authID, "principalType": "USER", "accountStatus": "ACTIVE", "accountRevision": revision}, bson.M{"$inc": bson.M{"authenticationFence": int64(1)}})
	if err != nil {
		return err
	}
	if result.MatchedCount != 1 {
		return port.ErrAuthenticationFailed
	}
	return nil
}
func (r *AuthenticationRepository) ConfirmIdentityTx(ctx context.Context, authID string) error {
	identity, ok := account.Identity(ctx)
	if !ok || identity.AuthID != authID {
		return port.ErrAuthenticationFailed
	}
	return r.ConfirmAccountTx(ctx, authID, identity.Revision)
}
