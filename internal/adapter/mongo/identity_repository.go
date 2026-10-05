package mongo

import (
	"context"
	"errors"
	"go.mongodb.org/mongo-driver/v2/bson"
	drivermongo "go.mongodb.org/mongo-driver/v2/mongo"
	authport "iwut-auth-center/internal/authentication/port"
	"iwut-auth-center/internal/identity/domain"
	"time"
)

type IdentityRepository struct{ authentication *AuthenticationRepository }

func NewIdentityRepository(authentication *AuthenticationRepository) (*IdentityRepository, error) {
	if authentication == nil {
		return nil, domain.ErrUnavailable
	}
	return &IdentityRepository{authentication}, nil
}
func (r *IdentityRepository) WithSession(ctx context.Context, digest []byte, prepare func(domain.Snapshot, time.Time) error) error {
	if len(digest) != 32 {
		return domain.ErrSessionInvalid
	}
	if prepare == nil {
		return domain.ErrUnavailable
	}
	a := r.authentication
	var applicationErr error
	err := a.WithAuthTransaction(ctx, func(tx context.Context) error {
		applicationErr = nil
		fail := func(err error) error { applicationErr = err; return authport.ErrUnavailable }
		now := a.currentTime(time.Time{})
		var raw bson.Raw
		err := a.database.Collection(SessionCollection).FindOne(tx, bson.M{"tokenDigest": digest}).Decode(&raw)
		if errors.Is(err, drivermongo.ErrNoDocuments) {
			return fail(domain.ErrSessionInvalid)
		}
		if err != nil {
			return err
		}
		if !identityFields(raw, map[string]bson.Type{"sessionId": bson.TypeString, "authId": bson.TypeString, "credentialId": bson.TypeString, "authenticationMethod": bson.TypeString, "tokenDigest": bson.TypeBinary, "createdAt": bson.TypeDateTime, "authenticatedAt": bson.TypeDateTime, "lastUsedAt": bson.TypeDateTime, "expiresAt": bson.TypeDateTime}) || !validRevokedField(raw) {
			return fail(domain.ErrUnavailable)
		}
		var session SessionDocument
		if bson.Unmarshal(raw, &session) != nil {
			return fail(domain.ErrUnavailable)
		}
		if session.RevokedAt != nil || !now.Before(session.ExpiresAt) {
			return fail(domain.ErrSessionInvalid)
		}
		if !validSession(session) {
			return fail(domain.ErrUnavailable)
		}
		err = a.database.Collection(CredentialCollection).FindOne(tx, bson.M{"credentialId": session.CredentialID}).Decode(&raw)
		if errors.Is(err, drivermongo.ErrNoDocuments) {
			return fail(domain.ErrSessionInvalid)
		}
		if err != nil {
			return err
		}
		if !identityFields(raw, map[string]bson.Type{"credentialId": bson.TypeString, "authId": bson.TypeString, "protocolVersion": bson.TypeString, "publicKey": bson.TypeBinary, "fingerprint": bson.TypeBinary, "createdAt": bson.TypeDateTime}) || !validRevokedField(raw) {
			return fail(domain.ErrUnavailable)
		}
		var credential CredentialDocument
		if bson.Unmarshal(raw, &credential) != nil {
			return fail(domain.ErrUnavailable)
		}
		if credential.AuthID != session.AuthID || credential.RevokedAt != nil {
			return fail(domain.ErrSessionInvalid)
		}
		if !validCredential(credential) {
			return fail(domain.ErrUnavailable)
		}
		err = a.database.Collection(PrincipalCollection).FindOne(tx, bson.M{"authId": session.AuthID}).Decode(&raw)
		if errors.Is(err, drivermongo.ErrNoDocuments) {
			return fail(domain.ErrSessionInvalid)
		}
		if err != nil {
			return err
		}
		if !identityFields(raw, map[string]bson.Type{"authId": bson.TypeString, "principalType": bson.TypeString, "accountStatus": bson.TypeString}) {
			return fail(domain.ErrUnavailable)
		}
		principalType := raw.Lookup("principalType").StringValue()
		accountStatus := raw.Lookup("accountStatus").StringValue()
		if principalType == "SYSTEM" || accountStatus == "DISABLED" || accountStatus == "CLOSED" {
			return fail(domain.ErrSessionInvalid)
		}
		if principalType != "USER" || accountStatus != "ACTIVE" {
			return fail(domain.ErrUnavailable)
		}
		if !identityFields(raw, map[string]bson.Type{"permissions": bson.TypeArray, "permissionRevision": bson.TypeInt64}) {
			return fail(domain.ErrUnavailable)
		}
		if err := a.ConfirmAccountTx(tx, session.AuthID, session.AccountRevision); errors.Is(err, authport.ErrAuthenticationFailed) {
			return fail(domain.ErrSessionInvalid)
		} else if err != nil {
			return err
		}
		snapshot := domain.Snapshot{AccountRevision: session.AccountRevision, AuthID: session.AuthID, PermissionRevision: raw.Lookup("permissionRevision").Int64(), SessionExpiresAt: session.ExpiresAt, Permissions: []string{}}
		values, err := raw.Lookup("permissions").Array().Values()
		if err != nil {
			return fail(domain.ErrUnavailable)
		}
		for _, v := range values {
			if v.Type != bson.TypeString {
				return fail(domain.ErrUnavailable)
			}
			snapshot.Permissions = append(snapshot.Permissions, v.StringValue())
		}
		status := raw.Lookup("developerStatus")
		switch status.Type {
		case bson.TypeNull:
		case bson.TypeString:
			snapshot.DeveloperStatus = status.StringValue()
			if snapshot.DeveloperStatus == "" {
				return fail(domain.ErrUnavailable)
			}
		default:
			return fail(domain.ErrUnavailable)
		}
		if !snapshot.Valid() {
			return fail(domain.ErrUnavailable)
		}
		// Writes to both participating records make concurrent direct capability,
		// disable and credential updates conflict even outside the shared fence.
		if err := a.ConfirmPrincipalCredentialTx(tx, session.AuthID, session.CredentialID, now); err != nil {
			return err
		}
		if err := prepare(snapshot, now); err != nil {
			return fail(err)
		}
		confirmed := a.currentTime(now)
		if !confirmed.Before(session.ExpiresAt) {
			return fail(domain.ErrSessionInvalid)
		}
		result, err := a.database.Collection(SessionCollection).UpdateOne(tx, bson.M{"sessionId": session.SessionID, "tokenDigest": digest, "revokedAt": nil, "expiresAt": bson.M{"$gt": confirmed}}, bson.M{"$max": bson.M{"lastUsedAt": confirmed}, "$inc": bson.M{"authenticationFence": int64(1)}})
		if err != nil {
			return err
		}
		if result.MatchedCount != 1 {
			return fail(domain.ErrSessionInvalid)
		}
		return nil
	})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		if applicationErr != nil {
			return applicationErr
		}
		return domain.ErrUnavailable
	}
	return nil
}
func identityFields(raw bson.Raw, fields map[string]bson.Type) bool {
	// Duplicate fields are ambiguous authoritative state, never silently select one.
	elements, err := raw.Elements()
	if err != nil {
		return false
	}
	seen := map[string]bool{}
	for _, element := range elements {
		key := element.Key()
		if seen[key] {
			return false
		}
		seen[key] = true
	}
	for k, t := range fields {
		if raw.Lookup(k).Type != t {
			return false
		}
	}
	return true
}
func validRevokedField(raw bson.Raw) bool {
	v := raw.Lookup("revokedAt")
	return v.Type == 0 || v.Type == bson.TypeNull || v.Type == bson.TypeDateTime
}
