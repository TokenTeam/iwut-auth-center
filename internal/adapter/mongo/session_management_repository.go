package mongo

import (
	"context"
	"errors"
	"sort"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	auth "iwut-auth-center/internal/authentication/port"
	password "iwut-auth-center/internal/password/domain"
	d "iwut-auth-center/internal/sessionmanagement/domain"
	"iwut-auth-center/internal/sessionmanagement/port"
)

const SessionManagementAuditCollection = "auth_session_management_audit_events"
const sessionScanLimit = 200

type SessionManagementRepository struct{ auth *AuthenticationRepository }

func NewSessionManagementRepository(auth *AuthenticationRepository) (*SessionManagementRepository, error) {
	if auth == nil {
		return nil, d.ErrUnavailable
	}
	return &SessionManagementRepository{auth}, nil
}
func EnsureSessionManagementSchema(ctx context.Context, db *m.Database) error {
	if db == nil {
		return d.ErrUnavailable
	}
	for name, models := range map[string][]m.IndexModel{
		SessionCollection: {{Keys: bson.D{{Key: "authId", Value: 1}, {Key: "createdAt", Value: -1}, {Key: "sessionId", Value: -1}}, Options: options.Index().SetName("session_owner_created_id")}},
		SessionManagementAuditCollection: {
			{Keys: bson.D{{Key: "eventId", Value: 1}}, Options: options.Index().SetUnique(true).SetName("session_management_event_unique")},
			{Keys: bson.D{{Key: "actorAuthId", Value: 1}, {Key: "occurredAt", Value: 1}}, Options: options.Index().SetName("session_management_actor_time")},
			{Keys: bson.D{{Key: "occurredAt", Value: 1}}, Options: options.Index().SetName("session_management_retention")},
		},
	} {
		if _, e := db.Collection(name).Indexes().CreateMany(ctx, models); e != nil {
			return d.ErrUnavailable
		}
	}
	return nil
}
func (r *SessionManagementRepository) transaction(ctx context.Context, fn func(context.Context) error) error {
	var failure error
	e := r.auth.WithAuthTransaction(ctx, func(tx context.Context) error {
		failure = fn(tx)
		return failure
	})
	if e == nil {
		return nil
	}
	for _, known := range []error{d.ErrInvalidRequest, d.ErrInvalidCursor, d.ErrCurrentSession, d.ErrSessionInvalid, d.ErrRateLimited} {
		if errors.Is(failure, known) {
			return known
		}
	}
	return d.ErrUnavailable
}
func (r *SessionManagementRepository) Authenticate(ctx context.Context, digest []byte, now time.Time) (string, error) {
	var id string
	e := r.transaction(ctx, func(tx context.Context) error {
		s, e := r.caller(tx, digest, r.auth.currentTime(now))
		id = s.AuthID
		return e
	})
	return id, e
}
func (r *SessionManagementRepository) List(ctx context.Context, digest []byte, pageSize int, cursor string, now time.Time) (d.Page, error) {
	if e := d.ValidateList(pageSize, cursor); e != nil {
		return d.Page{}, e
	}
	var page d.Page
	e := r.transaction(ctx, func(tx context.Context) error {
		observed := r.auth.currentTime(now)
		caller, e := r.caller(tx, digest, observed)
		if e != nil {
			return e
		}
		page = d.Page{CurrentSessionID: caller.SessionID, ObservedAt: observed, Sessions: []d.Summary{}}
		_, minimum, e := r.auth.CredentialBoundsTx(tx, caller.AuthID)
		if e != nil {
			return e
		}
		filter := bson.M{"authId": caller.AuthID}
		if cursor != "" {
			var raw bson.Raw
			e = r.auth.database.Collection(SessionCollection).FindOne(tx, bson.M{"authId": caller.AuthID, "sessionId": cursor}).Decode(&raw)
			if errors.Is(e, m.ErrNoDocuments) {
				return d.ErrInvalidCursor
			}
			if e != nil {
				return e
			}
			if !identityFields(raw, map[string]bson.Type{"createdAt": bson.TypeDateTime, "sessionId": bson.TypeString, "authId": bson.TypeString}) || raw.Lookup("createdAt").Time().IsZero() {
				return d.ErrUnavailable
			}
			created := raw.Lookup("createdAt").Time()
			filter["$or"] = bson.A{bson.M{"createdAt": bson.M{"$lt": created}}, bson.M{"createdAt": created, "sessionId": bson.M{"$lt": cursor}}}
		}
		cur, e := r.auth.database.Collection(SessionCollection).Find(tx, filter, options.Find().SetSort(bson.D{{Key: "createdAt", Value: -1}, {Key: "sessionId", Value: -1}}).SetLimit(sessionScanLimit+1))
		if e != nil {
			return e
		}
		defer cur.Close(tx)
		var candidates []bson.Raw
		if e = cur.All(tx, &candidates); e != nil {
			return e
		}
		n := len(candidates)
		if n > sessionScanLimit {
			n = sessionScanLimit
		}
		// Fetch bounded credential references once; validate each document only when
		// its candidate is actually selected for processing on this page.
		ids := make([]string, 0, n)
		for _, raw := range candidates[:n] {
			v := raw.Lookup("credentialId")
			if v.Type == bson.TypeString {
				ids = append(ids, v.StringValue())
			}
		}
		credentials, e := r.credentials(tx, caller.AuthID, ids)
		if e != nil {
			return e
		}
		var passwordRevision int64
		for i, raw := range candidates[:n] {
			session, e := managementSession(raw)
			if e != nil {
				return e
			}
			if session.AuthID != caller.AuthID {
				return d.ErrUnavailable
			}
			// Structural corruption never becomes an apparently empty successful page.
			active := session.RevokedAt == nil && observed.Before(session.ExpiresAt) && session.AccountRevision == caller.AccountRevision
			if active {
				available, e := managementCredential(credentials[session.CredentialID], session.AuthID)
				if e != nil {
					return e
				}
				if available {
					available = password.EligibleCredential(credentials[session.CredentialID].Lookup("credentialRevision").Int64(), minimum, caller.AccountRevision)
				}
				if available && (session.AuthenticationMethod == password.PasswordAndDevice || session.AuthenticationMethod == password.PasswordAndSession) {
					if passwordRevision == 0 {
						var raw bson.Raw
						if e = r.auth.database.Collection(PasswordCollection).FindOne(tx, bson.M{"authId": caller.AuthID}).Decode(&raw); e != nil {
							return d.ErrUnavailable
						}
						record, err := decodePassword(raw)
						if err != nil {
							return d.ErrUnavailable
						}
						passwordRevision = record.Revision
					}
					available = session.PasswordRevision == passwordRevision
				}
				if available {
					page.Sessions = append(page.Sessions, d.Summary{SessionID: session.SessionID, CredentialID: session.CredentialID, AuthenticationMethod: session.AuthenticationMethod, AuthenticatedAt: session.AuthenticatedAt, CreatedAt: session.CreatedAt, LastUsedAt: session.LastUsedAt, ExpiresAt: session.ExpiresAt, IsCurrent: session.SessionID == caller.SessionID})
				}
			}
			if len(page.Sessions) == pageSize || i == n-1 {
				if i+1 < len(candidates) {
					page.NextCursor = session.SessionID
				}
				break
			}
		}
		return nil
	})
	if e != nil {
		return d.Page{}, e
	}
	return page, nil
}
func (r *SessionManagementRepository) Revoke(ctx context.Context, digest []byte, ids []string, eventID string, now time.Time) error {
	if e := d.ValidateTargets(ids); e != nil {
		return e
	}
	if !d.ValidID(eventID) {
		return d.ErrInvalidRequest
	}
	return r.transaction(ctx, func(tx context.Context) error {
		observed := r.auth.currentTime(now)
		caller, e := r.caller(tx, digest, observed)
		if e != nil {
			return e
		}
		for _, id := range ids {
			if id == caller.SessionID {
				return d.ErrCurrentSession
			}
		}
		filter := bson.M{"authId": caller.AuthID, "sessionId": bson.M{"$in": ids}}
		cur, e := r.auth.database.Collection(SessionCollection).Find(tx, filter, options.Find().SetLimit(50))
		if e != nil {
			return e
		}
		defer cur.Close(tx)
		changed := []string{}
		for cur.Next(tx) {
			session, e := managementSession(cur.Current)
			if e != nil {
				return e
			}
			if session.AuthID != caller.AuthID {
				return d.ErrUnavailable
			}
			if session.RevokedAt == nil {
				changed = append(changed, session.SessionID)
			}
		}
		if e = cur.Err(); e != nil {
			return e
		}
		if len(changed) == 0 {
			return nil
		}
		sort.Strings(changed)
		result, e := r.auth.database.Collection(SessionCollection).UpdateMany(tx, bson.M{"authId": caller.AuthID, "sessionId": bson.M{"$in": changed}, "revokedAt": nil}, bson.M{"$set": bson.M{"revokedAt": observed}})
		if e != nil {
			return e
		}
		if result.ModifiedCount != int64(len(changed)) {
			return d.ErrUnavailable
		}
		_, e = r.auth.database.Collection(SessionManagementAuditCollection).InsertOne(tx, bson.M{"eventId": eventID, "action": "REVOKE_OWN_SESSIONS", "actorAuthId": caller.AuthID, "actorSessionId": caller.SessionID, "sessionIds": changed, "occurredAt": observed})
		return e
	})
}

// caller checks raw storage shapes, generation and source before establishing
// the same participant fences used by online checks, without touching usage times.
func (r *SessionManagementRepository) caller(ctx context.Context, digest []byte, now time.Time) (SessionDocument, error) {
	if len(digest) != 32 {
		return SessionDocument{}, d.ErrSessionInvalid
	}
	var raw bson.Raw
	e := r.auth.database.Collection(SessionCollection).FindOne(ctx, bson.M{"tokenDigest": digest}).Decode(&raw)
	if errors.Is(e, m.ErrNoDocuments) {
		return SessionDocument{}, d.ErrSessionInvalid
	}
	if e != nil {
		return SessionDocument{}, e
	}
	session, e := managementSession(raw)
	if e != nil {
		return SessionDocument{}, e
	}
	if session.RevokedAt != nil || !now.Before(session.ExpiresAt) {
		return SessionDocument{}, d.ErrSessionInvalid
	}
	var principal bson.Raw
	e = r.auth.database.Collection(PrincipalCollection).FindOne(ctx, bson.M{"authId": session.AuthID}).Decode(&principal)
	if errors.Is(e, m.ErrNoDocuments) {
		return SessionDocument{}, d.ErrSessionInvalid
	}
	if e != nil {
		return SessionDocument{}, e
	}
	if !identityFields(principal, map[string]bson.Type{"authId": bson.TypeString, "principalType": bson.TypeString, "accountStatus": bson.TypeString, "accountRevision": bson.TypeInt64}) || principal.Lookup("accountRevision").Int64() <= 0 {
		return SessionDocument{}, d.ErrUnavailable
	}
	typ, status := principal.Lookup("principalType").StringValue(), principal.Lookup("accountStatus").StringValue()
	if typ == "SYSTEM" || status == "DISABLED" || status == "CLOSED" {
		return SessionDocument{}, d.ErrSessionInvalid
	}
	if typ != "USER" || status != "ACTIVE" {
		return SessionDocument{}, d.ErrUnavailable
	}
	if session.AccountRevision != principal.Lookup("accountRevision").Int64() {
		return SessionDocument{}, d.ErrSessionInvalid
	}
	credentials, e := r.credentials(ctx, session.AuthID, []string{session.CredentialID})
	if e != nil {
		return SessionDocument{}, e
	}
	active, e := managementCredential(credentials[session.CredentialID], session.AuthID)
	if e != nil {
		return SessionDocument{}, e
	}
	if !active {
		return SessionDocument{}, d.ErrSessionInvalid
	}
	if e = r.auth.ConfirmAccountTx(ctx, session.AuthID, session.AccountRevision); e != nil {
		return SessionDocument{}, mapManagementAuthentication(e)
	}
	if e = r.auth.ConfirmPrincipalCredentialTx(ctx, session.AuthID, session.CredentialID, now); e != nil {
		return SessionDocument{}, mapManagementAuthentication(e)
	}
	result, e := r.auth.database.Collection(SessionCollection).UpdateOne(ctx, bson.M{"sessionId": session.SessionID, "authId": session.AuthID, "revokedAt": nil, "expiresAt": bson.M{"$gt": now}}, bson.M{"$inc": bson.M{"authenticationFence": int64(1)}})
	if e != nil {
		return SessionDocument{}, e
	}
	if result.MatchedCount != 1 {
		return SessionDocument{}, d.ErrSessionInvalid
	}
	return session, nil
}
func mapManagementAuthentication(e error) error {
	if errors.Is(e, auth.ErrAuthenticationFailed) || errors.Is(e, auth.ErrSessionInvalid) {
		return d.ErrSessionInvalid
	}
	return e
}
func (r *SessionManagementRepository) credentials(ctx context.Context, authID string, ids []string) (map[string]bson.Raw, error) {
	out := map[string]bson.Raw{}
	if len(ids) == 0 {
		return out, nil
	}
	cur, e := r.auth.database.Collection(CredentialCollection).Find(ctx, bson.M{"authId": authID, "credentialId": bson.M{"$in": ids}}, options.Find().SetLimit(sessionScanLimit))
	if e != nil {
		return nil, e
	}
	defer cur.Close(ctx)
	for cur.Next(ctx) {
		raw := append(bson.Raw(nil), cur.Current...)
		id := raw.Lookup("credentialId")
		if id.Type != bson.TypeString {
			return nil, d.ErrUnavailable
		}
		if _, exists := out[id.StringValue()]; exists {
			return nil, d.ErrUnavailable
		}
		out[id.StringValue()] = raw
	}
	return out, cur.Err()
}
func managementSession(raw bson.Raw) (SessionDocument, error) {
	if !identityFields(raw, map[string]bson.Type{"sessionId": bson.TypeString, "authId": bson.TypeString, "accountRevision": bson.TypeInt64, "credentialId": bson.TypeString, "authenticationMethod": bson.TypeString, "tokenDigest": bson.TypeBinary, "authenticatedAt": bson.TypeDateTime, "createdAt": bson.TypeDateTime, "lastUsedAt": bson.TypeDateTime, "expiresAt": bson.TypeDateTime}) || !validRevokedField(raw) {
		return SessionDocument{}, d.ErrUnavailable
	}
	var s SessionDocument
	if bson.Unmarshal(raw, &s) != nil {
		return s, d.ErrUnavailable
	}
	switch s.AuthenticationMethod {
	case "DEVICE_CREDENTIAL":
		v := raw.Lookup("emailBindingRevision")
		if v.Type != 0 && (v.Type != bson.TypeInt64 || v.Int64() != 0) {
			return s, d.ErrUnavailable
		}
	case "EMAIL_CODE_AND_DEVICE":
		v := raw.Lookup("emailBindingRevision")
		if v.Type != bson.TypeInt64 || v.Int64() <= 0 {
			return s, d.ErrUnavailable
		}
	case "PASSWORD_AND_DEVICE", "PASSWORD_AND_SESSION":
		if !validSessionMethod(s) {
			return s, d.ErrUnavailable
		}
	default:
		return s, d.ErrUnavailable
	}
	revoked := s.RevokedAt
	s.RevokedAt = nil
	valid := validSession(s)
	s.RevokedAt = revoked
	if !valid || revoked != nil && revoked.Before(s.CreatedAt) {
		return s, d.ErrUnavailable
	}
	return s, nil
}
func managementCredential(raw bson.Raw, authID string) (bool, error) {
	if len(raw) == 0 {
		return false, d.ErrUnavailable
	}
	if !identityFields(raw, map[string]bson.Type{"credentialId": bson.TypeString, "authId": bson.TypeString, "protocolVersion": bson.TypeString, "publicKey": bson.TypeBinary, "fingerprint": bson.TypeBinary, "createdAt": bson.TypeDateTime}) || !validRevokedField(raw) {
		return false, d.ErrUnavailable
	}
	var c CredentialDocument
	if bson.Unmarshal(raw, &c) != nil || c.AuthID != authID {
		return false, d.ErrUnavailable
	}
	revoked := c.RevokedAt
	c.RevokedAt = nil
	if !validCredential(c) || revoked != nil && revoked.Before(c.CreatedAt) {
		return false, d.ErrUnavailable
	}
	return revoked == nil, nil
}

var _ port.Repository = (*SessionManagementRepository)(nil)
