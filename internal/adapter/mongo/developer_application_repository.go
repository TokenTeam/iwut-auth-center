package mongo

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	ap "iwut-auth-center/internal/authentication/port"
	d "iwut-auth-center/internal/developer/domain"
	email "iwut-auth-center/internal/emailbinding/domain"
	"time"
)

const DeveloperActivationCollection = "auth_developer_activations"
const DeveloperApplicationAuditCollection = "auth_developer_application_audit"

type DeveloperApplicationRepository struct{ authentication *AuthenticationRepository }

func NewDeveloperApplicationRepository(a *AuthenticationRepository) (*DeveloperApplicationRepository, error) {
	if a == nil {
		return nil, d.ErrApplicationUnavailable
	}
	return &DeveloperApplicationRepository{a}, nil
}
func EnsureDeveloperApplicationSchema(ctx context.Context, db *m.Database) error {
	for collection, key := range map[string]string{DeveloperActivationCollection: "authId", DeveloperApplicationAuditCollection: "subjectAuthId"} {
		if _, err := db.Collection(collection).Indexes().CreateOne(ctx, m.IndexModel{Keys: bson.D{{Key: key, Value: 1}}, Options: options.Index().SetUnique(true)}); err != nil {
			return err
		}
	}
	return nil
}
func (r *DeveloperApplicationRepository) Evaluate(ctx context.Context, digest []byte, decide func(d.ApplicationState) (bool, error)) (d.ApplicationState, error) {
	if len(digest) != 32 {
		return d.ApplicationState{}, d.ErrApplicationSession
	}
	if decide == nil {
		return d.ApplicationState{}, d.ErrApplicationUnavailable
	}
	a := r.authentication
	var out d.ApplicationState
	var applicationErr error
	err := a.WithAuthTransaction(ctx, func(tx context.Context) error {
		out = d.ApplicationState{}
		applicationErr = nil
		fail := func(err error) error { applicationErr = err; return ap.ErrUnavailable }
		now := a.currentTime(time.Time{})
		session, err := a.CheckSessionTx(tx, digest, now)
		if errors.Is(err, ap.ErrSessionInvalid) {
			return fail(d.ErrApplicationSession)
		}
		if err != nil {
			return err
		}
		var raw bson.Raw
		if err = a.database.Collection(PrincipalCollection).FindOne(tx, bson.M{"authId": session.AuthID}).Decode(&raw); err != nil {
			return err
		}
		if !identityFields(raw, map[string]bson.Type{"authId": bson.TypeString, "principalType": bson.TypeString, "accountStatus": bson.TypeString}) {
			return fail(d.ErrApplicationUnavailable)
		}
		s := d.ApplicationState{AuthID: session.AuthID}
		switch v := raw.Lookup("developerStatus"); v.Type {
		case bson.TypeNull:
		case bson.TypeString:
			s.Status = d.DeveloperStatus(v.StringValue())
			if !s.Status.IsValid() {
				return fail(d.ErrApplicationUnavailable)
			}
		default:
			return fail(d.ErrApplicationUnavailable)
		}
		err = a.database.Collection(DeveloperActivationCollection).FindOne(tx, bson.M{"authId": s.AuthID}).Decode(&raw)
		if err == nil {
			if !identityFields(raw, map[string]bson.Type{"authId": bson.TypeString, "activatedAt": bson.TypeDateTime, "emailBindingRevision": bson.TypeInt64, "eventId": bson.TypeString}) || raw.Lookup("emailBindingRevision").Int64() <= 0 || raw.Lookup("eventId").StringValue() == "" {
				return fail(d.ErrApplicationUnavailable)
			}
			at := time.UnixMilli(raw.Lookup("activatedAt").DateTime()).UTC()
			s.ActivatedAt = &at
		} else if !errors.Is(err, m.ErrNoDocuments) {
			return err
		}
		if !s.Valid() {
			return fail(d.ErrApplicationUnavailable)
		}
		revision, err := r.emailRevision(tx, s.AuthID)
		if err != nil {
			return err
		}
		s.EmailRevision = revision
		activate, err := decide(s)
		if err != nil {
			return fail(err)
		}
		if activate {
			if s.Status != "" || s.EmailRevision <= 0 {
				return fail(d.ErrApplicationUnavailable)
			}
			eventID := uuid.NewString()
			result, err := a.database.Collection(PrincipalCollection).UpdateOne(tx, bson.M{"authId": s.AuthID, "principalType": "USER", "accountStatus": "ACTIVE", "developerStatus": nil}, bson.M{"$set": bson.M{"developerStatus": "APPROVED", "updatedAt": now}})
			if err != nil {
				return err
			}
			if result.MatchedCount != 1 {
				return fail(d.ErrApplicationUnavailable)
			}
			_, err = a.database.Collection(DeveloperActivationCollection).InsertOne(tx, bson.M{"authId": s.AuthID, "activatedAt": now, "emailBindingRevision": s.EmailRevision, "eventId": eventID})
			if err != nil {
				return err
			}
			_, err = a.database.Collection(DeveloperApplicationAuditCollection).InsertOne(tx, bson.M{"eventId": eventID, "actorAuthId": s.AuthID, "subjectAuthId": s.AuthID, "action": "APPLY_FOR_DEVELOPER", "beforeStatus": nil, "afterStatus": "APPROVED", "emailBindingRevision": s.EmailRevision, "occurredAt": now, "result": "APPROVED"})
			if err != nil {
				return err
			}
			s.Status = d.DeveloperStatusApproved
			s.ActivatedAt = &now
		}
		// Reconfirm expiry at the confirmation point, not just before reading state.
		if _, err = a.CheckSessionTx(tx, digest, a.currentTime(now)); err != nil {
			if errors.Is(err, ap.ErrSessionInvalid) {
				return fail(d.ErrApplicationSession)
			}
			return err
		}
		out = s
		return nil
	})
	if err != nil {
		if applicationErr != nil {
			return d.ApplicationState{}, applicationErr
		}
		return d.ApplicationState{}, d.ErrApplicationUnavailable
	}
	return out, nil
}
func (r *DeveloperApplicationRepository) emailRevision(ctx context.Context, id string) (int64, error) {
	var raw bson.Raw
	err := r.authentication.database.Collection(EmailBindingCollection).FindOne(ctx, bson.M{"authId": id}).Decode(&raw)
	if errors.Is(err, m.ErrNoDocuments) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if !identityFields(raw, map[string]bson.Type{"authId": bson.TypeString, "revision": bson.TypeInt64}) {
		return 0, d.ErrApplicationUnavailable
	}
	rev := raw.Lookup("revision").Int64()
	if rev < 0 {
		return 0, d.ErrApplicationUnavailable
	}
	// Pending-only rows have revision zero and no current email or verifiedAt.
	address, verified := raw.Lookup("email"), raw.Lookup("verifiedAt")
	if address.Type == 0 && verified.Type == 0 && rev == 0 {
		return 0, nil
	}
	if address.Type != bson.TypeString || verified.Type != bson.TypeDateTime || verified.DateTime() <= 0 || rev <= 0 {
		return 0, d.ErrApplicationUnavailable
	}
	normalized, err := email.NormalizeEmail(address.StringValue())
	if err != nil || normalized != address.StringValue() {
		return 0, d.ErrApplicationUnavailable
	}
	return rev, nil
}
