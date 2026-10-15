package mongo

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	ap "iwut-auth-center/internal/authentication/port"
	d "iwut-auth-center/internal/developer/domain"
)

const DeveloperActivationCollection = "auth_developer_activations"
const DeveloperApplicationAuditCollection = "auth_developer_application_audit"
const DeveloperHandleCollection = "auth_developer_handles"
const developerApplyAction = "APPLY_FOR_DEVELOPER"
const developerClaimAction = "CLAIM_DEVELOPER_HANDLE"

type DeveloperApplicationRepository struct{ authentication *AuthenticationRepository }

func NewDeveloperApplicationRepository(a *AuthenticationRepository) (*DeveloperApplicationRepository, error) {
	if a == nil {
		return nil, d.ErrApplicationUnavailable
	}
	return &DeveloperApplicationRepository{a}, nil
}
func EnsureDeveloperApplicationSchema(ctx context.Context, db *m.Database) error {
	if _, err := db.Collection(DeveloperActivationCollection).Indexes().CreateOne(ctx, m.IndexModel{Keys: bson.D{{Key: "authId", Value: 1}}, Options: options.Index().SetUnique(true)}); err != nil {
		return err
	}
	binary := &options.Collation{Locale: "simple"}
	for key, name := range map[string]string{"authId": "developer_auth_unique", "developerHandle": "developer_handle_unique"} {
		if _, err := db.Collection(DeveloperHandleCollection).Indexes().CreateOne(ctx, m.IndexModel{Keys: bson.D{{Key: key, Value: 1}}, Options: options.Index().SetUnique(true).SetName(name).SetCollation(binary)}); err != nil {
			return err
		}
	}
	// History is not an ownership authority, but prevents a damaged missing
	// ownership row from silently making a previously claimed name reusable.
	for _, collection := range []string{DeveloperActivationCollection, DeveloperApplicationAuditCollection} {
		if _, err := db.Collection(collection).Indexes().CreateOne(ctx, m.IndexModel{Keys: bson.D{{Key: "developerHandle", Value: 1}}, Options: options.Index().SetName("developer_handle_history").SetSparse(true).SetCollation(binary)}); err != nil {
			return err
		}
	}
	audit := db.Collection(DeveloperApplicationAuditCollection)
	// Add the replacement constraint first. A failed build/drop blocks startup,
	// leaves all events intact, and can be retried safely before listeners start.
	if _, err := audit.Indexes().CreateOne(ctx, m.IndexModel{Keys: bson.D{{Key: "subjectAuthId", Value: 1}, {Key: "action", Value: 1}}, Options: options.Index().SetUnique(true).SetName("developer_subject_action_unique").SetCollation(binary)}); err != nil {
		return err
	}
	indexes, err := audit.Indexes().List(ctx)
	if err != nil {
		return err
	}
	defer indexes.Close(ctx)
	var obsolete []string
	for indexes.Next(ctx) {
		var index struct {
			Name   string `bson:"name"`
			Key    bson.D `bson:"key"`
			Unique bool   `bson:"unique"`
		}
		if err = indexes.Decode(&index); err != nil {
			return err
		}
		if index.Unique && len(index.Key) == 1 && index.Key[0].Key == "subjectAuthId" {
			obsolete = append(obsolete, index.Name)
		}
	}
	if err = indexes.Err(); err != nil {
		return err
	}
	for _, name := range obsolete {
		if err = audit.Indexes().DropOne(ctx, name); err != nil {
			return err
		}
	}
	return nil
}
func (r *DeveloperApplicationRepository) Evaluate(ctx context.Context, digest []byte, decide func(d.ApplicationState) (d.HandleClaim, error)) (d.ApplicationState, error) {
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
		if raw.Lookup("developerRevision").Type != bson.TypeInt64 {
			return fail(d.ErrApplicationUnavailable)
		}
		developerRevision := raw.Lookup("developerRevision").Int64()
		if (s.Status == "" && developerRevision != 0) || (s.Status != "" && developerRevision < 1) {
			return fail(d.ErrApplicationUnavailable)
		}
		var activation bson.Raw
		err = a.database.Collection(DeveloperActivationCollection).FindOne(tx, bson.M{"authId": s.AuthID}).Decode(&activation)
		if err == nil {
			if !identityFields(activation, map[string]bson.Type{"authId": bson.TypeString, "activatedAt": bson.TypeDateTime, "emailBindingRevision": bson.TypeInt64, "eventId": bson.TypeString}) || activation.Lookup("emailBindingRevision").Int64() <= 0 || activation.Lookup("eventId").StringValue() == "" {
				return fail(d.ErrApplicationUnavailable)
			}
			at := time.UnixMilli(activation.Lookup("activatedAt").DateTime()).UTC()
			s.ActivatedAt = &at
		} else if !errors.Is(err, m.ErrNoDocuments) {
			return err
		}
		if !s.Valid() {
			return fail(d.ErrApplicationUnavailable)
		}
		s.DeveloperHandle, err = r.readHandleHistory(tx, s, activation)
		if err != nil {
			return err
		}
		if !s.Valid() {
			return fail(d.ErrApplicationUnavailable)
		}
		s.EmailRevision, err = r.emailRevision(tx, s.AuthID)
		if err != nil {
			return err
		}
		claim, err := decide(s)
		if err != nil {
			return fail(err)
		}
		if claim.DeveloperHandle != "" {
			handle, err := d.NormalizeDeveloperHandle(claim.DeveloperHandle)
			if err != nil || handle != claim.DeveloperHandle || s.DeveloperHandle != "" || (s.Status != "" && s.Status != d.DeveloperStatusApproved) || s.EmailRevision <= 0 {
				return fail(d.ErrApplicationUnavailable)
			}
			eventID := uuid.NewString()
			if err = r.claimHandle(tx, s.AuthID, handle, eventID, now); err != nil {
				if errors.Is(err, d.ErrHandleTaken) {
					return fail(err)
				}
				return err
			}
			action := developerClaimAction
			before := any("APPROVED")
			filterStatus := any("APPROVED")
			set := bson.M{"updatedAt": now}
			if s.Status == "" {
				action = developerApplyAction
				before = nil
				filterStatus = nil
				set["developerStatus"] = "APPROVED"
				set["developerRevision"] = int64(1)
				set["developerStatusChangedAt"] = now
			}
			result, err := a.database.Collection(PrincipalCollection).UpdateOne(tx, bson.M{"authId": s.AuthID, "principalType": "USER", "accountStatus": "ACTIVE", "developerStatus": filterStatus, "developerRevision": developerRevision}, bson.M{"$set": set})
			if err != nil {
				return err
			}
			if result.MatchedCount != 1 {
				return fail(d.ErrApplicationUnavailable)
			}
			if s.Status == "" {
				_, err = a.database.Collection(DeveloperActivationCollection).InsertOne(tx, bson.M{"authId": s.AuthID, "activatedAt": now, "emailBindingRevision": s.EmailRevision, "eventId": eventID, "developerHandle": handle})
				if err != nil {
					return err
				}
				s.ActivatedAt = &now
			}
			_, err = a.database.Collection(DeveloperApplicationAuditCollection).InsertOne(tx, bson.M{"eventId": eventID, "actorAuthId": s.AuthID, "subjectAuthId": s.AuthID, "action": action, "beforeStatus": before, "afterStatus": "APPROVED", "emailBindingRevision": s.EmailRevision, "occurredAt": now, "result": "APPROVED", "developerHandle": handle})
			if err != nil {
				return err
			}
			s.Status = d.DeveloperStatusApproved
			s.DeveloperHandle = handle
		}
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

func canonicalStoredHandle(value bson.RawValue) (string, error) {
	if value.Type != bson.TypeString {
		return "", d.ErrApplicationUnavailable
	}
	handle, err := d.NormalizeDeveloperHandle(value.StringValue())
	if err != nil || handle != value.StringValue() {
		return "", d.ErrApplicationUnavailable
	}
	return handle, nil
}
func validHandleDocument(raw bson.Raw) bool {
	if !identityFields(raw, map[string]bson.Type{"authId": bson.TypeString, "developerHandle": bson.TypeString, "claimedAt": bson.TypeDateTime, "eventId": bson.TypeString}) {
		return false
	}
	_, err := canonicalStoredHandle(raw.Lookup("developerHandle"))
	return err == nil && raw.Lookup("authId").StringValue() != "" && raw.Lookup("claimedAt").DateTime() > 0 && raw.Lookup("eventId").StringValue() != ""
}
func (r *DeveloperApplicationRepository) readHandleHistory(ctx context.Context, s d.ApplicationState, activation bson.Raw) (string, error) {
	var activationHandle string
	if v := activation.Lookup("developerHandle"); v.Type != 0 {
		var err error
		activationHandle, err = canonicalStoredHandle(v)
		if err != nil {
			return "", err
		}
	}
	cursor, err := r.authentication.database.Collection(DeveloperApplicationAuditCollection).Find(ctx, bson.M{"subjectAuthId": s.AuthID}, options.Find().SetLimit(3))
	if err != nil {
		return "", err
	}
	defer cursor.Close(ctx)
	var evidence bson.Raw
	seen := map[string]bool{}
	for cursor.Next(ctx) {
		var raw bson.Raw
		if err = cursor.Decode(&raw); err != nil {
			return "", err
		}
		if !identityFields(raw, map[string]bson.Type{"actorAuthId": bson.TypeString, "subjectAuthId": bson.TypeString, "eventId": bson.TypeString, "action": bson.TypeString, "occurredAt": bson.TypeDateTime, "emailBindingRevision": bson.TypeInt64, "afterStatus": bson.TypeString, "result": bson.TypeString}) || raw.Lookup("actorAuthId").StringValue() != s.AuthID || raw.Lookup("eventId").StringValue() == "" || raw.Lookup("occurredAt").DateTime() <= 0 || raw.Lookup("emailBindingRevision").Int64() <= 0 || raw.Lookup("afterStatus").StringValue() != "APPROVED" || raw.Lookup("result").StringValue() != "APPROVED" || s.Status == "" {
			return "", d.ErrApplicationUnavailable
		}
		action := raw.Lookup("action").StringValue()
		if seen[action] || (action != developerApplyAction && action != developerClaimAction) {
			return "", d.ErrApplicationUnavailable
		}
		seen[action] = true
		before := raw.Lookup("beforeStatus")
		if action == developerApplyAction && before.Type != bson.TypeNull || action == developerClaimAction && (before.Type != bson.TypeString || before.StringValue() != "APPROVED") {
			return "", d.ErrApplicationUnavailable
		}
		v := raw.Lookup("developerHandle")
		if v.Type == 0 && action == developerApplyAction {
			continue
		}
		h, err := canonicalStoredHandle(v)
		if err != nil {
			return "", err
		}
		if len(evidence) > 0 || (activationHandle != "" && activationHandle != h) {
			return "", d.ErrApplicationUnavailable
		}
		evidence = raw
	}
	if err = cursor.Err(); err != nil {
		return "", err
	}
	var ownership bson.Raw
	err = r.authentication.database.Collection(DeveloperHandleCollection).FindOne(ctx, bson.M{"authId": s.AuthID}, options.FindOne().SetCollation(&options.Collation{Locale: "simple"})).Decode(&ownership)
	if errors.Is(err, m.ErrNoDocuments) {
		if activationHandle != "" || len(evidence) > 0 {
			return "", d.ErrApplicationUnavailable
		}
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !validHandleDocument(ownership) || len(evidence) == 0 {
		return "", d.ErrApplicationUnavailable
	}
	handle := ownership.Lookup("developerHandle").StringValue()
	if handle != evidence.Lookup("developerHandle").StringValue() || ownership.Lookup("eventId").StringValue() != evidence.Lookup("eventId").StringValue() || ownership.Lookup("claimedAt").DateTime() != evidence.Lookup("occurredAt").DateTime() {
		return "", d.ErrApplicationUnavailable
	}
	if evidence.Lookup("action").StringValue() == developerApplyAction {
		if activationHandle != handle || activation.Lookup("eventId").StringValue() != ownership.Lookup("eventId").StringValue() || activation.Lookup("activatedAt").DateTime() != ownership.Lookup("claimedAt").DateTime() || activation.Lookup("emailBindingRevision").Int64() != evidence.Lookup("emailBindingRevision").Int64() {
			return "", d.ErrApplicationUnavailable
		}
	} else if activationHandle != "" {
		return "", d.ErrApplicationUnavailable
	}
	return handle, nil
}
func (r *DeveloperApplicationRepository) claimHandle(ctx context.Context, authID, handle, eventID string, now time.Time) error {
	collection := r.authentication.database.Collection(DeveloperHandleCollection)
	var owner bson.Raw
	err := collection.FindOne(ctx, bson.M{"developerHandle": handle}, options.FindOne().SetCollation(&options.Collation{Locale: "simple"})).Decode(&owner)
	if err == nil {
		if (!validHandleDocument(owner) && !validTerminalHandleDocument(owner)) || owner.Lookup("authId").StringValue() == authID {
			return d.ErrApplicationUnavailable
		}
		return d.ErrHandleTaken
	}
	if !errors.Is(err, m.ErrNoDocuments) {
		return err
	}
	for _, history := range []string{DeveloperActivationCollection, DeveloperApplicationAuditCollection} {
		err = r.authentication.database.Collection(history).FindOne(ctx, bson.M{"developerHandle": handle}, options.FindOne().SetProjection(bson.M{"_id": 1}).SetCollation(&options.Collation{Locale: "simple"})).Err()
		if err == nil {
			return d.ErrApplicationUnavailable
		}
		if !errors.Is(err, m.ErrNoDocuments) {
			return err
		}
	}
	_, err = collection.InsertOne(ctx, bson.M{"authId": authID, "developerHandle": handle, "claimedAt": now, "eventId": eventID})
	if duplicateDeveloperHandle(err, handle) {
		return d.ErrHandleTaken
	}
	return err
}

// Only a duplicate of this collection's exact developerHandle key/value is a
// name collision. Other indexes, write concern and unknown commits stay unavailable.
func duplicateDeveloperHandle(err error, handle string) bool {
	var failure m.WriteException
	if !errors.As(err, &failure) || failure.WriteConcernError != nil || len(failure.Labels) > 0 || len(failure.WriteErrors) != 1 {
		return false
	}
	we := failure.WriteErrors[0]
	if we.Code != 11000 {
		return false
	}
	pattern, ok := we.Raw.Lookup("keyPattern").DocumentOK()
	if !ok {
		return false
	}
	elements, err := pattern.Elements()
	if err != nil || len(elements) != 1 || elements[0].Key() != "developerHandle" {
		return false
	}
	value, ok := we.Raw.Lookup("keyValue").DocumentOK()
	if !ok {
		return false
	}
	v := value.Lookup("developerHandle")
	return v.Type == bson.TypeString && v.StringValue() == handle
}
func (r *DeveloperApplicationRepository) emailRevision(ctx context.Context, id string) (int64, error) {
	_, revision, err := ReadPrimaryEmailTx(ctx, r.authentication.database, id)
	if err != nil {
		return 0, d.ErrApplicationUnavailable
	}
	return revision, nil
}

func validTerminalHandleDocument(raw bson.Raw) bool {
	if !identityFields(raw, map[string]bson.Type{"authId": bson.TypeString, "developerHandle": bson.TypeString, "claimedAt": bson.TypeDateTime, "terminal": bson.TypeBoolean}) || !raw.Lookup("terminal").Boolean() || raw.Lookup("authId").StringValue() == "" || raw.Lookup("claimedAt").DateTime() <= 0 {
		return false
	}
	els, e := raw.Elements()
	if e != nil {
		return false
	}
	for _, v := range els {
		switch v.Key() {
		case "_id", "authId", "developerHandle", "claimedAt", "terminal":
		default:
			return false
		}
	}
	handle, e := d.NormalizeDeveloperHandle(raw.Lookup("developerHandle").StringValue())
	return e == nil && handle == raw.Lookup("developerHandle").StringValue()
}
