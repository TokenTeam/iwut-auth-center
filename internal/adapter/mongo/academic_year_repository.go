package mongo

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	d "iwut-auth-center/internal/academicyear/domain"
	administratordomain "iwut-auth-center/internal/administrator/domain"
)

const (
	AcademicYearAuditCollection = "auth_academic_year_audit_events"
	academicYearScheduleID      = "academic-year-policy"
	academicYearProvisionID     = "academic-year-policy-provision"
)

type AcademicYearRepository struct {
	authentication *AuthenticationRepository
}

func NewAcademicYearRepository(authentication *AuthenticationRepository) (*AcademicYearRepository, error) {
	if authentication == nil {
		return nil, d.ErrUnavailable
	}
	return &AcademicYearRepository{authentication: authentication}, nil
}

func EnsureAcademicYearSchema(ctx context.Context, database *m.Database) error {
	if database == nil {
		return d.ErrUnavailable
	}
	_, err := database.Collection(AcademicYearAuditCollection).Indexes().CreateMany(ctx, []m.IndexModel{
		{Keys: bson.D{{Key: "eventId", Value: 1}}, Options: options.Index().SetUnique(true).SetName("academic_year_event_unique")},
		{Keys: bson.D{{Key: "occurredAt", Value: 1}, {Key: "eventId", Value: 1}}, Options: options.Index().SetName("academic_year_history")},
	})
	if err != nil {
		return d.ErrUnavailable
	}
	return nil
}

func (repository *AcademicYearRepository) Initialize(ctx context.Context) error {
	return repository.transaction(ctx, func(tx context.Context) error {
		database := repository.authentication.database
		var scheduleRaw, markerRaw, runtimeRaw bson.Raw
		if err := database.Collection(AuthenticationRuntimeCollection).FindOne(tx, bson.M{"_id": "authentication"}).Decode(&runtimeRaw); err != nil {
			return d.ErrUnavailable
		}
		provisionedValue := runtimeRaw.Lookup("academicYearPolicyProvisioned")
		if provisionedValue.Type != 0 && provisionedValue.Type != bson.TypeBoolean {
			return d.ErrUnavailable
		}
		provisioned := provisionedValue.Type == bson.TypeBoolean && provisionedValue.Boolean()
		scheduleErr := database.Collection(AuthenticationRuntimeCollection).FindOne(tx, bson.M{"_id": academicYearScheduleID}).Decode(&scheduleRaw)
		markerErr := database.Collection(AuthenticationRuntimeCollection).FindOne(tx, bson.M{"_id": academicYearProvisionID}).Decode(&markerRaw)
		if errors.Is(scheduleErr, m.ErrNoDocuments) && errors.Is(markerErr, m.ErrNoDocuments) {
			if provisioned {
				return d.ErrUnavailable
			}
			state := d.DefaultState()
			if _, err := database.Collection(AuthenticationRuntimeCollection).InsertOne(tx, academicYearDocument(state)); err != nil {
				return d.ErrUnavailable
			}
			_, err := database.Collection(AuthenticationRuntimeCollection).InsertOne(tx, bson.M{"_id": academicYearProvisionID, "source": "SYSTEM_DEFAULT", "provisionedAt": repository.authentication.currentTime(time.Time{})})
			if err != nil {
				return d.ErrUnavailable
			}
			result, err := database.Collection(AuthenticationRuntimeCollection).UpdateOne(tx, bson.M{"_id": "authentication", "academicYearPolicyProvisioned": bson.M{"$exists": false}}, bson.M{"$set": bson.M{"academicYearPolicyProvisioned": true}})
			if err != nil || result.MatchedCount != 1 {
				return d.ErrUnavailable
			}
			return nil
		}
		if scheduleErr != nil || markerErr != nil {
			return d.ErrUnavailable
		}
		if !provisioned {
			return d.ErrUnavailable
		}
		if _, err := decodeAcademicYearState(scheduleRaw); err != nil || !validAcademicYearProvision(markerRaw) {
			return d.ErrUnavailable
		}
		return nil
	})
}

func academicYearDocument(state d.State) bson.M {
	document := bson.M{
		"_id":                academicYearScheduleID,
		"anchorAt":           exactInstantDocument(state.AnchorAt),
		"anchorAcademicYear": state.AnchorAcademicYear,
		"revision":           state.Revision,
		"updatedAt":          state.UpdatedAt.UTC(),
	}
	if state.UpdatedByAuthID != "" {
		document["updatedByAuthId"] = state.UpdatedByAuthID
	}
	return document
}

func exactInstantDocument(value time.Time) bson.M {
	value = value.UTC()
	return bson.M{"seconds": value.Unix(), "nanos": int32(value.Nanosecond())}
}

func decodeExactInstant(value bson.RawValue) (time.Time, bool) {
	if value.Type != bson.TypeEmbeddedDocument {
		return time.Time{}, false
	}
	document := value.Document()
	elements, err := document.Elements()
	if err != nil || len(elements) != 2 || !identityFields(document, map[string]bson.Type{"seconds": bson.TypeInt64, "nanos": bson.TypeInt32}) {
		return time.Time{}, false
	}
	seconds, nanos := document.Lookup("seconds").Int64(), document.Lookup("nanos").Int32()
	if nanos < 0 || nanos >= 1_000_000_000 {
		return time.Time{}, false
	}
	valueTime := time.Unix(seconds, int64(nanos)).UTC()
	if valueTime.Unix() != seconds || valueTime.Nanosecond() != int(nanos) || valueTime.Year() < 1 || valueTime.Year() > 9999 {
		return time.Time{}, false
	}
	return valueTime, true
}

func validAcademicYearProvision(raw bson.Raw) bool {
	return identityFields(raw, map[string]bson.Type{"_id": bson.TypeString, "source": bson.TypeString, "provisionedAt": bson.TypeDateTime}) && raw.Lookup("_id").StringValue() == academicYearProvisionID && raw.Lookup("source").StringValue() == "SYSTEM_DEFAULT" && raw.Lookup("provisionedAt").DateTime() > 0
}

func decodeAcademicYearState(raw bson.Raw) (d.State, error) {
	if !identityFields(raw, map[string]bson.Type{"_id": bson.TypeString, "anchorAt": bson.TypeEmbeddedDocument, "anchorAcademicYear": bson.TypeInt32, "revision": bson.TypeInt64, "updatedAt": bson.TypeDateTime}) || raw.Lookup("_id").StringValue() != academicYearScheduleID {
		return d.State{}, d.ErrUnavailable
	}
	anchorAt, ok := decodeExactInstant(raw.Lookup("anchorAt"))
	if !ok {
		return d.State{}, d.ErrUnavailable
	}
	state := d.State{
		AnchorAt:           anchorAt,
		AnchorAcademicYear: raw.Lookup("anchorAcademicYear").Int32(),
		Revision:           raw.Lookup("revision").Int64(),
		UpdatedAt:          time.UnixMilli(raw.Lookup("updatedAt").DateTime()).UTC(),
	}
	updatedBy := raw.Lookup("updatedByAuthId")
	if updatedBy.Type != 0 {
		if updatedBy.Type != bson.TypeString {
			return d.State{}, d.ErrUnavailable
		}
		state.UpdatedByAuthID = updatedBy.StringValue()
	}
	if !state.Valid() {
		return d.State{}, d.ErrUnavailable
	}
	baseline := d.DefaultState()
	if (state.Revision == 1 && (!state.AnchorAt.Equal(baseline.AnchorAt) || state.AnchorAcademicYear != baseline.AnchorAcademicYear || !state.UpdatedAt.Equal(baseline.UpdatedAt) || state.UpdatedByAuthID != "")) || (state.Revision > 1 && state.UpdatedByAuthID == "") {
		return d.State{}, d.ErrUnavailable
	}
	return state, nil
}

func readAcademicYearState(ctx context.Context, database *m.Database) (d.State, error) {
	var scheduleRaw, markerRaw, runtimeRaw bson.Raw
	if err := database.Collection(AuthenticationRuntimeCollection).FindOne(ctx, bson.M{"_id": "authentication"}).Decode(&runtimeRaw); err != nil {
		return d.State{}, d.ErrUnavailable
	}
	provisioned := runtimeRaw.Lookup("academicYearPolicyProvisioned")
	if provisioned.Type != bson.TypeBoolean || !provisioned.Boolean() {
		return d.State{}, d.ErrUnavailable
	}
	if err := database.Collection(AuthenticationRuntimeCollection).FindOne(ctx, bson.M{"_id": academicYearScheduleID}).Decode(&scheduleRaw); err != nil {
		return d.State{}, d.ErrUnavailable
	}
	if err := database.Collection(AuthenticationRuntimeCollection).FindOne(ctx, bson.M{"_id": academicYearProvisionID}).Decode(&markerRaw); err != nil || !validAcademicYearProvision(markerRaw) {
		return d.State{}, d.ErrUnavailable
	}
	return decodeAcademicYearState(scheduleRaw)
}

func (repository *AcademicYearRepository) CurrentAcademicYear(ctx context.Context, observedAt time.Time) (int32, error) {
	state, err := readAcademicYearState(ctx, repository.authentication.database)
	if err != nil {
		return 0, err
	}
	schedule, err := d.Project(state, observedAt)
	if err != nil {
		return 0, d.ErrUnavailable
	}
	return schedule.CurrentAcademicYear, nil
}

func (repository *AcademicYearRepository) transaction(ctx context.Context, operation func(context.Context) error) error {
	var semantic error
	err := repository.authentication.WithAuthTransaction(ctx, func(tx context.Context) error {
		semantic = operation(tx)
		return semantic
	})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		if semantic != nil {
			for _, known := range d.Errors {
				if errors.Is(semantic, known) {
					return semantic
				}
			}
		}
		return d.ErrUnavailable
	}
	return nil
}

func academicYearAdministratorError(err error) error {
	switch {
	case errors.Is(err, administratordomain.ErrIdentity):
		return d.ErrIdentity
	case errors.Is(err, administratordomain.ErrForbidden), errors.Is(err, administratordomain.ErrSubject):
		return d.ErrForbidden
	case err != nil:
		return d.ErrUnavailable
	default:
		return nil
	}
}

func (repository *AcademicYearRepository) Get(ctx context.Context, actor string) (d.Schedule, error) {
	var schedule d.Schedule
	err := repository.transaction(ctx, func(tx context.Context) error {
		if err := academicYearAdministratorError(repository.authentication.RequireAdministratorTx(tx, actor)); err != nil {
			return err
		}
		state, err := readAcademicYearState(tx, repository.authentication.database)
		if err != nil {
			return err
		}
		schedule, err = d.Project(state, repository.authentication.currentTime(time.Time{}))
		return err
	})
	if err != nil {
		return d.Schedule{}, err
	}
	return schedule, nil
}

func (repository *AcademicYearRepository) Update(ctx context.Context, command d.Command) (d.Schedule, error) {
	var schedule d.Schedule
	eventID := uuid.NewString()
	err := repository.transaction(ctx, func(tx context.Context) error {
		if err := academicYearAdministratorError(repository.authentication.RequireAdministratorTx(tx, command.ActorAuthID)); err != nil {
			return err
		}
		state, err := readAcademicYearState(tx, repository.authentication.database)
		if err != nil {
			return err
		}
		now := repository.authentication.currentTime(time.Time{})
		after, projected, changed, err := d.Change(state, command, now)
		if err != nil {
			return err
		}
		if !changed {
			schedule = projected
			return nil
		}
		before, err := d.Project(state, now)
		if err != nil {
			return err
		}
		result, err := repository.authentication.database.Collection(AuthenticationRuntimeCollection).ReplaceOne(tx, bson.M{"_id": academicYearScheduleID, "revision": state.Revision}, academicYearDocument(after))
		if err != nil {
			return d.ErrUnavailable
		}
		if result.MatchedCount != 1 {
			return d.ErrConflict
		}
		audit := bson.M{
			"eventId":               eventID,
			"actorAuthId":           command.ActorAuthID,
			"reason":                command.Reason,
			"beforeNextRolloverAt":  exactInstantDocument(before.NextRolloverAt),
			"afterNextRolloverAt":   exactInstantDocument(after.AnchorAt),
			"currentAcademicYear":   before.CurrentAcademicYear,
			"beforeRevision":        state.Revision,
			"afterRevision":         after.Revision,
			"occurredAt":            now,
			"newAnchorAcademicYear": after.AnchorAcademicYear,
		}
		if _, err = repository.authentication.database.Collection(AcademicYearAuditCollection).InsertOne(tx, audit); err != nil {
			return d.ErrUnavailable
		}
		schedule = projected
		return nil
	})
	if err != nil {
		return d.Schedule{}, err
	}
	return schedule, nil
}
