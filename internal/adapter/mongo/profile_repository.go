package mongo

import (
	"context"
	"errors"
	"go.mongodb.org/mongo-driver/v2/bson"
	drivermongo "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
	account "iwut-auth-center/internal/account/domain"
	"iwut-auth-center/internal/profile/domain"
	"iwut-auth-center/internal/profile/port"
)

type ProfileRepository struct {
	collection     *drivermongo.Collection
	authentication *AuthenticationRepository
}

func NewProfileRepository(database *drivermongo.Database, authentication ...*AuthenticationRepository) (*ProfileRepository, error) {
	if database == nil {
		return nil, domain.ErrUnavailable
	}
	var auth *AuthenticationRepository
	if len(authentication) > 0 {
		auth = authentication[0]
	}
	return &ProfileRepository{collection: database.Collection(PrincipalCollection, options.Collection().SetReadPreference(readpref.Primary())), authentication: auth}, nil
}
func (r *ProfileRepository) Transaction(ctx context.Context, operation func(context.Context) error) error {
	if r.authentication == nil {
		return operation(ctx)
	}
	var semantic error
	err := r.authentication.WithAuthTransaction(ctx, func(tx context.Context) error {
		semantic = operation(tx)
		return semantic
	})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		if semantic != nil {
			return semantic
		}
		return domain.ErrUnavailable
	}
	return nil
}
func (r *ProfileRepository) Read(ctx context.Context, id string) (domain.Principal, error) {
	return r.read(ctx, bson.M{"authId": id})
}
func (r *ProfileRepository) read(ctx context.Context, filter bson.M) (domain.Principal, error) {
	identity, ok := account.Identity(ctx)
	if !ok || identity.AuthID != filter["authId"] || identity.Revision <= 0 {
		return domain.Principal{}, domain.ErrIdentity
	}

	var raw bson.Raw
	e := r.collection.FindOne(ctx, filter).Decode(&raw)
	if errors.Is(e, drivermongo.ErrNoDocuments) {
		return domain.Principal{}, domain.ErrNotFound
	}
	if e != nil {
		return domain.Principal{}, domain.ErrUnavailable
	}
	if !identityFields(raw, map[string]bson.Type{"accountRevision": bson.TypeInt64}) || raw.Lookup("accountRevision").Int64() <= 0 {
		return domain.Principal{}, domain.ErrUnavailable
	}
	if raw.Lookup("accountRevision").Int64() != identity.Revision {
		return domain.Principal{}, domain.ErrIdentity
	}
	return decodeProfilePrincipal(raw)
}
func profileFilter(id string, revision int64) bson.M {
	return bson.M{"authId": id, "principalType": "USER", "accountStatus": "ACTIVE", "profile.revision": revision}
}
func (r *ProfileRepository) classify(ctx context.Context, id string) error {
	p, e := r.Read(ctx, id)
	if e != nil {
		return e
	}
	if e = domain.CheckPrincipal(p); e != nil {
		return e
	}
	return domain.ErrConflict
}
func (r *ProfileRepository) Confirm(ctx context.Context, id string, revision int64) (domain.Snapshot, error) {
	p, e := r.read(ctx, profileFilter(id, revision))
	if errors.Is(e, domain.ErrNotFound) {
		return domain.Snapshot{}, r.classify(ctx, id)
	}
	if e != nil {
		return domain.Snapshot{}, e
	}
	if e = domain.CheckPrincipal(p); e != nil {
		return domain.Snapshot{}, e
	}
	return p.Profile, nil
}
func (r *ProfileRepository) Commit(ctx context.Context, id string, revision int64, s domain.Snapshot) error {
	entries := make(bson.A, 0, len(s.Entries))
	for _, a := range s.Entries {
		var v any
		switch a.Value.Type {
		case domain.String, domain.Date:
			v = a.Value.Text
		case domain.Integer:
			v = a.Value.Integer
		case domain.Boolean:
			v = a.Value.Boolean
		case domain.StringSet:
			v = append([]string(nil), a.Value.Strings...)
		case domain.AcademicGrade:
			if a.Value.Academic == nil || a.Value.Academic.ConfirmedAt == nil {
				return domain.ErrUnavailable
			}
			v = bson.M{"stage": a.Value.Academic.Stage, "year": a.Value.Academic.Year, "finalYear": a.Value.Academic.FinalYear, "academicYear": a.Value.Academic.AcademicYear, "confirmedAt": *a.Value.Academic.ConfirmedAt}
		default:
			return domain.ErrUnavailable
		}
		entries = append(entries, bson.M{"key": a.Key, "valueType": string(a.Value.Type), "value": v})
	}
	identity, ok := account.Identity(ctx)
	if !ok || identity.AuthID != id || identity.Revision <= 0 {
		return domain.ErrIdentity
	}
	filter := profileFilter(id, revision)
	filter["accountRevision"] = identity.Revision
	result, e := r.collection.UpdateOne(ctx, filter, bson.M{"$set": bson.M{"profile.entries": entries, "profile.revision": s.Revision, "profile.updatedAt": s.UpdatedAt}})
	if e != nil {
		return domain.ErrUnavailable
	}
	if result.MatchedCount != 1 {
		return r.classify(ctx, id)
	}
	return nil
}
func decodeProfilePrincipal(raw bson.Raw) (domain.Principal, error) {
	p := domain.Principal{}
	var ok bool
	if p.AuthID, ok = raw.Lookup("authId").StringValueOK(); !ok || p.AuthID == "" {
		return p, domain.ErrUnavailable
	}
	if p.Type, ok = raw.Lookup("principalType").StringValueOK(); !ok {
		return p, domain.ErrUnavailable
	}
	if p.Type == "SYSTEM" {
		return p, nil
	}
	if p.AccountStatus, ok = raw.Lookup("accountStatus").StringValueOK(); !ok {
		return p, domain.ErrUnavailable
	}
	if p.AccountStatus == "DISABLED" || p.AccountStatus == "CLOSED" {
		return p, nil
	}
	profile, ok := raw.Lookup("profile").DocumentOK()
	if !ok {
		return p, domain.ErrUnavailable
	}
	if p.Profile.Revision, ok = profile.Lookup("revision").Int64OK(); !ok {
		return p, domain.ErrUnavailable
	}
	millis, ok := profile.Lookup("updatedAt").DateTimeOK()
	if !ok {
		return p, domain.ErrUnavailable
	}
	p.Profile.UpdatedAt = bson.DateTime(millis).Time().UTC()
	entries, ok := profile.Lookup("entries").ArrayOK()
	if !ok {
		return p, domain.ErrUnavailable
	}
	values, e := entries.Values()
	if e != nil {
		return p, domain.ErrUnavailable
	}
	p.Profile.Entries = make([]domain.Entry, 0, len(values))
	for _, v := range values {
		doc, ok := v.DocumentOK()
		if !ok {
			return p, domain.ErrUnavailable
		}
		key, ok := doc.Lookup("key").StringValueOK()
		if !ok {
			return p, domain.ErrUnavailable
		}
		typ, ok := doc.Lookup("valueType").StringValueOK()
		if !ok {
			return p, domain.ErrUnavailable
		}
		value := domain.Value{Type: domain.ValueType(typ)}
		switch value.Type {
		case domain.String, domain.Date:
			value.Text, ok = doc.Lookup("value").StringValueOK()
		case domain.Integer:
			value.Integer, ok = doc.Lookup("value").Int32OK()
		case domain.Boolean:
			value.Boolean, ok = doc.Lookup("value").BooleanOK()
		case domain.StringSet:
			var array bson.RawArray
			array, ok = doc.Lookup("value").ArrayOK()
			if ok {
				items, err := array.Values()
				if err != nil {
					ok = false
				} else {
					value.Strings = make([]string, 0, len(items))
					for _, item := range items {
						text, textOK := item.StringValueOK()
						if !textOK {
							ok = false
							break
						}
						value.Strings = append(value.Strings, text)
					}
				}
			}
		case domain.AcademicGrade:
			var gradeDoc bson.Raw
			gradeDoc, ok = doc.Lookup("value").DocumentOK()
			if ok {
				elements, err := gradeDoc.Elements()
				if err != nil || len(elements) != 5 {
					ok = false
				} else {
					grade := &domain.Grade{}
					grade.Stage, ok = gradeDoc.Lookup("stage").StringValueOK()
					if ok {
						grade.Year, ok = gradeDoc.Lookup("year").Int32OK()
					}
					if ok {
						grade.FinalYear, ok = gradeDoc.Lookup("finalYear").Int32OK()
					}
					if ok {
						grade.AcademicYear, ok = gradeDoc.Lookup("academicYear").Int32OK()
					}
					if ok {
						millis, dateOK := gradeDoc.Lookup("confirmedAt").DateTimeOK()
						ok = dateOK
						if dateOK {
							confirmed := bson.DateTime(millis).Time().UTC()
							grade.ConfirmedAt = &confirmed
						}
					}
					value.Academic = grade
				}
			}
		default:
			ok = false
		}
		if !ok {
			return p, domain.ErrUnavailable
		}
		p.Profile.Entries = append(p.Profile.Entries, domain.Entry{Key: key, Value: value})
	}
	if e = domain.ValidateSnapshot(p.Profile); e != nil {
		return p, e
	}
	domain.Sort(p.Profile.Entries)
	return p, nil
}

var _ port.Repository = (*ProfileRepository)(nil)
