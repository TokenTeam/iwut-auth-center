package mongo

import (
	"context"
	"errors"
	"math"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	admin "iwut-auth-center/internal/administrator/domain"
	od "iwut-auth-center/internal/oauth/domain"
	d "iwut-auth-center/internal/scopemanagement/domain"
	"iwut-auth-center/internal/scopemanagement/port"
)

const (
	ScopeManagementAuditCollection     = "auth_scope_management_audit"
	ScopeManagementOperationCollection = "auth_scope_management_operations"
	ScopeManagementContractCollection  = "auth_scope_management_contracts"
	scopeCatalogProvisionID            = "scope-catalog-provision"
)

type ScopeManagementRepository struct {
	auth      *AuthenticationRepository
	providers map[string]d.Definition
	validate  func([]od.Scope) error
}

func NewScopeManagementRepository(auth *AuthenticationRepository, providers []od.Scope, validate func([]od.Scope) error) (*ScopeManagementRepository, error) {
	if auth == nil || validate == nil {
		return nil, d.ErrUnavailable
	}
	defs, err := d.CanonicalDefinitions(scopeDefinitions(providers))
	if err != nil {
		return nil, d.ErrUnavailable
	}
	r := &ScopeManagementRepository{auth: auth, providers: map[string]d.Definition{}, validate: validate}
	for _, v := range defs {
		r.providers[v.Name] = v
	}
	return r, nil
}

func EnsureScopeManagementSchema(ctx context.Context, db *m.Database) error {
	if db == nil {
		return d.ErrUnavailable
	}
	for _, name := range []string{ScopeManagementAuditCollection, ScopeManagementOperationCollection, ScopeManagementContractCollection} {
		err := db.CreateCollection(ctx, name)
		var ce m.CommandError
		if err != nil && (!errors.As(err, &ce) || ce.Code != 48) {
			return d.ErrUnavailable
		}
	}
	for name, models := range map[string][]m.IndexModel{
		ScopeManagementAuditCollection:     {{Keys: bson.D{{Key: "operationId", Value: 1}}, Options: options.Index().SetUnique(true).SetName("scope_audit_operation_unique")}, {Keys: bson.D{{Key: "occurredAt", Value: 1}, {Key: "operationId", Value: 1}}, Options: options.Index().SetName("scope_audit_history")}},
		ScopeManagementOperationCollection: {{Keys: bson.D{{Key: "operationId", Value: 1}}, Options: options.Index().SetUnique(true).SetName("scope_operation_unique")}},
	} {
		if _, err := db.Collection(name).Indexes().CreateMany(ctx, models); err != nil {
			return d.ErrUnavailable
		}
	}
	return nil
}

func scopeDefinitions(scopes []od.Scope) []d.Definition {
	out := make([]d.Definition, 0, len(scopes))
	for _, s := range scopes {
		out = append(out, d.Definition{Name: s.Name, Label: s.Label, Description: s.Description, Kind: s.Kind, Audience: s.Audience, ProfileField: s.ProfileField, ProfileValueType: s.ProfileValueType, Enabled: s.Enabled})
	}
	return out
}
func oauthScopes(scopes []d.Definition) []od.Scope {
	out := make([]od.Scope, 0, len(scopes))
	for _, s := range scopes {
		out = append(out, od.Scope{Name: s.Name, Label: s.Label, Description: s.Description, Kind: s.Kind, Audience: s.Audience, ProfileField: s.ProfileField, ProfileValueType: s.ProfileValueType, Enabled: s.Enabled})
	}
	return out
}
func scopeAdministratorError(err error) error {
	switch {
	case errors.Is(err, admin.ErrIdentity):
		return d.ErrIdentity
	case errors.Is(err, admin.ErrForbidden), errors.Is(err, admin.ErrSubject):
		return d.ErrForbidden
	case err != nil:
		return d.ErrUnavailable
	default:
		return nil
	}
}
func (r *ScopeManagementRepository) transaction(ctx context.Context, fn func(context.Context) error) error {
	var semantic error
	err := r.auth.WithAuthTransaction(ctx, func(tx context.Context) error { semantic = nil; semantic = fn(tx); return semantic })
	if err == nil {
		return nil
	}
	// A timeout or uncertain commit never becomes an inferred success/failure.
	if ctx.Err() != nil {
		return d.ErrUnavailable
	}
	for _, known := range d.Errors {
		if errors.Is(semantic, known) {
			return known
		}
	}
	return d.ErrUnavailable
}

func (r *ScopeManagementRepository) Get(ctx context.Context, actor string) (d.Snapshot, error) {
	var result d.Snapshot
	err := r.transaction(ctx, func(tx context.Context) error {
		if err := scopeAdministratorError(r.auth.RequireAdministratorTx(tx, actor)); err != nil {
			return err
		}
		catalog, err := readManagedCatalog(tx, r.auth.database)
		if err != nil {
			return err
		}
		result, err = managedSnapshot(catalog)
		return err
	})
	if err != nil {
		return d.Snapshot{}, err
	}
	return result, nil
}
func managedSnapshot(catalog od.Catalog) (d.Snapshot, error) {
	defs, err := d.CanonicalDefinitions(scopeDefinitions(catalog.Scopes))
	if err != nil {
		return d.Snapshot{}, d.ErrUnavailable
	}
	digest, err := d.Digest(defs)
	if err != nil {
		return d.Snapshot{}, d.ErrUnavailable
	}
	return d.Snapshot{Revision: catalog.Revision, GeneratedAt: catalog.GeneratedAt, Digest: digest, Scopes: defs}, nil
}
func (r *ScopeManagementRepository) Operation(ctx context.Context, actor, id string) (d.Operation, error) {
	if !d.ValidOperationID(id) {
		return d.Operation{}, d.ErrInvalid
	}
	var result d.Operation
	err := r.transaction(ctx, func(tx context.Context) error {
		if err := scopeAdministratorError(r.auth.RequireAdministratorTx(tx, actor)); err != nil {
			return err
		}
		var err error
		result, err = readScopeOperation(tx, r.auth.database, id)
		return err
	})
	if err != nil {
		return d.Operation{}, err
	}
	return result, nil
}

func (r *ScopeManagementRepository) Change(ctx context.Context, command d.Command) (d.Operation, error) {
	command = command.Normalize()
	requestDigest, err := d.RequestDigest(command)
	if err != nil {
		return d.Operation{}, err
	}
	var result d.Operation
	err = r.transaction(ctx, func(tx context.Context) error {
		if err := scopeAdministratorError(r.auth.RequireAdministratorTx(tx, command.ActorAuthID)); err != nil {
			return err
		}
		previous, err := readScopeOperation(tx, r.auth.database, command.OperationID)
		if err == nil {
			if previous.ActorAuthID != command.ActorAuthID || previous.RequestDigest != requestDigest {
				return d.ErrOperationConflict
			}
			result = previous
			return nil
		}
		if !errors.Is(err, d.ErrNotFound) {
			return err
		}
		catalog, err := readManagedCatalog(tx, r.auth.database)
		if err != nil {
			return err
		}
		before, err := managedSnapshot(catalog)
		if err != nil {
			return err
		}
		if before.Revision != command.ExpectedRevision || before.Digest != command.ExpectedDigest {
			return d.ErrConflict
		}
		after, contracts, err := r.apply(before.Scopes, command.Changes)
		if err != nil {
			return err
		}
		if err = r.validate(oauthScopes(after)); err != nil {
			return d.ErrBlocked
		}
		digest, err := d.Digest(after)
		if err != nil {
			return d.ErrBlocked
		}
		now := r.auth.currentTime(time.Time{}).UTC().Truncate(time.Millisecond)
		if now.IsZero() || now.Year() < 1970 || now.Year() > 9999 || now.Before(before.GeneratedAt) {
			return d.ErrUnavailable
		}
		result = d.Operation{OperationID: command.OperationID, RequestDigest: requestDigest, ActorAuthID: command.ActorAuthID, Reason: command.Reason, Outcome: "NO_CHANGE", BaseRevision: before.Revision, ResultRevision: before.Revision, ResultGeneratedAt: before.GeneratedAt, ResultDigest: digest, OccurredAt: now}
		if digest != before.Digest {
			if before.Revision == math.MaxInt64 {
				return d.ErrRevisionExhausted
			}
			result.Outcome = "APPLIED"
			result.ResultRevision++
			result.ResultGeneratedAt = now
			next := od.Catalog{Revision: result.ResultRevision, GeneratedAt: now, Scopes: oauthScopes(after)}
			changed, err := r.auth.database.Collection("auth_oauth_catalog").ReplaceOne(tx, bson.M{"_id": "current", "data.revision": before.Revision}, oauthDocument[od.Catalog]{ID: "current", Data: next})
			if err != nil {
				return d.ErrUnavailable
			}
			if changed.MatchedCount != 1 {
				return d.ErrConflict
			}
		}
		for _, contract := range contracts {
			contract["operationId"] = command.OperationID
			contract["actorAuthId"] = command.ActorAuthID
			contract["registeredAt"] = now
			if _, err := r.auth.database.Collection(ScopeManagementContractCollection).InsertOne(tx, contract); err != nil {
				return d.ErrUnavailable
			}
		}
		audit := operationDocumentScope(result)
		audit["source"] = "ADMINISTRATOR"
		audit["before"] = scopeDefinitionsDocument(before.Scopes)
		audit["after"] = scopeDefinitionsDocument(after)
		if _, err := r.auth.database.Collection(ScopeManagementAuditCollection).InsertOne(tx, audit); err != nil {
			return d.ErrUnavailable
		}
		if _, err := r.auth.database.Collection(ScopeManagementOperationCollection).InsertOne(tx, operationDocumentScope(result)); err != nil {
			return d.ErrUnavailable
		}
		return nil
	})
	if err != nil {
		return d.Operation{}, err
	}
	return result, nil
}

func (r *ScopeManagementRepository) apply(before []d.Definition, changes []d.Change) ([]d.Definition, []bson.M, error) {
	values := map[string]d.Definition{}
	for _, v := range before {
		values[v.Name] = v
	}
	contracts := []bson.M{}
	for _, c := range changes {
		switch c.Kind {
		case "REGISTER":
			value := c.Definition
			if _, exists := values[value.Name]; exists {
				return nil, nil, d.ErrBlocked
			}
			provider, exists := r.providers[value.Name]
			if !exists {
				return nil, nil, d.ErrBlocked
			}
			// Only the trusted delivered manifest supplies the profile type. All
			// caller supplied mapping and initial text must match that provider.
			value.ProfileValueType = provider.ProfileValueType
			if !value.StableEqual(provider) || value.Label != provider.Label || value.Description != provider.Description {
				return nil, nil, d.ErrBlocked
			}
			values[value.Name] = value
			contracts = append(contracts, bson.M{"_id": value.Name, "source": "ADMINISTRATOR_REGISTRATION", "definition": definitionDocument(value), "contract": c.Contract, "providerEvidence": c.ProviderEvidence})
		case "CORRECT_TEXT":
			value, exists := values[c.Name]
			if !exists {
				return nil, nil, d.ErrBlocked
			}
			value.Label = c.Label
			value.Description = c.Description
			values[c.Name] = value
		case "SET_ENABLED":
			value, exists := values[c.Name]
			if !exists {
				return nil, nil, d.ErrBlocked
			}
			value.Enabled = c.Enabled
			values[c.Name] = value
		default:
			return nil, nil, d.ErrInvalid
		}
	}
	after := make([]d.Definition, 0, len(values))
	for _, value := range values {
		after = append(after, value)
	}
	canonical, err := d.CanonicalDefinitions(after)
	if err != nil {
		return nil, nil, d.ErrBlocked
	}
	return canonical, contracts, nil
}

func definitionDocument(v d.Definition) bson.M {
	return bson.M{"name": v.Name, "label": v.Label, "description": v.Description, "kind": v.Kind, "audience": v.Audience, "profileField": v.ProfileField, "profileValueType": v.ProfileValueType, "enabled": v.Enabled}
}
func scopeDefinitionsDocument(v []d.Definition) bson.A {
	out := bson.A{}
	for _, item := range v {
		out = append(out, definitionDocument(item))
	}
	return out
}
func operationDocumentScope(o d.Operation) bson.M {
	return bson.M{"_id": o.OperationID, "operationId": o.OperationID, "requestDigest": o.RequestDigest, "actorAuthId": o.ActorAuthID, "reason": o.Reason, "outcome": o.Outcome, "baseRevision": o.BaseRevision, "resultRevision": o.ResultRevision, "resultGeneratedAt": o.ResultGeneratedAt, "resultDigest": o.ResultDigest, "occurredAt": o.OccurredAt}
}

func readScopeOperation(ctx context.Context, db *m.Database, id string) (d.Operation, error) {
	var raw bson.Raw
	err := db.Collection(ScopeManagementOperationCollection).FindOne(ctx, bson.M{"_id": id}).Decode(&raw)
	if errors.Is(err, m.ErrNoDocuments) {
		return d.Operation{}, d.ErrNotFound
	}
	if err != nil {
		return d.Operation{}, d.ErrUnavailable
	}
	return decodeScopeOperation(raw, id)
}
func exactScopeFields(raw bson.Raw, fields map[string]bson.Type) bool {
	elements, err := raw.Elements()
	if err != nil || len(elements) != len(fields) {
		return false
	}
	seen := map[string]bool{}
	for _, v := range elements {
		kind, ok := fields[v.Key()]
		if !ok || seen[v.Key()] || v.Value().Type != kind {
			return false
		}
		seen[v.Key()] = true
	}
	return true
}
func decodeScopeOperation(raw bson.Raw, id string) (d.Operation, error) {
	fields := map[string]bson.Type{"_id": bson.TypeString, "operationId": bson.TypeString, "requestDigest": bson.TypeString, "actorAuthId": bson.TypeString, "reason": bson.TypeString, "outcome": bson.TypeString, "baseRevision": bson.TypeInt64, "resultRevision": bson.TypeInt64, "resultGeneratedAt": bson.TypeDateTime, "resultDigest": bson.TypeString, "occurredAt": bson.TypeDateTime}
	if !exactScopeFields(raw, fields) || raw.Lookup("_id").StringValue() != id || raw.Lookup("operationId").StringValue() != id {
		return d.Operation{}, d.ErrUnavailable
	}
	o := d.Operation{OperationID: id, RequestDigest: raw.Lookup("requestDigest").StringValue(), ActorAuthID: raw.Lookup("actorAuthId").StringValue(), Reason: raw.Lookup("reason").StringValue(), Outcome: raw.Lookup("outcome").StringValue(), BaseRevision: raw.Lookup("baseRevision").Int64(), ResultRevision: raw.Lookup("resultRevision").Int64(), ResultGeneratedAt: time.UnixMilli(raw.Lookup("resultGeneratedAt").DateTime()).UTC(), ResultDigest: raw.Lookup("resultDigest").StringValue(), OccurredAt: time.UnixMilli(raw.Lookup("occurredAt").DateTime()).UTC()}
	if !o.Valid() {
		return d.Operation{}, d.ErrUnavailable
	}
	return o, nil
}

var _ port.Repository = (*ScopeManagementRepository)(nil)
