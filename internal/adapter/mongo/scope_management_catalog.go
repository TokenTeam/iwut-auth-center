package mongo

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	od "iwut-auth-center/internal/oauth/domain"
	d "iwut-auth-center/internal/scopemanagement/domain"
)

func readManagedCatalog(ctx context.Context, db *m.Database) (od.Catalog, error) {
	var raw, marker, runtime bson.Raw
	if db.Collection(AuthenticationRuntimeCollection).FindOne(ctx, bson.M{"_id": "authentication"}).Decode(&runtime) != nil {
		return od.Catalog{}, d.ErrUnavailable
	}
	flag := runtime.Lookup("scopeCatalogProvisioned")
	if flag.Type != bson.TypeBoolean || !flag.Boolean() {
		return od.Catalog{}, d.ErrUnavailable
	}
	if db.Collection(AuthenticationRuntimeCollection).FindOne(ctx, bson.M{"_id": scopeCatalogProvisionID}).Decode(&marker) != nil || !validScopeProvision(marker) {
		return od.Catalog{}, d.ErrUnavailable
	}
	baseline, err := readScopeBaseline(ctx, db, marker)
	if err != nil {
		return od.Catalog{}, err
	}
	if db.Collection("auth_oauth_catalog").FindOne(ctx, bson.M{"_id": "current"}).Decode(&raw) != nil {
		return od.Catalog{}, d.ErrUnavailable
	}
	catalog, err := decodeManagedCatalog(raw)
	if err != nil {
		return od.Catalog{}, err
	}
	definitions := map[string]d.Definition{}
	for _, value := range scopeDefinitions(catalog.Scopes) {
		definitions[value.Name] = value
	}
	contracts, err := db.Collection(ScopeManagementContractCollection).Find(ctx, bson.M{}, options.Find().SetLimit(33))
	if err != nil {
		return od.Catalog{}, d.ErrUnavailable
	}
	defer contracts.Close(ctx)
	seen := map[string]bool{}
	for contracts.Next(ctx) {
		var contract bson.Raw
		if contracts.Decode(&contract) != nil || contract.Lookup("_id").Type != bson.TypeString {
			return od.Catalog{}, d.ErrUnavailable
		}
		name := contract.Lookup("_id").StringValue()
		value, ok := definitions[name]
		if !ok || seen[name] || !validScopeContract(contract, value) {
			return od.Catalog{}, d.ErrUnavailable
		}
		seen[name] = true
		if contract.Lookup("source").StringValue() == "SYSTEM_INITIAL_MANIFEST" {
			original, ok := baseline[value.Name]
			stored, err := decodeScopeDefinition(contract.Lookup("definition").Document(), true)
			if !ok || err != nil || stored != original {
				return od.Catalog{}, d.ErrUnavailable
			}
		}
	}
	if contracts.Err() != nil || len(seen) != len(definitions) {
		return od.Catalog{}, d.ErrUnavailable
	}
	return catalog, nil
}

func readScopeBaseline(ctx context.Context, db *m.Database, marker bson.Raw) (map[string]d.Definition, error) {
	var audit bson.Raw
	if db.Collection(ScopeManagementAuditCollection).FindOne(ctx, bson.M{"_id": scopeCatalogProvisionID}).Decode(&audit) != nil {
		return nil, d.ErrUnavailable
	}
	fields := map[string]bson.Type{"_id": bson.TypeString, "operationId": bson.TypeString, "source": bson.TypeString, "after": bson.TypeArray, "resultRevision": bson.TypeInt64, "resultDigest": bson.TypeString, "occurredAt": bson.TypeDateTime}
	if !exactScopeFields(audit, fields) || audit.Lookup("_id").StringValue() != scopeCatalogProvisionID || audit.Lookup("operationId").StringValue() != scopeCatalogProvisionID || audit.Lookup("source").StringValue() != "SYSTEM_INITIAL_MANIFEST" || audit.Lookup("resultRevision").Int64() != 1 || audit.Lookup("resultDigest").StringValue() != marker.Lookup("baselineDigest").StringValue() || audit.Lookup("occurredAt").DateTime() != marker.Lookup("provisionedAt").DateTime() {
		return nil, d.ErrUnavailable
	}
	values, err := audit.Lookup("after").Array().Values()
	if err != nil {
		return nil, d.ErrUnavailable
	}
	defs := make([]d.Definition, 0, len(values))
	out := map[string]d.Definition{}
	for _, value := range values {
		if value.Type != bson.TypeEmbeddedDocument {
			return nil, d.ErrUnavailable
		}
		def, err := decodeScopeDefinition(value.Document(), true)
		if err != nil {
			return nil, err
		}
		defs = append(defs, def)
		out[def.Name] = def
	}
	digest, err := d.Digest(defs)
	if err != nil || digest != marker.Lookup("baselineDigest").StringValue() {
		return nil, d.ErrUnavailable
	}
	return out, nil
}
func validScopeProvision(raw bson.Raw) bool {
	return exactScopeFields(raw, map[string]bson.Type{"_id": bson.TypeString, "source": bson.TypeString, "provisionedAt": bson.TypeDateTime, "baselineDigest": bson.TypeString}) && raw.Lookup("_id").StringValue() == scopeCatalogProvisionID && raw.Lookup("source").StringValue() == "SYSTEM_INITIAL_MANIFEST" && raw.Lookup("provisionedAt").DateTime() > 0 && d.ValidDigest(raw.Lookup("baselineDigest").StringValue())
}
func decodeManagedCatalog(raw bson.Raw) (od.Catalog, error) {
	if !exactScopeFields(raw, map[string]bson.Type{"_id": bson.TypeString, "data": bson.TypeEmbeddedDocument}) || raw.Lookup("_id").StringValue() != "current" {
		return od.Catalog{}, d.ErrUnavailable
	}
	data := raw.Lookup("data").Document()
	if !exactScopeFields(data, map[string]bson.Type{"revision": bson.TypeInt64, "generatedat": bson.TypeDateTime, "scopes": bson.TypeArray}) || data.Lookup("revision").Int64() < 1 || data.Lookup("generatedat").DateTime() <= 0 {
		return od.Catalog{}, d.ErrUnavailable
	}
	items, err := data.Lookup("scopes").Array().Values()
	if err != nil || len(items) < 1 || len(items) > 32 {
		return od.Catalog{}, d.ErrUnavailable
	}
	defs := make([]d.Definition, 0, len(items))
	for _, item := range items {
		if item.Type != bson.TypeEmbeddedDocument {
			return od.Catalog{}, d.ErrUnavailable
		}
		value, err := decodeScopeDefinition(item.Document(), false)
		if err != nil {
			return od.Catalog{}, err
		}
		defs = append(defs, value)
	}
	canonical, err := d.CanonicalDefinitions(defs)
	if err != nil {
		return od.Catalog{}, d.ErrUnavailable
	}
	if time.UnixMilli(data.Lookup("generatedat").DateTime()).Year() > 9999 {
		return od.Catalog{}, d.ErrUnavailable
	}
	// Stored order is canonical as well, preventing malformed duplicate or
	// reordered persistence from being hidden by response normalization.
	for i, v := range canonical {
		if defs[i] != v {
			return od.Catalog{}, d.ErrUnavailable
		}
	}
	return od.Catalog{Revision: data.Lookup("revision").Int64(), GeneratedAt: time.UnixMilli(data.Lookup("generatedat").DateTime()).UTC(), Scopes: oauthScopes(canonical)}, nil
}
func decodeScopeDefinition(raw bson.Raw, contract bool) (d.Definition, error) {
	field, typeField := "profilefield", "profilevaluetype"
	if contract {
		field, typeField = "profileField", "profileValueType"
	}
	if !exactScopeFields(raw, map[string]bson.Type{"name": bson.TypeString, "label": bson.TypeString, "description": bson.TypeString, "kind": bson.TypeString, "audience": bson.TypeString, field: bson.TypeString, typeField: bson.TypeString, "enabled": bson.TypeBoolean}) {
		return d.Definition{}, d.ErrUnavailable
	}
	v := d.Definition{Name: raw.Lookup("name").StringValue(), Label: raw.Lookup("label").StringValue(), Description: raw.Lookup("description").StringValue(), Kind: raw.Lookup("kind").StringValue(), Audience: raw.Lookup("audience").StringValue(), ProfileField: raw.Lookup(field).StringValue(), ProfileValueType: raw.Lookup(typeField).StringValue(), Enabled: raw.Lookup("enabled").Boolean()}
	if !v.Valid() {
		return d.Definition{}, d.ErrUnavailable
	}
	return v, nil
}
func validScopeContract(raw bson.Raw, current d.Definition) bool {
	fields := map[string]bson.Type{"_id": bson.TypeString, "source": bson.TypeString, "definition": bson.TypeEmbeddedDocument, "registeredAt": bson.TypeDateTime}
	source := raw.Lookup("source")
	if source.Type != bson.TypeString {
		return false
	}
	switch source.StringValue() {
	case "SYSTEM_INITIAL_MANIFEST":
	case "ADMINISTRATOR_REGISTRATION":
		fields["operationId"] = bson.TypeString
		fields["actorAuthId"] = bson.TypeString
		fields["contract"] = bson.TypeString
		fields["providerEvidence"] = bson.TypeString
	default:
		return false
	}
	if !exactScopeFields(raw, fields) || raw.Lookup("_id").StringValue() != current.Name || raw.Lookup("registeredAt").DateTime() <= 0 {
		return false
	}
	v, err := decodeScopeDefinition(raw.Lookup("definition").Document(), true)
	if err != nil || !v.StableEqual(current) {
		return false
	}
	if source.StringValue() == "ADMINISTRATOR_REGISTRATION" {
		c := d.Command{ActorAuthID: raw.Lookup("actorAuthId").StringValue(), OperationID: raw.Lookup("operationId").StringValue(), ExpectedRevision: 1, ExpectedDigest: "0000000000000000000000000000000000000000000000000000000000000000", Reason: "validation", Changes: []d.Change{{Kind: "REGISTER", Definition: v, Contract: raw.Lookup("contract").StringValue(), ProviderEvidence: raw.Lookup("providerEvidence").StringValue()}}}
		c.Changes[0].Definition.ProfileValueType = ""
		return c.Valid()
	}
	return true
}
