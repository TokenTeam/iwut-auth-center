package mongo

import (
	"context"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	d "iwut-auth-center/internal/oauth/domain"
	sd "iwut-auth-center/internal/scope/domain"
	sp "iwut-auth-center/internal/scope/port"
	management "iwut-auth-center/internal/scopemanagement/domain"
)

// OAuthCatalog exposes the same authoritative document to the internal Scope
// RPC and OAuth transactions. Startup only provisions a previously absent
// catalog; all subsequent text/enablement changes use administrator management.
type OAuthCatalog struct{ repository *OAuthRepository }

func NewOAuthCatalog(r *OAuthRepository) *OAuthCatalog { return &OAuthCatalog{r} }
func (r *OAuthRepository) SeedCatalog(ctx context.Context, scopes []d.Scope) error {
	return r.SeedCatalogValidated(ctx, scopes, nil)
}

// SeedCatalogValidated applies runtime constraints before first provisioning or
// to the authoritative live definitions on subsequent startup. The callback is
// pure and may be retried with the global authentication transaction.
func (r *OAuthRepository) SeedCatalogValidated(ctx context.Context, scopes []d.Scope, validate func([]d.Scope) error) error {
	defs, err := management.CanonicalDefinitions(scopeDefinitions(scopes))
	if err != nil {
		return d.ErrScope
	}
	providers := map[string]management.Definition{}
	for _, v := range defs {
		providers[v.Name] = v
	}
	var semantic error
	err = r.auth.WithAuthTransaction(ctx, func(tx context.Context) error {
		semantic = nil
		semantic = func() error {
			var marker, runtime, catalog bson.Raw
			if err := r.db.Collection(AuthenticationRuntimeCollection).FindOne(tx, bson.M{"_id": "authentication"}).Decode(&runtime); err != nil {
				return d.ErrUnavailable
			}
			flag := runtime.Lookup("scopeCatalogProvisioned")
			if flag.Type != 0 && flag.Type != bson.TypeBoolean {
				return d.ErrUnavailable
			}
			markerErr := r.db.Collection(AuthenticationRuntimeCollection).FindOne(tx, bson.M{"_id": scopeCatalogProvisionID}).Decode(&marker)
			catalogErr := r.db.Collection("auth_oauth_catalog").FindOne(tx, bson.M{"_id": "current"}).Decode(&catalog)
			if errors.Is(markerErr, m.ErrNoDocuments) && errors.Is(catalogErr, m.ErrNoDocuments) && flag.Type == 0 {
				if validate != nil && validate(oauthScopes(defs)) != nil {
					return d.ErrScope
				}
				now := r.auth.currentTime(time.Time{}).UTC().Truncate(time.Millisecond)
				if now.UnixMilli() <= 0 || now.Year() > 9999 {
					return d.ErrUnavailable
				}
				digest, _ := management.Digest(defs)
				baseline := d.Catalog{Revision: 1, GeneratedAt: now, Scopes: oauthScopes(defs)}
				if _, err := r.db.Collection("auth_oauth_catalog").InsertOne(tx, oauthDocument[d.Catalog]{ID: "current", Data: baseline}); err != nil {
					return d.ErrUnavailable
				}
				for _, v := range defs {
					if _, err := r.db.Collection(ScopeManagementContractCollection).InsertOne(tx, bson.M{"_id": v.Name, "source": "SYSTEM_INITIAL_MANIFEST", "definition": definitionDocument(v), "registeredAt": now}); err != nil {
						return d.ErrUnavailable
					}
				}
				if _, err := r.db.Collection(ScopeManagementAuditCollection).InsertOne(tx, bson.M{"_id": scopeCatalogProvisionID, "operationId": scopeCatalogProvisionID, "source": "SYSTEM_INITIAL_MANIFEST", "after": scopeDefinitionsDocument(defs), "resultRevision": int64(1), "resultDigest": digest, "occurredAt": now}); err != nil {
					return d.ErrUnavailable
				}
				if _, err := r.db.Collection(AuthenticationRuntimeCollection).InsertOne(tx, bson.M{"_id": scopeCatalogProvisionID, "source": "SYSTEM_INITIAL_MANIFEST", "provisionedAt": now, "baselineDigest": digest}); err != nil {
					return d.ErrUnavailable
				}
				result, err := r.db.Collection(AuthenticationRuntimeCollection).UpdateOne(tx, bson.M{"_id": "authentication", "scopeCatalogProvisioned": bson.M{"$exists": false}}, bson.M{"$set": bson.M{"scopeCatalogProvisioned": true}})
				if err != nil || result.MatchedCount != 1 {
					return d.ErrUnavailable
				}
				return nil
			}
			if markerErr != nil || catalogErr != nil || flag.Type != bson.TypeBoolean || !flag.Boolean() {
				return d.ErrUnavailable
			}
			live, err := readManagedCatalog(tx, r.db)
			if err != nil {
				return d.ErrUnavailable
			}
			for _, v := range scopeDefinitions(live.Scopes) {
				provider, ok := providers[v.Name]
				if !ok || !v.StableEqual(provider) {
					return d.ErrScope
				}
			}
			if validate != nil && validate(live.Scopes) != nil {
				return d.ErrScope
			}
			return nil
		}()
		return semantic
	})
	if err != nil {
		if errors.Is(semantic, d.ErrScope) {
			return d.ErrScope
		}
		return d.ErrUnavailable
	}
	return nil
}

// ReadCatalog is an internal startup read, not an administrator API. It verifies
// the durable provisioning marker and strict persisted representation.
func (r *OAuthRepository) ReadCatalog(ctx context.Context) (d.Catalog, error) {
	var catalog d.Catalog
	err := r.auth.WithAuthTransaction(ctx, func(tx context.Context) error {
		var err error
		catalog, err = readManagedCatalog(tx, r.db)
		return err
	})
	if err != nil {
		return d.Catalog{}, d.ErrUnavailable
	}
	return catalog, nil
}
func (c *OAuthCatalog) GetSnapshot(ctx context.Context) (sd.Snapshot, error) {
	doc, err := c.repository.ReadCatalog(ctx)
	if err != nil {
		return sd.Snapshot{}, sp.ErrScopeCatalogUnavailable
	}
	scopes := []sd.ScopeDefinition{}
	for _, s := range doc.Scopes {
		v, err := sd.NewScopeDefinition(s.Name, s.Enabled)
		if err != nil {
			return sd.Snapshot{}, sp.ErrScopeCatalogUnavailable
		}
		scopes = append(scopes, v)
	}
	snapshot, err := sd.NewSnapshot(doc.Revision, doc.GeneratedAt, scopes)
	if err != nil {
		return sd.Snapshot{}, sp.ErrScopeCatalogUnavailable
	}
	return snapshot, nil
}
