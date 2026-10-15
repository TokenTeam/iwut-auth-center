package mongo

import (
	"context"
	"reflect"
	"sort"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	d "iwut-auth-center/internal/oauth/domain"
	sd "iwut-auth-center/internal/scope/domain"
	sp "iwut-auth-center/internal/scope/port"
)

// OAuthCatalog exposes the same authoritative document to the internal Scope
// RPC and OAuth transactions. Seed changes are explicit startup migrations.
type OAuthCatalog struct{ repository *OAuthRepository }

func NewOAuthCatalog(r *OAuthRepository) *OAuthCatalog { return &OAuthCatalog{r} }
func (r *OAuthRepository) SeedCatalog(ctx context.Context, scopes []d.Scope) error {
	names := []string{}
	profileFields := map[string]bool{}
	for _, s := range scopes {
		names = append(names, s.Name)
		profile := s.Kind == "USERINFO_PROFILE"
		if s.Label == "" || s.Description == "" || !s.ValidMetadata() {
			return d.ErrScope
		}
		if profile {
			if profileFields[s.ProfileField] {
				return d.ErrScope
			}
			profileFields[s.ProfileField] = true
		}
	}
	if !d.ValidScopes(names) {
		return d.ErrScope
	}
	scopes = append([]d.Scope(nil), scopes...)
	sort.Slice(scopes, func(i, j int) bool { return scopes[i].Name < scopes[j].Name })
	return r.auth.WithAuthTransaction(ctx, func(ctx context.Context) error {
		tx := &oauthTx{ctx: ctx, r: r}
		old, err := tx.Catalog()
		if err != nil && err != d.ErrNotFound {
			return err
		}
		if reflect.DeepEqual(old.Scopes, scopes) {
			return nil
		}
		// Stable names cannot silently acquire different meanings or audiences.
		for _, a := range old.Scopes {
			if !d.Contains(names, a.Name) {
				return d.ErrScope
			}
			for _, b := range scopes {
				if a.Name == b.Name && (a.Kind != b.Kind || a.Audience != b.Audience || a.ProfileField != b.ProfileField || a.ProfileValueType != b.ProfileValueType) {
					return d.ErrScope
				}
			}
		}
		next := d.Catalog{Revision: old.Revision + 1, GeneratedAt: time.Now().UTC(), Scopes: scopes}
		return oauthSave(tx, "catalog", oauthDocument[d.Catalog]{ID: "current", Data: next})
	})
}
func (c *OAuthCatalog) GetSnapshot(ctx context.Context) (sd.Snapshot, error) {
	tx := &oauthTx{ctx: ctx, r: c.repository}
	doc, err := oauthGet[d.Catalog](tx, "catalog", bson.M{"_id": "current"})
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
