package mongo

import (
	"encoding/base64"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	d "iwut-auth-center/internal/oauth/domain"
)

func validOAuthPresentationBSON(value bson.RawValue) bool {
	// Legacy interactions have no evidence. They remain readable only so View
	// can bind a fresh presentation; Confirm never accepts them directly.
	if value.Type == 0 || value.Type == bson.TypeNull {
		return true
	}
	if value.Type != bson.TypeEmbeddedDocument {
		return false
	}
	raw := value.Document()
	if !identityFields(raw, map[string]bson.Type{"id": bson.TypeString, "digest": bson.TypeString, "preparedat": bson.TypeDateTime, "definitions": bson.TypeArray}) {
		return false
	}
	definitions, err := raw.Lookup("definitions").Array().Values()
	if err != nil {
		return false
	}
	for _, definition := range definitions {
		if definition.Type != bson.TypeEmbeddedDocument || !identityFields(definition.Document(), map[string]bson.Type{
			"name": bson.TypeString, "label": bson.TypeString, "description": bson.TypeString,
			"kind": bson.TypeString, "audience": bson.TypeString, "profilefield": bson.TypeString,
			"profilevaluetype": bson.TypeString, "enabled": bson.TypeBoolean,
		}) {
			return false
		}
	}
	return true
}

func validOAuthConsentAudit(v d.Audit) bool {
	if v.Action != "AUTHORIZE" {
		return v.ConsentSource == "" && v.Presentation == nil && v.ReusedGrantRevision == 0
	}
	if !d.ValidScopes(v.Scopes) || v.ReusedGrantRevision < 0 {
		return false
	}
	switch v.ConsentSource {
	case "EXPLICIT":
		if v.ReusedGrantRevision != 0 || v.Presentation == nil || !oauthDigest(v.Presentation.ID) {
			return false
		}
		names := make([]string, 0, len(v.Presentation.Definitions))
		for _, definition := range v.Presentation.Definitions {
			names = append(names, definition.Name)
		}
		return v.Presentation.Valid(names) && d.Subset(v.Scopes, names)
	case "PRIOR_GRANT_REUSE":
		return v.ReusedGrantRevision > 0 && v.Presentation == nil
	default:
		return false
	}
}

func oauthDigest(v string) bool {
	b, e := base64.RawURLEncoding.Strict().DecodeString(v)
	return e == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == v
}
func validOAuthDocument[T any](doc oauthDocument[T]) bool {
	if doc.ID == "" {
		return false
	}
	switch v := any(doc.Data).(type) {
	case d.Catalog:
		if doc.ID != "current" || v.Revision < 1 || v.GeneratedAt.IsZero() {
			return false
		}
		names := []string{}
		profileFields := map[string]bool{}
		for _, s := range v.Scopes {
			names = append(names, s.Name)
			if s.Label == "" || s.Description == "" || !s.ValidMetadata() {
				return false
			}
			if s.Kind == "USERINFO_PROFILE" {
				if profileFields[s.ProfileField] {
					return false
				}
				profileFields[s.ProfileField] = true
			}
		}
		return d.ValidScopes(names)
	case d.Grant:
		return v.ID == doc.ID && v.AuthID != "" && v.ApplicationID != "" && v.AuthID == doc.AuthID && v.ApplicationID == doc.ApplicationID && v.Channel == doc.Channel && d.ValidChannel(v.Channel) && v.Revision > 0 && v.RevocationEpoch > 0 && !v.CreatedAt.IsZero() && !v.UpdatedAt.Before(v.CreatedAt) && d.ValidScopes(v.Scopes) && (v.Status == "ACTIVE" && d.Contains(v.Scopes, "openid") || v.Status == "REVOKED" && len(v.Scopes) == 0)
	case d.Code:
		return v.AccountRevision > 0 && doc.ID == v.Digest && oauthDigest(v.Digest) && v.ClientID != "" && v.AuthID != "" && v.GrantID != "" && v.Runtime.Client.ID == v.ClientID && v.Runtime.Client.ApplicationID != "" && v.GrantRevision > 0 && v.GrantEpoch > 0 && !v.AuthenticatedAt.IsZero() && v.ExpiresAt.After(v.AuthenticatedAt) && d.ValidScopes(v.Scopes) && d.Contains(v.Scopes, "openid") && (!v.Consumed || v.FamilyID != "")
	case d.Interaction:
		if v.Presentation != nil && (!oauthDigest(v.Presentation.ID) || !v.Presentation.Valid(v.Request.Scopes)) {
			return false
		}
		return v.ID == doc.ID && oauthDigest(v.ID) && oauthDigest(v.CSRFHash) && v.Runtime.Client.ID == v.Request.ClientID && v.Request.Channel == v.Runtime.Client.Channel && v.Request.Major == v.Runtime.Major && !v.ExpiresAt.IsZero() && (v.Status == "PENDING" || v.Status == "APPROVED" || v.Status == "DENIED") && (v.AuthID == "" && v.SessionID == "" || v.AuthID != "" && v.SessionID != "" && v.AccountRevision > 0)
	case d.Family:
		return v.AccountRevision > 0 && v.ID == doc.ID && v.ClientID != "" && v.ApplicationID != "" && v.AuthID != "" && v.GrantID != "" && d.ValidMembership(v.Channel, v.TesterID) && v.Major > 0 && v.GrantEpoch > 0 && v.ClientEpoch > 0 && !v.CreatedAt.IsZero() && v.IdleExpiresAt.After(v.CreatedAt) && !v.IdleExpiresAt.After(v.AbsoluteExpiresAt) && v.AbsoluteExpiresAt.Sub(v.CreatedAt) <= 180*24*time.Hour && d.ValidScopes(v.ScopeCeiling) && d.Contains(v.ScopeCeiling, "openid")
	case d.Access:
		return v.AccountRevision > 0 && v.ID != "" && v.AuthID != "" && v.GrantID != "" && v.GrantRevision > 0 && v.GrantEpoch > 0 && v.ClientEpoch > 0 && !v.IssuedAt.IsZero() && v.ExpiresAt.After(v.IssuedAt) && v.Runtime.Client.ID != "" && v.Digest == doc.ID && oauthDigest(v.Digest) && v.FamilyID != "" && !v.ExpiresAt.IsZero() && d.ValidScopes(v.Scopes) && d.Contains(v.Scopes, "openid") && len(v.Audiences) > 0
	case d.Refresh:
		return v.Digest == doc.ID && oauthDigest(v.Digest) && v.FamilyID != ""
	case d.Sector:
		return v.ID == doc.ID && v.ApplicationID == doc.ApplicationID && v.ApplicationID != "" && v.Hostname == doc.Host && strings.HasPrefix(v.Hostname, v.ID+".")
	case d.Subject:
		return v.AuthID != "" && v.SectorID != "" && v.ID != "" && doc.ID == v.AuthID+":"+v.SectorID
	default:
		return false
	}
}
