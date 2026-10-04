package mongo

import (
	"encoding/base64"
	"strings"
	"time"

	d "iwut-auth-center/internal/oauth/domain"
)

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
		for _, s := range v.Scopes {
			names = append(names, s.Name)
			if s.Label == "" || s.Description == "" || s.Kind != "RESOURCE" && s.Kind != "PROTOCOL" || s.Kind == "RESOURCE" && s.Audience == "" {
				return false
			}
		}
		return d.ValidScopes(names)
	case d.Grant:
		return v.ID == doc.ID && v.AuthID != "" && v.ApplicationID != "" && v.AuthID == doc.AuthID && v.ApplicationID == doc.ApplicationID && v.Channel == doc.Channel && d.ValidChannel(v.Channel) && v.Revision > 0 && v.RevocationEpoch > 0 && !v.CreatedAt.IsZero() && !v.UpdatedAt.Before(v.CreatedAt) && d.ValidScopes(v.Scopes) && (v.Status == "ACTIVE" && d.Contains(v.Scopes, "openid") || v.Status == "REVOKED" && len(v.Scopes) == 0)
	case d.Code:
		return doc.ID == v.Digest && oauthDigest(v.Digest) && v.ClientID != "" && v.AuthID != "" && v.GrantID != "" && v.Runtime.Client.ID == v.ClientID && v.Runtime.Client.ApplicationID != "" && v.GrantRevision > 0 && v.GrantEpoch > 0 && !v.AuthenticatedAt.IsZero() && v.ExpiresAt.After(v.AuthenticatedAt) && d.ValidScopes(v.Scopes) && d.Contains(v.Scopes, "openid") && (!v.Consumed || v.FamilyID != "")
	case d.Interaction:
		return v.ID == doc.ID && oauthDigest(v.ID) && oauthDigest(v.CSRFHash) && v.Runtime.Client.ID == v.Request.ClientID && v.Request.Channel == v.Runtime.Client.Channel && v.Request.Major == v.Runtime.Major && !v.ExpiresAt.IsZero() && (v.Status == "PENDING" || v.Status == "APPROVED" || v.Status == "DENIED") && (v.AuthID == "" && v.SessionID == "" || v.AuthID != "" && v.SessionID != "")
	case d.Family:
		return v.ID == doc.ID && v.ClientID != "" && v.ApplicationID != "" && v.AuthID != "" && v.GrantID != "" && d.ValidMembership(v.Channel, v.TesterID) && v.Major > 0 && v.GrantEpoch > 0 && v.ClientEpoch > 0 && !v.CreatedAt.IsZero() && v.IdleExpiresAt.After(v.CreatedAt) && !v.IdleExpiresAt.After(v.AbsoluteExpiresAt) && v.AbsoluteExpiresAt.Sub(v.CreatedAt) <= 180*24*time.Hour && d.ValidScopes(v.ScopeCeiling) && d.Contains(v.ScopeCeiling, "openid")
	case d.Access:
		return v.ID != "" && v.AuthID != "" && v.GrantID != "" && v.GrantRevision > 0 && v.GrantEpoch > 0 && v.ClientEpoch > 0 && !v.IssuedAt.IsZero() && v.ExpiresAt.After(v.IssuedAt) && v.Runtime.Client.ID != "" && v.Digest == doc.ID && oauthDigest(v.Digest) && v.FamilyID != "" && !v.ExpiresAt.IsZero() && d.ValidScopes(v.Scopes) && d.Contains(v.Scopes, "openid") && len(v.Audiences) > 0
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
