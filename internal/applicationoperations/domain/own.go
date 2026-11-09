package domain

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// OwnState is an observation, not an authorization credential. It intentionally
// omits management membership, grant blockers and all unpublished permissions.
type OwnState struct {
	AuthID               string
	Revision             int64
	EffectivePermissions []string
}

func ProjectOwn(authID string, revision int64, permissions []string) (OwnState, error) {
	if !ValidID(authID) || revision <= 0 || permissions == nil {
		return OwnState{}, ErrUnavailable
	}
	seen := make(map[string]bool, len(permissions))
	for _, permission := range permissions {
		if permission == "" || !utf8.ValidString(permission) || strings.ContainsRune(permission, '*') || strings.ContainsFunc(permission, unicode.IsSpace) || seen[permission] {
			return OwnState{}, ErrUnavailable
		}
		seen[permission] = true
	}
	out := OwnState{AuthID: authID, Revision: revision, EffectivePermissions: []string{}}
	for _, permission := range Permissions() {
		if seen[permission] {
			out.EffectivePermissions = append(out.EffectivePermissions, permission)
		}
	}
	return out, nil
}
