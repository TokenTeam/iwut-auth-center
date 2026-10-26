// Package domain owns bounded, protocol-independent Scope Catalog mutations.
package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	ErrIdentity          = errors.New("INVALID_USER_IDENTITY")
	ErrInvalid           = errors.New("INVALID_SCOPE_MANAGEMENT_REQUEST")
	ErrForbidden         = errors.New("SCOPE_MANAGEMENT_FORBIDDEN")
	ErrConflict          = errors.New("SCOPE_CATALOG_CONFLICT")
	ErrOperationConflict = errors.New("SCOPE_OPERATION_CONFLICT")
	ErrNotFound          = errors.New("SCOPE_OPERATION_NOT_FOUND")
	ErrBlocked           = errors.New("SCOPE_CHANGE_BLOCKED")
	ErrRevisionExhausted = errors.New("SCOPE_CATALOG_REVISION_EXHAUSTED")
	ErrRate              = errors.New("SCOPE_MANAGEMENT_RATE_LIMITED")
	ErrUnavailable       = errors.New("SCOPE_MANAGEMENT_UNAVAILABLE")
)

var Errors = []error{ErrIdentity, ErrInvalid, ErrForbidden, ErrConflict, ErrOperationConflict, ErrNotFound, ErrBlocked, ErrRevisionExhausted, ErrRate, ErrUnavailable}

type Definition struct {
	Name, Label, Description, Kind, Audience, ProfileField, ProfileValueType string
	Enabled                                                                  bool
}

type Snapshot struct {
	Revision    int64
	GeneratedAt time.Time
	Digest      string
	Scopes      []Definition
}

type Change struct {
	Kind, Name                 string
	Definition                 Definition
	Label, Description         string
	Enabled                    bool
	Contract, ProviderEvidence string
}

type Command struct {
	ActorAuthID, OperationID, ExpectedDigest, Reason string
	ExpectedRevision                                 int64
	Changes                                          []Change
}

type Operation struct {
	OperationID, RequestDigest, ActorAuthID, Reason, Outcome string
	BaseRevision, ResultRevision                             int64
	ResultGeneratedAt                                        time.Time
	ResultDigest                                             string
	OccurredAt                                               time.Time
}

func ValidAuthID(s string) bool { return text(s, 256) }
func text(s string, limit int) bool {
	return len(s) > 0 && len(s) <= limit && utf8.ValidString(s) && strings.TrimSpace(s) == s
}
func ValidName(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}
func ValidDigest(s string) bool {
	if len(s) != 64 || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
func ValidOperationID(s string) bool {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' || s[14] != '4' || !strings.ContainsRune("89ab", rune(s[19])) {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if c < '0' || c > '9' {
			if c < 'a' || c > 'f' {
				return false
			}
		}
	}
	return true
}

func (v Definition) Valid() bool {
	if !ValidName(v.Name) || !text(v.Label, 256) || !text(v.Description, 4096) {
		return false
	}
	protocol := v.Name == "openid" || v.Name == "email" || v.Name == "offline_access"
	if protocol != (v.Kind == "PROTOCOL") || (v.Name == "campus.whut") != (v.Kind == "USERINFO_CAMPUS") {
		return false
	}
	switch v.Kind {
	case "PROTOCOL", "USERINFO_CAMPUS":
		return v.Audience == "" && v.ProfileField == "" && v.ProfileValueType == ""
	case "RESOURCE":
		return text(v.Audience, 256) && v.ProfileField == "" && v.ProfileValueType == ""
	case "USERINFO_PROFILE":
		return v.Audience == "" && text(v.ProfileField, 128) && v.Name == "profile."+v.ProfileField && (v.ProfileValueType == "STRING" || v.ProfileValueType == "INTEGER" || v.ProfileValueType == "BOOLEAN" || v.ProfileValueType == "DATE" || v.ProfileValueType == "STRING_SET" || v.ProfileValueType == "ACADEMIC_GRADE")
	default:
		return false
	}
}

// StableEqual excludes administrator-owned text and enablement.
func (v Definition) StableEqual(other Definition) bool {
	return v.Name == other.Name && v.Kind == other.Kind && v.Audience == other.Audience && v.ProfileField == other.ProfileField && v.ProfileValueType == other.ProfileValueType
}

func CanonicalDefinitions(scopes []Definition) ([]Definition, error) {
	if len(scopes) == 0 || len(scopes) > 32 {
		return nil, ErrBlocked
	}
	out := append([]Definition(nil), scopes...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	fields := map[string]bool{}
	for i, v := range out {
		if !v.Valid() || i > 0 && out[i-1].Name == v.Name {
			return nil, ErrBlocked
		}
		if v.ProfileField != "" {
			if fields[v.ProfileField] {
				return nil, ErrBlocked
			}
			fields[v.ProfileField] = true
		}
	}
	return out, nil
}

// All definition fields are explicitly encoded, including ProfileValueType.
// Do not hash OAuth's JSON representation (its profile type is json:"-").
func Digest(scopes []Definition) (string, error) {
	canonical, err := CanonicalDefinitions(scopes)
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", ErrUnavailable
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func (c Command) Normalize() Command {
	c.Reason = strings.TrimSpace(c.Reason)
	c.Changes = append([]Change(nil), c.Changes...)
	for i := range c.Changes {
		v := &c.Changes[i]
		v.Label = strings.TrimSpace(v.Label)
		v.Description = strings.TrimSpace(v.Description)
		v.Definition.Label = strings.TrimSpace(v.Definition.Label)
		v.Definition.Description = strings.TrimSpace(v.Definition.Description)
		v.Contract = strings.TrimSpace(v.Contract)
		v.ProviderEvidence = strings.TrimSpace(v.ProviderEvidence)
	}
	return c
}

func (c Command) Valid() bool {
	if !ValidAuthID(c.ActorAuthID) || !ValidOperationID(c.OperationID) || c.ExpectedRevision < 1 || !ValidDigest(c.ExpectedDigest) || !text(c.Reason, 1024) || len(c.Changes) == 0 || len(c.Changes) > 32 {
		return false
	}
	seen := map[string]bool{}
	for _, v := range c.Changes {
		name := v.Name
		switch v.Kind {
		case "REGISTER":
			name = v.Definition.Name
			if v.Name != "" || v.Label != "" || v.Description != "" || v.Enabled || v.Definition.ProfileValueType != "" || !text(v.Contract, 4096) || !text(v.ProviderEvidence, 1024) || !text(v.Definition.Label, 256) || !text(v.Definition.Description, 4096) {
				return false
			}
		case "CORRECT_TEXT":
			if v.Definition != (Definition{}) || v.Enabled || v.Contract != "" || v.ProviderEvidence != "" || !text(v.Label, 256) || !text(v.Description, 4096) {
				return false
			}
		case "SET_ENABLED":
			if v.Definition != (Definition{}) || v.Label != "" || v.Description != "" || v.Contract != "" || v.ProviderEvidence != "" {
				return false
			}
		default:
			return false
		}
		if !ValidName(name) || seen[name] {
			return false
		}
		seen[name] = true
	}
	return true
}

func RequestDigest(c Command) (string, error) {
	if !c.Valid() {
		return "", ErrInvalid
	}
	encoded, err := json.Marshal(c)
	if err != nil {
		return "", ErrUnavailable
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func (o Operation) Valid() bool {
	return ValidOperationID(o.OperationID) && ValidDigest(o.RequestDigest) && ValidAuthID(o.ActorAuthID) && text(o.Reason, 1024) && o.BaseRevision > 0 && (o.Outcome == "NO_CHANGE" && o.ResultRevision == o.BaseRevision || o.Outcome == "APPLIED" && o.BaseRevision < math.MaxInt64 && o.ResultRevision == o.BaseRevision+1) && validInstant(o.ResultGeneratedAt) && validInstant(o.OccurredAt) && !o.OccurredAt.Before(o.ResultGeneratedAt) && ValidDigest(o.ResultDigest)
}

func validInstant(v time.Time) bool {
	return !v.IsZero() && v.Year() >= 1970 && v.Year() <= 9999 && v.Equal(v.Truncate(time.Millisecond))
}
