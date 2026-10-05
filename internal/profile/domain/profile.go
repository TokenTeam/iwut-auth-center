package domain

import (
	"errors"
	"regexp"
	"sort"
	"time"
	"unicode/utf8"
)

const (
	MaxOperations   = 128
	MaxFields       = 64
	MaxProfileBytes = 32768
	MaxCommandBytes = 65536
	MaxMessageBytes = 131072
)

var (
	ErrIdentity        = errors.New("INVALID_USER_IDENTITY")
	ErrInvalidRevision = errors.New("INVALID_USER_PROFILE_EXPECTED_REVISION")
	ErrInvalidEdit     = errors.New("INVALID_USER_PROFILE_EDIT")
	ErrNotDefined      = errors.New("USER_PROFILE_FIELD_NOT_DEFINED")
	ErrInvalidValue    = errors.New("INVALID_USER_PROFILE_FIELD_VALUE")
	ErrLimit           = errors.New("USER_PROFILE_LIMIT_EXCEEDED")
	ErrConflict        = errors.New("USER_PROFILE_REVISION_CONFLICT")
	ErrExhausted       = errors.New("USER_PROFILE_REVISION_EXHAUSTED")
	ErrCatalog         = errors.New("PROFILE_FIELD_CATALOG_UNAVAILABLE")
	ErrUnavailable     = errors.New("USER_PROFILE_UNAVAILABLE")
	ErrNotFound        = errors.New("USER_PRINCIPAL_NOT_FOUND")
	ErrDenied          = errors.New("USER_PROFILE_ACCESS_DENIED")
	ErrDisabled        = errors.New("USER_ACCOUNT_DISABLED")
)

type ValueType string

const (
	String  ValueType = "STRING"
	Integer ValueType = "INTEGER"
	Boolean ValueType = "BOOLEAN"
	Date    ValueType = "DATE"
)

type Value struct {
	Type    ValueType
	Text    string
	Integer int32
	Boolean bool
}
type Entry struct {
	Key   string
	Value Value
}
type Snapshot struct {
	Entries   []Entry
	Revision  int64
	UpdatedAt time.Time
}
type Principal struct {
	AuthID        string
	Type          string
	AccountStatus string
	Profile       Snapshot
}
type Command struct {
	ExpectedRevision int64
	Set              []Entry
	Remove           []string
}
type Result struct {
	Changed bool
	Profile Snapshot
}
type Constraints struct {
	MinLength *int64 `json:"minLength,omitempty"`
	MaxLength *int64 `json:"maxLength,omitempty"`
	Minimum   *int32 `json:"minimum,omitempty"`
	Maximum   *int32 `json:"maximum,omitempty"`
}
type Definition struct {
	Key         string       `json:"key"`
	Label       string       `json:"label"`
	Description string       `json:"description"`
	ValueType   ValueType    `json:"valueType"`
	Constraints *Constraints `json:"constraints"`
}

var keyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`)

func ValidKey(key string) bool { return len(key) > 0 && len(key) <= 128 && keyPattern.MatchString(key) }
func (v Value) Valid() bool {
	switch v.Type {
	case String:
		return utf8.ValidString(v.Text) && v.Text != "" && v.Integer == 0 && !v.Boolean
	case Date:
		t, e := time.Parse("2006-01-02", v.Text)
		return e == nil && len(v.Text) == 10 && t.Year() >= 1 && t.Year() <= 9999 && v.Integer == 0 && !v.Boolean
	case Integer:
		return v.Text == "" && !v.Boolean
	case Boolean:
		return v.Text == "" && v.Integer == 0
	}
	return false
}
func (v Value) Size() int {
	switch v.Type {
	case Integer:
		return 4
	case Boolean:
		return 1
	default:
		return len(v.Text)
	}
}
func Sort(entries []Entry) {
	sort.Slice(entries, func(i, j int) bool { return entries[i].Key < entries[j].Key })
}
func ValidateCommand(c Command) error {
	if c.ExpectedRevision <= 0 {
		return ErrInvalidRevision
	}
	n := len(c.Set) + len(c.Remove)
	if n == 0 {
		return ErrInvalidEdit
	}
	if n > MaxOperations {
		return ErrLimit
	}
	keys := map[string]bool{}
	size := 0
	for _, e := range c.Set {
		if !ValidKey(e.Key) || !e.Value.validShape() || keys[e.Key] {
			return ErrInvalidEdit
		}
		keys[e.Key] = true
		size += len(e.Key) + e.Value.Size()
	}
	for _, k := range c.Remove {
		if !ValidKey(k) || keys[k] {
			return ErrInvalidEdit
		}
		keys[k] = true
		size += len(k)
	}
	if size > MaxCommandBytes {
		return ErrLimit
	}
	return nil
}
func ValidateSnapshot(s Snapshot) error {
	if s.Revision <= 0 || s.UpdatedAt.IsZero() {
		return ErrUnavailable
	}
	keys := map[string]bool{}
	size := 0
	for _, e := range s.Entries {
		if !ValidKey(e.Key) || !e.Value.Valid() || keys[e.Key] {
			return ErrUnavailable
		}
		keys[e.Key] = true
		size += len(e.Key) + e.Value.Size()
	}
	if len(s.Entries) > MaxFields || size > MaxProfileBytes {
		return ErrUnavailable
	}
	return nil
}
func CheckPrincipal(p Principal) error {
	if p.Type == "SYSTEM" {
		return ErrDenied
	}
	if p.Type != "USER" {
		return ErrUnavailable
	}
	if p.AccountStatus == "DISABLED" {
		return ErrDisabled
	}
	if p.AccountStatus != "ACTIVE" {
		return ErrUnavailable
	}
	return ValidateSnapshot(p.Profile)
}
func ValidateDefinitions(defs []Definition) error {
	seen := map[string]bool{}
	for _, d := range defs {
		if !ValidKey(d.Key) || seen[d.Key] || d.Label == "" || d.Description == "" || !utf8.ValidString(d.Label) || !utf8.ValidString(d.Description) || d.Constraints == nil {
			return ErrCatalog
		}
		seen[d.Key] = true
		c := d.Constraints
		switch d.ValueType {
		case String:
			min := int64(1)
			if c.MinLength != nil {
				min = *c.MinLength
			}
			if min <= 0 || c.MaxLength == nil || *c.MaxLength < min || c.Minimum != nil || c.Maximum != nil {
				return ErrCatalog
			}
		case Integer:
			if c.MinLength != nil || c.MaxLength != nil || (c.Minimum != nil && c.Maximum != nil && *c.Minimum > *c.Maximum) {
				return ErrCatalog
			}
		case Boolean, Date:
			if c.MinLength != nil || c.MaxLength != nil || c.Minimum != nil || c.Maximum != nil {
				return ErrCatalog
			}
		default:
			return ErrCatalog
		}
	}
	return nil
}
func ValidateAssignment(e Entry, d Definition) error {
	if e.Value.Type != d.ValueType || !e.Value.Valid() {
		return ErrInvalidValue
	}
	c := d.Constraints
	switch d.ValueType {
	case String:
		n := int64(utf8.RuneCountInString(e.Value.Text))
		min := int64(1)
		if c.MinLength != nil {
			min = *c.MinLength
		}
		if n < min || n > *c.MaxLength {
			return ErrInvalidValue
		}
	case Integer:
		if (c.Minimum != nil && e.Value.Integer < *c.Minimum) || (c.Maximum != nil && e.Value.Integer > *c.Maximum) {
			return ErrInvalidValue
		}
	}
	return nil
}

func (v Value) validShape() bool {
	switch v.Type {
	case String, Date:
		return v.Integer == 0 && !v.Boolean
	case Integer:
		return v.Text == "" && !v.Boolean
	case Boolean:
		return v.Text == "" && v.Integer == 0
	}
	return false
}
