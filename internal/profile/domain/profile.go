package domain

import (
	"errors"
	"math"
	"regexp"
	"slices"
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
	ErrIdentity             = errors.New("INVALID_USER_IDENTITY")
	ErrInvalidRevision      = errors.New("INVALID_USER_PROFILE_EXPECTED_REVISION")
	ErrInvalidEdit          = errors.New("INVALID_USER_PROFILE_EDIT")
	ErrNotDefined           = errors.New("USER_PROFILE_FIELD_NOT_DEFINED")
	ErrInvalidValue         = errors.New("INVALID_USER_PROFILE_FIELD_VALUE")
	ErrAcademicYearConflict = errors.New("USER_PROFILE_ACADEMIC_YEAR_CONFLICT")
	ErrLimit                = errors.New("USER_PROFILE_LIMIT_EXCEEDED")
	ErrConflict             = errors.New("USER_PROFILE_REVISION_CONFLICT")
	ErrExhausted            = errors.New("USER_PROFILE_REVISION_EXHAUSTED")
	ErrCatalog              = errors.New("PROFILE_FIELD_CATALOG_UNAVAILABLE")
	ErrAcademicYear         = errors.New("ACADEMIC_YEAR_UNAVAILABLE")
	ErrUnavailable          = errors.New("USER_PROFILE_UNAVAILABLE")
	ErrNotFound             = errors.New("USER_PRINCIPAL_NOT_FOUND")
	ErrDenied               = errors.New("USER_PROFILE_ACCESS_DENIED")
	ErrDisabled             = errors.New("USER_ACCOUNT_DISABLED")
)

type ValueType string

const (
	String          ValueType = "STRING"
	Integer         ValueType = "INTEGER"
	Boolean         ValueType = "BOOLEAN"
	Date            ValueType = "DATE"
	StringSet       ValueType = "STRING_SET"
	AcademicGrade   ValueType = "ACADEMIC_GRADE"
	ASCIICharacters           = "ASCII_DIGITS"
)

type Grade struct {
	Stage        string     `bson:"stage"`
	Year         int32      `bson:"year"`
	FinalYear    int32      `bson:"finalYear"`
	AcademicYear int32      `bson:"academicYear"`
	ConfirmedAt  *time.Time `bson:"confirmedAt"`
}

func (g Grade) valid(requireConfirmation bool) bool {
	if g.Stage != "UNDERGRADUATE" && g.Stage != "MASTER" && g.Stage != "DOCTORAL" {
		return false
	}
	if g.Year <= 0 || g.FinalYear <= 0 || g.Year > g.FinalYear || g.AcademicYear <= 0 {
		return false
	}
	return !requireConfirmation || g.ConfirmedAt != nil && !g.ConfirmedAt.IsZero() && g.ConfirmedAt.Year() >= 1 && g.ConfirmedAt.Year() <= 9999
}

func (g Grade) EffectiveYear(current int32) (int32, error) {
	if !g.valid(true) || current < g.AcademicYear {
		return 0, ErrAcademicYear
	}
	effective := int64(g.Year) + int64(current) - int64(g.AcademicYear)
	if effective > math.MaxInt32 {
		return 0, ErrAcademicYear
	}
	if effective > int64(g.FinalYear) {
		effective = int64(g.FinalYear)
	}
	return int32(effective), nil
}

type Value struct {
	Type     ValueType
	Text     string
	Integer  int32
	Boolean  bool
	Strings  []string
	Academic *Grade
}

func (v Value) Equal(other Value) bool {
	if v.Type != other.Type || v.Text != other.Text || v.Integer != other.Integer || v.Boolean != other.Boolean || !slices.Equal(v.Strings, other.Strings) {
		return false
	}
	if v.Academic == nil || other.Academic == nil {
		return v.Academic == nil && other.Academic == nil
	}
	a, b := *v.Academic, *other.Academic
	if a.Stage != b.Stage || a.Year != b.Year || a.FinalYear != b.FinalYear || a.AcademicYear != b.AcademicYear {
		return false
	}
	if a.ConfirmedAt == nil || b.ConfirmedAt == nil {
		return a.ConfirmedAt == nil && b.ConfirmedAt == nil
	}
	return a.ConfirmedAt.Equal(*b.ConfirmedAt)
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
	AuthID, Type, AccountStatus string
	Profile                     Snapshot
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
type Option struct {
	Value string `json:"value"`
	Label string `json:"label"`
}
type Constraints struct {
	MinLength     *int64   `json:"minLength,omitempty"`
	MaxLength     *int64   `json:"maxLength,omitempty"`
	Minimum       *int32   `json:"minimum,omitempty"`
	Maximum       *int32   `json:"maximum,omitempty"`
	CharacterSet  string   `json:"characterSet,omitempty"`
	Options       []Option `json:"options,omitempty"`
	MinItems      *int32   `json:"minItems,omitempty"`
	MaxItems      *int32   `json:"maxItems,omitempty"`
	NotAfterToday *bool    `json:"notAfterToday,omitempty"`
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
	if !v.validShape() {
		return false
	}
	switch v.Type {
	case String:
		return utf8.ValidString(v.Text) && v.Text != ""
	case Date:
		t, e := time.Parse("2006-01-02", v.Text)
		return e == nil && len(v.Text) == 10 && t.Year() >= 1 && t.Year() <= 9999
	case Integer, Boolean:
		return true
	case StringSet:
		if len(v.Strings) == 0 {
			return false
		}
		for i, item := range v.Strings {
			if item == "" || !utf8.ValidString(item) || i > 0 && v.Strings[i-1] >= item {
				return false
			}
		}
		return true
	case AcademicGrade:
		return v.Academic != nil && v.Academic.valid(true)
	}
	return false
}
func (v Value) Size() int {
	switch v.Type {
	case Integer:
		return 4
	case Boolean:
		return 1
	case StringSet:
		n := 0
		for _, item := range v.Strings {
			n += len(item)
		}
		return n
	case AcademicGrade:
		if v.Academic == nil {
			return 0
		}
		return len(v.Academic.Stage) + 12
	default:
		return len(v.Text)
	}
}
func Sort(entries []Entry) {
	sort.Slice(entries, func(i, j int) bool { return entries[i].Key < entries[j].Key })
}
func Canonicalize(v Value) Value {
	if v.Type == StringSet {
		v.Strings = append([]string(nil), v.Strings...)
		sort.Strings(v.Strings)
	}
	return v
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
	for index, e := range s.Entries {
		if !ValidKey(e.Key) || !e.Value.Valid() || keys[e.Key] {
			return ErrUnavailable
		}
		if index > 0 && s.Entries[index-1].Key >= e.Key {
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

func validOptions(options []Option) bool {
	seen := map[string]bool{}
	for _, option := range options {
		ascii := option.Value != ""
		for _, character := range []byte(option.Value) {
			ascii = ascii && character <= 0x7f
		}
		if !ascii || option.Label == "" || !utf8.ValidString(option.Label) || seen[option.Value] {
			return false
		}
		seen[option.Value] = true
	}
	return true
}
func scalarOnly(c *Constraints) bool {
	return c.CharacterSet == "" && len(c.Options) == 0 && c.MinItems == nil && c.MaxItems == nil && c.NotAfterToday == nil
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
			if min <= 0 || c.MaxLength == nil || *c.MaxLength < min || c.Minimum != nil || c.Maximum != nil || c.MinItems != nil || c.MaxItems != nil || c.NotAfterToday != nil || c.CharacterSet != "" && c.CharacterSet != ASCIICharacters || !validOptions(c.Options) {
				return ErrCatalog
			}
		case Integer:
			if !scalarOnly(c) || c.MinLength != nil || c.MaxLength != nil || c.Minimum != nil && c.Maximum != nil && *c.Minimum > *c.Maximum {
				return ErrCatalog
			}
		case Boolean:
			if !scalarOnly(c) || c.MinLength != nil || c.MaxLength != nil || c.Minimum != nil || c.Maximum != nil {
				return ErrCatalog
			}
		case Date:
			if c.MinLength != nil || c.MaxLength != nil || c.Minimum != nil || c.Maximum != nil || c.CharacterSet != "" || len(c.Options) != 0 || c.MinItems != nil || c.MaxItems != nil || c.NotAfterToday != nil && !*c.NotAfterToday {
				return ErrCatalog
			}
		case StringSet:
			if c.MinLength != nil || c.MaxLength != nil || c.Minimum != nil || c.Maximum != nil || c.CharacterSet != "" || c.NotAfterToday != nil || len(c.Options) == 0 || !validOptions(c.Options) || c.MinItems == nil || c.MaxItems == nil || *c.MinItems < 1 || *c.MinItems > *c.MaxItems || int(*c.MaxItems) > len(c.Options) {
				return ErrCatalog
			}
		case AcademicGrade:
			if !scalarOnly(c) || c.MinLength != nil || c.MaxLength != nil || c.Minimum != nil || c.Maximum != nil {
				return ErrCatalog
			}
		default:
			return ErrCatalog
		}
	}
	return nil
}

func ValidateAssignment(e Entry, d Definition, times ...time.Time) error {
	now := time.Now()
	if len(times) > 0 {
		now = times[0]
	}
	if e.Value.Type != d.ValueType || !e.Value.validShape() {
		return ErrInvalidValue
	}
	c := d.Constraints
	switch d.ValueType {
	case String:
		if !utf8.ValidString(e.Value.Text) || e.Value.Text == "" {
			return ErrInvalidValue
		}
		n := int64(utf8.RuneCountInString(e.Value.Text))
		min := int64(1)
		if c.MinLength != nil {
			min = *c.MinLength
		}
		if n < min || n > *c.MaxLength {
			return ErrInvalidValue
		}
		if c.CharacterSet == ASCIICharacters {
			for _, char := range []byte(e.Value.Text) {
				if char < '0' || char > '9' {
					return ErrInvalidValue
				}
			}
		}
		if len(c.Options) > 0 {
			found := false
			for _, option := range c.Options {
				found = found || option.Value == e.Value.Text
			}
			if !found {
				return ErrInvalidValue
			}
		}
	case Integer:
		if c.Minimum != nil && e.Value.Integer < *c.Minimum || c.Maximum != nil && e.Value.Integer > *c.Maximum {
			return ErrInvalidValue
		}
	case Date:
		if !e.Value.Valid() {
			return ErrInvalidValue
		}
		if c.NotAfterToday != nil && *c.NotAfterToday {
			location, err := time.LoadLocation("Asia/Shanghai")
			if err != nil {
				return ErrInvalidValue
			}
			if e.Value.Text > now.In(location).Format("2006-01-02") {
				return ErrInvalidValue
			}
		}
	case StringSet:
		if len(e.Value.Strings) < int(*c.MinItems) || len(e.Value.Strings) > int(*c.MaxItems) {
			return ErrInvalidValue
		}
		seen := map[string]bool{}
		allowed := map[string]bool{}
		for _, option := range c.Options {
			allowed[option.Value] = true
		}
		for _, item := range e.Value.Strings {
			if item == "" || seen[item] || !allowed[item] {
				return ErrInvalidValue
			}
			seen[item] = true
		}
	case AcademicGrade:
		if e.Value.Academic == nil || !e.Value.Academic.valid(false) || e.Value.Academic.ConfirmedAt != nil {
			return ErrInvalidValue
		}
	case Boolean:
	default:
		return ErrInvalidValue
	}
	return nil
}

func (v Value) validShape() bool {
	switch v.Type {
	case String, Date:
		return v.Integer == 0 && !v.Boolean && len(v.Strings) == 0 && v.Academic == nil
	case Integer:
		return v.Text == "" && !v.Boolean && len(v.Strings) == 0 && v.Academic == nil
	case Boolean:
		return v.Text == "" && v.Integer == 0 && len(v.Strings) == 0 && v.Academic == nil
	case StringSet:
		return v.Text == "" && v.Integer == 0 && !v.Boolean && v.Academic == nil
	case AcademicGrade:
		return v.Text == "" && v.Integer == 0 && !v.Boolean && len(v.Strings) == 0 && v.Academic != nil
	}
	return false
}
