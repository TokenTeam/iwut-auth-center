package domain

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestScalarAndCommandBoundaries(t *testing.T) {
	for _, v := range []Value{{Type: Boolean}, {Type: Integer}, {Type: Date, Text: "2024-02-29"}, {Type: String, Text: "  中文 "}} {
		if !v.Valid() {
			t.Fatalf("valid value rejected: %v", v)
		}
	}
	for _, v := range []Value{{Type: Date, Text: "2023-02-29"}, {Type: Date, Text: "0000-01-01"}, {Type: Date, Text: "2024-2-01"}, {Type: String}, {Type: String, Text: string([]byte{255})}, {Type: "OTHER"}, {Type: Integer, Text: "1"}} {
		if v.Valid() {
			t.Fatalf("invalid value accepted: %v", v)
		}
	}
	good := Entry{Key: "education.student_id", Value: Value{Type: String, Text: "0122256789101"}}
	for _, c := range []Command{{ExpectedRevision: 1}, {ExpectedRevision: 1, Set: []Entry{good, good}}, {ExpectedRevision: 1, Set: []Entry{good}, Remove: []string{good.Key}}, {ExpectedRevision: 1, Remove: []string{"x", "x"}}, {ExpectedRevision: 1, Remove: []string{"a.$"}}} {
		if ValidateCommand(c) != ErrInvalidEdit {
			t.Fatalf("invalid command accepted: %#v", c)
		}
	}
	if ValidateCommand(Command{Set: []Entry{good}}) != ErrInvalidRevision {
		t.Fatal("revision required")
	}
	if ValidateCommand(Command{ExpectedRevision: 1, Set: []Entry{{Key: "x", Value: Value{Type: String, Text: strings.Repeat("a", MaxCommandBytes-1)}}}}) != nil {
		t.Fatal("exact byte limit rejected")
	}
	if ValidateCommand(Command{ExpectedRevision: 1, Set: []Entry{{Key: "x", Value: Value{Type: String, Text: strings.Repeat("a", MaxCommandBytes)}}}}) != ErrLimit {
		t.Fatal("byte overflow accepted")
	}
}
func TestDefinitionsAndCodePointLength(t *testing.T) {
	maximum := int64(2)
	d := Definition{Key: "name", Label: "姓名", Description: "主动填写", ValueType: String, Constraints: &Constraints{MaxLength: &maximum}}
	if ValidateDefinitions([]Definition{d}) != nil {
		t.Fatal("valid definition rejected")
	}
	if ValidateAssignment(Entry{Key: "name", Value: Value{Type: String, Text: "小明"}}, d) != nil {
		t.Fatal("code points counted as bytes")
	}
	if ValidateAssignment(Entry{Key: "name", Value: Value{Type: String, Text: "小明啊"}}, d) != ErrInvalidValue {
		t.Fatal("max length not enforced")
	}
	if ValidateDefinitions([]Definition{d, d}) != ErrCatalog {
		t.Fatal("duplicate definition accepted")
	}
	d.Constraints = nil
	if ValidateDefinitions([]Definition{d}) != ErrCatalog {
		t.Fatal("missing constraints accepted")
	}
}
func TestSnapshotCorruption(t *testing.T) {
	s := Snapshot{Revision: 1, UpdatedAt: time.Now(), Entries: []Entry{{Key: "x", Value: Value{Type: Boolean}}}}
	if ValidateSnapshot(s) != nil {
		t.Fatal("valid false rejected")
	}
	s.Entries = append(s.Entries, s.Entries[0])
	if ValidateSnapshot(s) != ErrUnavailable {
		t.Fatal("duplicate persisted key accepted")
	}
}

func TestProductionValueConstraintsAndAcademicYear(t *testing.T) {
	minOne, maxSix := int32(1), int32(6)
	maxPhone := int64(11)
	minPhone := int64(11)
	phone := Definition{Key: "contact.phone", Label: "Phone", Description: "Self supplied", ValueType: String, Constraints: &Constraints{MinLength: &minPhone, MaxLength: &maxPhone, CharacterSet: ASCIICharacters}}
	if ValidateDefinitions([]Definition{phone}) != nil || ValidateAssignment(Entry{Key: phone.Key, Value: Value{Type: String, Text: "01234567890"}}, phone) != nil {
		t.Fatal("valid digit string rejected")
	}
	if ValidateAssignment(Entry{Key: phone.Key, Value: Value{Type: String, Text: "0123456789０"}}, phone) != ErrInvalidValue {
		t.Fatal("non-ASCII digit accepted")
	}
	set := Definition{Key: "education.campus_areas", Label: "Campus", Description: "Self supplied", ValueType: StringSet, Constraints: &Constraints{Options: []Option{{Value: "NANHU", Label: "南湖"}, {Value: "JIANHU", Label: "鉴湖"}}, MinItems: &minOne, MaxItems: &maxSix}}
	if ValidateDefinitions([]Definition{set}) != ErrCatalog {
		t.Fatal("maxItems beyond options accepted")
	}
	maxTwo := int32(2)
	set.Constraints.MaxItems = &maxTwo
	value := Value{Type: StringSet, Strings: []string{"NANHU", "JIANHU"}}
	if ValidateAssignment(Entry{Key: set.Key, Value: value}, set) != nil || !slices.Equal(Canonicalize(value).Strings, []string{"JIANHU", "NANHU"}) {
		t.Fatal("valid unordered set rejected or not canonicalized")
	}
	if ValidateAssignment(Entry{Key: set.Key, Value: Value{Type: StringSet, Strings: []string{"NANHU", "NANHU"}}}, set) != ErrInvalidValue {
		t.Fatal("duplicate set member accepted")
	}
	todayOnly := true
	birthday := Definition{Key: "personal.birthday", Label: "Birthday", Description: "Self supplied", ValueType: Date, Constraints: &Constraints{NotAfterToday: &todayOnly}}
	shanghaiBoundary := time.Date(2026, 1, 1, 16, 30, 0, 0, time.UTC)
	if ValidateAssignment(Entry{Key: birthday.Key, Value: Value{Type: Date, Text: "2026-01-03"}}, birthday, shanghaiBoundary) != ErrInvalidValue || ValidateAssignment(Entry{Key: birthday.Key, Value: Value{Type: Date, Text: "2026-01-02"}}, birthday, shanghaiBoundary) != nil {
		t.Fatal("birthday did not use Asia/Shanghai date")
	}

	confirmed := time.Date(2025, 9, 1, 0, 0, 0, 0, time.UTC)
	grade := Grade{Stage: "UNDERGRADUATE", Year: 3, FinalYear: 4, AcademicYear: 2025, ConfirmedAt: &confirmed}
	if year, err := grade.EffectiveYear(2027); err != nil || year != 4 {
		t.Fatalf("grade cap = %d, %v", year, err)
	}
	if _, err := grade.EffectiveYear(2024); err != ErrAcademicYear {
		t.Fatal("calendar before anchor accepted")
	}
}
