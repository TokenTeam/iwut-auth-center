package mongo

import (
	"go.mongodb.org/mongo-driver/v2/bson"
	"iwut-auth-center/internal/password/domain"
	"testing"
	"time"
)

func TestPasswordDocumentStrictTypesAndBounds(t *testing.T) {
	record := domain.Record{AuthID: "owner", Revision: 1, ChangedAt: time.Now().UTC().Truncate(time.Millisecond), Material: domain.Material{Algorithm: domain.Algorithm, FormatVersion: 1, NormalizationVersion: domain.NormalizationVersion, Parameters: domain.DefaultParameters(), Salt: make([]byte, 16), Hash: make([]byte, 32)}}
	data, _ := bson.Marshal(passwordDoc(record))
	if _, err := decodePassword(data); err != nil {
		t.Fatal(err)
	}
	var fields bson.M
	_ = bson.Unmarshal(data, &fields)
	for _, key := range []string{"passwordRevision", "formatVersion", "memoryKiB", "iterations", "parallelism"} {
		original := fields[key]
		for _, v := range []any{nil, int32(1), float64(1), "1", int64(0), int64(-1)} {
			fields[key] = v
			bad, _ := bson.Marshal(fields)
			if _, err := decodePassword(bad); err == nil {
				t.Fatalf("invalid %s accepted", key)
			}
		}
		delete(fields, key)
		bad, _ := bson.Marshal(fields)
		if _, err := decodePassword(bad); err == nil {
			t.Fatal("missing field defaulted")
		}
		fields[key] = original
	}
}

func TestPasswordSessionSourcesAndCredentialRevision(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	s := SessionDocument{AccountRevision: 2, SessionID: "11111111-1111-4111-8111-111111111111", CredentialID: "22222222-2222-4222-8222-222222222222", AuthID: "u", AuthenticationMethod: domain.PasswordAndSession, SourceSessionID: "33333333-3333-4333-8333-333333333333", PasswordRevision: 2, TokenDigest: make([]byte, 32), CreatedAt: now, AuthenticatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(time.Hour)}
	if !validSession(s) {
		t.Fatal("password Session rejected")
	}
	for _, mutate := range []func(*SessionDocument){func(s *SessionDocument) { s.SourceSessionID = s.SessionID }, func(s *SessionDocument) { s.SourceSessionID = "" }, func(s *SessionDocument) { s.PasswordRevision = 0 }, func(s *SessionDocument) { s.AuthenticationMethod = "UNKNOWN" }, func(s *SessionDocument) { s.EmailBindingRevision = 1 }} {
		bad := s
		mutate(&bad)
		if validSession(bad) {
			t.Fatal("invalid provenance accepted")
		}
	}
	s.AuthenticationMethod = domain.PasswordAndDevice
	s.SourceSessionID = ""
	if !validSession(s) {
		t.Fatal("password device Session rejected")
	}
	data, _ := bson.Marshal(s)
	var fields bson.M
	_ = bson.Unmarshal(data, &fields)
	fields["passwordRevision"] = int32(2)
	data, _ = bson.Marshal(fields)
	var parsed SessionDocument
	if bson.Unmarshal(data, &parsed) == nil {
		t.Fatal("coerced password provenance")
	}
	for _, v := range []any{nil, int32(1), float64(1), "1", int64(0), int64(-1)} {
		data, _ := bson.Marshal(bson.M{"credentialRevision": v})
		var c CredentialDocument
		if bson.Unmarshal(data, &c) == nil {
			t.Fatal("bad credential revision accepted")
		}
	}
}
