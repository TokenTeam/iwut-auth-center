package mongo

import (
	"go.mongodb.org/mongo-driver/v2/bson"
	"testing"
	"time"
)

func TestEmailSessionProvenanceFailsClosed(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	valid := SessionDocument{AccountRevision: 1, SessionID: "11111111-1111-4111-8111-111111111111", AuthID: "user", AuthenticationMethod: "EMAIL_CODE_AND_DEVICE", CredentialID: "22222222-2222-4222-8222-222222222222", TokenDigest: make([]byte, 32), EmailBindingRevision: 1, CreatedAt: now, AuthenticatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(time.Hour)}
	raw, e := bson.Marshal(valid)
	if e != nil {
		t.Fatal(e)
	}
	var roundtrip SessionDocument
	if e = bson.Unmarshal(raw, &roundtrip); e != nil || !validSession(roundtrip) {
		t.Fatal("valid provenance", e)
	}
	for _, revision := range []any{nil, int64(0), int64(-1), int32(1), float64(1), "1"} {
		var doc bson.M
		if e = bson.Unmarshal(raw, &doc); e != nil {
			t.Fatal(e)
		}
		doc["emailBindingRevision"] = revision
		data, _ := bson.Marshal(doc)
		var got SessionDocument
		if e = bson.Unmarshal(data, &got); e == nil && validSession(got) {
			t.Fatalf("bad provenance accepted: %T", revision)
		}
	}
	valid.AuthenticationMethod = "UNKNOWN"
	if validSession(valid) {
		t.Fatal("unknown method accepted")
	}
	valid.AuthenticationMethod = "DEVICE_CREDENTIAL"
	valid.EmailBindingRevision = 0
	if !validSession(valid) {
		t.Fatal("old Session requires migration")
	}
}
