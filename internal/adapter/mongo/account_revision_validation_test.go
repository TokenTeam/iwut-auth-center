package mongo

import (
	"go.mongodb.org/mongo-driver/v2/bson"
	"testing"
	"time"
)

func TestSessionAccountRevisionRequiresExactPositiveInt64(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	good := SessionDocument{AccountRevision: 1, SessionID: "11111111-1111-4111-8111-111111111111", AuthID: "u", CredentialID: "22222222-2222-4222-8222-222222222222", AuthenticationMethod: "DEVICE_CREDENTIAL", TokenDigest: make([]byte, 32), CreatedAt: now, AuthenticatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(time.Hour)}
	data, _ := bson.Marshal(good)
	var fields bson.M
	if err := bson.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	for _, v := range []any{nil, int32(1), float64(1), "1", int64(0), int64(-1)} {
		fields["accountRevision"] = v
		data, _ = bson.Marshal(fields)
		var decoded SessionDocument
		if err := bson.Unmarshal(data, &decoded); err == nil {
			t.Fatalf("invalid revision accepted: %T %v", v, v)
		}
	}
	delete(fields, "accountRevision")
	data, _ = bson.Marshal(fields)
	var decoded SessionDocument
	if err := bson.Unmarshal(data, &decoded); err == nil {
		t.Fatal("missing revision defaulted")
	}
}
