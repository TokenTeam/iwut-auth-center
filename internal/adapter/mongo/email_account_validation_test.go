package mongo

import (
	"go.mongodb.org/mongo-driver/v2/bson"
	auth "iwut-auth-center/internal/authentication/domain"
	d "iwut-auth-center/internal/emailaccount/domain"
	p "iwut-auth-center/internal/emailaccount/port"
	"strings"
	"testing"
	"time"
)

func TestEmailAccountOperationBSONHasNoLegacyDefaults(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	o := p.Operation{OperationID: "11111111-1111-4111-8111-111111111111", RequestID: "22222222-2222-4222-8222-222222222222", Purpose: d.Add, Actor: "owner", AuthID: "owner", Email: "address@example.test", ServiceID: "iwut-auth-center:test", KeyID: strings.Repeat("a", 64), Status: auth.Pending, RequestMAC: make([]byte, 32), CodeMAC: make([]byte, 32), AccountRevision: 1, DirectoryRevision: 2, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute), ResendAfter: now.Add(time.Minute), RetainUntil: now.Add(24 * time.Hour)}
	raw, _ := bson.Marshal(emailAccountOpDoc(o))
	if _, err := decodeEmailAccountOperation(raw); err != nil {
		t.Fatal("valid ADD with no device fields", err)
	}
	var fields bson.M
	if err := bson.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"accountRevision", "directoryRevision", "failedAttempts", "resultDirectoryRevision", "resultRoleRevision"} {
		old := fields[key]
		for _, bad := range []any{nil, int32(0), "1", float64(1)} {
			fields[key] = bad
			raw, _ = bson.Marshal(fields)
			if _, err := decodeEmailAccountOperation(raw); err == nil {
				t.Fatal("coerced", key, bad)
			}
		}
		delete(fields, key)
		raw, _ = bson.Marshal(fields)
		if _, err := decodeEmailAccountOperation(raw); err == nil {
			t.Fatal("defaulted missing field", key)
		}
		fields[key] = old
	}
	for key, bad := range map[string]any{"email": "Address@example.test", "keyId": strings.Repeat("z", 64), "status": "UNKNOWN", "resendAfter": now, "resultRoleRevision": int64(1)} {
		old := fields[key]
		fields[key] = bad
		raw, _ = bson.Marshal(fields)
		if _, err := decodeEmailAccountOperation(raw); err == nil {
			t.Fatal("bad immutable context", key)
		}
		fields[key] = old
	}
}
