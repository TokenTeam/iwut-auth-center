package mongo

import (
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	d "iwut-auth-center/internal/credentialmanagement/domain"
	"testing"
	"time"
)

func TestCredentialManagementClosureCleansNamedRevokedCredentialAndOperations(t *testing.T) {
	f := newClosureFixture(t)
	if err := EnsureCredentialManagementSchema(t.Context(), f.r.database); err != nil {
		t.Fatal(err)
	}
	repo, err := NewCredentialManagementRepository(f.r, "iwut-auth-center:test")
	if err != nil {
		t.Fatal(err)
	}
	session := f.authenticationFixture.login(t)
	digest, _ := f.p.TokenDigest(session.SessionToken)
	target := secondaryCredential(t, f.authenticationFixture, f.c.AuthID)
	if _, err = repo.SetLabel(t.Context(), digest, target.c.CredentialID, "旧手机", 0, uuid.NewString(), f.clock); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.Begin(t.Context(), digest, d.Operation{OperationID: uuid.NewString(), RequestID: uuid.NewString(), Purpose: d.Purpose, ServiceID: "iwut-auth-center:test", ApplicationID: "iwut-client", TargetCredentialID: target.c.CredentialID, Challenge: bytes32(1), CreatedAt: f.clock, ExpiresAt: f.clock.Add(5 * time.Minute), RetainUntil: f.clock.Add(24 * time.Hour), Status: d.Pending}, f.clock); err != nil {
		t.Fatal(err)
	}
	if _, err = f.r.database.Collection(CredentialCollection).UpdateOne(t.Context(), bson.M{"credentialId": target.c.CredentialID}, bson.M{"$set": bson.M{"revokedAt": f.clock}}); err != nil {
		t.Fatal(err)
	}
	closureInsert(t, f, CredentialManagementOperationCollection, bson.M{"operationId": uuid.NewString(), "authId": "other-owner"})
	closureInsert(t, f, CredentialManagementAuditCollection, bson.M{"eventId": uuid.NewString(), "actorAuthId": "active", "occurredAt": f.clock})
	closureInsert(t, f, PrincipalCollection, bson.M{"authId": "active", "accountStatus": "ACTIVE"})
	p := f.ready(t)
	f.close(t, p)
	f.acknowledge(t, p.OperationID)
	f.drain(t)
	for _, col := range []string{CredentialCollection, CredentialManagementOperationCollection} {
		if closureCount(t, f, col, bson.M{"authId": f.c.AuthID}) != 0 {
			t.Fatal("closed account retained credential-management private data", col)
		}
	}
	if closureCount(t, f, CredentialManagementOperationCollection, bson.M{"authId": "other-owner"}) != 1 || closureCount(t, f, CredentialTombstoneCollection, bson.M{"fingerprint": target.c.Fingerprint}) != 1 {
		t.Fatal("cleanup crossed owner boundary or forgot revoked-key occupancy")
	}
	if err = f.repo.Retain(t.Context(), f.clock.Add(179*24*time.Hour), 500); err != nil {
		t.Fatal(err)
	}
	if closureCount(t, f, CredentialManagementAuditCollection, bson.M{"actorAuthId": f.c.AuthID}) != 1 {
		t.Fatal("audit retired before 180 days")
	}
	if err = f.repo.Retain(t.Context(), f.clock.Add(181*24*time.Hour), 500); err != nil {
		t.Fatal(err)
	}
	if closureCount(t, f, CredentialManagementAuditCollection, bson.M{"actorAuthId": f.c.AuthID}) != 0 || closureCount(t, f, CredentialManagementAuditCollection, bson.M{"actorAuthId": "active"}) != 1 {
		t.Fatal("audit retention violated closed-account boundary")
	}
}
