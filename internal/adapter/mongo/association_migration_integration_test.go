package mongo

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	"iwut-auth-center/internal/adapter/associationcrypto"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	auth "iwut-auth-center/internal/authentication/domain"
	"iwut-auth-center/internal/registration/domain"
	"iwut-auth-center/internal/registration/port"
	"iwut-auth-center/internal/registration/usecase"
)

func TestAssociationMigrationRealMongoRetryRotationsAndStartupGate(t *testing.T) {
	f := newRegistrationFixture(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	k1 := associationcrypto.Key{Version: "v1", Encrypt: bytes.Repeat([]byte{1}, 32), Lookup: bytes.Repeat([]byte{2}, 32)}
	k2 := associationcrypto.Key{Version: "v2", Encrypt: bytes.Repeat([]byte{3}, 32), Lookup: bytes.Repeat([]byte{4}, 32)}
	k3 := associationcrypto.Key{Version: "v3", Encrypt: bytes.Repeat([]byte{5}, 32), Lookup: bytes.Repeat([]byte{6}, 32)}
	c2, _ := associationcrypto.New(k2, &k1)
	c3, _ := associationcrypto.New(k3, &k2)
	repo, _ := NewAssociationMigrationRepository(f.db)
	ids := make([]string, 502)
	docs := make([]any, 502)
	for i := range ids {
		ids[i] = uuid.NewString()
		token := sha256.Sum256([]byte(fmt.Sprint(i)))
		sealed, err := f.crypto.Seal("group", ids[i], domain.AssociationScheme, token[:])
		if err != nil {
			t.Fatal(err)
		}
		docs[i] = associationDoc(domain.Association{AssociationID: ids[i], SealedAssociation: sealed})
	}
	if _, err := f.db.Collection(AssociationCollection).InsertMany(ctx, docs); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Collection(AssociationMemberCollection).InsertOne(ctx, bson.M{"authId": "preserved-account", "associationId": ids[0], "trustLevel": "CLIENT_ASSERTED"}); err != nil {
		t.Fatal(err)
	}
	challenge := beginRegistration(t, f, newSigningKey(t), bytes.Repeat([]byte{8}, 32))
	// A current-only normal restart preserves the valid pending operation.
	if err := usecase.MigrateAssociations(ctx, repo, f.crypto, now); err != nil {
		t.Fatal(err)
	}
	op, _ := f.repo.GetOperation(ctx, challenge.OperationID)
	if op.Status != auth.Pending || len(op.Ciphertext) != 48 {
		t.Fatal("normal restart destroyed live registration")
	}
	// Simulate a partially successful batch whose count check fails. The first
	// document is durable at v2 while the second remains v1.
	var first, second associationDocument
	_ = f.db.Collection(AssociationCollection).FindOne(ctx, bson.M{"associationId": ids[0]}).Decode(&first)
	_ = f.db.Collection(AssociationCollection).FindOne(ctx, bson.M{"associationId": ids[1]}).Decode(&second)
	p1, _ := f.crypto.Open("group", first.AssociationID, first.association().SealedAssociation)
	s1, _ := c2.Seal("group", first.AssociationID, domain.AssociationScheme, p1)
	p2, _ := f.crypto.Open("group", second.AssociationID, second.association().SealedAssociation)
	s2, _ := c2.Seal("group", second.AssociationID, domain.AssociationScheme, p2)
	if err := repo.WriteMigrationBatch(ctx, []port.MigrationUpdate{{Key: first.ID, SourceVersion: "v1", Target: s1}, {Key: second.ID, SourceVersion: "wrong", Target: s2}}); err == nil {
		t.Fatal("count mismatch ignored")
	}
	if err := usecase.MigrateAssociations(ctx, repo, c2, now); err != nil {
		t.Fatal(err)
	}
	op, _ = f.repo.GetOperation(ctx, challenge.OperationID)
	if op.Status != auth.Closed || len(op.Ciphertext) != 0 {
		t.Fatal("migration retained unfinished old operation")
	}
	var after associationDocument
	_ = f.db.Collection(AssociationCollection).FindOne(ctx, bson.M{"associationId": ids[0]}).Decode(&after)
	if !bytes.Equal(after.Ciphertext, s1.Ciphertext) {
		t.Fatal("rerun reencrypted already migrated group")
	}
	currentOnly, _ := associationcrypto.New(k2, nil)
	if err := usecase.MigrateAssociations(ctx, repo, currentOnly, now); err != nil {
		t.Fatal(err)
	}
	if err := usecase.MigrateAssociations(ctx, repo, c3, now); err != nil {
		t.Fatal(err)
	}
	currentThird, _ := associationcrypto.New(k3, nil)
	if err := usecase.MigrateAssociations(ctx, repo, currentThird, now); err != nil {
		t.Fatal(err)
	}
	if countDocuments(t, f.db, AssociationCollection, bson.M{"keyVersion": "v3"}) != 502 || countDocuments(t, f.db, AssociationMemberCollection, bson.M{"authId": "preserved-account", "associationId": ids[0]}) != 1 {
		t.Fatal("migration changed relations")
	}
	limiter, _ := deviceprotocol.NewLimiter(deviceprotocol.DefaultRateLimits())
	newUC, err := usecase.NewRegistration(f.repo, f.protocol, currentThird, limiter, "iwut-auth-center:test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f.uc = newUC
	reusedToken := sha256.Sum256([]byte("0"))
	newKey := newSigningKey(t)
	newChallenge := beginRegistration(t, f, newKey, reusedToken[:])
	registered, err := f.uc.Complete(ctx, newChallenge.OperationID, signChallenge(t, newKey, newChallenge))
	if err != nil {
		t.Fatal(err)
	}
	if countDocuments(t, f.db, AssociationCollection, bson.M{}) != 502 || countDocuments(t, f.db, AssociationMemberCollection, bson.M{"authId": registered.AuthID, "associationId": ids[0]}) != 1 {
		t.Fatal("current-only registration lost original group after two rotations")
	}
	// Starting with only the first key is equivalent to restoring an old ENV
	// against a newer backup. It must not silently establish new groups.
	if err := usecase.MigrateAssociations(ctx, repo, f.crypto, now); err == nil {
		t.Fatal("unknown key version accepted")
	}
}

func TestAssociationStartupRejectsCiphertextTamperingAndPreservesCompletedMarker(t *testing.T) {
	f := newRegistrationFixture(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	key := newSigningKey(t)
	c := beginRegistration(t, f, key, bytes.Repeat([]byte{9}, 32))
	if _, err := f.uc.Complete(ctx, c.OperationID, signChallenge(t, key, c)); err != nil {
		t.Fatal(err)
	}
	// Completed operations from an older binary may still contain encrypted
	// residue. Startup clears it without losing the completed marker.
	_, err := f.db.Collection(AuthenticationOperationCollection).UpdateOne(ctx, bson.M{"operationId": c.OperationID}, bson.M{"$set": bson.M{"nonce": []byte{1}, "ciphertext": []byte{2}, "lookupKey": []byte{3}}})
	if err != nil {
		t.Fatal(err)
	}
	repo, _ := NewAssociationMigrationRepository(f.db)
	if err = usecase.MigrateAssociations(ctx, repo, f.crypto, now); err != nil {
		t.Fatal(err)
	}
	op, _ := f.repo.GetOperation(ctx, c.OperationID)
	if op.Status != auth.Completed || len(op.Ciphertext) != 0 {
		t.Fatal("completed marker lost")
	}
	var group associationDocument
	_ = f.db.Collection(AssociationCollection).FindOne(ctx, bson.M{}).Decode(&group)
	group.Ciphertext[0] ^= 1
	_, err = f.db.Collection(AssociationCollection).UpdateOne(ctx, bson.M{"associationId": group.AssociationID}, bson.M{"$set": bson.M{"ciphertext": group.Ciphertext}})
	if err != nil {
		t.Fatal(err)
	}
	if err = usecase.MigrateAssociations(ctx, repo, f.crypto, now); err == nil {
		t.Fatal("damaged ciphertext accepted")
	}
	var unchanged associationDocument
	_ = f.db.Collection(AssociationCollection).FindOne(ctx, bson.M{}).Decode(&unchanged)
	if !bytes.Equal(unchanged.Ciphertext, group.Ciphertext) {
		t.Fatal("failed record overwritten")
	}
}
