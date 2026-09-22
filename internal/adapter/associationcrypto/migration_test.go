package associationcrypto

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"iwut-auth-center/internal/registration/domain"
	"iwut-auth-center/internal/registration/port"
	"iwut-auth-center/internal/registration/usecase"
)

type memoryMigration struct {
	records   []port.MigrationRecord
	batches   []int
	failAfter int
	written   int
	prepared  []bool
	validated bool
}

func (r *memoryMigration) EnsureMigrationSchema(context.Context) error { return nil }
func (r *memoryMigration) PrepareOperations(_ context.Context, rotate bool, _ time.Time) error {
	r.prepared = append(r.prepared, rotate)
	return nil
}
func (r *memoryMigration) ValidateOperationSnapshots(context.Context, port.AssociationCipher, time.Time) error {
	r.validated = true
	return nil
}
func (r *memoryMigration) CountAssociations(context.Context) (int64, error) {
	return int64(len(r.records)), nil
}
func (r *memoryMigration) ScanAssociations(_ context.Context, visit func(port.MigrationRecord) error) error {
	for _, x := range r.records {
		if err := visit(x); err != nil {
			return err
		}
	}
	return nil
}
func (r *memoryMigration) WriteMigrationBatch(_ context.Context, updates []port.MigrationUpdate) error {
	r.batches = append(r.batches, len(updates))
	for _, u := range updates {
		if r.failAfter > 0 && r.written == r.failAfter {
			return errors.New("partial ordered batch failure")
		}
		i := u.Key.(int)
		if r.records[i].Association.KeyVersion != u.SourceVersion {
			return errors.New("matched count mismatch")
		}
		r.records[i].Association.SealedAssociation = u.Target
		r.written++
	}
	return nil
}

func fixtureKey(version string, b byte) Key {
	return Key{version, bytes.Repeat([]byte{b}, 32), bytes.Repeat([]byte{b + 1}, 32)}
}
func TestMigrationPartialBatchRetryAndTwoRotations(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	old := fixtureKey("k1", 1)
	next := fixtureKey("k2", 3)
	third := fixtureKey("k3", 5)
	c1, _ := New(old, nil)
	c2, _ := New(next, &old)
	c3, _ := New(third, &next)
	r := &memoryMigration{failAfter: 537}
	for i := 0; i < 1001; i++ {
		id := uuid.NewString()
		token := bytes.Repeat([]byte{byte(i % 251)}, 32)
		sealed, err := c1.Seal("group", id, domain.AssociationScheme, token)
		if err != nil {
			t.Fatal(err)
		}
		r.records = append(r.records, port.MigrationRecord{Key: i, Association: domain.Association{AssociationID: id, SealedAssociation: sealed}})
	}
	ids := make([]string, len(r.records))
	for i, v := range r.records {
		ids[i] = v.Association.AssociationID
	}
	if err := usecase.MigrateAssociations(ctx, r, c2, now); err == nil || r.validated {
		t.Fatal("partial migration opened readiness")
	}
	if r.written != 537 {
		t.Fatal("wrong partial point", r.written)
	}
	firstCipher := append([]byte(nil), r.records[0].Association.Ciphertext...)
	r.failAfter = 0
	if err := usecase.MigrateAssociations(ctx, r, c2, now); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstCipher, r.records[0].Association.Ciphertext) {
		t.Fatal("already migrated group reencrypted")
	}
	if r.batches[len(r.batches)-1] != 464 {
		t.Fatal("tail not flushed", r.batches)
	}
	currentOnly, _ := New(next, nil)
	if err := usecase.MigrateAssociations(ctx, r, currentOnly, now); err != nil {
		t.Fatal(err)
	}
	if r.prepared[len(r.prepared)-1] {
		t.Fatal("ordinary startup invalidated live challenges")
	}
	if err := usecase.MigrateAssociations(ctx, r, c3, now); err != nil {
		t.Fatal(err)
	}
	thirdOnly, _ := New(third, nil)
	if err := usecase.MigrateAssociations(ctx, r, thirdOnly, now); err != nil {
		t.Fatal(err)
	}
	for i, v := range r.records {
		if v.Association.AssociationID != ids[i] || v.Association.KeyVersion != "k3" {
			t.Fatal("identity changed")
		}
	}
	for _, n := range r.batches {
		if n < 1 || n > 500 {
			t.Fatal("oversized batch")
		}
	}
}

func TestMigrationFailsClosedForUnknownOrDamagedRecords(t *testing.T) {
	old := fixtureKey("k1", 1)
	next := fixtureKey("k2", 3)
	writer, _ := New(old, nil)
	target, _ := New(next, &old)
	for _, what := range []string{"unknown", "damaged-source", "wrong-lookup", "current-only-old", "damaged-target"} {
		t.Run(what, func(t *testing.T) {
			id := uuid.NewString()
			sealed, _ := writer.Seal("group", id, domain.AssociationScheme, bytes.Repeat([]byte{9}, 32))
			c := target
			switch what {
			case "unknown":
				sealed.KeyVersion = "k0"
			case "damaged-source":
				sealed.Ciphertext[0] ^= 1
			case "wrong-lookup":
				sealed.LookupKey[0] ^= 1
			case "current-only-old":
				c, _ = New(next, nil)
			case "damaged-target":
				sealed, _ = target.Seal("group", id, domain.AssociationScheme, bytes.Repeat([]byte{9}, 32))
				sealed.Ciphertext[0] ^= 1
			}
			r := &memoryMigration{records: []port.MigrationRecord{{Key: 0, Association: domain.Association{AssociationID: id, SealedAssociation: sealed}}}}
			before := append([]byte(nil), sealed.Ciphertext...)
			if err := usecase.MigrateAssociations(context.Background(), r, c, time.Now()); err == nil {
				t.Fatal("damaged data accepted")
			}
			if r.validated || r.written != 0 || !bytes.Equal(before, r.records[0].Association.Ciphertext) {
				t.Fatal("failed record overwritten or readiness opened")
			}
		})
	}
}
