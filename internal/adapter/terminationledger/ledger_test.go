package terminationledger

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"iwut-auth-center/internal/accountclosure/domain"
)

func privateDirectory(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func fixture() domain.Termination {
	return domain.Termination{AuthID: "student-account", AccountRevision: 4,
		TerminatedAt: time.Date(2026, 10, 5, 12, 1, 2, 3000000, time.UTC),
		OperationID:  "99999999-9999-4999-8999-000000000001"}
}

func TestDurableIdempotentRecordSurvivesReopen(t *testing.T) {
	dir := privateDirectory(t)
	l, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	value := fixture()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := l.Store(context.Background(), value); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	records, err := reopened.Records(context.Background())
	if err != nil || len(records) != 1 || records[0] != value {
		t.Fatalf("replay = %#v, %v", records, err)
	}
	value.AccountRevision++
	if err := l.Store(context.Background(), value); err == nil {
		t.Fatal("conflicting overwrite accepted")
	}
	records, err = reopened.Records(context.Background())
	if err != nil || records[0] != fixture() {
		t.Fatalf("original record changed: %#v %v", records, err)
	}
}

func TestLedgerFailsClosedOnCorruption(t *testing.T) {
	for _, mutation := range []string{"truncated", "unknown_field", "duplicate_field", "wrong_name", "permissive", "symlink", "second_termination"} {
		t.Run(mutation, func(t *testing.T) {
			dir := privateDirectory(t)
			l, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			value := fixture()
			if err := l.Store(context.Background(), value); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, value.OperationID+".json")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "truncated":
				err = os.WriteFile(path, data[:len(data)-5], 0600)
			case "unknown_field":
				err = os.WriteFile(path, append([]byte(`{"ignored":1,`), data[1:]...), 0600)
			case "duplicate_field":
				err = os.WriteFile(path, append([]byte(`{"version":1,`), data[1:]...), 0600)
			case "wrong_name":
				err = os.Rename(path, filepath.Join(dir, "other.json"))
			case "permissive":
				err = os.Chmod(path, 0644)
			case "symlink":
				outside := filepath.Join(t.TempDir(), "record.json")
				if err = os.Rename(path, outside); err == nil {
					err = os.Symlink(outside, path)
				}
			case "second_termination":
				value.OperationID = "99999999-9999-4999-8999-000000000002"
				data, err = canonical(value)
				if err == nil {
					err = os.WriteFile(filepath.Join(dir, value.OperationID+".json"), data, 0600)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = l.Records(context.Background()); err == nil {
				t.Fatal("corrupt ledger accepted")
			}
			if _, err = Open(dir); err == nil {
				t.Fatal("corrupt ledger reopened")
			}
		})
	}
}

func TestMissingMountIsNeverCreated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing")
	if _, err := Open(path); err == nil {
		t.Fatal("missing directory accepted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("missing directory created: %v", err)
	}
	dir := privateDirectory(t)
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(alias); err == nil {
		t.Fatal("symlink directory accepted")
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("public directory accepted")
	}
}

func TestInterruptedPublishAndCancellation(t *testing.T) {
	dir := privateDirectory(t)
	l, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".pending-crashed"), []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	if entries, err := l.Records(context.Background()); err != nil || len(entries) != 0 {
		t.Fatalf("unacknowledged record replayed: %#v %v", entries, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := l.Store(ctx, fixture()); err == nil {
		t.Fatal("cancelled write accepted")
	}
	if err := l.Store(context.Background(), fixture()); err != nil {
		t.Fatal(err)
	}
	if entries, err := l.Records(context.Background()); err != nil || len(entries) != 1 {
		t.Fatalf("retry failed: %#v %v", entries, err)
	}
}
