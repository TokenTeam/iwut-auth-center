package terminationledger

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	d "iwut-auth-center/internal/accountclosure/domain"
	p "iwut-auth-center/internal/accountclosure/port"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

// This snapshot deliberately contains keys and a handle absent from an older
// business backup: startup consumers receive all original namespace occupancy.
func reservationsFixture(t d.Termination) d.NamespaceReservations {
	oldKey, newKey := sha256.Sum256([]byte("old-key")), sha256.Sum256([]byte("new-key-after-backup"))
	return d.NamespaceReservations{AuthID: t.AuthID, OperationID: t.OperationID, Fingerprints: [][]byte{oldKey[:], newKey[:]}, Handle: &d.HandleReservation{DeveloperHandle: "handle_after_backup", ClaimedAt: t.TerminatedAt.Add(-time.Hour)}}
}
func storeReservation(t *testing.T, l *Ledger, value d.Termination) {
	t.Helper()
	if err := l.StoreReservations(t.Context(), reservationsFixture(value)); err != nil {
		t.Fatal(err)
	}
}
func TestNamespacesDurableBeforeTerminationAndSurviveOlderBackup(t *testing.T) {
	ctx := t.Context()
	dir := privateDirectory(t)
	l, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	fact := fixture()
	if err = l.Store(ctx, fact); !errors.Is(err, p.ErrReservationsNotFound) {
		t.Fatalf("fact without namespaces: %v", err)
	}
	want := reservationsFixture(fact)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := l.StoreReservations(ctx, want); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	// A crash between the two durable publications is a valid unacknowledged state.
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if records, err := reopened.Records(ctx); err != nil || len(records) != 0 {
		t.Fatalf("reservation became termination: %v %v", records, err)
	}
	if err = reopened.Store(ctx, fact); err != nil {
		t.Fatal(err)
	}
	newer, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := newer.Reservations(ctx, fact.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	expected, _ := canonicalReservations(want)
	actual, _ := canonicalReservations(got)
	if !bytes.Equal(actual, expected) || len(got.Fingerprints) != 2 || got.Handle.DeveloperHandle != "handle_after_backup" {
		t.Fatalf("restore lost occupancy: %#v", got)
	}
	// Capturing the old backup's subset cannot overwrite the durable full snapshot.
	oldBackup := want
	oldBackup.Fingerprints = want.Fingerprints[:1]
	oldBackup.Handle = nil
	if err = newer.StoreReservations(ctx, oldBackup); err == nil {
		t.Fatal("old backup overwrote namespace occupancy")
	}
	again, err := newer.Reservations(ctx, fact.OperationID)
	if err != nil || !reflect.DeepEqual(got, again) {
		t.Fatalf("snapshot changed: %v", err)
	}
}
func TestNamespaceCanonicalSortingDeduplicationAndInvalidInput(t *testing.T) {
	l, err := Open(privateDirectory(t))
	if err != nil {
		t.Fatal(err)
	}
	value := reservationsFixture(fixture())
	canonical := value
	value.Fingerprints = [][]byte{value.Fingerprints[1], value.Fingerprints[0], value.Fingerprints[1]}
	if err = l.StoreReservations(t.Context(), value); err != nil {
		t.Fatal(err)
	}
	if err = l.StoreReservations(t.Context(), canonical); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"short_key", "upper_handle", "bad_handle", "zero_claim", "bad_id", "bad_auth"} {
		t.Run(mutation, func(t *testing.T) {
			v := reservationsFixture(fixture())
			switch mutation {
			case "short_key":
				v.Fingerprints = [][]byte{{1}}
			case "upper_handle":
				v.Handle.DeveloperHandle = "Upper"
			case "bad_handle":
				v.Handle.DeveloperHandle = "has.dots"
			case "zero_claim":
				v.Handle.ClaimedAt = time.Time{}
			case "bad_id":
				v.OperationID = "../fact"
			case "bad_auth":
				v.AuthID = " bad "
			}
			if err := l.StoreReservations(t.Context(), v); err == nil {
				t.Fatal("invalid namespace accepted")
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := l.StoreReservations(ctx, canonical); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
func TestNamespaceCorruptionFailsClosedAtReadStoreAndStartup(t *testing.T) {
	for _, mutation := range []string{"missing", "truncated", "unknown", "duplicate", "unsorted", "duplicate_key", "wrong_auth", "wrong_name", "permissive", "symlink", "future_claim"} {
		t.Run(mutation, func(t *testing.T) {
			dir := privateDirectory(t)
			l, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			fact := fixture()
			storeReservation(t, l, fact)
			if err = l.Store(t.Context(), fact); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, fact.OperationID+reservationsSuffix)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "missing":
				err = os.Remove(path)
			case "truncated":
				err = os.WriteFile(path, data[:len(data)-3], 0600)
			case "unknown":
				err = os.WriteFile(path, append([]byte(`{"extra":1,`), data[1:]...), 0600)
			case "duplicate":
				err = os.WriteFile(path, append([]byte(`{"version":1,`), data[1:]...), 0600)
			case "unsorted", "duplicate_key":
				var record reservationsRecord
				if err = json.Unmarshal(data, &record); err != nil {
					t.Fatal(err)
				}
				if mutation == "unsorted" {
					record.Fingerprints[0], record.Fingerprints[1] = record.Fingerprints[1], record.Fingerprints[0]
				} else {
					record.Fingerprints = append(record.Fingerprints, record.Fingerprints[0])
				}
				data, err = json.Marshal(record)
				if err == nil {
					err = os.WriteFile(path, append(data, '\n'), 0600)
				}
			case "wrong_auth":
				v := reservationsFixture(fact)
				v.AuthID = "other"
				data, err = canonicalReservations(v)
				if err == nil {
					err = os.WriteFile(path, data, 0600)
				}
			case "wrong_name":
				err = os.Rename(path, filepath.Join(dir, "wrong"+reservationsSuffix))
			case "permissive":
				err = os.Chmod(path, 0644)
			case "symlink":
				outside := filepath.Join(t.TempDir(), "record")
				if err = os.Rename(path, outside); err == nil {
					err = os.Symlink(outside, path)
				}
			case "future_claim":
				v := reservationsFixture(fact)
				v.Handle.ClaimedAt = fact.TerminatedAt.Add(time.Hour)
				data, err = canonicalReservations(v)
				if err == nil {
					err = os.WriteFile(path, data, 0600)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = l.Store(t.Context(), fact); err == nil {
				t.Fatal("termination acknowledged corrupt namespace")
			}
			if _, err = l.Records(t.Context()); err == nil {
				t.Fatal("corrupt namespace replay accepted")
			}
			if _, err = Open(dir); err == nil {
				t.Fatal("corrupt namespace startup accepted")
			}
		})
	}
}

func TestConflictingPermanentNamespacesFailStartup(t *testing.T) {
	for _, collision := range []string{"fingerprint", "handle"} {
		t.Run(collision, func(t *testing.T) {
			dir := privateDirectory(t)
			l, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			fact := fixture()
			storeReservation(t, l, fact)
			if err = l.Store(t.Context(), fact); err != nil {
				t.Fatal(err)
			}
			other := fact
			other.AuthID = "other-account"
			other.OperationID = "99999999-9999-4999-8999-000000000002"
			reservation := reservationsFixture(other)
			if collision == "fingerprint" {
				reservation.Handle = nil
			} else {
				key := sha256.Sum256([]byte("other-key"))
				reservation.Fingerprints = [][]byte{key[:]}
			}
			// Simulates individually well-formed files from inconsistent storage: neither
			// ordinary Mongo namespace transaction can create this duplicate ownership.
			if err = l.StoreReservations(t.Context(), reservation); err != nil {
				t.Fatal(err)
			}
			if err = l.Store(t.Context(), other); err != nil {
				t.Fatal(err)
			}
			if _, err = Open(dir); err == nil {
				t.Fatal("conflicting permanent namespace accepted")
			}
		})
	}
}
