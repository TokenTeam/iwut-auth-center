package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	d "iwut-auth-center/internal/oauth/domain"
)

type storageTestTx struct {
	userInfoTimeTx
	storage *d.StorageNamespace
}

func (tx *storageTestTx) Access(string) (d.Access, error) {
	client := d.Client{ID: "client", ApplicationID: "application", Channel: "TEST"}
	return d.Access{AccountRevision: 1, AuthID: "user", GrantID: "grant", GrantEpoch: 1, ClientEpoch: 1, Runtime: d.Runtime{Client: client, Major: 1, TesterID: "tester"}, FamilyID: "family", Scopes: []string{"openid", "storage.read", "storage.write"}, Audiences: []string{applicationUserStorageAudience}, ExpiresAt: tx.base.Add(time.Minute)}, nil
}

func (tx *storageTestTx) Grant(string) (d.Grant, error) {
	return d.Grant{ID: "grant", AuthID: "user", ApplicationID: "application", Channel: "TEST", Status: "ACTIVE", Scopes: []string{"openid", "storage.read", "storage.write"}, Revision: 1, RevocationEpoch: 1}, nil
}

func (tx *storageTestTx) Catalog() (d.Catalog, error) {
	return d.Catalog{Revision: 1, GeneratedAt: tx.base, Scopes: []d.Scope{
		{Name: "openid", Kind: "PROTOCOL", Enabled: true},
		{Name: "storage.read", Kind: "RESOURCE", Audience: applicationUserStorageAudience, Enabled: true},
		{Name: "storage.write", Kind: "RESOURCE", Audience: applicationUserStorageAudience, Enabled: true},
	}}, nil
}

func (tx *storageTestTx) ApplicationUserStorage(_, _, _ string) (d.StorageNamespace, error) {
	if tx.storage == nil {
		return d.StorageNamespace{}, d.ErrNotFound
	}
	return *tx.storage, nil
}

func (tx *storageTestTx) SaveApplicationUserStorage(expected int64, value d.StorageNamespace) error {
	current := int64(0)
	if tx.storage != nil {
		current = tx.storage.Revision
	}
	if current != expected {
		return d.ErrStorageConflict
	}
	tx.storage = &value
	return nil
}

type storageTestApp struct{ userInfoTimeApp }

func (a *storageTestApp) Runtime(_ context.Context, client d.Client, _ int32) (d.Runtime, error) {
	return d.Runtime{Client: client, Major: 1, AdminID: "user", TesterID: "tester", Required: []string{"openid"}, Optional: []string{"storage.read", "storage.write"}, ObservedAt: a.base, ValidUntil: a.base.Add(5 * time.Second)}, nil
}

func TestApplicationUserStorageCASAndNoOp(t *testing.T) {
	base := time.Date(2026, time.October, 10, 0, 0, 0, 0, time.UTC)
	tx := &storageTestTx{userInfoTimeTx: userInfoTimeTx{base: base}}
	service, err := New(userInfoTimeStore{tx: tx}, &storageTestApp{userInfoTimeApp{base: base}}, userInfoTimeCrypto{}, Config{Issuer: "https://issuer.example", SectorSuffix: "sectors.example"})
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return base }
	result, err := service.MutateApplicationUserStorage(t.Context(), "token", 0, []d.StorageMutation{{Key: "theme", Action: "PUT", Value: "dark"}})
	if err != nil || !result.Changed || result.Revision != 1 {
		t.Fatalf("first mutation = %#v, %v", result, err)
	}
	result, err = service.MutateApplicationUserStorage(t.Context(), "token", 1, []d.StorageMutation{{Key: "theme", Action: "PUT", Value: "dark"}})
	if err != nil || result.Changed || result.Revision != 1 {
		t.Fatalf("no-op mutation = %#v, %v", result, err)
	}
	if _, err = service.MutateApplicationUserStorage(t.Context(), "token", 0, []d.StorageMutation{{Key: "theme", Action: "DELETE"}}); !errors.Is(err, d.ErrStorageConflict) {
		t.Fatalf("stale mutation = %v", err)
	} else {
		var conflict d.StorageConflict
		if !errors.As(err, &conflict) || conflict.MinimumRevision != 1 {
			t.Fatalf("stale mutation metadata = %#v", err)
		}
	}
	snapshot, err := service.BatchGetApplicationUserStorage(t.Context(), "token", []string{"missing", "theme"})
	if err != nil || snapshot.Revision != 1 || len(snapshot.Entries) != 1 || snapshot.Entries[0].Value != "dark" || len(snapshot.MissingKeys) != 1 || snapshot.MissingKeys[0] != "missing" {
		t.Fatalf("snapshot = %#v, %v", snapshot, err)
	}
}

func TestApplicationUserStorageRejectsInvalidAndOversizedMutations(t *testing.T) {
	base := time.Date(2026, time.October, 10, 0, 0, 0, 0, time.UTC)
	tx := &storageTestTx{userInfoTimeTx: userInfoTimeTx{base: base}}
	service, _ := New(userInfoTimeStore{tx: tx}, &storageTestApp{userInfoTimeApp{base: base}}, userInfoTimeCrypto{}, Config{Issuer: "https://issuer.example", SectorSuffix: "sectors.example"})
	service.now = func() time.Time { return base }
	if _, err := service.MutateApplicationUserStorage(t.Context(), "token", 0, []d.StorageMutation{{Key: "bad/key", Action: "PUT", Value: "x"}}); !errors.Is(err, d.ErrRequest) {
		t.Fatalf("invalid key = %v", err)
	}
	if _, err := service.MutateApplicationUserStorage(t.Context(), "token", 0, []d.StorageMutation{{Key: "value", Action: "PUT", Value: string(make([]byte, 8*1024+1))}}); !errors.Is(err, d.ErrRequest) {
		t.Fatalf("oversized value = %v", err)
	}
}
