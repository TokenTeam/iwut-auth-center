package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	"iwut-auth-center/internal/scope/domain"
	"iwut-auth-center/internal/scope/port"
)

type fakeCatalog struct {
	snapshot domain.Snapshot
	err      error
	calls    int
}

func (catalog *fakeCatalog) GetSnapshot(context.Context) (domain.Snapshot, error) {
	catalog.calls++
	return catalog.snapshot, catalog.err
}

func TestGetScopeCatalogSnapshotHandler_BR_SCP_002_ReturnsAuthoritativeSnapshot(t *testing.T) {
	definition, _ := domain.NewScopeDefinition("profile.basic", true)
	want, _ := domain.NewSnapshot(3, time.Now(), []domain.ScopeDefinition{definition})
	catalog := &fakeCatalog{snapshot: want}
	handler := NewGetScopeCatalogSnapshotHandler(catalog)

	got, err := handler.Handle(t.Context())
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}
	if catalog.calls != 1 || got.Revision() != want.Revision() {
		t.Fatalf("Handle() = revision %d after %d calls", got.Revision(), catalog.calls)
	}
}

func TestGetScopeCatalogSnapshotHandler_BR_SCP_002_PropagatesUnavailable(t *testing.T) {
	cause := errors.New("dependency failed")
	handler := NewGetScopeCatalogSnapshotHandler(&fakeCatalog{err: errors.Join(port.ErrScopeCatalogUnavailable, cause)})

	_, err := handler.Handle(t.Context())
	if !errors.Is(err, port.ErrScopeCatalogUnavailable) || !errors.Is(err, cause) {
		t.Fatalf("Handle() error = %v", err)
	}

	var nilHandler *GetScopeCatalogSnapshotHandler
	if _, err := nilHandler.Handle(t.Context()); !errors.Is(err, port.ErrScopeCatalogUnavailable) {
		t.Fatalf("nil Handle() error = %v", err)
	}
}
