package usecase

import (
	"context"
	"fmt"

	"iwut-auth-center/internal/scope/domain"
	"iwut-auth-center/internal/scope/port"
)

type GetScopeCatalogSnapshotHandler struct {
	catalog port.Catalog
}

func NewGetScopeCatalogSnapshotHandler(catalog port.Catalog) *GetScopeCatalogSnapshotHandler {
	return &GetScopeCatalogSnapshotHandler{catalog: catalog}
}

func (handler *GetScopeCatalogSnapshotHandler) Handle(ctx context.Context) (domain.Snapshot, error) {
	if handler == nil || handler.catalog == nil {
		return domain.Snapshot{}, port.ErrScopeCatalogUnavailable
	}
	snapshot, err := handler.catalog.GetSnapshot(ctx)
	if err != nil {
		return domain.Snapshot{}, fmt.Errorf("get authoritative scope catalog snapshot: %w", err)
	}
	return snapshot, nil
}
