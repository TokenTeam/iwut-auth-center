package catalog

import (
	"context"
	"time"

	"iwut-auth-center/internal/scope/domain"
)

const HardcodedRevision int64 = 1

var HardcodedGeneratedAt = time.Date(2026, time.September, 21, 0, 0, 0, 0, time.UTC)

// HardcodedCatalog is a temporary development and E2E provider. It is not the
// production authority required by BR-SCP-001 and must be replaced by a
// persistent Auth-owned adapter before the UC can be marked complete.
type HardcodedCatalog struct {
	snapshot domain.Snapshot
}

func NewHardcodedCatalog() (*HardcodedCatalog, error) {
	profile, err := domain.NewScopeDefinition("profile.basic", true)
	if err != nil {
		return nil, err
	}
	schedule, err := domain.NewScopeDefinition("schedule.read", true)
	if err != nil {
		return nil, err
	}
	legacy, err := domain.NewScopeDefinition("legacy.profile", false)
	if err != nil {
		return nil, err
	}
	snapshot, err := domain.NewSnapshot(
		HardcodedRevision,
		HardcodedGeneratedAt,
		[]domain.ScopeDefinition{schedule, legacy, profile},
	)
	if err != nil {
		return nil, err
	}
	return &HardcodedCatalog{snapshot: snapshot}, nil
}

func (catalog *HardcodedCatalog) GetSnapshot(ctx context.Context) (domain.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return domain.Snapshot{}, err
	}
	return catalog.snapshot, nil
}
