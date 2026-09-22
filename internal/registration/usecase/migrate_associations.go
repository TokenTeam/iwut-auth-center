package usecase

import (
	"context"
	"errors"
	"fmt"
	"iwut-auth-center/internal/registration/port"
	"time"
)

// MigrateAssociations is the startup gate. The caller must stop the old writer
// before invoking it and must not serve traffic until it succeeds.
func MigrateAssociations(ctx context.Context, repo port.MigrationRepository, crypto port.AssociationCipher, now time.Time) error {
	if repo == nil || crypto == nil {
		return errors.New("association startup gate: missing dependency")
	}
	if err := repo.EnsureMigrationSchema(ctx); err != nil {
		return err
	}
	rotating := crypto.PreviousVersion() != ""
	if err := repo.PrepareOperations(ctx, rotating, now); err != nil {
		return err
	}
	count, err := repo.CountAssociations(ctx)
	if err != nil {
		return err
	}
	// Preflight all versions before mutating any group.
	err = repo.ScanAssociations(ctx, func(r port.MigrationRecord) error {
		v := r.Association.KeyVersion
		if v != crypto.CurrentVersion() && (!rotating || v != crypto.PreviousVersion()) {
			return errors.New("association startup gate: unknown key version")
		}
		return nil
	})
	if err != nil {
		return err
	}
	batch := make([]port.MigrationUpdate, 0, 500)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if err := repo.WriteMigrationBatch(ctx, batch); err != nil {
			return err
		}
		batch = batch[:0]
		return nil
	}
	if rotating {
		err = repo.ScanAssociations(ctx, func(r port.MigrationRecord) error {
			if r.Association.KeyVersion == crypto.CurrentVersion() {
				return nil
			}
			if r.Association.KeyVersion != crypto.PreviousVersion() {
				return errors.New("association startup gate: unknown key version")
			}
			token, err := crypto.Open("group", r.Association.AssociationID, r.Association.SealedAssociation)
			if err != nil {
				return errors.New("association startup gate: source authentication failed")
			}
			sealed, err := crypto.Seal("group", r.Association.AssociationID, r.Association.SchemeVersion, token)
			clear(token)
			if err != nil {
				return errors.New("association startup gate: target encryption failed")
			}
			batch = append(batch, port.MigrationUpdate{Key: r.Key, SourceVersion: r.Association.KeyVersion, Target: sealed})
			if len(batch) == 500 {
				return flush()
			}
			return nil
		})
		if err != nil {
			return err
		}
		if err = flush(); err != nil {
			return err
		}
	}
	var verified int64
	err = repo.ScanAssociations(ctx, func(r port.MigrationRecord) error {
		if r.Association.KeyVersion != crypto.CurrentVersion() {
			return errors.New("association startup gate: incomplete migration")
		}
		token, err := crypto.Open("group", r.Association.AssociationID, r.Association.SealedAssociation)
		clear(token)
		if err != nil {
			return errors.New("association startup gate: target authentication failed")
		}
		verified++
		return nil
	})
	if err != nil {
		return err
	}
	after, err := repo.CountAssociations(ctx)
	if err != nil {
		return err
	}
	if count != after || verified != count {
		return fmt.Errorf("association startup gate: group count changed")
	}
	if err := repo.EnsureMigrationSchema(ctx); err != nil {
		return err
	}
	return repo.ValidateOperationSnapshots(ctx, crypto, now)
}
