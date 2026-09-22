package port

import (
	"context"
	"iwut-auth-center/internal/registration/domain"
	"time"
)

type AssociationCipher interface {
	CurrentVersion() string
	PreviousVersion() string
	Seal(kind, id, scheme string, token []byte) (domain.SealedAssociation, error)
	Open(kind, id string, sealed domain.SealedAssociation) ([]byte, error)
	AssociationDigest(scheme string, token []byte) ([]byte, error)
}

// MigrationRecord uses a repository-issued stable cursor key opaque to the core.
type MigrationRecord struct {
	Key         any
	Association domain.Association
}
type MigrationUpdate struct {
	Key           any
	SourceVersion string
	Target        domain.SealedAssociation
}

type MigrationRepository interface {
	EnsureMigrationSchema(context.Context) error
	PrepareOperations(context.Context, bool, time.Time) error
	ValidateOperationSnapshots(context.Context, AssociationCipher, time.Time) error
	CountAssociations(context.Context) (int64, error)
	ScanAssociations(context.Context, func(MigrationRecord) error) error
	WriteMigrationBatch(context.Context, []MigrationUpdate) error
}
