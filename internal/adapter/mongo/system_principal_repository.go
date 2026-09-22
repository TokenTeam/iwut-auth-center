package mongo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	drivermongo "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"iwut-auth-center/internal/systemprincipal/domain"
	"iwut-auth-center/internal/systemprincipal/port"
)

type systemPrincipalDocument struct {
	AuthID        string `bson:"authId"`
	PrincipalType string `bson:"principalType"`
	SystemPurpose string `bson:"systemPurpose"`
}

type SystemPrincipalRepository struct{ collection *drivermongo.Collection }

func NewSystemPrincipalRepository(database *drivermongo.Database) (*SystemPrincipalRepository, error) {
	if database == nil {
		return nil, errors.New("system principal repository: database is required")
	}
	return &SystemPrincipalRepository{collection: database.Collection(PrincipalCollection)}, nil
}

func EnsureSystemPrincipalSchema(ctx context.Context, database *drivermongo.Database) error {
	_, err := database.Collection(PrincipalCollection).Indexes().CreateOne(ctx, drivermongo.IndexModel{
		Keys: bson.D{{Key: "systemPurpose", Value: 1}},
		Options: options.Index().SetName("system_purpose_unique").SetUnique(true).
			SetPartialFilterExpression(bson.M{"principalType": "SYSTEM"}),
	})
	if err != nil {
		return fmt.Errorf("ensure system principal purpose index: %w", err)
	}
	return nil
}

func BootstrapSystemPrincipals(ctx context.Context, database *drivermongo.Database) error {
	if database == nil {
		return errors.New("bootstrap system principals: database is required")
	}
	purpose := domain.PurposeAppCenterReviewAutoRejection
	authID, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("generate system principal auth id: %w", err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	_, err = database.Collection(PrincipalCollection).UpdateOne(
		ctx,
		bson.M{"principalType": "SYSTEM", "systemPurpose": string(purpose)},
		bson.M{"$setOnInsert": bson.M{
			"authId": authID.String(), "principalType": "SYSTEM", "developerStatus": nil,
			"systemPurpose": string(purpose), "createdAt": now, "updatedAt": now,
		}},
		options.UpdateOne().SetUpsert(true),
	)
	if drivermongo.IsDuplicateKeyError(err) {
		// Two instances may both observe a missing purpose before either upsert
		// commits. The unique purpose index chooses the winner; accepting the
		// winner after validating it keeps concurrent deployment idempotent.
		var existing systemPrincipalDocument
		findErr := database.Collection(PrincipalCollection).FindOne(ctx, bson.M{
			"principalType": "SYSTEM", "systemPurpose": string(purpose),
		}).Decode(&existing)
		if findErr == nil {
			if _, validationErr := domain.NewPrincipal(existing.AuthID, domain.Purpose(existing.SystemPurpose)); validationErr == nil {
				return nil
			}
		}
	}
	if err != nil {
		return fmt.Errorf("bootstrap system principal %q: %w", purpose, err)
	}
	return nil
}

func (repository *SystemPrincipalRepository) Resolve(ctx context.Context, purpose domain.Purpose) (domain.Principal, error) {
	if repository == nil || repository.collection == nil {
		return domain.Principal{}, port.ErrSystemPrincipalUnavailable
	}
	var document systemPrincipalDocument
	err := repository.collection.FindOne(ctx, bson.M{
		"principalType": "SYSTEM", "systemPurpose": string(purpose),
	}).Decode(&document)
	if errors.Is(err, drivermongo.ErrNoDocuments) {
		return domain.Principal{}, port.ErrSystemPrincipalNotFound
	}
	if err != nil {
		return domain.Principal{}, fmt.Errorf("%w: resolve system principal: %v", port.ErrSystemPrincipalUnavailable, err)
	}
	principal, err := domain.NewPrincipal(document.AuthID, domain.Purpose(document.SystemPurpose))
	if err != nil {
		return domain.Principal{}, fmt.Errorf("%w: invalid system principal", port.ErrSystemPrincipalUnavailable)
	}
	return principal, nil
}

var _ port.Repository = (*SystemPrincipalRepository)(nil)
