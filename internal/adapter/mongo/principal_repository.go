package mongo

import (
	"context"
	"errors"
	"fmt"

	"go.mongodb.org/mongo-driver/v2/bson"
	drivermongo "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"iwut-auth-center/internal/developer/domain"
	"iwut-auth-center/internal/developer/port"
)

const PrincipalCollection = "auth_principals"

type principalDocument struct {
	AccountStatus   string  `bson:"accountStatus"`
	AuthID          string  `bson:"authId"`
	PrincipalType   string  `bson:"principalType"`
	DeveloperStatus *string `bson:"developerStatus"`
}

type PrincipalRepository struct {
	collection *drivermongo.Collection
}

func NewPrincipalRepository(database *drivermongo.Database) (*PrincipalRepository, error) {
	if database == nil {
		return nil, errors.New("principal repository: database is required")
	}
	return &PrincipalRepository{collection: database.Collection(PrincipalCollection)}, nil
}

func EnsurePrincipalSchema(ctx context.Context, database *drivermongo.Database) error {
	if database == nil {
		return errors.New("principal schema: database is required")
	}
	_, err := database.Collection(PrincipalCollection).Indexes().CreateOne(ctx, drivermongo.IndexModel{
		Keys: bson.D{{Key: "authId", Value: 1}},
		Options: options.Index().
			SetName("auth_id_unique").
			SetUnique(true),
	})
	if err != nil {
		return fmt.Errorf("ensure principal authId index: %w", err)
	}
	return nil
}

func (repository *PrincipalRepository) BatchGet(
	ctx context.Context,
	authIDs []domain.AuthID,
) ([]domain.Principal, error) {
	if repository == nil || repository.collection == nil {
		return nil, fmt.Errorf("%w: repository is unavailable", port.ErrDeveloperStatusUnavailable)
	}
	values := make([]string, len(authIDs))
	for index, authID := range authIDs {
		values[index] = authID.String()
	}
	cursor, err := repository.collection.Find(
		ctx,
		bson.M{"authId": bson.M{"$in": values}},
	)
	if err != nil {
		return nil, fmt.Errorf("%w: batch read principals: %v", port.ErrDeveloperStatusUnavailable, err)
	}
	defer func() { _ = cursor.Close(ctx) }()

	principals := make([]domain.Principal, 0, len(authIDs))
	for cursor.Next(ctx) {
		var raw bson.Raw
		if err := cursor.Decode(&raw); err != nil {
			return nil, fmt.Errorf("%w: decode principal: %v", port.ErrDeveloperStatusUnavailable, err)
		}
		if !identityFields(raw, map[string]bson.Type{"authId": bson.TypeString, "principalType": bson.TypeString}) {
			return nil, port.ErrDeveloperStatusUnavailable
		}
		if raw.Lookup("principalType").StringValue() == "USER" {
			account := raw.Lookup("accountStatus")
			if account.Type != bson.TypeString {
				return nil, port.ErrDeveloperStatusUnavailable
			}
			if account.StringValue() == "CLOSED" {
				if !validClosedPrincipal(raw) {
					return nil, port.ErrDeveloperStatusUnavailable
				}
			} else if !validDeveloperLifecycle(raw) {
				return nil, port.ErrDeveloperStatusUnavailable
			}
		}
		var document principalDocument
		if bson.Unmarshal(raw, &document) != nil {
			return nil, port.ErrDeveloperStatusUnavailable
		}
		principal, err := principalFromDocument(document)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid principal record: %v", port.ErrDeveloperStatusUnavailable, err)
		}
		principals = append(principals, principal)
	}
	if err := cursor.Err(); err != nil {
		return nil, fmt.Errorf("%w: read principals: %v", port.ErrDeveloperStatusUnavailable, err)
	}
	return principals, nil
}

func principalFromDocument(document principalDocument) (domain.Principal, error) {
	authID, err := domain.NewAuthID(document.AuthID)
	if err != nil {
		return domain.Principal{}, err
	}
	status := domain.DeveloperStatus("")
	if document.DeveloperStatus != nil {
		status = domain.DeveloperStatus(*document.DeveloperStatus)
	}
	return domain.NewPrincipalWithAccountStatus(authID, domain.PrincipalType(document.PrincipalType), status, domain.AccountStatus(document.AccountStatus))
}

var _ port.PrincipalRepository = (*PrincipalRepository)(nil)
