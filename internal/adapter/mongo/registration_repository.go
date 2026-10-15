package mongo

import (
	"bytes"
	"context"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	drivermongo "go.mongodb.org/mongo-driver/v2/mongo"
	auth "iwut-auth-center/internal/authentication/domain"
	authport "iwut-auth-center/internal/authentication/port"
	"iwut-auth-center/internal/registration/port"
)

type RegistrationRepository struct {
	*AuthenticationRepository
	db *drivermongo.Database
}

func NewRegistrationRepository(db *drivermongo.Database, authentication *AuthenticationRepository) (*RegistrationRepository, error) {
	if db == nil || authentication == nil {
		return nil, port.ErrUnavailable
	}
	return &RegistrationRepository{AuthenticationRepository: authentication, db: db}, nil
}

func (r *RegistrationRepository) CompleteRegistration(ctx context.Context, c port.RegistrationCommit, now time.Time) error {
	// The no-email completion path is permanently retired, including direct
	// repository calls. Only verified EmailRepository.Complete may create a USER.
	return authport.ErrAuthenticationFailed
}

func sameRegistrationSnapshot(a, b auth.Operation) bool {
	return a.AccountRevision == b.AccountRevision && a.OperationID == b.OperationID && a.Purpose == b.Purpose && a.ProtocolVersion == b.ProtocolVersion && a.ServiceID == b.ServiceID && a.ApplicationID == b.ApplicationID && a.ExpiresAt.Equal(b.ExpiresAt) && a.LocatorKind == b.LocatorKind && bytes.Equal(a.Challenge, b.Challenge) && bytes.Equal(a.PublicKey, b.PublicKey) && bytes.Equal(a.LocatorValue, b.LocatorValue)
}

// CreateRegisteredUserTx initializes a verified email registration; its caller
// owns the complete email transaction and proof consumption.
func (r *RegistrationRepository) CreateRegisteredUserTx(tx context.Context, c port.RegistrationCommit, now time.Time) error {
	var err error
	// The shared transaction fence serializes concurrent registrations; the
	// fingerprint index remains the durable guard after operation cleanup.
	existing, err := r.db.Collection(CredentialCollection).CountDocuments(tx, bson.M{"fingerprint": c.Credential.Fingerprint})
	if err != nil {
		return err
	}
	if existing > 0 {
		return authport.ErrCredentialRegistered
	}
	_, err = r.db.Collection(PrincipalCollection).InsertOne(tx, bson.M{
		"authId": c.Credential.AuthID, "principalType": "USER", "accountStatus": "ACTIVE", "accountRevision": int64(1), "minimumCredentialRevision": int64(1), "developerRevision": int64(0), "developerStatus": nil, "permissions": bson.A{}, "permissionRevision": int64(1), "createdAt": now, "updatedAt": now,
		"profile": bson.M{"entries": bson.A{}, "revision": int64(1), "updatedAt": now},
	})
	if err != nil {
		return err
	}
	if err = r.InsertCredentialTx(tx, c.Credential); err != nil {
		if drivermongo.IsDuplicateKeyError(err) {
			return authport.ErrCredentialRegistered
		}
		return err
	}
	c.Session.AccountRevision = 1
	return r.CreateSessionTx(tx, c.Session, now)
}
