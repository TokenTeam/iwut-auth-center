package mongo

import (
	"bytes"
	"context"
	"errors"
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
	return r.WithAuthTransaction(ctx, func(tx context.Context) error {
		now := r.currentTime(now)
		op, err := r.GetOperation(tx, c.Operation.OperationID)
		if err != nil {
			return err
		}
		if op.Purpose != auth.Register {
			return authport.ErrAuthenticationFailed
		}
		if op.Status == auth.Completed {
			return authport.ErrAlreadyCompleted
		}
		if !op.Acceptable || !sameRegistrationSnapshot(op, c.Operation) {
			return authport.ErrAuthenticationFailed
		}
		if c.Credential.AuthID == "" || c.Credential.CredentialID == "" || c.Credential.AuthID != c.Session.AuthID || c.Credential.CredentialID != c.Session.CredentialID || !bytes.Equal(c.Credential.PublicKey, op.PublicKey) || !bytes.Equal(c.Credential.Fingerprint, op.LocatorValue) || c.Association.KeyVersion != op.KeyVersion || c.Association.SchemeVersion != op.SchemeVersion || !bytes.Equal(c.Association.LookupKey, op.LookupKey) {
			return authport.ErrAuthenticationFailed
		}
		if err := r.ConsumeOperationTx(tx, op.OperationID, auth.Register, c.Credential.AuthID, c.Credential.CredentialID, c.Session.SessionID, now); err != nil {
			return err
		}
		return r.CreateRegisteredUserTx(tx, c, now)
	})
}

func sameRegistrationSnapshot(a, b auth.Operation) bool {
	return a.OperationID == b.OperationID && a.ProtocolVersion == b.ProtocolVersion && a.ServiceID == b.ServiceID && a.ApplicationID == b.ApplicationID && a.ExpiresAt.Equal(b.ExpiresAt) && a.LocatorKind == b.LocatorKind && a.SchemeVersion == b.SchemeVersion && a.KeyVersion == b.KeyVersion && bytes.Equal(a.Challenge, b.Challenge) && bytes.Equal(a.PublicKey, b.PublicKey) && bytes.Equal(a.LocatorValue, b.LocatorValue) && bytes.Equal(a.LookupKey, b.LookupKey) && bytes.Equal(a.Nonce, b.Nonce) && bytes.Equal(a.Ciphertext, b.Ciphertext)
}

// CreateRegisteredUserTx is shared by device and email registration; the caller owns the transaction and proof consumption.
func (r *RegistrationRepository) CreateRegisteredUserTx(tx context.Context, c port.RegistrationCommit, now time.Time) error {
	op := c.Operation
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
		"authId": c.Credential.AuthID, "principalType": "USER", "accountStatus": "ACTIVE", "developerStatus": nil, "permissions": bson.A{}, "permissionRevision": int64(1), "createdAt": now, "updatedAt": now,
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
	var group associationDocument
	err = r.db.Collection(AssociationCollection).FindOne(tx, bson.M{"keyVersion": c.Association.KeyVersion, "lookupKey": c.Association.LookupKey}).Decode(&group)
	if errors.Is(err, drivermongo.ErrNoDocuments) {
		group = associationDoc(c.Association)
		if _, err = r.db.Collection(AssociationCollection).InsertOne(tx, group); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if group.AssociationID == "" || group.SchemeVersion != op.SchemeVersion || len(group.Nonce) != 12 || len(group.Ciphertext) != 48 {
		return authport.ErrUnavailable
	}
	_, err = r.db.Collection(AssociationMemberCollection).InsertOne(tx, bson.M{"authId": c.Credential.AuthID, "associationId": group.AssociationID, "trustLevel": "CLIENT_ASSERTED", "createdAt": now})
	if err != nil {
		return err
	}
	return r.CreateSessionTx(tx, c.Session, now)
}
