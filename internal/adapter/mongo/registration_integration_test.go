package mongo

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	drivermongo "go.mongodb.org/mongo-driver/v2/mongo"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	auth "iwut-auth-center/internal/authentication/domain"
	ap "iwut-auth-center/internal/authentication/port"
	rp "iwut-auth-center/internal/registration/port"
)

// Shared email test resources contain no student association or migration dependency.
type registrationFixture struct {
	db       *drivermongo.Database
	repo     *RegistrationRepository
	protocol *deviceprotocol.Protocol
}

func newSigningKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return k
}
func signChallenge(t *testing.T, key *ecdsa.PrivateKey, c auth.Challenge) []byte {
	t.Helper()
	h := sha256.Sum256(c.SigningPayload)
	s, e := ecdsa.SignASN1(rand.Reader, key, h[:])
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func countDocuments(t *testing.T, db *drivermongo.Database, c string, filter bson.M) int64 {
	t.Helper()
	n, e := db.Collection(c).CountDocuments(context.Background(), filter)
	if e != nil {
		t.Fatal(e)
	}
	return n
}
func TestRetiredNoEmailRepositoryCannotCreateAccount(t *testing.T) {
	f := newEmailFixture(t)
	err := f.repo.CompleteRegistration(t.Context(), rp.RegistrationCommit{Operation: auth.Operation{Purpose: auth.Register}}, time.Now())
	if !errors.Is(err, ap.ErrAuthenticationFailed) {
		t.Fatal("retired completion accepted", err)
	}
	for _, c := range []string{PrincipalCollection, CredentialCollection, SessionCollection, EmailBindingCollection, AssociationCollection, AssociationMemberCollection} {
		if n := countDocuments(t, f.db, c, bson.M{}); n != 0 {
			t.Fatal("retired completion wrote", c, n)
		}
	}
}
