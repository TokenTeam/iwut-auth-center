package mongo

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	d "iwut-auth-center/internal/password/domain"
	p "iwut-auth-center/internal/password/port"
	u "iwut-auth-center/internal/password/usecase"
)

func TestPasswordReauthUsesCurrentPasswordWithoutReapplyingNewPolicy(t *testing.T) {
	f := attachPassword(t, newAuthenticationFixture(t))
	service, err := u.NewReauth(f.repository, f.engine, f.quota)
	if err != nil {
		t.Fatal(err)
	}
	request := p.ReauthRequest{AuthID: f.c.AuthID, CredentialID: f.c.CredentialID, AccountRevision: 1, Password: initialPassword, Source: "127.0.0.1"}
	if revision, err := service.VerifyPassword(t.Context(), request); err != nil || revision != 1 {
		t.Fatal("current password rejected", revision, err)
	}
	request.Password = "wrong current password"
	if _, err = service.VerifyPassword(t.Context(), request); !errors.Is(err, d.ErrAuthentication) {
		t.Fatal("wrong password accepted", err)
	}
	// Existing hashes remain verifiable even when a newer policy would reject
	// that value as a newly selected password.
	oldMaterial, err := f.engine.Rehash(t.Context(), "short")
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.r.database.Collection(PasswordCollection).ReplaceOne(t.Context(), bson.M{"authId": f.c.AuthID}, passwordDoc(d.Record{AuthID: f.c.AuthID, Revision: 2, Material: oldMaterial, ChangedAt: time.Now().UTC().Truncate(time.Millisecond)}))
	if err != nil {
		t.Fatal(err)
	}
	request.Password = "short"
	if revision, err := service.VerifyPassword(t.Context(), request); err != nil || revision != 2 {
		t.Fatal("reauthentication reapplied new-password policy", revision, err)
	}
}

func TestPasswordReauthAccountAndCredentialBoundary(t *testing.T) {
	cases := []struct {
		name                  string
		principal, credential bson.M
		allowDisabled         bool
		accountRevision       int64
		want                  error
	}{
		{"disabled-denied", bson.M{"accountStatus": "DISABLED"}, nil, false, 1, d.ErrAuthentication},
		{"disabled-dedicated", bson.M{"accountStatus": "DISABLED"}, nil, true, 1, nil},
		{"closed-dedicated-denied", bson.M{"accountStatus": "CLOSED"}, nil, true, 1, d.ErrAuthentication},
		{"system-denied", bson.M{"principalType": "SYSTEM"}, nil, true, 1, d.ErrAuthentication},
		{"stale-account", bson.M{"accountRevision": int64(2)}, nil, true, 1, d.ErrAuthentication},
		{"revoked-key", nil, bson.M{"revokedAt": time.Now()}, true, 1, d.ErrAuthentication},
		{"retired-key", bson.M{"accountRevision": int64(2), "minimumCredentialRevision": int64(2)}, nil, true, 2, d.ErrAuthentication},
		{"bad-floor", bson.M{"minimumCredentialRevision": int64(2)}, nil, true, 1, d.ErrUnavailable},
		{"null-floor", bson.M{"minimumCredentialRevision": nil}, nil, true, 1, d.ErrUnavailable},
		{"int32-floor", bson.M{"minimumCredentialRevision": int32(1)}, nil, true, 1, d.ErrUnavailable},
		{"int32-account", bson.M{"accountRevision": int32(1)}, nil, true, 1, d.ErrUnavailable},
		{"zero-account", bson.M{"accountRevision": int64(0)}, nil, true, 1, d.ErrUnavailable},
		{"bad-status", bson.M{"accountStatus": "unknown"}, nil, true, 1, d.ErrUnavailable},
		{"zero-key-revision", nil, bson.M{"credentialRevision": int64(0)}, false, 1, d.ErrUnavailable},
		{"future-key-revision", nil, bson.M{"credentialRevision": int64(2)}, false, 1, d.ErrUnavailable},
		{"int32-key-revision", nil, bson.M{"credentialRevision": int32(1)}, false, 1, d.ErrUnavailable},
		{"null-key-revision", nil, bson.M{"credentialRevision": nil}, false, 1, d.ErrUnavailable},
		{"damaged-fingerprint", nil, bson.M{"fingerprint": bytes32(0)}, false, 1, d.ErrUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := attachPassword(t, newAuthenticationFixture(t))
			if tc.principal != nil {
				if _, err := f.r.database.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": f.c.AuthID}, bson.M{"$set": tc.principal}, options.UpdateOne().SetBypassDocumentValidation(true)); err != nil {
					t.Fatal(err)
				}
			}
			if tc.credential != nil {
				if _, err := f.r.database.Collection(CredentialCollection).UpdateOne(t.Context(), bson.M{"credentialId": f.c.CredentialID}, bson.M{"$set": tc.credential}, options.UpdateOne().SetBypassDocumentValidation(true)); err != nil {
					t.Fatal(err)
				}
			}
			record, err := f.repository.ReadReauth(t.Context(), p.ReauthRequest{AuthID: f.c.AuthID, CredentialID: f.c.CredentialID, AccountRevision: tc.accountRevision, AllowDisabled: tc.allowDisabled}, time.Now())
			if !errors.Is(err, tc.want) || (err == nil && record.Revision != 1) {
				t.Fatal("incorrect final boundary", record.Revision, err, tc.want)
			}
		})
	}
}

func TestPasswordReauthMissingTargetAndMalformedPasswordFailClosed(t *testing.T) {
	f := attachPassword(t, newAuthenticationFixture(t))
	request := p.ReauthRequest{AuthID: f.c.AuthID, CredentialID: uuid.NewString(), AccountRevision: 1}
	if _, err := f.repository.ReadReauth(t.Context(), request, time.Now()); !errors.Is(err, d.ErrAuthentication) {
		t.Fatal("unknown device accepted", err)
	}
	request.CredentialID = f.c.CredentialID
	if _, err := f.r.database.Collection(PasswordCollection).UpdateOne(t.Context(), bson.M{"authId": f.c.AuthID}, bson.M{"$set": bson.M{"passwordRevision": int32(1)}}, options.UpdateOne().SetBypassDocumentValidation(true)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.repository.ReadReauth(t.Context(), request, time.Now()); !errors.Is(err, d.ErrUnavailable) {
		t.Fatal("malformed password storage treated as credential failure", err)
	}
}

func TestPasswordReauthRejectsLegalNonUserAndClosedTombstones(t *testing.T) {
	for _, principal := range []bson.M{
		{"principalType": "USER", "accountStatus": "CLOSED"},
		{"principalType": "SYSTEM"},
	} {
		f := attachPassword(t, newAuthenticationFixture(t))
		principal["authId"] = f.c.AuthID
		if _, err := f.r.database.Collection(PrincipalCollection).ReplaceOne(t.Context(), bson.M{"authId": f.c.AuthID}, principal, options.Replace().SetBypassDocumentValidation(true)); err != nil {
			t.Fatal(err)
		}
		if _, err := f.repository.ReadReauth(t.Context(), p.ReauthRequest{AuthID: f.c.AuthID, CredentialID: f.c.CredentialID, AccountRevision: 1, AllowDisabled: true}, time.Now()); !errors.Is(err, d.ErrAuthentication) {
			t.Fatal("inactive fields required from a closed/non-user principal", err)
		}
	}
}
