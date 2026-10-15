package mongo

import (
	"bytes"
	"context"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	drivermongo "go.mongodb.org/mongo-driver/v2/mongo"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	auth "iwut-auth-center/internal/authentication/port"
	d "iwut-auth-center/internal/password/domain"
	p "iwut-auth-center/internal/password/port"
)

func (r *PasswordRepository) ReadReauth(ctx context.Context, in p.ReauthRequest, now time.Time) (d.Record, error) {
	var record d.Record
	err := r.auth.WithAuthTransaction(ctx, func(tx context.Context) error {
		var principal bson.Raw
		if err := r.auth.database.Collection(PrincipalCollection).FindOne(tx, bson.M{"authId": in.AuthID}).Decode(&principal); err != nil {
			return d.ErrUnavailable
		}
		if !identityFields(principal, map[string]bson.Type{"principalType": bson.TypeString}) {
			return d.ErrUnavailable
		}
		principalType := principal.Lookup("principalType").StringValue()
		if principalType == "SYSTEM" {
			return d.ErrAuthentication
		}
		if principalType != "USER" || !identityFields(principal, map[string]bson.Type{"accountStatus": bson.TypeString}) {
			return d.ErrUnavailable
		}
		// A legal CLOSED tombstone deliberately lacks active authentication
		// material. Reject it before requiring fields retained only by live users.
		status := principal.Lookup("accountStatus").StringValue()
		if status == "CLOSED" {
			return d.ErrAuthentication
		}
		if !identityFields(principal, map[string]bson.Type{"accountRevision": bson.TypeInt64, "minimumCredentialRevision": bson.TypeInt64}) {
			return d.ErrUnavailable
		}
		revision := principal.Lookup("accountRevision").Int64()
		minimum := principal.Lookup("minimumCredentialRevision").Int64()
		if revision <= 0 || minimum <= 0 || minimum > revision || (status != "ACTIVE" && status != "DISABLED") {
			return d.ErrUnavailable
		}
		if revision != in.AccountRevision || (status != "ACTIVE" && (!in.AllowDisabled || status != "DISABLED")) {
			return d.ErrAuthentication
		}
		var raw bson.Raw
		if err := r.auth.database.Collection(CredentialCollection).FindOne(tx, bson.M{"authId": in.AuthID, "credentialId": in.CredentialID}).Decode(&raw); errors.Is(err, drivermongo.ErrNoDocuments) {
			return d.ErrAuthentication
		} else if err != nil {
			return d.ErrUnavailable
		}
		if !identityFields(raw, map[string]bson.Type{"credentialRevision": bson.TypeInt64}) {
			return d.ErrUnavailable
		}
		var credential CredentialDocument
		if err := bson.Unmarshal(raw, &credential); err != nil {
			return d.ErrUnavailable
		}
		unrevoked := credential
		unrevoked.RevokedAt = nil
		if !validCredential(unrevoked) || credential.CredentialRevision > revision {
			return d.ErrUnavailable
		}
		if credential.RevokedAt != nil || !d.EligibleCredential(credential.CredentialRevision, minimum, revision) {
			return d.ErrAuthentication
		}
		// The key is immutable; verify its persisted fingerprint too before trusting
		// a caller's already verified signature snapshot.
		protocol, err := deviceprotocol.New("password-reauth")
		if err != nil {
			return d.ErrUnavailable
		}
		fp, err := protocol.Fingerprint(credential.PublicKey)
		if err != nil || !bytes.Equal(fp, credential.Fingerprint) {
			return d.ErrUnavailable
		}
		record, err = r.readPasswordTx(tx, in.AuthID)
		return err
	})
	if err == auth.ErrUnavailable {
		return d.Record{}, d.ErrUnavailable
	}
	return record, err
}
