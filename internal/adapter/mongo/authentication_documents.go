package mongo

import (
	"errors"
	"go.mongodb.org/mongo-driver/v2/bson"
	"iwut-auth-center/internal/authentication/domain"
	credential "iwut-auth-center/internal/credentialmanagement/domain"
)

func operationDocument(v domain.Operation) OperationDocument {
	return OperationDocument{AccountRevision: v.AccountRevision, OperationID: v.OperationID, Purpose: v.Purpose, ProtocolVersion: v.ProtocolVersion, ServiceID: v.ServiceID, ApplicationID: v.ApplicationID, Challenge: v.Challenge, ExpiresAt: v.ExpiresAt, CreatedAt: v.CreatedAt, LocatorKind: v.LocatorKind, LocatorValue: v.LocatorValue, CredentialID: v.CredentialID, AuthID: v.AuthID, PublicKey: v.PublicKey, Acceptable: v.Acceptable, Status: v.Status, FailedAttempts: v.FailedAttempts, CompletedAuthID: v.CompletedAuthID, CompletedCredentialID: v.CompletedCredentialID, CompletedSessionID: v.CompletedSessionID, SchemeVersion: v.SchemeVersion, KeyVersion: v.KeyVersion, LookupKey: v.LookupKey, Nonce: v.Nonce, Ciphertext: v.Ciphertext}
}
func (v OperationDocument) Domain() domain.Operation {
	return domain.Operation{AccountRevision: v.AccountRevision, OperationID: v.OperationID, Purpose: v.Purpose, ProtocolVersion: v.ProtocolVersion, ServiceID: v.ServiceID, ApplicationID: v.ApplicationID, Challenge: v.Challenge, ExpiresAt: v.ExpiresAt, CreatedAt: v.CreatedAt, LocatorKind: v.LocatorKind, LocatorValue: v.LocatorValue, CredentialID: v.CredentialID, AuthID: v.AuthID, PublicKey: v.PublicKey, Acceptable: v.Acceptable, Status: v.Status, FailedAttempts: v.FailedAttempts, CompletedAuthID: v.CompletedAuthID, CompletedCredentialID: v.CompletedCredentialID, CompletedSessionID: v.CompletedSessionID, SchemeVersion: v.SchemeVersion, KeyVersion: v.KeyVersion, LookupKey: v.LookupKey, Nonce: v.Nonce, Ciphertext: v.Ciphertext}
}
func credentialDocument(v domain.Credential) CredentialDocument {
	return CredentialDocument{CredentialRevision: v.CredentialRevision, CredentialID: v.CredentialID, AuthID: v.AuthID, ProtocolVersion: v.ProtocolVersion, PublicKey: v.PublicKey, Fingerprint: v.Fingerprint, CreatedAt: v.CreatedAt, RevokedAt: v.RevokedAt}
}
func (v CredentialDocument) Domain() domain.Credential {
	return domain.Credential{CredentialRevision: v.CredentialRevision, CredentialID: v.CredentialID, AuthID: v.AuthID, ProtocolVersion: v.ProtocolVersion, PublicKey: v.PublicKey, Fingerprint: v.Fingerprint, CreatedAt: v.CreatedAt, RevokedAt: v.RevokedAt}
}
func sessionDocument(v domain.Session) SessionDocument {
	return SessionDocument{PasswordRevision: v.PasswordRevision, SourceSessionID: v.SourceSessionID, AccountRevision: v.AccountRevision, SessionID: v.SessionID, AuthID: v.AuthID, AuthenticationMethod: v.AuthenticationMethod, EmailBindingRevision: v.EmailBindingRevision, CredentialID: v.CredentialID, TokenDigest: v.TokenDigest, AuthenticatedAt: v.AuthenticatedAt, CreatedAt: v.CreatedAt, LastUsedAt: v.LastUsedAt, ExpiresAt: v.ExpiresAt, RevokedAt: v.RevokedAt}
}
func (v SessionDocument) Domain() domain.Session {
	return domain.Session{PasswordRevision: v.PasswordRevision, SourceSessionID: v.SourceSessionID, AccountRevision: v.AccountRevision, SessionID: v.SessionID, AuthID: v.AuthID, AuthenticationMethod: v.AuthenticationMethod, EmailBindingRevision: v.EmailBindingRevision, CredentialID: v.CredentialID, TokenDigest: v.TokenDigest, AuthenticatedAt: v.AuthenticatedAt, CreatedAt: v.CreatedAt, LastUsedAt: v.LastUsedAt, ExpiresAt: v.ExpiresAt, RevokedAt: v.RevokedAt}
}

// Email provenance is an exact positive int64; coercing a damaged BSON value
// would let different Session consumers disagree about its authentication method.
func (v *SessionDocument) UnmarshalBSON(data []byte) error {
	type plain SessionDocument
	var value plain
	if err := bson.Unmarshal(data, &value); err != nil {
		return err
	}
	rawRevision := bson.Raw(data).Lookup("accountRevision")
	if rawRevision.Type != bson.TypeInt64 || rawRevision.Int64() <= 0 {
		return errors.New("invalid account revision")
	}
	if value.AuthenticationMethod == "EMAIL_CODE_AND_DEVICE" {
		raw := bson.Raw(data).Lookup("emailBindingRevision")
		if raw.Type != bson.TypeInt64 || raw.Int64() <= 0 {
			return errors.New("invalid email session provenance")
		}
	}
	if value.AuthenticationMethod == "PASSWORD_AND_DEVICE" || value.AuthenticationMethod == "PASSWORD_AND_SESSION" {
		raw := bson.Raw(data).Lookup("passwordRevision")
		if raw.Type != bson.TypeInt64 || raw.Int64() <= 0 {
			return errors.New("invalid password session provenance")
		}
	}
	if !validSessionMethod(SessionDocument(value)) {
		return errors.New("invalid session provenance")
	}
	*v = SessionDocument(value)
	return nil
}

func (v *CredentialDocument) UnmarshalBSON(data []byte) error {
	type plain CredentialDocument
	var value plain
	if err := bson.Unmarshal(data, &value); err != nil {
		return err
	}
	revision := bson.Raw(data).Lookup("credentialRevision")
	if revision.Type != bson.TypeInt64 || revision.Int64() <= 0 {
		return errors.New("invalid credential revision")
	}
	label, labelRevision := bson.Raw(data).Lookup("label"), bson.Raw(data).Lookup("labelRevision")
	// Both absent is the only permitted legacy metadata shape, never a default
	// for security fields. A partial pair, null, coercion or invalid label fails.
	if label.Type != 0 || labelRevision.Type != 0 {
		if label.Type != bson.TypeString || labelRevision.Type != bson.TypeInt64 || labelRevision.Int64() < 0 {
			return errors.New("invalid credential label metadata")
		}
		canonical, err := credential.Label(label.StringValue())
		if err != nil || canonical != label.StringValue() {
			return errors.New("invalid credential label metadata")
		}
	}
	*v = CredentialDocument(value)
	return nil
}

func (v *OperationDocument) UnmarshalBSON(data []byte) error {
	type plain OperationDocument
	var value plain
	if err := bson.Unmarshal(data, &value); err != nil {
		return err
	}
	if value.AccountRevision != 0 || (value.Purpose == domain.Login && value.Acceptable) || value.Purpose == "BIND_EMAIL" {
		revision := bson.Raw(data).Lookup("accountRevision")
		if revision.Type != bson.TypeInt64 || revision.Int64() <= 0 {
			return errors.New("invalid operation account revision")
		}
	}
	*v = OperationDocument(value)
	return nil
}
