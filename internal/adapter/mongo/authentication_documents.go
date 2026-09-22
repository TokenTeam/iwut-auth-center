package mongo

import "iwut-auth-center/internal/authentication/domain"

func operationDocument(v domain.Operation) OperationDocument {
	return OperationDocument{OperationID: v.OperationID, Purpose: v.Purpose, ProtocolVersion: v.ProtocolVersion, ServiceID: v.ServiceID, ApplicationID: v.ApplicationID, Challenge: v.Challenge, ExpiresAt: v.ExpiresAt, CreatedAt: v.CreatedAt, LocatorKind: v.LocatorKind, LocatorValue: v.LocatorValue, CredentialID: v.CredentialID, AuthID: v.AuthID, PublicKey: v.PublicKey, Acceptable: v.Acceptable, Status: v.Status, FailedAttempts: v.FailedAttempts, CompletedAuthID: v.CompletedAuthID, CompletedCredentialID: v.CompletedCredentialID, CompletedSessionID: v.CompletedSessionID, SchemeVersion: v.SchemeVersion, KeyVersion: v.KeyVersion, LookupKey: v.LookupKey, Nonce: v.Nonce, Ciphertext: v.Ciphertext}
}
func (v OperationDocument) Domain() domain.Operation {
	return domain.Operation{OperationID: v.OperationID, Purpose: v.Purpose, ProtocolVersion: v.ProtocolVersion, ServiceID: v.ServiceID, ApplicationID: v.ApplicationID, Challenge: v.Challenge, ExpiresAt: v.ExpiresAt, CreatedAt: v.CreatedAt, LocatorKind: v.LocatorKind, LocatorValue: v.LocatorValue, CredentialID: v.CredentialID, AuthID: v.AuthID, PublicKey: v.PublicKey, Acceptable: v.Acceptable, Status: v.Status, FailedAttempts: v.FailedAttempts, CompletedAuthID: v.CompletedAuthID, CompletedCredentialID: v.CompletedCredentialID, CompletedSessionID: v.CompletedSessionID, SchemeVersion: v.SchemeVersion, KeyVersion: v.KeyVersion, LookupKey: v.LookupKey, Nonce: v.Nonce, Ciphertext: v.Ciphertext}
}
func credentialDocument(v domain.Credential) CredentialDocument {
	return CredentialDocument{CredentialID: v.CredentialID, AuthID: v.AuthID, ProtocolVersion: v.ProtocolVersion, PublicKey: v.PublicKey, Fingerprint: v.Fingerprint, CreatedAt: v.CreatedAt, RevokedAt: v.RevokedAt}
}
func (v CredentialDocument) Domain() domain.Credential {
	return domain.Credential{CredentialID: v.CredentialID, AuthID: v.AuthID, ProtocolVersion: v.ProtocolVersion, PublicKey: v.PublicKey, Fingerprint: v.Fingerprint, CreatedAt: v.CreatedAt, RevokedAt: v.RevokedAt}
}
func sessionDocument(v domain.Session) SessionDocument {
	return SessionDocument{SessionID: v.SessionID, AuthID: v.AuthID, AuthenticationMethod: v.AuthenticationMethod, CredentialID: v.CredentialID, TokenDigest: v.TokenDigest, AuthenticatedAt: v.AuthenticatedAt, CreatedAt: v.CreatedAt, LastUsedAt: v.LastUsedAt, ExpiresAt: v.ExpiresAt, RevokedAt: v.RevokedAt}
}
func (v SessionDocument) Domain() domain.Session {
	return domain.Session{SessionID: v.SessionID, AuthID: v.AuthID, AuthenticationMethod: v.AuthenticationMethod, CredentialID: v.CredentialID, TokenDigest: v.TokenDigest, AuthenticatedAt: v.AuthenticatedAt, CreatedAt: v.CreatedAt, LastUsedAt: v.LastUsedAt, ExpiresAt: v.ExpiresAt, RevokedAt: v.RevokedAt}
}
