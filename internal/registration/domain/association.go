package domain

const AssociationScheme = "iwut-student-association-v1"

// SealedAssociation carries authenticated ciphertext, never a plaintext token.
type SealedAssociation struct {
	SchemeVersion, KeyVersion    string
	LookupKey, Nonce, Ciphertext []byte
}

type Association struct {
	AssociationID string
	SealedAssociation
}
