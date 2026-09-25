package port

import (
	"context"
	auth "iwut-auth-center/internal/authentication/domain"
	"iwut-auth-center/internal/emaillogin/domain"
	"time"
)

type Repository interface {
	// Begin freezes the shared email directory/subject/credential snapshot, deducts
	// shared mail quotas and persists or returns the same idempotent operation.
	Begin(context.Context, domain.Operation, string, time.Time) (domain.Operation, bool, error)
	Get(context.Context, string) (domain.Operation, error)
	Fail(context.Context, string, time.Time) error
	// Complete must fence current subject, email revision and credential facts,
	// consume the operation, create/reuse the device, enforce Session LRU and audit
	// in the same shared authentication transaction. An unknown commit is an error.
	Complete(context.Context, Commit, time.Time) (string, error)
}
type Protocol interface {
	KeyID() string
	ValidID(string) bool
	NormalizeEmail(string) (string, error)
	ValidCode(string) bool
	ValidSignature([]byte) bool
	RequestMAC(domain.Begin) []byte
	CodeMAC(domain.Operation, string) []byte
	Payload(domain.Operation) ([]byte, error)
	NewCode() (string, error)
}
type Sender interface {
	Send(context.Context, string, string, string, time.Time) error
}

// Commit candidates stay stable across transaction retries.
type Commit struct {
	Operation  domain.Operation
	Credential auth.Credential
	Session    auth.Session
}
