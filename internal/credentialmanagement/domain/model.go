package domain

import (
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	ErrInvalid       = errors.New("INVALID_CREDENTIAL_MANAGEMENT_REQUEST")
	ErrCursor        = errors.New("INVALID_CREDENTIAL_CURSOR")
	ErrCurrent       = errors.New("CURRENT_CREDENTIAL_NOT_ALLOWED")
	ErrSession       = errors.New("SESSION_INVALID")
	ErrNotFound      = errors.New("CREDENTIAL_NOT_FOUND")
	ErrProof         = errors.New("CREDENTIAL_REAUTH_FAILED")
	ErrLabelConflict = errors.New("CREDENTIAL_LABEL_CONFLICT")
	ErrConflict      = errors.New("CREDENTIAL_REVOCATION_REQUEST_CONFLICT")
	ErrCompleted     = errors.New("CREDENTIAL_REVOCATION_ALREADY_COMPLETED")
	ErrRate          = errors.New("CREDENTIAL_MANAGEMENT_RATE_LIMITED")
	ErrUnavailable   = errors.New("CREDENTIAL_MANAGEMENT_UNAVAILABLE")
)
var Errors = []error{ErrInvalid, ErrCursor, ErrCurrent, ErrSession, ErrNotFound, ErrProof, ErrLabelConflict, ErrConflict, ErrCompleted, ErrRate, ErrUnavailable}

const (
	Purpose   = "REVOKE_OTHER_CREDENTIAL"
	Pending   = "PENDING"
	Completed = "COMPLETED"
	Failed    = "FAILED"
)

var idPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func ValidID(id string) bool { return idPattern.MatchString(id) }
func Label(input string) (string, error) {
	if !utf8.ValidString(input) {
		return "", ErrInvalid
	}
	value := strings.TrimSpace(input)
	if len(value) > 256 || utf8.RuneCountInString(value) > 64 {
		return "", ErrInvalid
	}
	for _, r := range value {
		if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Cs, r) {
			return "", ErrInvalid
		}
	}
	return value, nil
}

type Caller struct {
	AuthID, SessionID, CredentialID string
	AccountRevision                 int64
}
type LabelResult struct {
	CredentialID, Label string
	Revision            int64
}
type Summary struct {
	CredentialID, Label string
	LabelRevision       int64
	CreatedAt           time.Time
	IsCurrent           bool
}
type Page struct {
	CurrentCredentialID string
	ObservedAt          time.Time
	Credentials         []Summary
	NextCursor          string
}
type Operation struct {
	OperationID, RequestID, Purpose, ServiceID, ApplicationID, AuthID, SessionID, CallerCredentialID, TargetCredentialID string
	AccountRevision, PasswordRevision, FailedAttempts                                                                    int64
	PublicKey, Challenge                                                                                                 []byte
	CreatedAt, ExpiresAt, RetainUntil                                                                                    time.Time
	Status                                                                                                               string
	CompletedAt                                                                                                          *time.Time
}
type Started struct {
	Operation      Operation
	SigningPayload []byte
}
