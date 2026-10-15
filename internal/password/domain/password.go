// Package domain contains password values without crypto or persistence dependencies.
package domain

import (
	"errors"
	"math"
	"time"
)

var (
	ErrInvalidInput     = errors.New("invalid password request")
	ErrPolicy           = errors.New("password policy rejected")
	ErrAuthentication   = errors.New("password authentication failed")
	ErrUnchanged        = errors.New("password unchanged")
	ErrConflict         = errors.New("password revision conflict")
	ErrRequestConflict  = errors.New("password request conflict")
	ErrAlreadyCompleted = errors.New("password change already completed")
	ErrSessionInvalid   = errors.New("session invalid")
	ErrLimited          = errors.New("password rate limited")
	ErrUnavailable      = errors.New("password unavailable")
)

var Errors = []error{ErrInvalidInput, ErrPolicy, ErrAuthentication, ErrUnchanged, ErrConflict, ErrRequestConflict, ErrAlreadyCompleted, ErrSessionInvalid, ErrLimited, ErrUnavailable}

const (
	Algorithm            = "argon2id"
	FormatVersion        = 1
	NormalizationVersion = "nfc-unicode-15.0.0"
	PasswordAndDevice    = "PASSWORD_AND_DEVICE"
	PasswordAndSession   = "PASSWORD_AND_SESSION"
)

type Parameters struct {
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
}

func DefaultParameters() Parameters { return Parameters{19456, 2, 1} }

// Valid bounds both the reviewed minimum and hostile stored work factors.
func (p Parameters) Valid() bool {
	return p.MemoryKiB >= 19456 && p.MemoryKiB <= 262144 && p.Iterations >= 2 && p.Iterations <= 6 && p.Parallelism >= 1 && p.Parallelism <= 4
}

type Material struct {
	Algorithm            string
	FormatVersion        int
	NormalizationVersion string
	Parameters           Parameters
	Salt, Hash           []byte
}

func (m Material) Valid() bool {
	return m.Algorithm == Algorithm && m.FormatVersion == FormatVersion && m.NormalizationVersion == NormalizationVersion && m.Parameters.Valid() && len(m.Salt) == 16 && len(m.Hash) == 32
}

type Record struct {
	AuthID    string
	Revision  int64
	Material  Material
	ChangedAt time.Time
}

func (r Record) Valid() bool {
	return r.AuthID != "" && r.Revision > 0 && !r.ChangedAt.IsZero() && r.Material.Valid()
}

// NextRevisions does not change status, consent or developer state. The caller
// commits all returned values together under the shared authentication fence.
func NextRevisions(account, minimumCredential, password int64) (int64, int64, error) {
	if account <= 0 || password <= 0 || minimumCredential <= 0 || minimumCredential > account || account == math.MaxInt64 || password == math.MaxInt64 {
		return 0, 0, ErrConflict
	}
	return account + 1, password + 1, nil
}

func EligibleCredential(credential, minimum, account int64) bool {
	return minimum > 0 && account >= minimum && credential >= minimum && credential <= account
}
