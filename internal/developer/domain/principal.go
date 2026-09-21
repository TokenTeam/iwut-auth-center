package domain

import (
	"errors"
	"unicode/utf8"
)

const MaxAuthIDBytes = 200

type AuthID string

func NewAuthID(value string) (AuthID, error) {
	if value == "" || len([]byte(value)) > MaxAuthIDBytes || !utf8.ValidString(value) {
		return "", errors.New("invalid auth id")
	}
	return AuthID(value), nil
}

func (id AuthID) String() string { return string(id) }

type PrincipalType string

const (
	PrincipalTypeUser   PrincipalType = "USER"
	PrincipalTypeSystem PrincipalType = "SYSTEM"
)

type DeveloperStatus string

const (
	DeveloperStatusPending   DeveloperStatus = "PENDING"
	DeveloperStatusApproved  DeveloperStatus = "APPROVED"
	DeveloperStatusRejected  DeveloperStatus = "REJECTED"
	DeveloperStatusSuspended DeveloperStatus = "SUSPENDED"
)

func (status DeveloperStatus) IsValid() bool {
	switch status {
	case DeveloperStatusPending, DeveloperStatusApproved, DeveloperStatusRejected, DeveloperStatusSuspended:
		return true
	default:
		return false
	}
}

type Principal struct {
	authID          AuthID
	principalType   PrincipalType
	developerStatus DeveloperStatus
}

func NewPrincipal(authID AuthID, principalType PrincipalType, status DeveloperStatus) (Principal, error) {
	if authID == "" {
		return Principal{}, errors.New("auth id is required")
	}
	if principalType != PrincipalTypeUser && principalType != PrincipalTypeSystem {
		return Principal{}, errors.New("invalid principal type")
	}
	if principalType == PrincipalTypeUser && !status.IsValid() {
		return Principal{}, errors.New("user principal requires developer status")
	}
	if principalType == PrincipalTypeSystem && status != "" {
		return Principal{}, errors.New("system principal cannot have developer status")
	}
	return Principal{authID: authID, principalType: principalType, developerStatus: status}, nil
}

func (principal Principal) AuthID() AuthID                   { return principal.authID }
func (principal Principal) PrincipalType() PrincipalType     { return principal.principalType }
func (principal Principal) DeveloperStatus() DeveloperStatus { return principal.developerStatus }
