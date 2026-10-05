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
	DeveloperStatusWithdrawn DeveloperStatus = "WITHDRAWN"
)

func (status DeveloperStatus) IsValid() bool {
	switch status {
	case DeveloperStatusPending, DeveloperStatusApproved, DeveloperStatusRejected, DeveloperStatusSuspended, DeveloperStatusWithdrawn:
		return true
	default:
		return false
	}
}

type AccountStatus string

const (
	AccountActive   AccountStatus = "ACTIVE"
	AccountDisabled AccountStatus = "DISABLED"
	AccountClosed   AccountStatus = "CLOSED"
)

type Principal struct {
	accountStatus   AccountStatus
	authID          AuthID
	principalType   PrincipalType
	developerStatus DeveloperStatus
}

func NewPrincipal(authID AuthID, principalType PrincipalType, status DeveloperStatus) (Principal, error) {
	return NewPrincipalWithAccountStatus(authID, principalType, status, AccountActive)
}

func NewPrincipalWithAccountStatus(authID AuthID, principalType PrincipalType, status DeveloperStatus, account AccountStatus) (Principal, error) {
	if principalType == PrincipalTypeUser && account != AccountActive && account != AccountDisabled && account != AccountClosed {
		return Principal{}, errors.New("invalid account status")
	}
	if account == AccountClosed && (principalType != PrincipalTypeUser || status != "") {
		return Principal{}, errors.New("invalid closed principal")
	}
	if authID == "" {
		return Principal{}, errors.New("auth id is required")
	}
	if principalType != PrincipalTypeUser && principalType != PrincipalTypeSystem {
		return Principal{}, errors.New("invalid principal type")
	}
	if principalType == PrincipalTypeUser && status != "" && !status.IsValid() {
		return Principal{}, errors.New("invalid user developer status")
	}
	if principalType == PrincipalTypeSystem && status != "" {
		return Principal{}, errors.New("system principal cannot have developer status")
	}
	return Principal{authID: authID, principalType: principalType, developerStatus: status, accountStatus: account}, nil
}

func (principal Principal) AuthID() AuthID                   { return principal.authID }
func (principal Principal) PrincipalType() PrincipalType     { return principal.principalType }
func (principal Principal) DeveloperStatus() DeveloperStatus { return principal.developerStatus }

func (p Principal) AccountStatus() AccountStatus { return p.accountStatus }
