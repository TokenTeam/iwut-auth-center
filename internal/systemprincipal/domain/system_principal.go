package domain

import "errors"

type Purpose string

const PurposeAppCenterReviewAutoRejection Purpose = "app-center.review-auto-rejection"

func NewPurpose(value string) (Purpose, error) {
	purpose := Purpose(value)
	if purpose != PurposeAppCenterReviewAutoRejection {
		return "", errors.New("invalid system principal purpose")
	}
	return purpose, nil
}

type Principal struct {
	authID  string
	purpose Purpose
}

func NewPrincipal(authID string, purpose Purpose) (Principal, error) {
	if authID == "" {
		return Principal{}, errors.New("system principal auth id is required")
	}
	if _, err := NewPurpose(string(purpose)); err != nil {
		return Principal{}, err
	}
	return Principal{authID: authID, purpose: purpose}, nil
}

func (principal Principal) AuthID() string   { return principal.authID }
func (principal Principal) Purpose() Purpose { return principal.purpose }
