package mongo

import (
	"context"
	"errors"
	"time"

	d "iwut-auth-center/internal/applicationuserstorage/domain"
	oauthd "iwut-auth-center/internal/oauth/domain"
	oauthp "iwut-auth-center/internal/oauth/port"
)

type ApplicationUserStorageRepository struct {
	oauth *OAuthRepository
}

func NewApplicationUserStorageRepository(auth *AuthenticationRepository) (*ApplicationUserStorageRepository, error) {
	if auth == nil {
		return nil, d.ErrUnavailable
	}
	return &ApplicationUserStorageRepository{oauth: NewOAuthRepository(auth, auth.database)}, nil
}

func (r *ApplicationUserStorageRepository) Clear(ctx context.Context, authID, applicationID string, at time.Time) (bool, error) {
	changed := false
	err := r.oauth.Transaction(ctx, func(tx oauthp.Tx) error {
		user, err := tx.User(authID)
		if err != nil {
			return err
		}
		if user.AuthID != authID || user.AccountRevision <= 0 {
			return oauthd.ErrUnavailable
		}
		changed, err = tx.ClearApplicationUserStorage(authID, applicationID, at)
		return err
	})
	if err != nil {
		if errors.Is(err, oauthd.ErrGrant) || errors.Is(err, oauthd.ErrLogin) {
			return false, d.ErrIdentity
		}
		return false, d.ErrUnavailable
	}
	return changed, nil
}
