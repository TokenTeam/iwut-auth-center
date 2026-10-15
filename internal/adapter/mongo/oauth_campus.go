package mongo

import (
	"errors"

	cd "iwut-auth-center/internal/campuscertification/domain"
	d "iwut-auth-center/internal/oauth/domain"
)

func (tx *oauthTx) CampusCertification(authID string) (d.CampusCertification, error) {
	fact, err := ReadCurrentCampusBasisTx(tx.ctx, tx.r.db, authID)
	if errors.Is(err, cd.ErrNotFound) {
		return d.CampusCertification{}, d.ErrNotFound
	}
	if err != nil {
		return d.CampusCertification{}, d.ErrUnavailable
	}
	return d.CampusCertification{AuthID: authID, Institution: fact.Institution, CertifiedAt: fact.CertifiedAt}, nil
}
