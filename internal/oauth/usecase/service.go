package usecase

import (
	"context"
	"errors"
	d "iwut-auth-center/internal/oauth/domain"
	"iwut-auth-center/internal/oauth/port"
	"time"
)

type Config struct {
	SigningHealthy                         func() bool
	Issuer, SectorSuffix                   string
	RefreshEnabled                         bool
	AccessTTL, IDTTL, IdleTTL, AbsoluteTTL time.Duration
}
type Service struct {
	store  port.Store
	app    port.App
	crypto port.Crypto
	cfg    Config
	now    func() time.Time
}

func New(store port.Store, app port.App, crypto port.Crypto, cfg Config) (*Service, error) {
	if store == nil || app == nil || crypto == nil || cfg.Issuer == "" || cfg.SectorSuffix == "" {
		return nil, d.ErrRequest
	}
	if cfg.AccessTTL == 0 {
		cfg.AccessTTL = 15 * time.Minute
	}
	if cfg.IDTTL == 0 {
		cfg.IDTTL = 5 * time.Minute
	}
	if cfg.IdleTTL == 0 {
		cfg.IdleTTL = 30 * 24 * time.Hour
	}
	if cfg.AbsoluteTTL == 0 {
		cfg.AbsoluteTTL = 180 * 24 * time.Hour
	}
	if cfg.AccessTTL <= 0 || cfg.AccessTTL > 15*time.Minute || cfg.IDTTL <= 0 || cfg.IDTTL > 5*time.Minute || cfg.IdleTTL <= 0 || cfg.IdleTTL > 30*24*time.Hour || cfg.AbsoluteTTL < cfg.IdleTTL || cfg.AbsoluteTTL > 180*24*time.Hour {
		return nil, d.ErrRequest
	}
	return &Service{store: store, app: app, crypto: crypto, cfg: cfg, now: time.Now}, nil
}
func (s *Service) transaction(ctx context.Context, fn func(port.Tx) error) error {
	return s.store.Transaction(ctx, fn)
}
func (s *Service) user(tx port.Tx, authID string, rt d.Runtime) (d.User, error) {
	if !d.ValidMembership(rt.Client.Channel, rt.TesterID) {
		return d.User{}, d.ErrUnavailable
	}
	u, err := tx.User(authID)
	if err != nil {
		return u, err
	}
	owner, err := tx.User(rt.AdminID)
	if err != nil {
		return u, err
	}
	if !owner.DeveloperApproved {
		return u, d.ErrGrant
	}
	return u, nil
}
func (s *Service) catalog(tx port.Tx) (d.Catalog, error) {
	c, err := tx.Catalog()
	if err != nil {
		return c, d.ErrUnavailable
	}
	if c.Revision <= 0 || c.GeneratedAt.IsZero() {
		return c, d.ErrUnavailable
	}
	return c, nil
}
func (s *Service) checkScopes(tx port.Tx, rt d.Runtime, scopes []string) (d.Catalog, error) {
	c, err := s.catalog(tx)
	if err != nil {
		return c, err
	}
	if !d.ValidScopes(scopes) || !d.Contains(scopes, "openid") || !d.Subset(rt.Required, scopes) || !d.Subset(scopes, d.Intersect(d.Union(rt.Required, rt.Optional), c.Enabled(s.cfg.RefreshEnabled))) {
		return c, d.ErrScope
	}
	return c, nil
}
func (s *Service) fresh(rt d.Runtime) error {
	if !rt.Fresh(s.now()) {
		return d.ErrUnavailable
	}
	return nil
}
func missing(err error) bool { return errors.Is(err, d.ErrNotFound) }
func (s *Service) audit(tx port.Tx, g d.Grant, client, action string, scopes []string) error {
	return tx.Audit(d.Audit{ID: s.crypto.ID(), AuthID: g.AuthID, GrantID: g.ID, ClientID: client, Action: action, Scopes: scopes, Revision: g.Revision, Epoch: g.RevocationEpoch, At: s.now()})
}
