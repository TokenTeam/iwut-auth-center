package port

import (
	"context"
	d "iwut-auth-center/internal/oauth/domain"
	"time"
)

type App interface {
	Client(context.Context, string) (d.Client, error)
	VerifySecret(context.Context, d.Client, string) (bool, error)
	Runtime(context.Context, d.Client, int32) (d.Runtime, error)
	Authorize(context.Context, d.Runtime, string) (d.Runtime, error)
	Redirects(context.Context, string) (d.RedirectSnapshot, error)
}
type Store interface {
	Transaction(context.Context, func(Tx) error) error
}
type Tx interface {
	Registrations(string, string) ([]d.Registration, error)
	SaveRegistration(d.Registration) error
	Session(string, time.Time) (d.Session, error)
	User(string) (d.User, error)
	Catalog() (d.Catalog, error)
	Interaction(string) (d.Interaction, error)
	SaveInteraction(d.Interaction) error
	Grant(string) (d.Grant, error)
	FindGrant(string, string, string) (d.Grant, error)
	ListGrants(string, string, int) ([]d.Grant, error)
	SaveGrant(d.Grant) error
	Code(string) (d.Code, error)
	SaveCode(d.Code) error
	Family(string) (d.Family, error)
	SaveFamily(d.Family) error
	Access(string) (d.Access, error)
	SaveAccess(d.Access) error
	Refresh(string) (d.Refresh, error)
	SaveRefresh(d.Refresh) error
	Sector(string) (d.Sector, error)
	SectorByHost(string) (d.Sector, error)
	SaveSector(d.Sector) error
	Subject(string, string) (d.Subject, error)
	SaveSubject(d.Subject) error
	Audit(d.Audit) error
}
type Crypto interface {
	Random() (string, error)
	ID() string
	Digest(string, string) string
	ValidOpaque(string) bool
	ValidChallenge(string) bool
	VerifyPKCE(string, string) bool
	SignID(map[string]any) (string, error)
	SignDelegation(map[string]any) (string, error)
	AccessHash(string) string
	JWKS() any
}
