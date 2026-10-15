package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	d "iwut-auth-center/internal/oauth/domain"
)

type campusInfoTx struct {
	userInfoTimeTx
	channel                  string
	tokenScopes, grantScopes []string
	campusEnabled            bool
	closed                   bool
	userErr, campusErr       error
	certification            d.CampusCertification
	reads                    int
}

func (tx *campusInfoTx) Access(key string) (d.Access, error) {
	a, err := tx.userInfoTimeTx.Access(key)
	a.Scopes = tx.tokenScopes
	a.Runtime.Client.Channel = tx.channel
	if tx.channel != "TEST" {
		a.Runtime.TesterID = ""
	}
	return a, err
}
func (tx *campusInfoTx) Family(key string) (d.Family, error) {
	f, err := tx.userInfoTimeTx.Family(key)
	f.Channel = tx.channel
	if tx.channel != "TEST" {
		f.TesterID = ""
	}
	return f, err
}
func (tx *campusInfoTx) Grant(key string) (d.Grant, error) {
	g, err := tx.userInfoTimeTx.Grant(key)
	g.Scopes = tx.grantScopes
	g.Channel = tx.channel
	return g, err
}
func (tx *campusInfoTx) User(key string) (d.User, error) {
	if tx.userErr != nil {
		return d.User{}, tx.userErr
	}
	return tx.userInfoTimeTx.User(key)
}
func (tx *campusInfoTx) ApplicationOpen(string) (bool, error) { return !tx.closed, nil }
func (tx *campusInfoTx) Catalog() (d.Catalog, error) {
	return d.Catalog{Revision: 1, GeneratedAt: tx.base, Scopes: []d.Scope{
		{Name: "openid", Kind: "PROTOCOL", Enabled: true},
		{Name: "campus.whut", Kind: "USERINFO_CAMPUS", Enabled: tx.campusEnabled},
	}}, nil
}
func (tx *campusInfoTx) CampusCertification(string) (d.CampusCertification, error) {
	tx.reads++
	return tx.certification, tx.campusErr
}

type campusInfoApp struct {
	userInfoTimeApp
	channel  string
	optional []string
	err      error
}

func (a *campusInfoApp) Client(context.Context, string) (d.Client, error) {
	return d.Client{ID: "client", ApplicationID: "application", Channel: a.channel, AuthorizationEpoch: 1}, nil
}
func (a *campusInfoApp) Runtime(_ context.Context, client d.Client, _ int32) (d.Runtime, error) {
	if a.err != nil {
		return d.Runtime{}, a.err
	}
	r := d.Runtime{Client: client, Major: 1, AdminID: "user", Required: []string{"openid"}, Optional: a.optional, ObservedAt: a.base, ValidUntil: a.base.Add(5 * time.Second)}
	if a.channel == "TEST" {
		r.TesterID = "tester"
	}
	return r, nil
}

func campusInfoService(t *testing.T, channel string) (*Service, *campusInfoTx, *campusInfoApp) {
	t.Helper()
	base := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	tx := &campusInfoTx{userInfoTimeTx: userInfoTimeTx{base: base}, channel: channel, tokenScopes: []string{"openid", "campus.whut"}, grantScopes: []string{"openid", "campus.whut"}, campusEnabled: true, certification: d.CampusCertification{AuthID: "user", Institution: "WHUT", CertifiedAt: base.Add(-time.Hour)}}
	app := &campusInfoApp{userInfoTimeApp: userInfoTimeApp{base: base}, channel: channel, optional: []string{"campus.whut"}}
	s, err := New(userInfoTimeStore{tx: tx}, app, userInfoTimeCrypto{}, Config{Issuer: "https://issuer.example", SectorSuffix: "sectors.example"})
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return base }
	return s, tx, app
}

func TestUserInfoCampusCurrentIntersectionAndRestoration(t *testing.T) {
	for _, channel := range []string{"TEST", "GREY", "STABLE"} {
		t.Run(channel, func(t *testing.T) {
			s, tx, app := campusInfoService(t, channel)
			info, err := s.UserInfo(t.Context(), "access")
			if err != nil || info.Campus == nil || info.Subject != "subject" || info.Email != "" || len(info.Profile) != 0 {
				t.Fatalf("initial campus: %#v, %v", info, err)
			}
			for _, source := range []string{"token", "grant", "version", "catalog"} {
				tx.reads = 0
				switch source {
				case "token":
					tx.tokenScopes = []string{"openid"}
				case "grant":
					tx.grantScopes = []string{"openid"}
				case "version":
					app.optional = nil
				case "catalog":
					tx.campusEnabled = false
				}
				info, err = s.UserInfo(t.Context(), "access")
				if err != nil || info.Campus != nil || tx.reads != 0 || info.Subject != "subject" {
					t.Fatalf("%s removed: %#v %v reads=%d", source, info, err, tx.reads)
				}
				tx.tokenScopes = []string{"openid", "campus.whut"}
				tx.grantScopes = []string{"openid", "campus.whut"}
				app.optional = []string{"campus.whut"}
				tx.campusEnabled = true
				info, err = s.UserInfo(t.Context(), "access")
				if err != nil || info.Campus == nil || tx.reads != 1 || info.Subject != "subject" {
					t.Fatalf("%s restored: %#v %v reads=%d", source, info, err, tx.reads)
				}
			}
		})
	}
}

func TestUserInfoCampusAbsentAndMalformedFailClosed(t *testing.T) {
	for name, mutate := range map[string]func(*campusInfoTx){
		"storage failure":   func(tx *campusInfoTx) { tx.campusErr = errors.New("storage unavailable") },
		"wrong user":        func(tx *campusInfoTx) { tx.certification.AuthID = "other" },
		"wrong institution": func(tx *campusInfoTx) { tx.certification.Institution = "OTHER" },
		"missing time":      func(tx *campusInfoTx) { tx.certification.CertifiedAt = time.Time{} },
		"pre-epoch time":    func(tx *campusInfoTx) { tx.certification.CertifiedAt = time.Unix(-1, 0) },
		"future time":       func(tx *campusInfoTx) { tx.certification.CertifiedAt = tx.base.Add(time.Hour) },
	} {
		t.Run(name, func(t *testing.T) {
			s, tx, _ := campusInfoService(t, "TEST")
			mutate(tx)
			info, err := s.UserInfo(t.Context(), "access")
			if !errors.Is(err, d.ErrUnavailable) || info.Subject != "" || info.Campus != nil {
				t.Fatalf("partial/corrupt response: %#v %v", info, err)
			}
			tx.tokenScopes = []string{"openid"}
			if info, err = s.UserInfo(t.Context(), "access"); err != nil || info.Campus != nil || tx.reads != 1 {
				t.Fatalf("no scope depended on storage: %#v %v reads=%d", info, err, tx.reads)
			}
		})
	}
	s, tx, _ := campusInfoService(t, "TEST")
	tx.campusErr = d.ErrNotFound
	if info, err := s.UserInfo(t.Context(), "access"); err != nil || info.Campus != nil || info.Subject != "subject" {
		t.Fatalf("missing fact: %#v %v", info, err)
	}
}

func TestUserInfoCampusStillRequiresCurrentEligibility(t *testing.T) {
	for _, channel := range []string{"TEST", "GREY", "STABLE"} {
		for _, cause := range []string{"application closed", "account disabled", "account closed", "channel ineligible"} {
			t.Run(channel+"/"+cause, func(t *testing.T) {
				s, tx, app := campusInfoService(t, channel)
				switch cause {
				case "application closed":
					tx.closed = true
				case "account disabled", "account closed":
					tx.userErr = d.ErrGrant
				case "channel ineligible":
					app.err = d.ErrGrant
				}
				if info, err := s.UserInfo(t.Context(), "access"); !errors.Is(err, d.ErrToken) || info.Campus != nil || tx.reads != 0 {
					t.Fatalf("gate bypassed: %#v %v reads=%d", info, err, tx.reads)
				}
			})
		}
	}
}

func TestDiscoveryCampusScopeTracksEnabledCatalog(t *testing.T) {
	s, tx, _ := campusInfoService(t, "TEST")
	for _, enabled := range []bool{true, false, true} {
		tx.campusEnabled = enabled
		discovery, err := s.Discovery(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if d.Contains(discovery["scopes_supported"].([]string), "campus.whut") != enabled || !d.Contains(discovery["claims_supported"].([]string), "iwut_campus") {
			t.Fatal(discovery)
		}
	}
}
