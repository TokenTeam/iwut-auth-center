package usecase

import (
	"context"
	"testing"
	"time"

	d "iwut-auth-center/internal/oauth/domain"
	"iwut-auth-center/internal/oauth/port"
)

type userInfoTimeStore struct{ tx port.Tx }

func (s userInfoTimeStore) Transaction(_ context.Context, fn func(port.Tx) error) error {
	return fn(s.tx)
}

type userInfoTimeTx struct {
	port.Tx
	base             time.Time
	academicObserved time.Time
}

func (tx *userInfoTimeTx) Access(string) (d.Access, error) {
	client := d.Client{ID: "client", ApplicationID: "application", Channel: "TEST"}
	return d.Access{AccountRevision: 1, AuthID: "user", GrantID: "grant", GrantEpoch: 1, ClientEpoch: 1, Runtime: d.Runtime{Client: client, Major: 1, TesterID: "tester"}, FamilyID: "family", Scopes: []string{"openid", "profile.academic_grade"}, Audiences: []string{"https://issuer.example/userinfo"}, ExpiresAt: tx.base.Add(time.Second)}, nil
}

func (tx *userInfoTimeTx) Family(string) (d.Family, error) {
	return d.Family{AccountRevision: 1, ID: "family", AuthID: "user", ClientID: "client", ApplicationID: "application", GrantID: "grant", Channel: "TEST", TesterID: "tester", Major: 1, GrantEpoch: 1, ClientEpoch: 1, IdleExpiresAt: tx.base.Add(time.Hour), AbsoluteExpiresAt: tx.base.Add(time.Hour)}, nil
}

func (*userInfoTimeTx) ApplicationOpen(string) (bool, error) { return true, nil }

func (*userInfoTimeTx) User(string) (d.User, error) {
	return d.User{AccountRevision: 1, AuthID: "user", DeveloperApproved: true}, nil
}

func (*userInfoTimeTx) Grant(string) (d.Grant, error) {
	return d.Grant{ID: "grant", AuthID: "user", ApplicationID: "application", Channel: "TEST", Status: "ACTIVE", Scopes: []string{"openid", "profile.academic_grade"}, Revision: 1, RevocationEpoch: 1}, nil
}

func (tx *userInfoTimeTx) Catalog() (d.Catalog, error) {
	return d.Catalog{Revision: 1, GeneratedAt: tx.base, Scopes: []d.Scope{
		{Name: "openid", Kind: "PROTOCOL", Enabled: true},
		{Name: "profile.academic_grade", Kind: "USERINFO_PROFILE", ProfileField: "academic_grade", ProfileValueType: "ACADEMIC_GRADE", Enabled: true},
	}}, nil
}

func (*userInfoTimeTx) Sector(string) (d.Sector, error) {
	return d.Sector{ID: "sector", ApplicationID: "application"}, nil
}

func (*userInfoTimeTx) Subject(string, string) (d.Subject, error) {
	return d.Subject{ID: "subject", AuthID: "user", SectorID: "sector"}, nil
}

func (tx *userInfoTimeTx) Profile(string) (d.Profile, error) {
	confirmedAt := tx.base.Add(-time.Hour)
	return d.Profile{Entries: []d.ProfileEntry{{Key: "academic_grade", Value: d.ProfileValue{Type: "ACADEMIC_GRADE", Academic: &d.ProfileGrade{Stage: "UNDERGRADUATE", Year: 2, FinalYear: 4, AcademicYear: 2025, ConfirmedAt: &confirmedAt}}}}}, nil
}

func (tx *userInfoTimeTx) AcademicYear(observedAt time.Time) (int32, error) {
	tx.academicObserved = observedAt
	return 2026, nil
}

type userInfoTimeApp struct {
	port.App
	base time.Time
}

func (*userInfoTimeApp) Client(context.Context, string) (d.Client, error) {
	return d.Client{ID: "client", ApplicationID: "application", Channel: "TEST", AuthorizationEpoch: 1}, nil
}

func (a *userInfoTimeApp) Runtime(_ context.Context, client d.Client, _ int32) (d.Runtime, error) {
	return d.Runtime{Client: client, Major: 1, AdminID: "user", TesterID: "tester", Required: []string{"openid"}, Optional: []string{"profile.academic_grade"}, ObservedAt: a.base, ValidUntil: a.base.Add(5 * time.Second)}, nil
}

func (*userInfoTimeApp) Authorize(_ context.Context, runtime d.Runtime, _ string) (d.Runtime, error) {
	return runtime, nil
}

type userInfoTimeCrypto struct{ port.Crypto }

func (userInfoTimeCrypto) ValidOpaque(string) bool      { return true }
func (userInfoTimeCrypto) Digest(string, string) string { return "digest" }

func TestUserInfoUsesOneObservedTimePerTransactionAttempt(t *testing.T) {
	base := time.Date(2026, time.September, 1, 0, 0, 0, 0, time.FixedZone("Asia/Shanghai", 8*60*60))
	tx := &userInfoTimeTx{base: base}
	service, err := New(userInfoTimeStore{tx: tx}, &userInfoTimeApp{base: base}, userInfoTimeCrypto{}, Config{Issuer: "https://issuer.example", SectorSuffix: "sectors.example"})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	service.now = func() time.Time {
		calls++
		return base.Add(time.Duration(calls-1) * 2 * time.Second)
	}
	if _, err = service.UserInfo(t.Context(), "access-token"); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || !tx.academicObserved.Equal(base) {
		t.Fatalf("userinfo used inconsistent observed time: calls=%d academic=%s", calls, tx.academicObserved)
	}
}
