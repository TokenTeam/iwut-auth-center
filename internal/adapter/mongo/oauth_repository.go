package mongo

import (
	"context"
	"errors"
	"strconv"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	academicyear "iwut-auth-center/internal/academicyear/domain"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	ap "iwut-auth-center/internal/authentication/port"
	d "iwut-auth-center/internal/oauth/domain"
	p "iwut-auth-center/internal/oauth/port"
)

type OAuthRepository struct {
	auth *AuthenticationRepository
	db   *m.Database
}

func NewOAuthRepository(auth *AuthenticationRepository, db *m.Database) *OAuthRepository {
	return &OAuthRepository{auth: auth, db: db}
}
func (r *OAuthRepository) Transaction(ctx context.Context, fn func(p.Tx) error) error {
	var semantic error
	err := r.auth.WithAuthTransaction(ctx, func(ctx context.Context) error {
		semantic = nil
		semantic = fn(&oauthTx{ctx: ctx, r: r})
		return semantic
	})
	if err != nil {
		if semantic != nil {
			return semantic
		}
		return d.ErrUnavailable
	}
	return nil
}

type oauthTx struct {
	ctx context.Context
	r   *OAuthRepository
}

func (tx *oauthTx) AcademicYear(observedAt time.Time) (int32, error) {
	state, err := readAcademicYearState(tx.ctx, tx.r.db)
	if err != nil {
		return 0, d.ErrUnavailable
	}
	schedule, err := academicyear.Project(state, observedAt)
	if err != nil {
		return 0, d.ErrUnavailable
	}
	return schedule.CurrentAcademicYear, nil
}

func (tx *oauthTx) ApplicationOpen(applicationID string) (bool, error) {
	closed, err := (&ApplicationClosureRepository{auth: tx.r.auth}).IsClosedTx(tx.ctx, applicationID)
	if err != nil {
		return false, d.ErrUnavailable
	}
	return !closed, nil
}

type oauthDocument[T any] struct {
	RetainUntil   time.Time `bson:"retainUntil,omitempty"`
	ID            string    `bson:"_id"`
	AuthID        string    `bson:"authId,omitempty"`
	ApplicationID string    `bson:"applicationId,omitempty"`
	Channel       string    `bson:"channel,omitempty"`
	Host          string    `bson:"host,omitempty"`
	Data          T         `bson:"data"`
}

func oauthGet[T any](tx *oauthTx, kind string, query bson.M) (T, error) {
	var doc oauthDocument[T]
	raw, err := tx.r.db.Collection("auth_oauth_"+kind).FindOne(tx.ctx, query).Raw()
	if err == nil {
		fields := map[string]bson.Type{"_id": bson.TypeString, "data": bson.TypeEmbeddedDocument}
		if !identityFields(raw, fields) {
			return doc.Data, d.ErrUnavailable
		}
		data := raw.Lookup("data").Document()
		required := map[string]bson.Type{}
		switch kind {
		case "codes", "refresh":
			required["consumed"] = bson.TypeBoolean
		case "access", "families":
			required["revoked"] = bson.TypeBoolean
		}
		if kind == "codes" || kind == "access" || kind == "families" {
			required["accountrevision"] = bson.TypeInt64
		}
		if kind == "interactions" && data.Lookup("authid").Type == bson.TypeString && data.Lookup("authid").StringValue() != "" {
			required["accountrevision"] = bson.TypeInt64
		}
		if kind == "interactions" && !validOAuthPresentationBSON(data.Lookup("presentation")) {
			return doc.Data, d.ErrUnavailable
		}
		if !identityFields(data, required) || bson.Unmarshal(raw, &doc) != nil {
			return doc.Data, d.ErrUnavailable
		}
	}
	if errors.Is(err, m.ErrNoDocuments) {
		return doc.Data, d.ErrNotFound
	}
	if err != nil {
		return doc.Data, d.ErrUnavailable
	}
	if !validOAuthDocument(doc) {
		return doc.Data, d.ErrUnavailable
	}
	return doc.Data, nil
}
func oauthSave[T any](tx *oauthTx, kind string, doc oauthDocument[T]) error {
	_, err := tx.r.db.Collection("auth_oauth_"+kind).ReplaceOne(tx.ctx, bson.M{"_id": doc.ID}, doc, options.Replace().SetUpsert(true))
	if err != nil {
		return d.ErrUnavailable
	}
	return nil
}
func (tx *oauthTx) Session(raw string, now time.Time) (d.Session, error) {
	protocol, _ := deviceprotocol.New("oauth-session")
	digest, err := protocol.TokenDigest(raw)
	if err != nil {
		return d.Session{}, d.ErrLogin
	}
	ss, err := tx.r.auth.CheckSessionTx(tx.ctx, digest, now)
	if err != nil {
		if errors.Is(err, ap.ErrSessionInvalid) {
			return d.Session{}, d.ErrLogin
		}
		return d.Session{}, d.ErrUnavailable
	}
	return d.Session{AccountRevision: ss.AccountRevision, ID: ss.SessionID, AuthID: ss.AuthID, AuthenticatedAt: ss.AuthenticatedAt, ExpiresAt: ss.ExpiresAt}, nil
}
func (tx *oauthTx) User(id string) (d.User, error) {
	var raw bson.Raw
	err := tx.r.db.Collection(PrincipalCollection).FindOne(tx.ctx, bson.M{"authId": id}).Decode(&raw)
	if errors.Is(err, m.ErrNoDocuments) {
		return d.User{}, d.ErrGrant
	}
	if err != nil {
		return d.User{}, d.ErrUnavailable
	}
	if !identityFields(raw, map[string]bson.Type{"authId": bson.TypeString, "principalType": bson.TypeString, "accountStatus": bson.TypeString}) {
		return d.User{}, d.ErrUnavailable
	}
	if raw.Lookup("authId").StringValue() != id || raw.Lookup("principalType").StringValue() != "USER" || raw.Lookup("accountStatus").StringValue() != "ACTIVE" {
		return d.User{}, d.ErrGrant
	}
	if !validDeveloperLifecycle(raw) {
		return d.User{}, d.ErrUnavailable
	}
	if _, err := tx.r.db.Collection(PrincipalCollection).UpdateOne(tx.ctx, bson.M{"authId": id, "accountStatus": "ACTIVE"}, bson.M{"$inc": bson.M{"authenticationFence": int64(1)}}); err != nil {
		return d.User{}, d.ErrUnavailable
	}
	revision, e := tx.r.auth.AccountRevisionTx(tx.ctx, id)
	if e != nil {
		if errors.Is(e, ap.ErrAuthenticationFailed) {
			return d.User{}, d.ErrGrant
		}
		return d.User{}, d.ErrUnavailable
	}
	user := d.User{AccountRevision: revision, AuthID: id, DeveloperApproved: raw.Lookup("developerStatus").Type == bson.TypeString && raw.Lookup("developerStatus").StringValue() == "APPROVED"}
	binding, _, err := ReadPrimaryEmailTx(tx.ctx, tx.r.db, id)
	if err != nil {
		return user, d.ErrUnavailable
	}
	user.Email = binding.Email
	user.EmailVerified = true
	if user.DeveloperApproved {
		var owner struct {
			Handle string `bson:"developerHandle"`
		}
		err = tx.r.db.Collection("auth_developer_handles").FindOne(tx.ctx, bson.M{"authId": id}).Decode(&owner)
		if err != nil {
			return user, d.ErrUnavailable
		}
		user.DeveloperHandle = owner.Handle
		if owner.Handle == "" {
			return user, d.ErrUnavailable
		}
	}
	return user, nil
}
func (tx *oauthTx) Profile(id string) (d.Profile, error) {
	var raw bson.Raw
	err := tx.r.db.Collection(PrincipalCollection).FindOne(tx.ctx, bson.M{"authId": id, "principalType": "USER", "accountStatus": "ACTIVE"}).Decode(&raw)
	if errors.Is(err, m.ErrNoDocuments) {
		return d.Profile{}, d.ErrGrant
	}
	if err != nil {
		return d.Profile{}, d.ErrUnavailable
	}
	principal, err := decodeProfilePrincipal(raw)
	if err != nil || principal.AuthID != id || principal.Type != "USER" || principal.AccountStatus != "ACTIVE" {
		return d.Profile{}, d.ErrUnavailable
	}
	out := d.Profile{Revision: principal.Profile.Revision, UpdatedAt: principal.Profile.UpdatedAt, Entries: make([]d.ProfileEntry, 0, len(principal.Profile.Entries))}
	for _, entry := range principal.Profile.Entries {
		value := d.ProfileValue{Type: string(entry.Value.Type), Text: entry.Value.Text, Integer: entry.Value.Integer, Boolean: entry.Value.Boolean, Strings: append([]string(nil), entry.Value.Strings...)}
		if entry.Value.Academic != nil {
			value.Academic = &d.ProfileGrade{Stage: entry.Value.Academic.Stage, Year: entry.Value.Academic.Year, FinalYear: entry.Value.Academic.FinalYear, AcademicYear: entry.Value.Academic.AcademicYear, ConfirmedAt: entry.Value.Academic.ConfirmedAt}
		}
		out.Entries = append(out.Entries, d.ProfileEntry{Key: entry.Key, Value: value})
	}
	return out, nil
}
func (tx *oauthTx) Catalog() (d.Catalog, error) {
	catalog, err := readManagedCatalog(tx.ctx, tx.r.db)
	if err != nil {
		return d.Catalog{}, d.ErrUnavailable
	}
	return catalog, nil
}
func (tx *oauthTx) FindGrant(auth, app, channel string) (d.Grant, error) {
	return oauthGet[d.Grant](tx, "grants", bson.M{"authId": auth, "applicationId": app, "channel": channel})
}
func (tx *oauthTx) ListGrants(auth, cursor string, limit int) ([]d.Grant, error) {
	q := bson.M{"authId": auth}
	if cursor != "" {
		previous, err := tx.Grant(cursor)
		if err != nil || previous.AuthID != auth {
			return nil, d.ErrRequest
		}
		q["$or"] = bson.A{bson.M{"applicationId": bson.M{"$gt": previous.ApplicationID}}, bson.M{"applicationId": previous.ApplicationID, "channel": bson.M{"$gt": previous.Channel}}}
	}
	cur, err := tx.r.db.Collection("auth_oauth_grants").Find(tx.ctx, q, options.Find().SetSort(bson.D{{Key: "applicationId", Value: 1}, {Key: "channel", Value: 1}}).SetLimit(int64(limit)))
	if err != nil {
		return nil, d.ErrUnavailable
	}
	defer cur.Close(tx.ctx)
	var docs []oauthDocument[d.Grant]
	if cur.All(tx.ctx, &docs) != nil {
		return nil, d.ErrUnavailable
	}
	out := make([]d.Grant, 0, len(docs))
	for _, v := range docs {
		if !validOAuthDocument(v) {
			return nil, d.ErrUnavailable
		}
		out = append(out, v.Data)
	}
	return out, nil
}
func (tx *oauthTx) SaveGrant(g d.Grant) error {
	return oauthSave(tx, "grants", oauthDocument[d.Grant]{ID: g.ID, AuthID: g.AuthID, ApplicationID: g.ApplicationID, Channel: g.Channel, Data: g})
}
func (tx *oauthTx) Sector(app string) (d.Sector, error) {
	return oauthGet[d.Sector](tx, "sectors", bson.M{"applicationId": app})
}
func (tx *oauthTx) SectorByHost(host string) (d.Sector, error) {
	return oauthGet[d.Sector](tx, "sectors", bson.M{"host": host})
}
func (tx *oauthTx) SaveSector(v d.Sector) error {
	return oauthSave(tx, "sectors", oauthDocument[d.Sector]{ID: v.ID, ApplicationID: v.ApplicationID, Host: v.Hostname, Data: v})
}
func (tx *oauthTx) Subject(auth, sector string) (d.Subject, error) {
	return oauthGet[d.Subject](tx, "subjects", bson.M{"_id": auth + ":" + sector})
}
func (tx *oauthTx) SaveSubject(v d.Subject) error {
	return oauthSave(tx, "subjects", oauthDocument[d.Subject]{ID: v.AuthID + ":" + v.SectorID, Data: v})
}
func (tx *oauthTx) Audit(v d.Audit) error {
	if !validOAuthConsentAudit(v) {
		return d.ErrUnavailable
	}
	_, err := tx.r.db.Collection("auth_oauth_audit").InsertOne(tx.ctx, oauthDocument[d.Audit]{ID: v.ID, Data: v})
	if err != nil {
		return d.ErrUnavailable
	}
	return nil
}
func EnsureOAuthSchema(ctx context.Context, db *m.Database) error {
	indexes := map[string][]m.IndexModel{
		"registrations": {{Keys: bson.D{{Key: "data.origins", Value: 1}, {Key: "data.type", Value: 1}, {Key: "data.clientid", Value: 1}}}},
		"grants":        {{Keys: bson.D{{Key: "authId", Value: 1}, {Key: "applicationId", Value: 1}, {Key: "channel", Value: 1}}, Options: options.Index().SetUnique(true).SetName("grant_owner_application_channel")}},
		"sectors":       {{Keys: bson.D{{Key: "applicationId", Value: 1}}, Options: options.Index().SetUnique(true)}, {Keys: bson.D{{Key: "host", Value: 1}}, Options: options.Index().SetUnique(true)}},
		"refresh":       {{Keys: bson.D{{Key: "data.familyid", Value: 1}}, Options: options.Index().SetUnique(true).SetPartialFilterExpression(bson.M{"data.consumed": false}).SetName("one_active_refresh_per_family")}},
		"subjects":      {{Keys: bson.D{{Key: "data.authid", Value: 1}, {Key: "data.sectorid", Value: 1}}, Options: options.Index().SetUnique(true)}, {Keys: bson.D{{Key: "data.id", Value: 1}}, Options: options.Index().SetUnique(true)}},
		"interactions":  {{Keys: bson.D{{Key: "data.expiresat", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0)}},
	}
	for _, kind := range []string{"registrations", "catalog", "grants", "sectors", "subjects", "interactions", "codes", "families", "access", "refresh", "audit"} {
		err := db.CreateCollection(ctx, "auth_oauth_"+kind)
		var ce m.CommandError
		if err != nil && (!errors.As(err, &ce) || ce.Code != 48) {
			return err
		}
	}
	for _, kind := range []string{"codes", "access", "refresh", "families"} {
		indexes[kind] = append(indexes[kind], m.IndexModel{Keys: bson.D{{Key: "retainUntil", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0)})
	}
	for kind, models := range indexes {
		if _, err := db.Collection("auth_oauth_"+kind).Indexes().CreateMany(ctx, models); err != nil {
			return err
		}
	}
	return EnsureScopeManagementSchema(ctx, db)
}
func (tx *oauthTx) Interaction(id string) (d.Interaction, error) {
	return oauthGet[d.Interaction](tx, "interactions", bson.M{"_id": id})
}
func (tx *oauthTx) SaveInteraction(v d.Interaction) error {
	return oauthSave(tx, "interactions", oauthDocument[d.Interaction]{ID: v.ID, Data: v})
}
func (tx *oauthTx) Grant(id string) (d.Grant, error) {
	return oauthGet[d.Grant](tx, "grants", bson.M{"_id": id})
}
func (tx *oauthTx) Code(id string) (d.Code, error) {
	return oauthGet[d.Code](tx, "codes", bson.M{"_id": id})
}
func (tx *oauthTx) SaveCode(v d.Code) error {
	return oauthSave(tx, "codes", oauthDocument[d.Code]{ID: v.Digest, Data: v, RetainUntil: v.ExpiresAt.Add(181 * 24 * time.Hour)})
}
func (tx *oauthTx) Family(id string) (d.Family, error) {
	return oauthGet[d.Family](tx, "families", bson.M{"_id": id})
}
func (tx *oauthTx) SaveFamily(v d.Family) error {
	return oauthSave(tx, "families", oauthDocument[d.Family]{ID: v.ID, Data: v, RetainUntil: v.AbsoluteExpiresAt.Add(24 * time.Hour)})
}
func (tx *oauthTx) Access(id string) (d.Access, error) {
	return oauthGet[d.Access](tx, "access", bson.M{"_id": id})
}
func (tx *oauthTx) SaveAccess(v d.Access) error {
	return oauthSave(tx, "access", oauthDocument[d.Access]{ID: v.Digest, Data: v, RetainUntil: v.ExpiresAt.Add(24 * time.Hour)})
}
func (tx *oauthTx) Refresh(id string) (d.Refresh, error) {
	return oauthGet[d.Refresh](tx, "refresh", bson.M{"_id": id})
}
func (tx *oauthTx) SaveRefresh(v d.Refresh) error {
	family, err := tx.Family(v.FamilyID)
	if err != nil {
		return err
	}
	return oauthSave(tx, "refresh", oauthDocument[d.Refresh]{ID: v.Digest, Data: v, RetainUntil: family.AbsoluteExpiresAt.Add(24 * time.Hour)})
}

var _ p.Store = (*OAuthRepository)(nil)

func (tx *oauthTx) SaveRegistration(v d.Registration) error {
	return oauthSave(tx, "registrations", oauthDocument[d.Registration]{ID: v.ClientID + ":" + strconv.Itoa(int(v.Major)), Data: v})
}
func (tx *oauthTx) Registrations(origin, client string) ([]d.Registration, error) {
	query := bson.M{"data.origins": origin, "data.type": "PUBLIC_PKCE"}
	if client != "" {
		query["data.clientid"] = client
	}
	cur, e := tx.r.db.Collection("auth_oauth_registrations").Find(tx.ctx, query, options.Find().SetLimit(65))
	if e != nil {
		return nil, d.ErrUnavailable
	}
	defer cur.Close(tx.ctx)
	var docs []oauthDocument[d.Registration]
	if cur.All(tx.ctx, &docs) != nil || len(docs) > 64 {
		return nil, d.ErrUnavailable
	}
	out := []d.Registration{}
	for _, v := range docs {
		if v.Data.ClientID == "" || v.Data.Major < 1 {
			return nil, d.ErrUnavailable
		}
		out = append(out, v.Data)
	}
	return out, nil
}

func (r *OAuthRepository) CheckSectorSuffix(ctx context.Context, suffix string) error {
	cursor, err := r.db.Collection("auth_oauth_sectors").Find(ctx, bson.M{})
	if err != nil {
		return d.ErrUnavailable
	}
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		var v oauthDocument[d.Sector]
		if cursor.Decode(&v) != nil || !validOAuthDocument(v) || v.Data.Hostname != v.Data.ID+"."+suffix {
			return d.ErrUnavailable
		}
	}
	if cursor.Err() != nil {
		return d.ErrUnavailable
	}
	return nil
}
