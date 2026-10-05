package transport

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/user_profile"
	"github.com/go-kratos/kratos/v2/middleware"
	kt "github.com/go-kratos/kratos/v2/transport"
	"google.golang.org/grpc/codes"
	"io"
	account "iwut-auth-center/internal/account/domain"
	"iwut-auth-center/internal/config"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const UserIdentityHeader = "x-iwut-identity"

type userIdentityContextKey struct{}
type UserIdentityVerifier struct {
	issuer       string
	keys         map[string]*rsa.PublicKey
	maxTTL, skew time.Duration
	now          func() time.Time
}

func NewUserIdentityVerifier(c config.UserIdentityConfig) (*UserIdentityVerifier, error) {
	if strings.TrimSpace(c.Issuer) == "" || len(c.PublicKeyPEMByKID) == 0 || c.MaxTTL <= 0 || c.ClockSkew < 0 {
		return nil, errors.New("invalid user identity configuration")
	}
	v := &UserIdentityVerifier{issuer: c.Issuer, keys: map[string]*rsa.PublicKey{}, maxTTL: c.MaxTTL, skew: c.ClockSkew, now: time.Now}
	for kid, data := range c.PublicKeyPEMByKID {
		k, e := parseServiceRSAPublicKey(data)
		if strings.TrimSpace(kid) == "" || e != nil || k.N == nil || k.N.BitLen() < 2048 {
			return nil, errors.New("invalid user identity public key")
		}
		v.keys[kid] = k
	}
	return v, nil
}
func strictJSONObject(data []byte, target any) error {
	if !utf8.Valid(data) {
		return errors.New("invalid JSON")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return errors.New("expected object")
	}
	seen := map[string]bool{}
	for d.More() {
		k, e := d.Token()
		if e != nil {
			return e
		}
		key := k.(string)
		if seen[key] {
			return errors.New("duplicate claim")
		}
		seen[key] = true
		var raw json.RawMessage
		if e = d.Decode(&raw); e != nil {
			return e
		}
	}
	if _, e = d.Token(); e != nil {
		return e
	}
	if _, e = d.Token(); e != io.EOF {
		return errors.New("trailing JSON")
	}
	return json.Unmarshal(data, target)
}

type verifiedUser struct {
	AccountRevision int64
	AuthID          string
	Permissions     []string
}

func (v *UserIdentityVerifier) Verify(token string) (string, error) {
	identity, err := v.verifyIdentity(token)
	return identity.AuthID, err
}
func (v *UserIdentityVerifier) verifyIdentity(token string) (verifiedUser, error) {
	invalid := errors.New("invalid user identity")
	if v == nil || len(token) > 16384 {
		return verifiedUser{}, invalid
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return verifiedUser{}, invalid
	}
	decoded := make([][]byte, 3)
	for i, p := range parts {
		b, e := base64.RawURLEncoding.Strict().DecodeString(p)
		if e != nil || p == "" || base64.RawURLEncoding.EncodeToString(b) != p {
			return verifiedUser{}, invalid
		}
		decoded[i] = b
	}
	var h serviceJOSEHeader
	if strictJSONObject(decoded[0], &h) != nil || h.Alg != "RS256" || h.Typ != "JWT" || h.Kid == "" {
		return verifiedUser{}, invalid
	}
	key := v.keys[h.Kid]
	if key == nil {
		return verifiedUser{}, invalid
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], decoded[2]) != nil {
		return verifiedUser{}, invalid
	}
	var claims struct {
		AccountRevision *string         `json:"account_revision"`
		Iss             *string         `json:"iss"`
		Sub             *string         `json:"sub"`
		Aud             json.RawMessage `json:"aud"`
		Iat             *float64        `json:"iat"`
		Nbf             *float64        `json:"nbf"`
		Exp             *float64        `json:"exp"`
		Jti             *string         `json:"jti"`
		DeveloperStatus json.RawMessage `json:"developer_status"`
		Permissions     json.RawMessage `json:"permissions"`
	}
	if strictJSONObject(decoded[1], &claims) != nil || claims.Iss == nil || *claims.Iss != v.issuer || claims.Sub == nil || *claims.Sub == "" || claims.Jti == nil || *claims.Jti == "" || claims.Iat == nil || claims.Nbf == nil || claims.Exp == nil || !userAudienceContains(claims.Aud, "iwut-auth-center") {
		return verifiedUser{}, invalid
	}
	if claims.AccountRevision == nil {
		return verifiedUser{}, invalid
	}
	revision, err := strconv.ParseInt(*claims.AccountRevision, 10, 64)
	if err != nil || revision <= 0 || strconv.FormatInt(revision, 10) != *claims.AccountRevision {
		return verifiedUser{}, invalid
	}
	if claims.DeveloperStatus != nil {
		var status string
		if json.Unmarshal(claims.DeveloperStatus, &status) != nil {
			return verifiedUser{}, invalid
		}
		switch status {
		case "PENDING", "APPROVED", "REJECTED", "SUSPENDED":
		default:
			return verifiedUser{}, invalid
		}
	}
	var permissions []string
	if claims.Permissions != nil {
		if bytes.Equal(claims.Permissions, []byte("null")) || json.Unmarshal(claims.Permissions, &permissions) != nil {
			return verifiedUser{}, invalid
		}
		seen := map[string]bool{}
		for _, p := range permissions {
			if p == "" || p != strings.TrimSpace(p) || seen[p] {
				return verifiedUser{}, invalid
			}
			seen[p] = true
		}
	}
	now := float64(v.now().Unix())
	skew := v.skew.Seconds()
	if *claims.Exp <= *claims.Iat || *claims.Exp <= *claims.Nbf || *claims.Exp-*claims.Iat > v.maxTTL.Seconds() || now > *claims.Exp+skew || *claims.Nbf-skew > now || *claims.Iat > now+skew {
		return verifiedUser{}, invalid
	}
	return verifiedUser{AccountRevision: revision, AuthID: *claims.Sub, Permissions: permissions}, nil
}

func userAudienceContains(raw json.RawMessage, want string) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == want
	}
	var many []json.RawMessage
	if json.Unmarshal(raw, &many) != nil {
		return false
	}
	found := false
	for _, item := range many {
		var value *string
		if json.Unmarshal(item, &value) != nil || value == nil {
			return false
		}
		if *value == want {
			found = true
		}
	}
	return found
}
func IsUserProfileOperation(op string) bool {
	switch op {
	case pb.UserProfileService_EditOwnProfile_FullMethodName, pb.UserProfileService_GetOwnProfile_FullMethodName, pb.UserProfileService_GetProfileEditingSchema_FullMethodName:
		return true
	}
	return false
}

// The composition root dispatches this middleware only for the exact profile RPCs.
func UserProfileIdentityMiddleware(v *UserIdentityVerifier) middleware.Middleware {
	return func(next middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req any) (any, error) {
			t, ok := kt.FromServerContext(ctx)
			if !ok || !IsUserProfileOperation(t.Operation()) {
				return nil, transportStatus(codes.PermissionDenied, "USER_PROFILE_ACCESS_DENIED", "profile operation forbidden")
			}
			values := t.RequestHeader().Values(UserIdentityHeader)
			if len(values) == 0 || (len(values) == 1 && values[0] == "") {
				return nil, transportStatus(codes.Unauthenticated, "USER_IDENTITY_REQUIRED", "user identity required")
			}
			if len(values) != 1 {
				return nil, transportStatus(codes.Unauthenticated, "INVALID_USER_IDENTITY", "invalid user identity")
			}
			identity, e := v.verifyIdentity(values[0])
			if e != nil {
				return nil, transportStatus(codes.Unauthenticated, "INVALID_USER_IDENTITY", "invalid user identity")
			}
			return next(context.WithValue(account.WithIdentity(ctx, identity.AuthID, identity.AccountRevision), userIdentityContextKey{}, identity.AuthID), req)
		}
	}
}
func profileAuthID(ctx context.Context) (string, error) {
	id, ok := ctx.Value(userIdentityContextKey{}).(string)
	if !ok || id == "" {
		return "", transportStatus(codes.Unauthenticated, "USER_IDENTITY_REQUIRED", "user identity required")
	}
	return id, nil
}
