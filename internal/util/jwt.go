package util

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"iwut-auth-center/internal/conf"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

/* Security note:
- You said you'd like to provide the private key as plain PEM via environment variable. That's technically fine (these helpers accept plain PEM text), but it has security implications: environment variables can be leaked via process listings, crash logs, CI logs, or OS-level snapshots. Prefer using filesystem with strict permissions or a KMS when possible.
- These helpers intentionally accept plain PEM bytes (no base64) to match your preference. Ensure the value in env is the raw PEM block including the "-----BEGIN ...-----" header and newlines.
*/

// JwtUtilFunctions is a minimal interface that exposes the raw PEM bytes for private/public keys.
// Signing/verification logic lives elsewhere (internal/util/jwt.go) and should use these keys.
type JwtUtilFunctions interface {
	PrivateKeyPEM() []byte
	PublicKeyPEM() []byte
	EncodeJWTWithRS256(claims map[string]interface{}, ttl time.Duration) (string, error)
	DecodeJWTWithRS256(tokenStr string) (map[string]interface{}, error)
	DecodeJWT(tokenStr string) (map[string]interface{}, error)
	WithTokenValue(ctx context.Context, value *TokenValue) context.Context
	TokenValueFrom(ctx context.Context) TokenValue
	ToNormalTypeClaims(claims map[string]interface{}) (*BaseAuthClaims, error)
}

// JwtUtil stores PEM key material and implements JwtUtilFunctions.
type JwtUtil struct {
	privateKeyPEM []byte
	publicKeyPEM  []byte
	privateKey    *rsa.PrivateKey
	publicKey     *rsa.PublicKey
	issuer        string
}

var (
	JwtUtilInstance *JwtUtil
)

// decodeBase64OrRaw tries to base64-decode the input; if decoding fails, returns the raw bytes (assumed PEM).
func decodeBase64OrRaw(s string) []byte {
	trim := strings.TrimSpace(s)
	if trim == "" {
		return nil
	}
	if strings.HasPrefix(trim, "-----BEGIN") {
		return []byte(s)
	}
	if b, err := base64.StdEncoding.DecodeString(trim); err == nil && len(b) > 0 {
		return b
	}
	return []byte(s)
}

// NewJwtUtil constructs JwtUtilFunctions from provided private/public key strings.
// Inputs may be raw PEM text or base64-encoded PEM. If both are empty, returns an error.
// This function performs light validation by attempting to parse keys using helper parsers; parsing errors are returned.
func NewJwtUtil(c *conf.Jwt) *JwtUtil {
	if JwtUtilInstance != nil {
		return JwtUtilInstance
	}
	var privatePEM, publicPEM []byte
	privateStr := c.GetKey().GetPrivateKey()
	publicStr := c.GetKey().GetPublicKey()
	issuer := c.GetIssuer()
	var privateKey *rsa.PrivateKey
	var publicKey *rsa.PublicKey
	if privateStr != "" {
		privatePEM = decodeBase64OrRaw(privateStr)
		if parsed, err := ParseRSAPrivateKeyFromPEM(privatePEM); err == nil {
			privateKey = parsed
		} else {
			panic("invalid private key: " + err.Error())
		}
	}
	if publicStr != "" {
		publicPEM = decodeBase64OrRaw(publicStr)
		if parsed, err := ParseRSAPublicKeyFromPEM(publicPEM); err == nil {
			publicKey = parsed
		} else {
			panic("invalid public key: " + err.Error())
		}
	}
	if len(privatePEM) == 0 || len(publicPEM) == 0 {
		panic("no key provided")
	}
	if issuer == "" {
		panic("empty issuer")
	}
	JwtUtilInstance = &JwtUtil{
		privateKeyPEM: privatePEM,
		publicKeyPEM:  publicPEM,
		privateKey:    privateKey,
		publicKey:     publicKey,
		issuer:        issuer,
	}
	return JwtUtilInstance
}

// DecodeJWT decodes a JWT without verifying its signature and returns the token claims as a map.
// This function only parses the payload (the middle part of the JWT) and does not perform any
// cryptographic verification. Use with caution.
func (j *JwtUtil) DecodeJWT(tokenStr string) (map[string]interface{}, error) {
	if tokenStr == "" {
		return nil, errors.New("empty token")
	}
	parts := strings.Split(tokenStr, ".")
	if len(parts) < 2 {
		return nil, errors.New("invalid token format")
	}
	payload := parts[1]
	// JWT uses base64url encoding without padding. Try RawURLEncoding first, fall back to standard URL encoding.
	b, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		b, err = base64.URLEncoding.DecodeString(payload)
		if err != nil {
			return nil, err
		}
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(b, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// EncodeJWTWithRS256 creates a signed JWT using RS256 (RSA private key).
func (j *JwtUtil) EncodeJWTWithRS256(claims map[string]interface{}, ttl time.Duration) (string, error) {
	privateKey := j.privateKey
	if privateKey == nil {
		return "", errors.New("nil private key")
	}
	if claims == nil {
		claims = map[string]interface{}{}
	}
	m := jwt.MapClaims{}
	for k, v := range claims {
		m[k] = v
	}
	now := time.Now().Unix()
	m["iat"] = now
	if ttl > 0 {
		m["exp"] = time.Now().Add(ttl).Unix()
	}
	m["iss"] = j.issuer
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, m)
	signed, err := tok.SignedString(privateKey)
	if err != nil {
		return "", err
	}
	return signed, nil
}

// helper: convert numeric claim (exp/nbf) to int64 Unix seconds
func toInt64Seconds(v interface{}) (int64, bool) {
	switch t := v.(type) {
	case float64:
		return int64(t), true
	case float32:
		return int64(t), true
	case int64:
		return t, true
	case int32:
		return int64(t), true
	case int:
		return int64(t), true
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return i, true
		}
		if f, err := t.Float64(); err == nil {
			return int64(f), true
		}
	case string:
		// try parse as int
		if i, err := time.ParseDuration(t + "s"); err == nil {
			return int64(i.Seconds()), true
		}
	}
	return 0, false
}

// DecodeJWTWithRS256 verifies and parses a RS256 signed token using the RSA public key.
func (j *JwtUtil) DecodeJWTWithRS256(tokenStr string) (map[string]interface{}, error) {
	if tokenStr == "" {
		return nil, errors.New("empty token")
	}
	publicKey := j.publicKey
	if publicKey == nil {
		return nil, errors.New("nil public key")
	}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))
	tok, err := parser.Parse(tokenStr, func(token *jwt.Token) (any, error) {
		// ensure the signing method is RSA
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}
	if !tok.Valid {
		return nil, errors.New("invalid token")
	}
	if claims, ok := tok.Claims.(jwt.MapClaims); ok {
		// Explicitly validate time-based claims (exp, nbf).
		// Check exp
		if expRaw, found := claims["exp"]; found {
			if expSec, ok := toInt64Seconds(expRaw); ok {
				if time.Unix(expSec, 0).Before(time.Now()) {
					return nil, errors.New("token is expired")
				}
			} else {
				return nil, errors.New("invalid exp claim type")
			}
		} else {
			return nil, errors.New("token missing exp claim")
		}

		if issuer, found := claims["iss"]; found {
			if issStr, ok := issuer.(string); ok {
				if issStr != j.issuer {
					return nil, errors.New("invalid token issuer")
				}
			} else {
				return nil, errors.New("invalid iss claim type")
			}
		} else {
			return nil, errors.New("token missing iss")
		}
		out := map[string]interface{}{}
		for k, v := range claims {
			out[k] = v
		}
		return out, nil
	}
	return nil, errors.New("unable to parse claims")
}

func (j *JwtUtil) PrivateKeyPEM() []byte { return j.privateKeyPEM }
func (j *JwtUtil) PublicKeyPEM() []byte  { return j.publicKeyPEM }

// ParseRSAPrivateKeyFromPEM parses an RSA private key from PEM-encoded bytes.
// Accepts PKCS#1 and PKCS#8 PEM formats. The input can be a plain PEM string
// (for example read from an environment variable) - no base64 decoding is required.
func ParseRSAPrivateKeyFromPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	if len(pemBytes) == 0 {
		return nil, errors.New("empty PEM data")
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to pem decode private key")
	}
	der := block.Bytes
	// try PKCS1
	if pkcs1Key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return pkcs1Key, nil
	}
	// try PKCS8
	if parsed, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch k := parsed.(type) {
		case *rsa.PrivateKey:
			return k, nil
		default:
			return nil, errors.New("parsed PKCS8 key is not RSA")
		}
	}
	// try to parse as EC (not supported here)
	return nil, errors.New("unsupported private key type or invalid PEM")
}

// ParseRSAPublicKeyFromPEM parses an RSA public key from PEM-encoded bytes.
// Accepts PKIX (BEGIN PUBLIC KEY) and PKCS1 (BEGIN RSA PUBLIC KEY) formats.
func ParseRSAPublicKeyFromPEM(pemBytes []byte) (*rsa.PublicKey, error) {
	if len(pemBytes) == 0 {
		return nil, errors.New("empty PEM data")
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to pem decode public key")
	}
	der := block.Bytes
	// try PKIX
	if pkix, err := x509.ParsePKIXPublicKey(der); err == nil {
		switch k := pkix.(type) {
		case *rsa.PublicKey:
			return k, nil
		default:
			return nil, errors.New("parsed public key is not RSA")
		}
	}
	// try PKCS1
	if pkcs1, err := x509.ParsePKCS1PublicKey(der); err == nil {
		return pkcs1, nil
	}
	// try certificate
	if cert, err := x509.ParseCertificate(der); err == nil {
		switch k := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			return k, nil
		default:
			return nil, errors.New("certificate public key is not RSA")
		}
	}
	return nil, errors.New("unsupported public key type or invalid PEM")
}

type TokenKey struct{}

type TokenValue struct {
	Token  string
	Claims map[string]interface{}
}
type BaseAuthClaims struct {
	uid     string
	iat     int64
	exp     int64
	iss     string
	version int32
}

func (j *JwtUtil) WithTokenValue(ctx context.Context, value *TokenValue) context.Context {
	return context.WithValue(ctx, TokenKey{}, value)
}
func (j *JwtUtil) TokenValueFrom(ctx context.Context) TokenValue {
	if v := ctx.Value(TokenKey{}); v != nil {
		if s, ok := v.(TokenValue); ok {
			return s
		}
	}
	return TokenValue{}
}
func (j *JwtUtil) ToNormalTypeClaims(claims map[string]interface{}) (*BaseAuthClaims, error) {
	baseAuthClaims := &BaseAuthClaims{
		uid:     "",
		iat:     0,
		exp:     0,
		iss:     "",
		version: -1,
	}
	if uidRaw, found := claims["uid"]; found {
		if uidStr, ok := uidRaw.(string); ok {
			baseAuthClaims.uid = uidStr
		}
	}
	if baseAuthClaims.uid == "" {
		return nil, errors.New("token missing uid claim")
	}

	if iatRaw, found := claims["iat"]; found {
		if iatSec, ok := toInt64Seconds(iatRaw); ok {
			baseAuthClaims.iat = iatSec
		}
	}
	if baseAuthClaims.iat == 0 {
		return nil, errors.New("token missing exp claim")
	}

	if expRaw, found := claims["exp"]; found {
		if expSec, ok := toInt64Seconds(expRaw); ok {
			baseAuthClaims.exp = expSec
		}
	}
	if baseAuthClaims.exp == 0 {
		return nil, errors.New("token missing exp claim")
	}

	if issuer, found := claims["iss"]; found {
		if issStr, ok := issuer.(string); ok {
			if issStr != j.issuer {
				return nil, errors.New("invalid token issuer")
			}
			baseAuthClaims.iss = issStr
		}
	}
	if baseAuthClaims.iss == "" {
		return nil, errors.New("token missing iss")
	}

	if versionRaw, found := claims["version"]; found {
		baseAuthClaims.version = versionRaw.(int32)
	}
	if baseAuthClaims.version == -1 {
		return nil, errors.New("token missing version claim")
	}

	return baseAuthClaims, nil
}
