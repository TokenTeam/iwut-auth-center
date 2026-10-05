package transport

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"iwut-auth-center/internal/config"
)

const (
	ServiceAuthorizationHeader          = "authorization"
	PermissionIdentityIssue             = "auth.identity.issue"
	PermissionScopeCatalogRead          = "auth.scope-catalog.read"
	PermissionDeveloperStatusRead       = "auth.developer-status.read"
	PermissionSystemPrincipalResolve    = "auth.system-principal.resolve"
	PurposeAppCenterReviewAutoRejection = "app-center.review-auto-rejection"
	minimumServiceRSAKeyBits            = 2048
)

var (
	errServiceIdentityRequired = errors.New("service identity is required")
	errServiceIdentityInvalid  = errors.New("service identity is invalid")
	errServicePermissionDenied = errors.New("service permission is denied")
)

type serviceClock interface{ Now() time.Time }

type ServiceIdentity struct {
	ServiceID               string
	permissions             map[string]struct{}
	systemPrincipalPurposes map[string]struct{}
	identityAudiences       map[string]struct{}
}

func (identity ServiceIdentity) MayIssueIdentity(audience string) bool {
	_, ok := identity.identityAudiences[audience]
	return ok
}

func (identity ServiceIdentity) HasPermission(permission string) bool {
	_, ok := identity.permissions[permission]
	return ok
}

func (identity ServiceIdentity) MayResolveSystemPrincipal(purpose string) bool {
	_, ok := identity.systemPrincipalPurposes[purpose]
	return ok
}

type registeredServiceCaller struct {
	active                  bool
	publicKeys              map[string]*rsa.PublicKey
	permissions             map[string]struct{}
	systemPrincipalPurposes map[string]struct{}
	identityAudiences       map[string]struct{}
}

type ServiceIdentityVerifier struct {
	callers   map[string]registeredServiceCaller
	audience  string
	maxTTL    time.Duration
	clockSkew time.Duration
	clock     serviceClock
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

func NewServiceIdentityVerifier(configuration config.Config) (*ServiceIdentityVerifier, error) {
	if len(configuration.ServiceCallers) == 0 || configuration.ServiceIdentityMaxTTL <= 0 || configuration.ServiceIdentityClockSkew < 0 {
		return nil, errors.New("service identity verifier: invalid configuration")
	}
	callers := make(map[string]registeredServiceCaller, len(configuration.ServiceCallers))
	for _, registration := range configuration.ServiceCallers {
		if _, duplicate := callers[registration.ServiceID]; duplicate {
			return nil, fmt.Errorf("service identity verifier: duplicate service %q", registration.ServiceID)
		}
		keys := make(map[string]*rsa.PublicKey, len(registration.PublicKeyPEMByKID))
		for kid, pemBytes := range registration.PublicKeyPEMByKID {
			key, err := parseServiceRSAPublicKey(pemBytes)
			if err != nil || key.N == nil || key.N.BitLen() < minimumServiceRSAKeyBits {
				return nil, fmt.Errorf("service identity verifier: invalid key %q for %q", kid, registration.ServiceID)
			}
			keys[kid] = key
		}
		permissions := make(map[string]struct{}, len(registration.Permissions))
		for _, permission := range registration.Permissions {
			switch permission {
			case PermissionOwnerExitRead, PermissionOAuthDelegationIssue, PermissionIdentityIssue, PermissionScopeCatalogRead, PermissionDeveloperStatusRead, PermissionSystemPrincipalResolve:
				permissions[permission] = struct{}{}
			default:
				return nil, fmt.Errorf("service identity verifier: unknown permission %q", permission)
			}
		}
		purposes := make(map[string]struct{}, len(registration.SystemPrincipalPurposes))
		for _, purpose := range registration.SystemPrincipalPurposes {
			if purpose != PurposeAppCenterReviewAutoRejection {
				return nil, fmt.Errorf("service identity verifier: unknown system principal purpose %q", purpose)
			}
			purposes[purpose] = struct{}{}
		}
		audiences := map[string]struct{}{}
		for _, a := range registration.IdentityAudiences {
			if a != "iwut-auth-center" && a != "iwut-app-center" {
				return nil, errors.New("service identity verifier: unknown identity audience")
			}
			if _, ok := audiences[a]; ok {
				return nil, errors.New("service identity verifier: duplicate identity audience")
			}
			audiences[a] = struct{}{}
		}
		_, issue := permissions[PermissionIdentityIssue]
		if issue != (len(audiences) > 0) {
			return nil, errors.New("service identity verifier: issue permission requires audiences")
		}
		callers[registration.ServiceID] = registeredServiceCaller{
			identityAudiences: audiences,
			active:            registration.Status == "ACTIVE", publicKeys: keys, permissions: permissions,
			systemPrincipalPurposes: purposes,
		}
	}
	return &ServiceIdentityVerifier{
		callers: callers, audience: "iwut-auth-center", maxTTL: configuration.ServiceIdentityMaxTTL,
		clockSkew: configuration.ServiceIdentityClockSkew, clock: systemClock{},
	}, nil
}

type serviceJOSEHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

type serviceIdentityClaims struct {
	Iss *string         `json:"iss"`
	Sub *string         `json:"sub"`
	Aud json.RawMessage `json:"aud"`
	Iat *float64        `json:"iat"`
	Nbf *float64        `json:"nbf"`
	Exp *float64        `json:"exp"`
	Jti *string         `json:"jti"`
}

func (verifier *ServiceIdentityVerifier) Verify(token string) (ServiceIdentity, error) {
	if verifier == nil || token == "" || token != strings.TrimSpace(token) {
		return ServiceIdentity{}, errServiceIdentityInvalid
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return ServiceIdentity{}, errServiceIdentityInvalid
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return ServiceIdentity{}, errServiceIdentityInvalid
	}
	var header serviceJOSEHeader
	if json.Unmarshal(headerBytes, &header) != nil || header.Alg != "RS256" || header.Typ != "JWT" || header.Kid == "" {
		return ServiceIdentity{}, errServiceIdentityInvalid
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ServiceIdentity{}, errServiceIdentityInvalid
	}
	var claims serviceIdentityClaims
	if json.Unmarshal(payloadBytes, &claims) != nil || claims.Iss == nil || claims.Sub == nil || claims.Jti == nil ||
		claims.Iat == nil || claims.Nbf == nil || claims.Exp == nil || *claims.Iss == "" || *claims.Sub != *claims.Iss || *claims.Jti == "" {
		return ServiceIdentity{}, errServiceIdentityInvalid
	}
	caller, found := verifier.callers[*claims.Iss]
	if !found || !caller.active {
		return ServiceIdentity{}, errServiceIdentityInvalid
	}
	key := caller.publicKeys[header.Kid]
	if key == nil {
		return ServiceIdentity{}, errServiceIdentityInvalid
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return ServiceIdentity{}, errServiceIdentityInvalid
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) != nil {
		return ServiceIdentity{}, errServiceIdentityInvalid
	}
	if !serviceAudienceContains(claims.Aud, verifier.audience) || *claims.Exp <= *claims.Iat || *claims.Exp <= *claims.Nbf ||
		*claims.Exp-*claims.Iat > verifier.maxTTL.Seconds() {
		return ServiceIdentity{}, errServiceIdentityInvalid
	}
	now := float64(verifier.clock.Now().UTC().Unix())
	skew := verifier.clockSkew.Seconds()
	if now > *claims.Exp+skew || *claims.Nbf-skew > now || *claims.Iat > now+skew {
		return ServiceIdentity{}, errServiceIdentityInvalid
	}
	return ServiceIdentity{ServiceID: *claims.Sub, permissions: caller.permissions, systemPrincipalPurposes: caller.systemPrincipalPurposes, identityAudiences: caller.identityAudiences}, nil
}

func parseServiceRSAPublicKey(data []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	if parsed, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		key, ok := parsed.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("not RSA")
		}
		return key, nil
	}
	return x509.ParsePKCS1PublicKey(block.Bytes)
}

func serviceAudienceContains(raw json.RawMessage, want string) bool {
	var single string
	if json.Unmarshal(raw, &single) == nil {
		return single == want
	}
	var many []string
	if json.Unmarshal(raw, &many) != nil {
		return false
	}
	for _, candidate := range many {
		if candidate == want {
			return true
		}
	}
	return false
}
