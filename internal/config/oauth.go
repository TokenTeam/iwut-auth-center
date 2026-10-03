package config

import (
	"encoding/json"
	"io"
	"net/url"
	"os"
	"strings"
)

// OAuth is an explicit deployment manifest. Keys remain separate by purpose;
// readiness declarations do not constitute a UI/Gateway acceptance test.
type OAuth struct {
	IPPerMinute          int                  `json:"ipPerMinute"`
	ClientPerMinute      int                  `json:"clientPerMinute"`
	UserConfirmPerMinute int                  `json:"userConfirmPerMinute"`
	ClockObservationFile string               `json:"clockObservationFile"`
	ResourceScopesReady  bool                 `json:"resourceScopesReady"`
	Issuer               string               `json:"issuer"`
	PortalOrigin         string               `json:"portalOrigin"`
	PortalLoginURL       string               `json:"portalLoginURL"`
	SectorSuffix         string               `json:"sectorSuffix"`
	CatalogFile          string               `json:"catalogFile"`
	AppTarget            string               `json:"appTarget"`
	AppServerName        string               `json:"appServerName"`
	AppCAFile            string               `json:"appCAFile"`
	AppPlaintextLoopback bool                 `json:"appPlaintextLoopback"`
	ServiceKeyFile       string               `json:"serviceKeyFile"`
	ServiceKeyID         string               `json:"serviceKeyId"`
	OIDCKeyFile          string               `json:"oidcKeyFile"`
	OIDCKeyID            string               `json:"oidcKeyId"`
	OldOIDCPublicKeys    map[string]string    `json:"oldOidcPublicKeys"`
	DelegationKeyFile    string               `json:"delegationKeyFile"`
	DelegationKeyID      string               `json:"delegationKeyId"`
	RoutePolicyFile      string               `json:"routePolicyFile"`
	PublicEnabled        bool                 `json:"publicEnabled"`
	PortalReady          bool                 `json:"portalReady"`
	GatewayReady         bool                 `json:"gatewayReady"`
	RefreshEnabled       bool                 `json:"refreshEnabled"`
	PublicClientContexts []OAuthClientContext `json:"publicClientContexts"`
}
type OAuthClientContext struct {
	ClientID string `json:"clientId"`
	Major    int32  `json:"rpcApiMajor"`
}

func loadOAuth(lookup LookupEnv) (*OAuth, error) {
	path, ok := lookup("AUTH_CENTER_OAUTH_CONFIG_FILE")
	if !ok {
		return nil, nil
	}
	if path == "" {
		return nil, ErrInvalidConfiguration
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	defer file.Close()
	var cfg OAuth
	dec := json.NewDecoder(io.LimitReader(file, 128*1024))
	dec.DisallowUnknownFields()
	if dec.Decode(&cfg) != nil || dec.Decode(&struct{}{}) != io.EOF {
		return nil, ErrInvalidConfiguration
	}
	u, err := url.Parse(cfg.Issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.HasSuffix(cfg.Issuer, "/") {
		return nil, ErrInvalidConfiguration
	}
	origin := "https://" + u.Host
	if cfg.PortalOrigin != origin {
		return nil, ErrInvalidConfiguration
	}
	login, err := url.Parse(cfg.PortalLoginURL)
	if err != nil || login.Scheme+"://"+login.Host != origin || login.User != nil || login.RawQuery != "" || login.Fragment != "" {
		return nil, ErrInvalidConfiguration
	}
	if cfg.SectorSuffix == "" || strings.ContainsAny(cfg.SectorSuffix, "/:@ ") || cfg.CatalogFile == "" || cfg.AppTarget == "" || cfg.ServiceKeyFile == "" || cfg.OIDCKeyFile == "" || cfg.DelegationKeyFile == "" || cfg.ServiceKeyID == "" || cfg.ServiceKeyID == cfg.OIDCKeyID || cfg.ServiceKeyID == cfg.DelegationKeyID || cfg.PublicEnabled && (!cfg.PortalReady || !cfg.GatewayReady) {
		return nil, ErrInvalidConfiguration
	}
	if cfg.IPPerMinute < 0 || cfg.IPPerMinute > 120 || cfg.ClientPerMinute < 0 || cfg.ClientPerMinute > 300 || cfg.UserConfirmPerMinute < 0 || cfg.UserConfirmPerMinute > 30 || len(cfg.PublicClientContexts) > 64 {
		return nil, ErrInvalidConfiguration
	}
	for _, v := range cfg.PublicClientContexts {
		if v.ClientID == "" || v.Major < 1 {
			return nil, ErrInvalidConfiguration
		}
	}
	return &cfg, nil
}
