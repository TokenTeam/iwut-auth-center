// Package oauthclient is the Auth consumer of App019. Responses are never
// cached: every security decision obtains the provider's current snapshot.
package oauthclient

import (
	"context"
	"net/url"
	"time"

	pb "github.com/TokenTeam/iwut-api-proto/gen/go/app_center/v1/oauth_client"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"iwut-auth-center/internal/adapter/oauthcrypto"
	d "iwut-auth-center/internal/oauth/domain"
)

type Client struct {
	rpc pb.OAuthClientProviderServiceClient
	key oauthcrypto.Key
}

func New(conn grpc.ClientConnInterface, key oauthcrypto.Key) *Client {
	return &Client{pb.NewOAuthClientProviderServiceClient(conn), key}
}
func (c *Client) context(ctx context.Context) (context.Context, context.CancelFunc, error) {
	now := time.Now()
	token, err := oauthcrypto.Sign(c.key, "JWT", map[string]any{"iss": "iwut-auth-center", "sub": "iwut-auth-center", "aud": "iwut-app-center", "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(30 * time.Second).Unix(), "jti": uuid.NewString()})
	if err != nil {
		return nil, func() {}, d.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	return metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+token)), cancel, nil
}
func providerError(err, errorKind error) error {
	if err == nil {
		return nil
	}
	switch status.Code(err) {
	case codes.NotFound, codes.FailedPrecondition, codes.InvalidArgument:
		return errorKind
	default:
		return d.ErrUnavailable
	}
}
func (c *Client) Client(ctx context.Context, id string) (d.Client, error) {
	ctx, cancel, err := c.context(ctx)
	if err != nil {
		return d.Client{}, err
	}
	defer cancel()
	r, err := c.rpc.GetClientConfiguration(ctx, &pb.GetClientConfigurationRequest{ClientId: id})
	if err != nil {
		return d.Client{}, providerError(err, d.ErrClient)
	}
	v := r.GetConfiguration()
	if v == nil || v.ClientId != id || v.ApplicationId == "" || v.Status != pb.OAuthClientStatus_OAUTH_CLIENT_STATUS_ACTIVE || v.RegistrationRevision < 1 || v.AuthorizationEpoch < 1 || !d.ValidChannel(channelName(v.Channel)) {
		return d.Client{}, d.ErrClient
	}
	typ := ""
	switch v.Type {
	case pb.OAuthClientType_OAUTH_CLIENT_TYPE_PUBLIC_PKCE:
		if v.TokenEndpointAuthMethod != pb.TokenEndpointAuthMethod_TOKEN_ENDPOINT_AUTH_METHOD_NONE || v.CredentialRevision != nil {
			return d.Client{}, d.ErrUnavailable
		}
		typ = "PUBLIC_PKCE"
	case pb.OAuthClientType_OAUTH_CLIENT_TYPE_CONFIDENTIAL_SECRET:
		if v.TokenEndpointAuthMethod != pb.TokenEndpointAuthMethod_TOKEN_ENDPOINT_AUTH_METHOD_CLIENT_SECRET_BASIC || v.GetCredentialRevision() < 1 {
			return d.Client{}, d.ErrUnavailable
		}
		typ = "CONFIDENTIAL_SECRET"
	default:
		return d.Client{}, d.ErrUnavailable
	}
	return d.Client{ID: id, ApplicationID: v.ApplicationId, Type: typ, Channel: channelName(v.Channel), RegistrationRevision: v.RegistrationRevision, AuthorizationEpoch: v.AuthorizationEpoch, CredentialRevision: v.GetCredentialRevision()}, nil
}
func (c *Client) VerifySecret(ctx context.Context, cl d.Client, secret string) (bool, error) {
	ctx, cancel, err := c.context(ctx)
	if err != nil {
		return false, err
	}
	defer cancel()
	r, err := c.rpc.VerifyClientSecret(ctx, &pb.VerifyClientSecretRequest{ClientId: cl.ID, ClientSecret: secret, ExpectedCredentialRevision: cl.CredentialRevision})
	if err != nil {
		return false, providerError(err, d.ErrClient)
	}
	return r.GetVerified() && r.GetCredentialRevision() == cl.CredentialRevision, nil
}
func runtime(v *pb.RuntimeConfiguration, cl d.Client, major int32) (d.Runtime, error) {
	if v == nil || v.ClientId != cl.ID || v.ApplicationId != cl.ApplicationID || !d.ValidChannel(cl.Channel) || channelName(v.Channel) != cl.Channel || v.RpcApiMajor != major || v.RegistrationRevision != cl.RegistrationRevision || v.AuthorizationEpoch != cl.AuthorizationEpoch || v.AdminAuthId == "" || v.VersionId == "" || v.PublicationRevision < 1 || v.Display == nil || v.Display.ProfileRevisionId == "" || v.Display.DisplayName == "" || v.ObservedAt == nil || v.ValidUntil == nil || v.ObservedAt.CheckValid() != nil || v.ValidUntil.CheckValid() != nil || !d.ValidScopes(v.RequiredScopes) || !d.ValidScopes(v.OptionalScopes) || len(d.Intersect(v.RequiredScopes, v.OptionalScopes)) > 0 || len(v.RedirectUris) == 0 {
		return d.Runtime{}, d.ErrUnavailable
	}
	if cl.Type == "PUBLIC_PKCE" && v.Type != pb.OAuthClientType_OAUTH_CLIENT_TYPE_PUBLIC_PKCE || cl.Type == "CONFIDENTIAL_SECRET" && v.Type != pb.OAuthClientType_OAUTH_CLIENT_TYPE_CONFIDENTIAL_SECRET {
		return d.Runtime{}, d.ErrUnavailable
	}
	for _, uri := range v.RedirectUris {
		u, err := url.Parse(uri)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
			return d.Runtime{}, d.ErrUnavailable
		}
	}
	r := d.Runtime{Client: cl, Major: major, AdminID: v.AdminAuthId, VersionID: v.VersionId, ProfileID: v.Display.ProfileRevisionId, DisplayName: v.Display.DisplayName, PublicationRevision: v.PublicationRevision, Redirects: v.RedirectUris, Required: v.RequiredScopes, Optional: v.OptionalScopes, ObservedAt: v.ObservedAt.AsTime(), ValidUntil: v.ValidUntil.AsTime()}
	if !r.Fresh(time.Now()) {
		return d.Runtime{}, d.ErrUnavailable
	}
	return r, nil
}
func (c *Client) Runtime(ctx context.Context, cl d.Client, major int32) (d.Runtime, error) {
	ctx, cancel, err := c.context(ctx)
	if err != nil {
		return d.Runtime{}, err
	}
	defer cancel()
	r, err := c.rpc.ResolveClientRuntimeConfiguration(ctx, &pb.ResolveClientRuntimeConfigurationRequest{ClientId: cl.ID, Channel: channelProto(cl.Channel), RpcApiMajor: major, ExpectedRegistrationRevision: cl.RegistrationRevision})
	if err != nil {
		return d.Runtime{}, providerError(err, d.ErrGrant)
	}
	return runtime(r.GetRuntime(), cl, major)
}
func (c *Client) Authorize(ctx context.Context, rt d.Runtime, auth string) (d.Runtime, error) {
	ctx, cancel, err := c.context(ctx)
	if err != nil {
		return d.Runtime{}, err
	}
	defer cancel()
	r, err := c.rpc.ResolveAuthorizationContext(ctx, &pb.ResolveAuthorizationContextRequest{ClientId: rt.Client.ID, AuthId: auth, Channel: channelProto(rt.Client.Channel), RpcApiMajor: rt.Major, ExpectedRegistrationRevision: rt.Client.RegistrationRevision, ExpectedRuntimeVersion: &pb.RuntimeVersion{VersionId: rt.VersionID, PublicationRevision: rt.PublicationRevision, ProfileRevisionId: rt.ProfileID, AdminAuthId: rt.AdminID}})
	if err != nil {
		return d.Runtime{}, providerError(err, d.ErrGrant)
	}
	v := r.GetContext()
	if v == nil || v.AuthId != auth || !d.ValidMembership(rt.Client.Channel, v.TesterMembershipId) {
		return d.Runtime{}, d.ErrUnavailable
	}
	out, err := runtime(v.Runtime, rt.Client, rt.Major)
	if err != nil {
		return out, err
	}
	out.TesterID = v.TesterMembershipId
	return out, nil
}
func (c *Client) Redirects(ctx context.Context, app string) (d.RedirectSnapshot, error) {
	ctx, cancel, err := c.context(ctx)
	if err != nil {
		return d.RedirectSnapshot{}, err
	}
	defer cancel()
	r, err := c.rpc.GetApplicationPublishedRedirects(ctx, &pb.GetApplicationPublishedRedirectsRequest{ApplicationId: app})
	if err != nil {
		return d.RedirectSnapshot{}, providerError(err, d.ErrNotFound)
	}
	v := r.GetSnapshot()
	if v == nil || v.ApplicationId != app || v.ObservedAt == nil || v.ValidUntil == nil || v.ObservedAt.CheckValid() != nil || v.ValidUntil.CheckValid() != nil {
		return d.RedirectSnapshot{}, d.ErrUnavailable
	}
	out := d.RedirectSnapshot{ApplicationID: app, URIs: v.RedirectUris, ObservedAt: v.ObservedAt.AsTime(), ValidUntil: v.ValidUntil.AsTime()}
	for _, e := range v.Entries {
		if e == nil || !d.ValidChannel(channelName(e.Channel)) || e.RpcApiMajor < 1 || e.VersionId == "" || e.PublicationRevision < 1 {
			return out, d.ErrUnavailable
		}
		out.Entries = append(out.Entries, d.RedirectEntry{Channel: channelName(e.Channel), Major: e.RpcApiMajor, VersionID: e.VersionId, PublicationRevision: e.PublicationRevision})
	}
	return out, nil
}

// Explicit mappings reject unspecified/future values instead of granting them
// the semantics of another channel.
func channelName(channel pb.OAuthChannel) string {
	switch channel {
	case pb.OAuthChannel_OAUTH_CHANNEL_TEST:
		return "TEST"
	case pb.OAuthChannel_OAUTH_CHANNEL_STABLE:
		return "STABLE"
	case pb.OAuthChannel_OAUTH_CHANNEL_GREY:
		return "GREY"
	default:
		return ""
	}
}
func channelProto(channel string) pb.OAuthChannel {
	switch channel {
	case "TEST":
		return pb.OAuthChannel_OAUTH_CHANNEL_TEST
	case "STABLE":
		return pb.OAuthChannel_OAUTH_CHANNEL_STABLE
	case "GREY":
		return pb.OAuthChannel_OAUTH_CHANNEL_GREY
	default:
		return pb.OAuthChannel_OAUTH_CHANNEL_UNSPECIFIED
	}
}
