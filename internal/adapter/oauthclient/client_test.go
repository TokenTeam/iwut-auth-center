package oauthclient

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	pb "github.com/TokenTeam/iwut-api-proto/gen/go/app_center/v1/oauth_client"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
	"iwut-auth-center/internal/adapter/oauthcrypto"
	d "iwut-auth-center/internal/oauth/domain"
)

type channelProvider struct {
	pb.OAuthClientProviderServiceClient
	t          *testing.T
	runtime    *pb.RuntimeConfiguration
	membership string
	entries    []*pb.PublishedRedirectEntry
}

func (p *channelProvider) GetClientConfiguration(_ context.Context, r *pb.GetClientConfigurationRequest, _ ...grpc.CallOption) (*pb.GetClientConfigurationResponse, error) {
	return &pb.GetClientConfigurationResponse{Configuration: &pb.OAuthClientConfiguration{ClientId: r.ClientId, ApplicationId: p.runtime.ApplicationId, Type: p.runtime.Type, Channel: p.runtime.Channel, RegistrationRevision: p.runtime.RegistrationRevision, AuthorizationEpoch: p.runtime.AuthorizationEpoch, Status: pb.OAuthClientStatus_OAUTH_CLIENT_STATUS_ACTIVE, TokenEndpointAuthMethod: pb.TokenEndpointAuthMethod_TOKEN_ENDPOINT_AUTH_METHOD_NONE}}, nil
}
func (p *channelProvider) ResolveClientRuntimeConfiguration(_ context.Context, r *pb.ResolveClientRuntimeConfigurationRequest, _ ...grpc.CallOption) (*pb.ResolveClientRuntimeConfigurationResponse, error) {
	if r.Channel != p.runtime.Channel {
		p.t.Fatalf("runtime channel rewritten: %v", r.Channel)
	}
	return &pb.ResolveClientRuntimeConfigurationResponse{Runtime: p.runtime}, nil
}
func (p *channelProvider) ResolveAuthorizationContext(_ context.Context, r *pb.ResolveAuthorizationContextRequest, _ ...grpc.CallOption) (*pb.ResolveAuthorizationContextResponse, error) {
	if r.Channel != p.runtime.Channel {
		p.t.Fatalf("authorization channel rewritten: %v", r.Channel)
	}
	return &pb.ResolveAuthorizationContextResponse{Context: &pb.AuthorizationContext{Runtime: p.runtime, AuthId: r.AuthId, TesterMembershipId: p.membership}}, nil
}
func (p *channelProvider) GetApplicationPublishedRedirects(_ context.Context, r *pb.GetApplicationPublishedRedirectsRequest, _ ...grpc.CallOption) (*pb.GetApplicationPublishedRedirectsResponse, error) {
	return &pb.GetApplicationPublishedRedirectsResponse{Snapshot: &pb.PublishedRedirectSnapshot{ApplicationId: r.ApplicationId, Entries: p.entries, RedirectUris: []string{"https://client.example/cb"}, ObservedAt: p.runtime.ObservedAt, ValidUntil: p.runtime.ValidUntil}}, nil
}
func TestOAuthProviderChannelsAndMembership(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, ch := range []string{"TEST", "STABLE", "GREY"} {
		t.Run(ch, func(t *testing.T) {
			now := time.Now()
			rt := &pb.RuntimeConfiguration{ClientId: "client", ApplicationId: "app", Channel: channelProto(ch), Type: pb.OAuthClientType_OAUTH_CLIENT_TYPE_PUBLIC_PKCE, RpcApiMajor: 1, RegistrationRevision: 1, AuthorizationEpoch: 1, AdminAuthId: "owner", VersionId: "version", PublicationRevision: 1, Display: &pb.ApplicationDisplay{ProfileRevisionId: "profile", DisplayName: "App"}, RequiredScopes: []string{"openid"}, RedirectUris: []string{"https://client.example/cb"}, ObservedAt: timestamppb.New(now), ValidUntil: timestamppb.New(now.Add(5 * time.Second))}
			provider := &channelProvider{t: t, runtime: rt}
			if ch == "TEST" {
				provider.membership = "episode"
			}
			c := &Client{rpc: provider, key: oauthcrypto.Key{ID: "service", Private: key}}
			client := d.Client{ID: "client", ApplicationID: "app", Channel: ch, Type: "PUBLIC_PKCE", RegistrationRevision: 1, AuthorizationEpoch: 1}
			resolved, err := c.Client(t.Context(), client.ID)
			if err != nil || resolved != client {
				t.Fatal("client channel", resolved, err)
			}
			snapshot, err := c.Runtime(t.Context(), client, 1)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = c.Authorize(t.Context(), snapshot, "user"); err != nil {
				t.Fatal(err)
			}
			if ch == "TEST" {
				provider.membership = ""
			} else {
				provider.membership = "unexpected-episode"
			}
			if _, err = c.Authorize(t.Context(), snapshot, "user"); err == nil {
				t.Fatal("invalid membership shape accepted")
			}
			for _, entryChannel := range []pb.OAuthChannel{pb.OAuthChannel_OAUTH_CHANNEL_TEST, pb.OAuthChannel_OAUTH_CHANNEL_GREY, pb.OAuthChannel_OAUTH_CHANNEL_STABLE} {
				provider.entries = append(provider.entries, &pb.PublishedRedirectEntry{Channel: entryChannel, RpcApiMajor: 1, VersionId: "version", PublicationRevision: 1})
			}
			if snap, err := c.Redirects(t.Context(), "app"); err != nil || len(snap.Entries) != 3 {
				t.Fatal("mixed-channel redirects", err)
			}
			provider.entries = append(provider.entries, &pb.PublishedRedirectEntry{Channel: pb.OAuthChannel(99), RpcApiMajor: 1, VersionId: "version", PublicationRevision: 1})
			if _, err := c.Redirects(t.Context(), "app"); err == nil {
				t.Fatal("unknown redirect channel accepted")
			}
			provider.entries[len(provider.entries)-1] = nil
			if _, err := c.Redirects(t.Context(), "app"); err == nil {
				t.Fatal("nil redirect entry accepted")
			}
			originalChannel := rt.Channel
			rt.Channel = pb.OAuthChannel_OAUTH_CHANNEL_GREY
			if ch == "GREY" {
				rt.Channel = pb.OAuthChannel_OAUTH_CHANNEL_STABLE
			}
			if _, err := runtime(rt, client, 1); err == nil {
				t.Fatal("cross-channel runtime accepted")
			}
			rt.Channel = originalChannel
			rt.Channel = pb.OAuthChannel(99)
			if _, err := c.Client(t.Context(), client.ID); err == nil {
				t.Fatal("unknown client channel accepted")
			}
			if _, err := runtime(rt, client, 1); err == nil {
				t.Fatal("unknown channel accepted")
			}
		})
	}
}
