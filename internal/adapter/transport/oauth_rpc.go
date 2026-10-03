package transport

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	dp "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/oauth_delegation"
	gp "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/oauth_grant"
	kerrors "github.com/go-kratos/kratos/v2/errors"
	kt "github.com/go-kratos/kratos/v2/transport"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	d "iwut-auth-center/internal/oauth/domain"
	"iwut-auth-center/internal/oauth/usecase"
)

const PermissionOAuthDelegationIssue = "auth.oauth.delegation.issue"

type OAuthGrantService struct {
	gp.UnimplementedOAuthGrantServiceServer
	Service *usecase.Service
}

func oauthGrantMethod(method string) bool {
	return method == gp.OAuthGrantService_ListOwnApplicationGrants_FullMethodName || method == gp.OAuthGrantService_RevokeOwnApplicationGrant_FullMethodName
}
func oauthSession(ctx context.Context, r proto.Message) (string, error) {
	if r == nil || !r.ProtoReflect().IsValid() || hasUnknown(r) || proto.Size(r) > 16*1024 {
		return "", oauthRPCError(d.ErrRequest)
	}
	tr, ok := kt.FromServerContext(ctx)
	if !ok {
		return "", oauthRPCError(d.ErrLogin)
	}
	v := tr.RequestHeader().Values("x-iwut-session")
	for _, h := range []string{"authorization", "cookie", "x-iwut-identity", "x-iwut-access-token"} {
		if len(tr.RequestHeader().Values(h)) > 0 {
			return "", oauthRPCError(d.ErrLogin)
		}
	}
	if len(v) != 1 || !canonicalSessionToken(v[0]) {
		return "", oauthRPCError(d.ErrLogin)
	}
	return v[0], nil
}
func grantProto(g d.Grant) *gp.ApplicationGrant {
	return &gp.ApplicationGrant{GrantId: g.ID, ApplicationId: g.ApplicationID, Channel: g.Channel, Status: g.Status, GrantedScopes: g.Scopes, Revision: g.Revision, DisplayName: g.DisplayName, CreatedAt: timestamppb.New(g.CreatedAt), UpdatedAt: timestamppb.New(g.UpdatedAt)}
}
func (h *OAuthGrantService) ListOwnApplicationGrants(ctx context.Context, r *gp.ListOwnApplicationGrantsRequest) (*gp.ListOwnApplicationGrantsResponse, error) {
	raw, e := oauthSession(ctx, r)
	if e != nil {
		return nil, e
	}
	limit := int(r.PageSize)
	if limit == 0 {
		limit = 20
	}
	rows, e := h.Service.ListGrants(ctx, raw, r.Cursor, limit)
	if e != nil {
		return nil, oauthRPCError(e)
	}
	out := &gp.ListOwnApplicationGrantsResponse{}
	for _, g := range rows {
		out.Grants = append(out.Grants, grantProto(g))
	}
	if len(rows) == limit {
		out.NextCursor = rows[len(rows)-1].ID
	}
	return out, nil
}
func (h *OAuthGrantService) RevokeOwnApplicationGrant(ctx context.Context, r *gp.RevokeOwnApplicationGrantRequest) (*gp.RevokeOwnApplicationGrantResponse, error) {
	raw, e := oauthSession(ctx, r)
	if e != nil {
		return nil, e
	}
	if r.ExpectedRevision == nil || r.Mode != gp.RevocationMode_REVOCATION_MODE_ALL && r.Mode != gp.RevocationMode_REVOCATION_MODE_SCOPES {
		return nil, oauthRPCError(d.ErrRequest)
	}
	g, e := h.Service.RevokeGrant(ctx, raw, r.GrantId, *r.ExpectedRevision, r.Mode == gp.RevocationMode_REVOCATION_MODE_ALL, r.Scopes)
	if e != nil {
		err := oauthRPCError(e)
		if errors.Is(e, d.ErrConflict) {
			b, _ := json.Marshal(map[string]any{"grantId": g.ID, "revision": g.Revision, "status": g.Status, "scopes": g.Scopes})
			return nil, kerrors.Conflict("OAUTH_GRANT_REVISION_CONFLICT", "grant changed").WithMetadata(map[string]string{"currentGrant": string(b)})
		}
		return nil, err
	}
	return &gp.RevokeOwnApplicationGrantResponse{Grant: grantProto(g)}, nil
}
func oauthRPCError(e error) error {
	code := codes.InvalidArgument
	switch {
	case errors.Is(e, d.ErrUnavailable):
		code = codes.Unavailable
	case errors.Is(e, d.ErrLogin), errors.Is(e, d.ErrToken):
		code = codes.Unauthenticated
	case errors.Is(e, d.ErrInsufficient):
		code = codes.PermissionDenied
	case errors.Is(e, d.ErrNotFound):
		code = codes.NotFound
	case errors.Is(e, d.ErrConflict):
		code = codes.Aborted
	}
	return transportStatus(code, "OAUTH_"+strings.ToUpper(e.Error()), "OAuth request failed")
}

type OAuthDelegationCaller struct {
	Routes    []string `json:"routes"`
	Audiences []string `json:"audiences"`
}
type OAuthDelegationService struct {
	dp.UnimplementedOAuthDelegationServiceServer
	Service *usecase.Service
	Digest  string
	Routes  map[string]d.Route
	Callers map[string]OAuthDelegationCaller
}

func (h *OAuthDelegationService) IssueDelegationContext(ctx context.Context, r *dp.IssueDelegationContextRequest) (*dp.IssueDelegationContextResponse, error) {
	caller, ok := serviceIdentityFromContext(ctx)
	if !ok || !caller.HasPermission(PermissionOAuthDelegationIssue) {
		return nil, oauthRPCError(d.ErrInsufficient)
	}
	if r == nil || hasUnknown(r) || proto.Size(r) > 16*1024 {
		return nil, oauthRPCError(d.ErrRequest)
	}
	route, ok := h.Routes[r.RouteId]
	access, allowed := h.Callers[caller.ServiceID]
	if !ok || !allowed || !d.Contains(access.Routes, route.ID) || !d.Contains(access.Audiences, route.Audience) {
		return nil, oauthRPCError(d.ErrInsufficient)
	}
	tr, ok := kt.FromServerContext(ctx)
	if !ok {
		return nil, oauthRPCError(d.ErrToken)
	}
	values := tr.RequestHeader().Values("x-iwut-access-token")
	if len(values) != 1 || !canonicalSessionToken(values[0]) || len(tr.RequestHeader().Values("x-iwut-session")) > 0 || len(tr.RequestHeader().Values("cookie")) > 0 {
		return nil, oauthRPCError(d.ErrToken)
	}
	out, e := h.Service.Delegate(ctx, values[0], d.DelegationRequest{RouteID: r.RouteId, PolicyDigest: r.PolicyDigest, Protocol: r.Protocol, Method: r.Method, TargetPath: r.TargetPath}, route, h.Digest)
	if e != nil {
		return nil, oauthRPCError(e)
	}
	return &dp.IssueDelegationContextResponse{DelegationToken: out.Token, ExpiresAt: timestamppb.New(out.ExpiresAt)}, nil
}
