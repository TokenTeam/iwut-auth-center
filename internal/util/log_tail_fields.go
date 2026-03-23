package util

import (
	"context"

	"github.com/go-kratos/kratos/v2/log"
)

func RequestTailProcess() []any {
	return []any{
		"ip", log.Valuer(func(ctx context.Context) any {
			ip := RequestIpFrom(ctx)
			if ip == nil {
				return ""
			}
			return *ip
		}),
		"ua", log.Valuer(func(ctx context.Context) any {
			ua := RequestUAFrom(ctx)
			if ua == nil {
				return ""
			}
			return *ua
		}),
		"user_id", log.Valuer(func(ctx context.Context) any {
			userID := RequestUserIDFrom(ctx)
			if userID == nil {
				return ""
			}
			return *userID
		}),
		"client_id", log.Valuer(func(ctx context.Context) any {
			clientID := RequestClientIDFrom(ctx)
			if clientID == nil {
				return ""
			}
			return *clientID
		}),
	}
}

func RequestUserIDFrom(ctx context.Context) *string {
	if jwtUserID := RequestUserIDFromJWT(ctx); jwtUserID != nil {
		return jwtUserID
	}
	if audit := RequestAuditFrom(ctx); audit != nil {
		if userID := audit.UserID(); userID != "" {
			uid := userID
			return &uid
		}
	}
	return nil
}

func RequestClientIDFrom(ctx context.Context) *string {
	if jwtClientID := RequestClientIDFromJWT(ctx); jwtClientID != nil {
		return jwtClientID
	}
	if audit := RequestAuditFrom(ctx); audit != nil {
		if clientID := audit.ClientID(); clientID != "" {
			cid := clientID
			return &cid
		}
	}
	return nil
}

func RequestUserIDFromJWT(ctx context.Context) *string {
	if JwtUtilInstance == nil {
		return nil
	}
	jwtValue := JwtUtilInstance.TokenValueFrom(ctx)
	if jwtValue == nil {
		return nil
	}
	if jwtValue.BaseAuthClaims != nil && jwtValue.BaseAuthClaims.Uid != "" {
		uid := jwtValue.BaseAuthClaims.Uid
		return &uid
	}
	if jwtValue.OAuthClaims != nil && jwtValue.OAuthClaims.Uid != "" {
		uid := jwtValue.OAuthClaims.Uid
		return &uid
	}
	return nil
}

func RequestClientIDFromJWT(ctx context.Context) *string {
	if JwtUtilInstance == nil {
		return nil
	}
	jwtValue := JwtUtilInstance.TokenValueFrom(ctx)
	if jwtValue == nil {
		return nil
	}
	if jwtValue.OAuthClaims != nil && jwtValue.OAuthClaims.Azp != "" {
		azp := jwtValue.OAuthClaims.Azp
		return &azp
	}
	return nil
}
