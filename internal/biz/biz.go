package biz

import (
	"iwut-auth-center/internal/biz/mail"

	"github.com/go-kratos/kratos/v2/errors"
	"github.com/google/wire"
)

var (
	CaptchaNotUsableError                     = errors.BadRequest("", "captcha not usable")
	UserNotFoundError                         = errors.NotFound("", "user not found or cannot be accessed")
	UserAlreadyExistsError                    = errors.Conflict("", "user already exists")
	UserPermissionDeniedError                 = errors.Forbidden("", "user permission denied")
	UserHasBeenDeletedError                   = errors.New(410, "", "user has been deleted")
	AskingCaptchaTooFrequentlyError           = errors.New(429, "", "asking captcha too frequently")
	OfficialInfoMemoryLimitationExceededError = errors.New(413, "", "official info memory limitation exceeded")
	OAuth2InfoMemoryLimitationExceededError   = errors.New(413, "", "oauth2 info memory limitation exceeded")
)

// ProviderSet is biz providers.
var ProviderSet = wire.NewSet(NewAuditUsecase, NewAuthUsecase, NewUserUsecase, NewOauth2Usecase, mail.NewMailUsecase)
