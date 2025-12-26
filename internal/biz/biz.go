package biz

import (
	"iwut-auth-center/internal/biz/mail"

	"github.com/go-kratos/kratos/v2/errors"
	"github.com/google/wire"
)

var (
	CaptchaNotUsableError                     = errors.BadRequest("", "captcha not usable")
	UserNotFoundError                         = errors.NotFound("", "user not found or incorrect password")
	UserAlreadyExistsError                    = errors.Conflict("", "user already exists")
	UserHasBeenDeletedError                   = errors.New(410, "", "user has been deleted")
	AskingCaptchaTooFrequentlyError           = errors.New(429, "", "asking captcha too frequently")
	OfficialInfoMemoryLimitationExceededError = errors.New(413, "", "official info memory limitation exceeded")
)

// ProviderSet is biz providers.
var ProviderSet = wire.NewSet(NewAuthUsecase, NewUserUsecase, mail.NewMailUsecase)
