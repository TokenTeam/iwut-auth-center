package biz

import (
	"fmt"
	"iwut-auth-center/internal/biz/mail"

	"github.com/google/wire"
)

var (
	CaptchaNotUsableError           = &ReturnableError{Code: 400, Message: "captcha not usable"}
	UserNotFoundError               = &ReturnableError{Code: 404, Message: "user not found or incorrect password"}
	UserAlreadyExistsError          = &ReturnableError{Code: 409, Message: "user already exists"}
	UserHasBeenDeletedError         = &ReturnableError{Code: 410, Message: "user has been deleted"}
	AskingCaptchaTooFrequentlyError = &ReturnableError{Code: 429, Message: "asking captcha too frequently"}
)

type ReturnableError struct {
	Code    int32
	Message string
}

func (e *ReturnableError) Error() string {
	return fmt.Sprintf("code: %d, message: %s", e.Code, e.Message)
}

// ProviderSet is biz providers.
var ProviderSet = wire.NewSet(NewAuthUsecase, NewUserUsecase, mail.NewMailUsecase)
