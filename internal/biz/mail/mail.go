package mail

import (
	"context"
	"errors"
	"fmt"
	"iwut-auth-center/internal/conf"
	"iwut-auth-center/internal/util"
	"net/smtp"
	"strconv"
	"strings"

	"github.com/go-kratos/kratos/v2/log"
)

type Usecase struct {
	loginAuth *LoginAuth
	hostname  string
	logger    *log.Helper
}

func NewMailUsecase(c *conf.Mail, logger log.Logger) *Usecase {
	return &Usecase{
		loginAuth: &LoginAuth{
			username: c.GetUsername(),
			password: c.GetPassword(),
		},
		hostname: fmt.Sprintf("%s:%d", c.GetHost(), c.GetPort()),
		logger:   log.NewHelper(logger),
	}
}

func (m *Usecase) SendVerifyCodeMail(ctx context.Context, expireTime int32, captcha string, to []string) error {
	if len(to) == 0 {
		reqId := util.RequestIDFrom(ctx)
		m.logger.Errorf("trying to send a mail without recipients. reqId: %s", reqId)
		return fmt.Errorf("no recipients")
	}
	body := mailTemplate
	body = strings.ReplaceAll(body, "{{ExpireTime}}", strconv.FormatInt(int64(expireTime), 10))
	body = strings.ReplaceAll(body, "{{Info}}", "您正在进行验证操作，这是您验证帐户所需的令牌验证码")
	body = strings.ReplaceAll(body, "{{Title}}", "验证码")
	body = strings.ReplaceAll(body, "{{Captcha}}", captcha)
	subject := "掌上吾理--用户验证 " + captcha
	return m.SendEmail(ctx, subject, to, body)
}

func (m *Usecase) SendResetPasswordMail(ctx context.Context, expireTime int32, url string, to []string) error {
	if len(to) == 0 {
		reqId := util.RequestIDFrom(ctx)
		m.logger.Errorf("trying to send a mail without recipients. reqId: %s", reqId)
		return fmt.Errorf("no recipients")
	}
	body := mailTemplate
	body = strings.ReplaceAll(body, "{{ExpireTime}}", strconv.FormatInt(int64(expireTime), 10))
	body = strings.ReplaceAll(body, "{{Info}}", "您正在重置密码，这是您重置密码所需的重置链接")
	body = strings.ReplaceAll(body, "{{Title}}", "链接")
	body = strings.ReplaceAll(body, "{{Captcha}}", "<a href=\""+url+"\">点击跳转</a>")
	subject := "掌上吾理--密码重置链接"
	return m.SendEmail(ctx, subject, to, body)
}

func (m *Usecase) SendEmail(ctx context.Context, subject string, recipients []string, body string) error {
	hostname := m.hostname
	authentication := m.loginAuth
	sender := m.loginAuth.username

	body += "\r\n"

	headers := map[string]string{
		"From":         sender,
		"To":           strings.Join(recipients, ","),
		"Subject":      subject,
		"MIME-Version": "1.0",
		"Content-Type": `text/html; charset="utf-8"`,
	}

	// 构造消息
	var msg strings.Builder
	for k, v := range headers {
		msg.WriteString(k + ": " + v + "\r\n")
	}
	msg.WriteString("\r\n")
	msg.WriteString(body)

	err := smtp.SendMail(
		hostname,
		authentication,
		sender,
		recipients,
		[]byte(msg.String()),
	)

	if err != nil {
		m.logger.Errorf("send email fail. reqId:%s, err: %v", util.RequestIDFrom(ctx), err)
		return err
	}
	return nil
}

type LoginAuth struct {
	username string
	password string
}

func (l LoginAuth) Start(*smtp.ServerInfo) (proto string, toServer []byte, err error) {
	return "LOGIN", []byte{}, nil
}

func (l LoginAuth) Next(fromServer []byte, more bool) (toServer []byte, err error) {
	if more {
		switch string(fromServer) {
		case "Username:":
			return []byte(l.username), nil
		case "Password:":
			return []byte(l.password), nil
		default:
			return nil, errors.New("unknown fromServer")
		}
	}
	return nil, nil
}
