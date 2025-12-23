package mail

import (
	"errors"
	"fmt"
	"iwut-auth-center/internal/conf"
	"net/smtp"
	"strings"
)

type Usecase struct {
	loginAuth *LoginAuth
	hostname  string
}

func NewMailUsecase(c *conf.Mail) *Usecase {
	return &Usecase{
		loginAuth: &LoginAuth{
			username: c.GetUsername(),
			password: c.GetPassword(),
		},
		hostname: fmt.Sprintf("%s:%d", c.GetHost(), c.GetPort()),
	}
}

func (m *Usecase) SendVerifyCodeMail(expireTime int32, captcha string, to []string) error {
	if len(to) == 0 {
		return fmt.Errorf("no recipients")
	}
	body := verifyCodeTemplate
	body = strings.ReplaceAll(body, "{{ExpireTime}}", string(expireTime))
	body = strings.ReplaceAll(body, "{{Captcha}}", captcha)
	subject := "掌上吾理--用户验证 " + captcha
	return m.SendEmail(subject, to, body)
}

func (m *Usecase) SendEmail(subject string, recipients []string, body string) error {
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
			return nil, errors.New("Unkown fromServer")
		}
	}
	return nil, nil
}
