package util

import (
	"crypto/sha256"
	"encoding/base64"
	"iwut-auth-center/internal/conf"
)

type Sha256UtilInterface interface {
	HashPassword(password string) string
}
type Sha256Util struct {
	salt string
}

var (
	Sha256UtilInstance *Sha256Util
)

func NewSha256Util(c *conf.Jwt) *Sha256Util {
	if Sha256UtilInstance != nil {
		return Sha256UtilInstance
	}
	Sha256UtilInstance = &Sha256Util{salt: c.GetSalt()}
	return Sha256UtilInstance
}

// HashPassword 该函数逻辑试图与之前的 C# iwut-Auth 保持一致 但是仍需更多测试 因为我还不清楚传入的secret是怎样的 即kotlin段对密码进行了何种处理
func (s *Sha256Util) HashPassword(password string) string {
	h := sha256.New()
	salt := s.salt
	h.Write([]byte(salt))
	h.Write([]byte(password))
	h.Write([]byte(salt))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
