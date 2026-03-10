package util

import (
	"regexp"
	"strings"
)

// 预编译正则：匹配常见敏感字段，支持前缀/后缀（如 user_email, password_hash）
// 匹配格式如：email:"xxx" 或 password:123
var piiRegex = regexp.MustCompile(`(?i)\b([a-z0-9_]*(?:password|token|secret|email|phone|mobile|id_card)[a-z0-9_]*)\b\s*:\s*("[^"]*"|[^ \n\r\t]+)`)

// MaskArgsString 接受原始日志字符串，返回脱敏后的字符串
func MaskArgsString(input string) string {
	return piiRegex.ReplaceAllStringFunc(input, func(match string) string {
		// match 的内容类似： email:"li_chx@qq.com" 或 password:123
		parts := strings.SplitN(match, ":", 2)
		if len(parts) != 2 {
			return match
		}

		key := strings.TrimSpace(parts[0])
		rawVal := strings.TrimSpace(parts[1])

		// 提取真实的值（去除可能的双引号）
		val := rawVal
		hasQuotes := strings.HasPrefix(rawVal, `"`) && strings.HasSuffix(rawVal, `"`)
		if hasQuotes && len(rawVal) >= 2 {
			val = rawVal[1 : len(rawVal)-1]
		}

		// 根据 Key 的特征路由到不同的打码函数
		lowerKey := strings.ToLower(key)
		var maskedVal string

		switch {
		case strings.Contains(lowerKey, "password"), strings.Contains(lowerKey, "token"), strings.Contains(lowerKey, "secret"):
			maskedVal = "***" // L4级别：全脱敏
		case strings.Contains(lowerKey, "email"):
			maskedVal = maskEmail(val) // L2级别：部分脱敏
		case strings.Contains(lowerKey, "phone"), strings.Contains(lowerKey, "mobile"):
			maskedVal = maskPhone(val) // L3级别：部分脱敏
		case strings.Contains(lowerKey, "id_card"):
			maskedVal = maskIDCard(val) // L3级别：部分脱敏
		default:
			maskedVal = "***" // 命中正则但未定义的，默认全脱敏保底
		}

		// 恢复双引号（如果原本有的话）
		if hasQuotes {
			maskedVal = `"` + maskedVal + `"`
		}

		return key + ":" + maskedVal
	})
}

// === 下面是具体的打码策略函数，注重防止 Panic ===

// 邮箱打码：保留首字母和域名，例如 l***@qq.com
func maskEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 || len(parts[0]) == 0 {
		return "***" // 格式不合法，直接全打码
	}
	name := parts[0]
	domain := parts[1]

	if len(name) <= 2 {
		return name[:1] + "***@" + domain
	}
	return name[:1] + "***" + name[len(name)-1:] + "@" + domain
}

// 手机号打码：前3后4，例如 138****5678
func maskPhone(phone string) string {
	if len(phone) < 7 {
		return "***" // 数据异常，全打码
	}
	return phone[:3] + "****" + phone[len(phone)-4:]
}

// 身份证打码：前6后4，例如 110105********123X
func maskIDCard(idCard string) string {
	if len(idCard) < 11 {
		return "***"
	}
	return idCard[:6] + "********" + idCard[len(idCard)-4:]
}
