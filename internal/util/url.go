package util

import (
	"net/url"
	"strings"
)

// BuildRedirectURL 根据 baseURL 和查询参数构造最终跳转 URL，自动处理末尾 `/`
func BuildRedirectURL(baseURL string, params map[string]string) (string, error) {
	if baseURL == "" {
		return "", nil
	}

	// 记录原始字符串是否以 '/' 结尾（用于决定是否保留单个根路径 '/'）
	origEndsWithSlash := strings.HasSuffix(baseURL, "/")

	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// 规范化 path：
	// - 如果 path 为空但原始 baseURL 以 '/' 结尾，保留单个 '/'（例如 "https://a.com/"）
	// - 否则去掉 path 末尾多余的 '/'（但不要把单个 '/' 去掉）
	if u.Path == "" {
		if origEndsWithSlash {
			u.Path = "/"
		}
	} else {
		if u.Path != "/" {
			trimmed := strings.TrimRight(u.Path, "/")
			if trimmed == "" && origEndsWithSlash {
				// 原 path 由多重 '/' 组成且原始字符串以 '/' 结尾，保留单个 '/'
				u.Path = "/"
			} else {
				u.Path = trimmed
			}
		}
	}

	q := u.Query()
	for k, v := range params {
		if v == "" {
			continue
		}
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
