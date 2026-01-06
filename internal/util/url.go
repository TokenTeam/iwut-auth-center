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

	// 去掉末尾多余 `/`（保留单个 `/` 的场景，如 "https://a.com/"）
	for strings.HasSuffix(baseURL, "/") && len(baseURL) > len("https://a.com") {
		// 简单处理：只去掉末尾连续 `/`，不做复杂 host 判断
		baseURL = strings.TrimRight(baseURL, "/")
	}

	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
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
