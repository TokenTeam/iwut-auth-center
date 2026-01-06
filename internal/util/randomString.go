package util

import (
	"crypto/rand"
	"fmt"
)

const codeCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"

// GenerateString 生成长度为 n 的随机 code，用于 OAuth2 authorization code 等场景
func GenerateString(n int) (string, error) {
	if n <= 0 {
		return "", fmt.Errorf("invalid code length: %d", n)
	}

	b := make([]byte, n)
	charsetLen := byte(len(codeCharset))

	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random bytes failed: %w", err)
	}

	for i := range b {
		b[i] = codeCharset[int(b[i])%int(charsetLen)]
	}

	return string(b), nil
}
