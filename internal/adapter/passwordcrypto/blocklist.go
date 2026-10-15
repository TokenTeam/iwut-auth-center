package passwordcrypto

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"iwut-auth-center/internal/password/domain"
	"strings"
)

// Blocklist contains whole normalized-password SHA-256 digests, NOT password
// verifiers. It is immutable after loading. There is no empty/default fallback.
type Blocklist struct {
	Version, Source string
	hashes          map[[32]byte]struct{}
}

// LoadBlocklist accepts a pinned local digest list. Metadata/content digest are
// operator supplied; production origin approval remains a deployment gate.
// Each line is exactly 64 lowercase hex characters followed by LF.
func LoadBlocklist(reader io.Reader, version, source, expectedSHA256 string) (*Blocklist, error) {
	if reader == nil || len(version) == 0 || len(version) > 128 || len(source) == 0 || len(source) > 256 || len(expectedSHA256) != 64 {
		return nil, domain.ErrUnavailable
	}
	expected, err := hex.DecodeString(expectedSHA256)
	if err != nil || hex.EncodeToString(expected) != expectedSHA256 {
		return nil, domain.ErrUnavailable
	}
	const maxBytes = 65 * 1000000
	limited := io.LimitReader(reader, maxBytes+1)
	h := sha256.New()
	counted := &countingReader{reader: io.TeeReader(limited, h)}
	scanner := bufio.NewScanner(counted)
	scanner.Buffer(make([]byte, 128), 128)
	b := &Blocklist{version, source, make(map[[32]byte]struct{})}
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) != 64 || line != strings.ToLower(line) || strings.ContainsAny(line, "\r\t ") {
			return nil, domain.ErrUnavailable
		}
		raw, e := hex.DecodeString(line)
		if e != nil {
			return nil, domain.ErrUnavailable
		}
		var digest [32]byte
		copy(digest[:], raw)
		if _, exists := b.hashes[digest]; exists {
			return nil, domain.ErrUnavailable
		}
		b.hashes[digest] = struct{}{}
		if len(b.hashes) > 1000000 {
			return nil, domain.ErrUnavailable
		}
	}
	if scanner.Err() != nil || counted.bytes > maxBytes || counted.bytes != len(b.hashes)*65 || len(b.hashes) == 0 || hex.EncodeToString(h.Sum(nil)) != expectedSHA256 {
		return nil, domain.ErrUnavailable
	}
	return b, nil
}

type countingReader struct {
	reader io.Reader
	bytes  int
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.bytes += n
	return n, err
}

func (b *Blocklist) Contains(normalized string) bool {
	_, found := b.hashes[sha256.Sum256([]byte(normalized))]
	return found
}
