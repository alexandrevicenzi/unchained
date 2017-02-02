package pbkdf2

import (
	"crypto/hmac"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"hash"
	"strconv"
	"strings"
)

type PBKDF2Hasher struct {
	algorithm string
	size      int
	digest    func() hash.Hash
}

// Encode encode raw password using PBKDF2 hasher.
func (h *PBKDF2Hasher) Encode(password string, salt string, iterations int) string {
	d := pbkdf2.Key([]byte(password), []byte(salt), iterations, h.size, h.digest)
	hash := b64encode(d)
	return fmt.Sprintf("%s$%d$%s$%s", h.algorithm, iterations, salt, hash)
}

// Verify validate raw password using PBKDF2 hasher.
func (h *PBKDF2Hasher) Verify(password string, encoded string) bool {
	s := strings.Split(encoded, "$")

	if len(s) != 4 {
		return false
	}

	algorithm, iterations, salt := s[0], s[1], s[2]

	if algorithm != h.algorithm {
		return false
	}

	i, err := strconv.Atoi(iterations)

	if err != nil {
		return false
	}

	newencoded := h.Encode(password, salt, i)
	return compareDigest(newencoded, encoded)
}

func compareDigest(val1, val2 string) bool {
	return hmac.Equal([]byte(val1), []byte(val2))
}

func b64encode(bytes []byte) string {
	return base64.StdEncoding.EncodeToString(bytes)
}
