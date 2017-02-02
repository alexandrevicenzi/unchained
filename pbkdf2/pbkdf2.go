package pbkdf2

import (
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"hash"
	"strconv"
	"strings"
)

var (
	ErrHashComponentUnreadable = errors.New("unchained/pbkdf2: unreadable component in hashed password")
	ErrHashComponentMismatch   = errors.New("unchained/pbkdf2: hashed password components mismatch")
	ErrAlgorithmMismatch       = errors.New("unchained/pbkdf2: algorithm mismatch")
)

type PBKDF2Hasher struct {
	algorithm string
	size      int
	digest    func() hash.Hash
}

// Encode encode raw password using PBKDF2 hasher.
func (h *PBKDF2Hasher) Encode(password string, salt string, iterations int) (string, error) {
	d := pbkdf2.Key([]byte(password), []byte(salt), iterations, h.size, h.digest)
	hash := b64encode(d)
	return fmt.Sprintf("%s$%d$%s$%s", h.algorithm, iterations, salt, hash), nil
}

// Verify validate raw password using PBKDF2 hasher.
func (h *PBKDF2Hasher) Verify(password string, encoded string) (bool, error) {
	s := strings.Split(encoded, "$")

	if len(s) != 4 {
		return false, ErrHashComponentMismatch
	}

	algorithm, iterations, salt := s[0], s[1], s[2]

	if algorithm != h.algorithm {
		return false, ErrAlgorithmMismatch
	}

	i, err := strconv.Atoi(iterations)

	if err != nil {
		return false, ErrHashComponentUnreadable
	}

	newencoded, _ := h.Encode(password, salt, i)
	return compareDigest(newencoded, encoded), nil
}

func compareDigest(val1, val2 string) bool {
	return hmac.Equal([]byte(val1), []byte(val2))
}

func b64encode(bytes []byte) string {
	return base64.StdEncoding.EncodeToString(bytes)
}
