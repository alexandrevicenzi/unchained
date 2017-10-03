package bcrypt

import (
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrHashComponentUnreadable = errors.New("unchained/bcrypt: unreadable component in hashed password")
	ErrHashComponentMismatch   = errors.New("unchained/bcrypt: hashed password components mismatch")
	ErrAlgorithmMismatch       = errors.New("unchained/bcrypt: algorithm mismatch")
)

type BcryptHasher struct {
	algorithm string
	size      int
	digest    func() hash.Hash
}

// Encode encode raw password using bcrypt hasher.
func (h *BcryptHasher) Encode(password string, cost int) (string, error) {
	d, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}
	hash := base64.StdEncoding.EncodeToString(d)
	return fmt.Sprintf("%s$%d$%s", h.algorithm, cost, hash), nil
}

// Verify validate raw password using bcrypt hasher.
func (h *BcryptHasher) Verify(password string, encoded string) (bool, error) {
	s := strings.Split(encoded, "$")

	if len(s) != 3 {
		return false, ErrHashComponentMismatch
	}

	algorithm, cost, hashedPassword := s[0], s[1], s[2]

	if algorithm != h.algorithm {
		return false, ErrAlgorithmMismatch
	}

	_, err := strconv.Atoi(cost)

	if err != nil {
		return false, ErrHashComponentUnreadable
	}

	decoded, err := base64.StdEncoding.DecodeString(hashedPassword)

	if err != nil {
		return false, err
	}
	if bcrypt.CompareHashAndPassword([]byte(decoded), []byte(password)) == nil {
		return true, nil
	}
	return false, nil
}
