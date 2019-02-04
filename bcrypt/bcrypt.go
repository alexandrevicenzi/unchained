package bcrypt

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrHashComponentMismatch = errors.New("unchained/bcrypt: hashed password components mismatch")
	ErrAlgorithmMismatch     = errors.New("unchained/bcrypt: algorithm mismatch")
)

type BCryptHasher struct {
	algorithm string
	digest    func() hash.Hash
	cost      int
}

// Encode encode raw password using BCrypt hasher.
func (h *BCryptHasher) Encode(password string) (string, error) {
	if h.digest != nil {
		d := h.digest()
		d.Write([]byte(password))
		password = hex.EncodeToString(d.Sum(nil))
	}

	bytes, err := bcrypt.GenerateFromPassword([]byte(password), h.cost)

	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s$%s", h.algorithm, string(bytes)), nil
}

// Verify validate raw password using BCrypt hasher.
func (h *BCryptHasher) Verify(password string, encoded string) (bool, error) {
	s := strings.SplitN(encoded, "$", 2)

	if len(s) != 2 {
		return false, ErrHashComponentMismatch
	}

	algorithm, hash := s[0], s[1]

	if algorithm != h.algorithm {
		return false, ErrAlgorithmMismatch
	}

	if h.digest != nil {
		d := h.digest()
		d.Write([]byte(password))
		password = hex.EncodeToString(d.Sum(nil))
	}

	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil, nil
}

func NewBCryptHasher() *BCryptHasher {
	return &BCryptHasher{
		algorithm: "bcrypt",
		digest:    nil,
		cost:      12,
	}
}

func NewBCryptSHA256Hasher() *BCryptHasher {
	return &BCryptHasher{
		algorithm: "bcrypt_sha256",
		digest:    sha256.New,
		cost:      12,
	}
}
