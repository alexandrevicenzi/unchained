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

// Encode turns a plain-text password into a hash.
//
// Parameter salt is currently ignored.
func (h *BCryptHasher) Encode(password string, salt string) (string, error) {
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

// Verify if a plain-text password matches the encoded digest.
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

// Secure password hashing using the bcrypt algorithm.
//
// This hasher does not first hash the password which means it is subject to
// bcrypt's 72 bytes password truncation.
func NewBCryptHasher() *BCryptHasher {
	return &BCryptHasher{
		algorithm: "bcrypt",
		digest:    nil,
		cost:      12,
	}
}

// Secure password hashing using the bcrypt algorithm.
//
// This hasher first hash the password with SHA-256.
func NewBCryptSHA256Hasher() *BCryptHasher {
	return &BCryptHasher{
		algorithm: "bcrypt_sha256",
		digest:    sha256.New,
		cost:      12,
	}
}
