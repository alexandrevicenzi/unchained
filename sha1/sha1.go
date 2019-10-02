package sha1

import (
	"crypto/hmac"
	"crypto/sha1"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Errors returned by SHA1PasswordHasher.
var (
	ErrHashComponentMismatch  = errors.New("unchained/sha1: hashed password components mismatch")
	ErrAlgorithmMismatch      = errors.New("unchained/sha1: algorithm mismatch")
	ErrSaltContainsDollarSing = errors.New("unchained/sha1: salt contains dollar sign ($)")
	ErrSaltIsEmpty            = errors.New("unchained/sha1: salt is empty")
)

// UnsaltedSHA1PasswordHasher implements Salted SHA1 password hasher.
type SHA1PasswordHasher struct {
	// Algorithm identifier.
	Algorithm string
	// Use salt to encode.
	Salted bool
}

// Encode turns a plain-text password into a hash.
func (h *SHA1PasswordHasher) Encode(password string, salt string) (string, error) {
	if h.Salted {
		if len(salt) == 0 {
			return "", ErrSaltIsEmpty
		}

		if strings.Contains(salt, "$") {
			return "", ErrSaltContainsDollarSing
		}
	} else {
		salt = ""
	}

	hasher := sha1.New()

	if h.Salted {
		io.WriteString(hasher, salt)
	}

	io.WriteString(hasher, password)

	return fmt.Sprintf("sha1$%s$%x", salt, hasher.Sum(nil)), nil
}

// Verify if a plain-text password matches the encoded digest.
func (h *SHA1PasswordHasher) Verify(password string, encoded string) (bool, error) {
	s := strings.Split(encoded, "$")

	if len(s) != 3 {
		return false, ErrHashComponentMismatch
	}

	algorithm, salt := s[0], s[1]

	if algorithm != "sha1" {
		return false, ErrAlgorithmMismatch
	}

	newencoded, err := h.Encode(password, salt)

	if err != nil {
		return false, err
	}

	return hmac.Equal([]byte(newencoded), []byte(encoded)), nil
}

// NewUnsaltedSHA1PasswordHasher is an incredibly insecure algorithm
// that should never be used. It stores unsalted SHA1 hashes with an empty salt.
//
// This algorithm is implemented because Django used to store passwords this way
// and to accept such password hashes.
func NewUnsaltedSHA1PasswordHasher() *SHA1PasswordHasher {
	return &SHA1PasswordHasher{
		Algorithm: "unsalted_sha1",
		Salted:    false,
	}
}

// NewUnsaltedSHA1PasswordHasher secures password hashing using Salted SHA1 algorithm (not recommended).
func NewSHA1PasswordHasher() *SHA1PasswordHasher {
	return &SHA1PasswordHasher{
		Algorithm: "sha1",
		Salted:    true,
	}
}
