package md5

import (
	"crypto/hmac"
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Errors returned by UnsaltedMD5PasswordHasher and/or MD5PasswordHasher.
var (
	ErrHashComponentMismatch  = errors.New("unchained/md5: hashed password components mismatch")
	ErrAlgorithmMismatch      = errors.New("unchained/md5: algorithm mismatch")
	ErrSaltContainsDollarSing = errors.New("unchained/md5: salt contains dollar sign ($)")
)

// UnsaltedMD5PasswordHasher implements a simple MD5 password hasher.
type UnsaltedMD5PasswordHasher struct {
	// Algorithm identifier.
	Algorithm string
}

// Encode turns a plain-text password into a hash.
func (h *UnsaltedMD5PasswordHasher) Encode(password string) (string, error) {
	hasher := md5.New()
	io.WriteString(hasher, password)
	return fmt.Sprintf("%x", hasher.Sum(nil)), nil
}

// Verify if a plain-text password matches the encoded digest.
func (h *UnsaltedMD5PasswordHasher) Verify(password string, encoded string) (bool, error) {
	if len(encoded) == 37 && strings.HasPrefix(encoded, "md5$$") {
		encoded = encoded[5:]
	}

	newencoded, err := h.Encode(password)

	if err != nil {
		return false, err
	}

	return hmac.Equal([]byte(newencoded), []byte(encoded)), nil
}

// MD5PasswordHasher implements Salted MD5 password hasher.
type MD5PasswordHasher struct {
	// Algorithm identifier.
	Algorithm string
}

// Encode turns a plain-text password into a hash.
func (h *MD5PasswordHasher) Encode(password string, salt string) (string, error) {
	if strings.Contains(salt, "$") {
		return "", ErrSaltContainsDollarSing
	}

	hasher := md5.New()
	io.WriteString(hasher, salt)
	io.WriteString(hasher, password)
	return fmt.Sprintf("%s$%s$%x", h.Algorithm, salt, hasher.Sum(nil)), nil
}

// Verify if a plain-text password matches the encoded digest.
func (h *MD5PasswordHasher) Verify(password string, encoded string) (bool, error) {
	s := strings.Split(encoded, "$")

	if len(s) != 3 {
		return false, ErrHashComponentMismatch
	}

	algorithm, salt := s[0], s[1]

	if algorithm != h.Algorithm {
		return false, ErrAlgorithmMismatch
	}

	newencoded, err := h.Encode(password, salt)

	if err != nil {
		return false, err
	}

	return hmac.Equal([]byte(newencoded), []byte(encoded)), nil
}

// NewUnsaltedMD5PasswordHasher is an incredibly insecure algorithm
// that should never be used. It stores unsalted MD5 hashes without
// the algorithm prefix, also hashes with an empty salt.
//
// This algorithm is implemented because Django used to store passwords this way
// and to accept such password hashes.
func NewUnsaltedMD5PasswordHasher() *UnsaltedMD5PasswordHasher {
	return &UnsaltedMD5PasswordHasher{
		Algorithm: "unsalted_md5",
	}
}

// NewMD5PasswordHasher secures password hashing using Salted MD5 algorithm (not recommended).
func NewMD5PasswordHasher() *MD5PasswordHasher {
	return &MD5PasswordHasher{
		Algorithm: "md5",
	}
}
