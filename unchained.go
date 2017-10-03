// Package unchained implements Django password hashers in Go.
package unchained

import (
	"fmt"
	"strings"

	"github.com/alexandrevicenzi/unchained/pbkdf2"
)

func hashAlgorithm(encoded string) string {
	return strings.Split(encoded, "$")[0]
}

// IsPasswordUsable returns true if encoded password is usable.
func IsPasswordUsable(encoded string) bool {
	if strings.HasPrefix("!", encoded) {
		return false
	}

	algorithm := hashAlgorithm(encoded)

	switch algorithm {
	case
		"argon2",
		"bcrypt",
		"bcrypt_sha256",
		"crypt",
		"md5",
		"pbkdf2_sha1",
		"pbkdf2_sha256",
		"sha1",
		"unsalted_md5",
		"unsalted_sha1":
		return true
	}

	return false
}

// CheckPassword validate if the raw password matches the encoded digest.
// This is a shortcut that discovers the algorithm used in the encoded digest
// to perform the correct validation.
func CheckPassword(password string, encoded string) (bool, error) {
	if !IsPasswordUsable(encoded) {
		return false, nil
	}

	algorithm := hashAlgorithm(encoded)

	switch algorithm {
	case "pbkdf2_sha256":
		return pbkdf2.NewPBKDF2SHA256Hasher().Verify(password, encoded)
	case "pbkdf2_sha1":
		return pbkdf2.NewPBKDF2SHA1Hasher().Verify(password, encoded)
	case "bcrypt":
		return bcrypt.NewBcrypt.Hasher().Verify(password, encoded)
	case
		"argon2",
		"bcrypt_sha256",
		"crypt",
		"md5",
		"sha1",
		"unsalted_md5",
		"unsalted_sha1":
		return false, fmt.Errorf("unchained: hasher not implemented %s", algorithm)
	}

	return false, fmt.Errorf("unchained: invaid hasher %s", algorithm)
}
