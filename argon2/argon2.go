package argon2

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	ErrHashComponentUnreadable = errors.New("unchained/argon2: unreadable component in hashed password")
	ErrHashComponentMismatch   = errors.New("unchained/argon2: hashed password components mismatch")
	ErrAlgorithmMismatch       = errors.New("unchained/argon2: algorithm mismatch")
	ErrIncompatibleVersion     = errors.New("unchained/argon2: incompatible version")
)

type Argon2Hasher struct {
	algorithm string
	time      uint32
	memory    uint32
	threads   uint8
	length    uint32
}

// Encode turns a plain-text password into a hash.
func (h *Argon2Hasher) Encode(password string, salt string) (string, error) {
	bSalt := []byte(salt)
	hash := argon2.Key([]byte(password), bSalt, h.time, h.memory, h.threads, h.length)

	b64Salt := base64.RawStdEncoding.EncodeToString(bSalt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	s := fmt.Sprintf("%s$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		h.algorithm,
		"argon2i",
		argon2.Version,
		h.memory,
		h.time,
		h.threads,
		b64Salt,
		b64Hash,
	)

	return s, nil
}

// Verify if a plain-text password matches the encoded digest.
func (h *Argon2Hasher) Verify(password string, encoded string) (bool, error) {
	s := strings.Split(encoded, "$")

	if len(s) != 6 {
		return false, ErrHashComponentMismatch
	}

	algorithm, method, version, params, salt, hash := s[0], s[1], s[2], s[3], s[4], s[5]

	if algorithm != h.algorithm || method != "argon2i" {
		return false, ErrAlgorithmMismatch
	}

	var v int
	var err error

	_, err = fmt.Sscanf(version, "v=%d", &v)

	if err != nil {
		return false, ErrHashComponentUnreadable
	}

	if v != argon2.Version {
		return false, ErrIncompatibleVersion
	}

	_, err = fmt.Sscanf(params, "m=%d,t=%d,p=%d", &h.memory, &h.time, &h.threads)

	if err != nil {
		return false, ErrHashComponentUnreadable
	}

	bSalt, err := base64.RawStdEncoding.DecodeString(salt)
	bHash, err := base64.RawStdEncoding.DecodeString(hash)

	newHash := argon2.Key([]byte(password), bSalt, h.time, h.memory, h.threads, h.length)

	return subtle.ConstantTimeCompare(bHash, newHash) == 1, nil
}

// NewArgon2Hasher secures password hashing using the argon2 algorithm.
func NewArgon2Hasher() *Argon2Hasher {
	return &Argon2Hasher{
		algorithm: "argon2",
		time:      2,
		memory:    512,
		threads:   2,
		length:    16,
	}
}
