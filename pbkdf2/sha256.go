package pbkdf2

import (
	"crypto/sha256"
)

func NewPBKDF2SHA256Hasher() *PBKDF2Hasher {
	return &PBKDF2Hasher{
		"pbkdf2_sha256",
		sha256.Size,
		sha256.New,
	}
}
