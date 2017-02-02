package pbkdf2

import (
	"crypto/sha1"
)

func NewPBKDF2SHA1Hasher() *PBKDF2Hasher {
	return &PBKDF2Hasher{
		"pbkdf2_sha1",
		sha1.Size,
		sha1.New,
	}
}
