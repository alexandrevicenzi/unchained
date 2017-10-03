package bcrypt

import (
	"crypto/sha256"
)

func NewBcryptHasher() *BcryptHasher {
	return &BcryptHasher{
		"bcrypt",
		sha256.Size,
		sha256.New,
	}
}
