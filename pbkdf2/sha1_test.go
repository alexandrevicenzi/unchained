package pbkdf2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPBKDF2SHA1Encode1(t *testing.T) {
	encoded, err := NewPBKDF2SHA1Hasher().Encode("admin", "1TMOT0Rohg3g", 120000)
	assert.Nil(t, err)
	assert.Equal(t, encoded, "pbkdf2_sha1$120000$1TMOT0Rohg3g$zVJ4+gcRcano9Qks+kcsgKeRnVs=")
}

func TestPBKDF2SHA1Encode2(t *testing.T) {
	encoded, err := NewPBKDF2SHA1Hasher().Encode("this-is-my-password", "G8rkK8UFRZWr", 80000)
	assert.Nil(t, err)
	assert.Equal(t, encoded, "pbkdf2_sha1$80000$G8rkK8UFRZWr$/UGcDmP7BCJDdBMTNVN5fG8Ty1g=")
}

func TestPBKDF2SHA1Encode3(t *testing.T) {
	encoded, err := NewPBKDF2SHA1Hasher().Encode("Th1S1sMYp4ssw0rd", "jkHRJ7pu8k0v", 120000)
	assert.Nil(t, err)
	assert.Equal(t, encoded, "pbkdf2_sha1$120000$jkHRJ7pu8k0v$bXzu5MnzrIHkCR76ramj/z9DTKY=")
}

func TestPBKDF2SHA1Encode4(t *testing.T) {
	encoded, err := NewPBKDF2SHA1Hasher().Encode("this$is#my@PASSWORD", "1TMOT0Rohg3g", 180000)
	assert.Nil(t, err)
	assert.Equal(t, encoded, "pbkdf2_sha1$180000$1TMOT0Rohg3g$1OBUXq+UswNEbPkNKGnB2BzVW4g=")
}

func TestPBKDF2SHA1Verify1(t *testing.T) {
	valid, err := NewPBKDF2SHA1Hasher().Verify("admin", "pbkdf2_sha1$120000$1TMOT0Rohg3g$zVJ4+gcRcano9Qks+kcsgKeRnVs=")
	assert.Nil(t, err)
	assert.True(t, valid)
}

func TestPBKDF2SHA1Verify2(t *testing.T) {
	valid, err := NewPBKDF2SHA1Hasher().Verify("this-is-my-password", "pbkdf2_sha1$80000$G8rkK8UFRZWr$/UGcDmP7BCJDdBMTNVN5fG8Ty1g=")
	assert.Nil(t, err)
	assert.True(t, valid)
}

func TestPBKDF2SHA1Verify3(t *testing.T) {
	valid, err := NewPBKDF2SHA1Hasher().Verify("Th1S1sMYp4ssw0rd", "pbkdf2_sha1$120000$1TMOT0Rohg3g$KQkAqdJmqnZZM3aY5KbPDXS6aDo=")
	assert.Nil(t, err)
	assert.True(t, valid)
}

func TestPBKDF2SHA1Verify4(t *testing.T) {
	valid, err := NewPBKDF2SHA1Hasher().Verify("this$is#my@PASSWORD", "pbkdf2_sha1$180000$1TMOT0Rohg3g$1OBUXq+UswNEbPkNKGnB2BzVW4g=")
	assert.Nil(t, err)
	assert.True(t, valid)
}

func TestPBKDF2SHA1VerifyInvalidPassword(t *testing.T) {
	valid, err := NewPBKDF2SHA1Hasher().Verify("wrongpassword", "pbkdf2_sha1$120000$1TMOT0Rohg3g$zVJ4+gcRcano9Qks+kcsgKeRnVs=")
	assert.Nil(t, err)
	assert.False(t, valid)
}
