package pbkdf2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPBKDF2SHA1ValidPassword(t *testing.T) {
	valid := NewPBKDF2SHA1Hasher().Verify("test", "pbkdf2_sha1$24000$zX573SspyROA$eqWjJBui5kY/TRXg2TwvSwA+2wk=")
	assert.True(t, valid)
}

func TestPBKDF2SHA1InvalidPassword(t *testing.T) {
	valid := NewPBKDF2SHA1Hasher().Verify("wrongpassword", "pbkdf2_sha1$24000$zX573SspyROA$eqWjJBui5kY/TRXg2TwvSwA+2wk=")
	assert.False(t, valid)
}
