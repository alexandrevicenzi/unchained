package unchained

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckPasswordPBKDF2SHA256(t *testing.T) {
	valid, err := CheckPassword("admin", "pbkdf2_sha256$24000$JMO9TJawIXB1$5iz40fwwc+QW6lZY+TuNciua3YVMV3GXdgkhXrcvWag=")
	assert.Nil(t, err)
	assert.True(t, valid)
}

func TestCheckPasswordPBKDF2SHA1(t *testing.T) {
	valid, err := CheckPassword("test", "pbkdf2_sha1$24000$zX573SspyROA$eqWjJBui5kY/TRXg2TwvSwA+2wk=")
	assert.Nil(t, err)
	assert.True(t, valid)
}

func TestIsPasswordUsableWithValidPassword(t *testing.T) {
	usable := IsPasswordUsable("pbkdf2_sha256$24000$JMO9TJawIXB1$5iz40fwwc+QW6lZY+TuNciua3YVMV3GXdgkhXrcvWag=")
	assert.True(t, usable)
}

func TestIsPasswordUsableWithUnusablePassword(t *testing.T) {
	usable := IsPasswordUsable("!")
	assert.False(t, usable)
}
