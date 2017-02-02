package pbkdf2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPBKDF2SHA256ValidPassword(t *testing.T) {
	valid, err := NewPBKDF2SHA256Hasher().Verify("admin", "pbkdf2_sha256$24000$JMO9TJawIXB1$5iz40fwwc+QW6lZY+TuNciua3YVMV3GXdgkhXrcvWag=")
	assert.Nil(t, err)
	assert.True(t, valid)
}

func TestPBKDF2SHA256InvalidPassword(t *testing.T) {
	valid, err := NewPBKDF2SHA256Hasher().Verify("wrongpassword", "pbkdf2_sha256$24000$JMO9TJawIXB1$5iz40fwwc+QW6lZY+TuNciua3YVMV3GXdgkhXrcvWag=")
	assert.Nil(t, err)
	assert.False(t, valid)
}
