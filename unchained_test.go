package unchained

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckPasswordPBKDF2SHA1(t *testing.T) {
	valid, err := CheckPassword("admin", "pbkdf2_sha1$120000$1TMOT0Rohg3g$zVJ4+gcRcano9Qks+kcsgKeRnVs=")
	assert.Nil(t, err)
	assert.True(t, valid)
}

func TestCheckPasswordPBKDF2SHA256(t *testing.T) {
	valid, err := CheckPassword("admin", "pbkdf2_sha256$120000$WZrFZhpl3wOU$yPimyWN658IuAu0XErvg1Nowfd55k60hu4o+eDUlBDM=")
	assert.Nil(t, err)
	assert.True(t, valid)
}

func TestCheckPasswordBCrypto(t *testing.T) {
	valid, err := CheckPassword("admin", "bcrypt$$2b$12$qcNExitVe89wMG.nmRD4Qupn2hFm0pxvnu6VC.w6LShOx30l.F9/.")
	assert.Nil(t, err)
	assert.True(t, valid)
}

func TestCheckPasswordBCryptoSHA256(t *testing.T) {
	valid, err := CheckPassword("admin", "bcrypt_sha256$$2b$12$WZK9cb9qKN.Q5LCYPq/gj.6gvry1b37HUsJER6KhQBnIWmPyyaaqi")
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
