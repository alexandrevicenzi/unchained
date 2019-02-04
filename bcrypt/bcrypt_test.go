package bcrypt

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBCryptEncode(t *testing.T) {
	encoded, err := NewBCryptHasher().Encode("admin")
	assert.Nil(t, err)
	assert.True(t, strings.HasPrefix(encoded, "bcrypt$$2a$12$"))
}

func TestBCryptVerify1(t *testing.T) {
	valid, err := NewBCryptHasher().Verify("admin", "bcrypt$$2b$12$qcNExitVe89wMG.nmRD4Qupn2hFm0pxvnu6VC.w6LShOx30l.F9/.")
	assert.Nil(t, err)
	assert.True(t, valid)
}

func TestBCryptVerify2(t *testing.T) {
	valid, err := NewBCryptHasher().Verify("this-is-my-password", "bcrypt$$2b$12$5o1LTEa5PhHOyWTT/rNhkeZLUpjs7i45Mh17Hw9yZ8xqD0u31SxH2")
	assert.Nil(t, err)
	assert.True(t, valid)
}

func TestBCryptVerify3(t *testing.T) {
	valid, err := NewBCryptHasher().Verify("Th1S1sMYp4ssw0rd", "bcrypt$$2b$12$RH89OglFPsQTjmHl1WN.aO7I2SV5qvn5iNAnZlGbLgzeiOEvrHFiG")
	assert.Nil(t, err)
	assert.True(t, valid)
}

func TestBCryptVerify4(t *testing.T) {
	valid, err := NewBCryptHasher().Verify("this$is#my@PASSWORD", "bcrypt$$2b$12$HDMQLhINvA1bGpihQwjCzuA4deBmPQvwj85ehmi5RgJqzM5OnNQRy")
	assert.Nil(t, err)
	assert.True(t, valid)
}

func TestBCryptVerifyInvalidPassword(t *testing.T) {
	valid, err := NewBCryptHasher().Verify("wrongpassword", "bcrypt$$2b$12$qcNExitVe89wMG.nmRD4Qupn2hFm0pxvnu6VC.w6LShOx30l.F9/.")
	assert.Nil(t, err)
	assert.False(t, valid)
}

func TestBCryptSHA256Encode(t *testing.T) {
	encoded, err := NewBCryptSHA256Hasher().Encode("admin")
	assert.Nil(t, err)
	assert.True(t, strings.HasPrefix(encoded, "bcrypt_sha256$$2a$12$"))
}

func TestBCryptSHA256Verify1(t *testing.T) {
	valid, err := NewBCryptSHA256Hasher().Verify("admin", "bcrypt_sha256$$2b$12$WZK9cb9qKN.Q5LCYPq/gj.6gvry1b37HUsJER6KhQBnIWmPyyaaqi")
	assert.Nil(t, err)
	assert.True(t, valid)
}

func TestBCryptSHA265Verify2(t *testing.T) {
	valid, err := NewBCryptSHA256Hasher().Verify("this-is-my-password", "bcrypt_sha256$$2b$12$xElgTm6AlLk0LUEBUEJEbeFStoCKaPTALOnBhL0ud0AB3sdj80qZe")
	assert.Nil(t, err)
	assert.True(t, valid)
}

func TestBCryptSHA265Verify3(t *testing.T) {
	valid, err := NewBCryptSHA256Hasher().Verify("Th1S1sMYp4ssw0rd", "bcrypt_sha256$$2b$12$V3VD.MINozdbSpinl/CgeebGTX05O/udPatDyirSv.GsVKE34m5d.")
	assert.Nil(t, err)
	assert.True(t, valid)
}

func TestBCryptSHA265Verify4(t *testing.T) {
	valid, err := NewBCryptSHA256Hasher().Verify("this$is#my@PASSWORD", "bcrypt_sha256$$2b$12$32j.pIs5XjE9sbEcHRKHW./6llXm9QgpXIX8jbG21hHQmOgAPRhx.")
	assert.Nil(t, err)
	assert.True(t, valid)
}

func TestBCryptSHA265VerifyInvalidPassword(t *testing.T) {
	valid, err := NewBCryptSHA256Hasher().Verify("wrongpassword", "bcrypt_sha256$$2b$12$kXm66dejMbp4YV7AfxOhpOFxm1FggUmu52MU24gRvQwqfXxSu.7Li")
	assert.Nil(t, err)
	assert.False(t, valid)
}
