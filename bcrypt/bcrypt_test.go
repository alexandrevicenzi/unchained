package bcrypt

import (
	"strings"
	"testing"
)

func TestBCryptEncode(t *testing.T) {
	encoded, err := NewBCryptHasher().Encode("admin", "")

	if err != nil {
		t.Fatalf("Encode error: %s", err)
	}

	if !strings.HasPrefix(encoded, "bcrypt$$2a$12$") {
		t.Fatal("Encoded hash is not bcrypt.")
	}
}

func TestBCryptVerify1(t *testing.T) {
	valid, err := NewBCryptHasher().Verify("admin", "bcrypt$$2b$12$qcNExitVe89wMG.nmRD4Qupn2hFm0pxvnu6VC.w6LShOx30l.F9/.")

	if err != nil {
		t.Fatalf("Verify error: %s", err)
	}

	if !valid {
		t.Fatal("Password should be valid.")
	}
}

func TestBCryptVerify2(t *testing.T) {
	valid, err := NewBCryptHasher().Verify("this-is-my-password", "bcrypt$$2b$12$5o1LTEa5PhHOyWTT/rNhkeZLUpjs7i45Mh17Hw9yZ8xqD0u31SxH2")

	if err != nil {
		t.Fatalf("Verify error: %s", err)
	}

	if !valid {
		t.Fatal("Password should be valid.")
	}
}

func TestBCryptVerify3(t *testing.T) {
	valid, err := NewBCryptHasher().Verify("Th1S1sMYp4ssw0rd", "bcrypt$$2b$12$RH89OglFPsQTjmHl1WN.aO7I2SV5qvn5iNAnZlGbLgzeiOEvrHFiG")

	if err != nil {
		t.Fatalf("Verify error: %s", err)
	}

	if !valid {
		t.Fatal("Password should be valid.")
	}
}

func TestBCryptVerify4(t *testing.T) {
	valid, err := NewBCryptHasher().Verify("this$is#my@PASSWORD", "bcrypt$$2b$12$HDMQLhINvA1bGpihQwjCzuA4deBmPQvwj85ehmi5RgJqzM5OnNQRy")

	if err != nil {
		t.Fatalf("Verify error: %s", err)
	}

	if !valid {
		t.Fatal("Password should be valid.")
	}
}

func TestBCryptVerifyInvalidPassword(t *testing.T) {
	valid, err := NewBCryptHasher().Verify("wrongpassword", "bcrypt$$2b$12$qcNExitVe89wMG.nmRD4Qupn2hFm0pxvnu6VC.w6LShOx30l.F9/.")

	if err != nil {
		t.Fatalf("Verify error: %s", err)
	}

	if valid {
		t.Fatal("Password should not be valid.")
	}
}

func TestBCryptSHA256Encode(t *testing.T) {
	encoded, err := NewBCryptSHA256Hasher().Encode("admin", "")

	if err != nil {
		t.Fatalf("Encode error: %s", err)
	}

	if !strings.HasPrefix(encoded, "bcrypt_sha256$$2a$12$") {
		t.Fatal("Encoded hash is not bcrypt.")
	}
}

func TestBCryptSHA256Verify1(t *testing.T) {
	valid, err := NewBCryptSHA256Hasher().Verify("admin", "bcrypt_sha256$$2b$12$WZK9cb9qKN.Q5LCYPq/gj.6gvry1b37HUsJER6KhQBnIWmPyyaaqi")

	if err != nil {
		t.Fatalf("Verify error: %s", err)
	}

	if !valid {
		t.Fatal("Password should be valid.")
	}
}

func TestBCryptSHA265Verify2(t *testing.T) {
	valid, err := NewBCryptSHA256Hasher().Verify("this-is-my-password", "bcrypt_sha256$$2b$12$xElgTm6AlLk0LUEBUEJEbeFStoCKaPTALOnBhL0ud0AB3sdj80qZe")

	if err != nil {
		t.Fatalf("Verify error: %s", err)
	}

	if !valid {
		t.Fatal("Password should be valid.")
	}
}

func TestBCryptSHA265Verify3(t *testing.T) {
	valid, err := NewBCryptSHA256Hasher().Verify("Th1S1sMYp4ssw0rd", "bcrypt_sha256$$2b$12$V3VD.MINozdbSpinl/CgeebGTX05O/udPatDyirSv.GsVKE34m5d.")

	if err != nil {
		t.Fatalf("Verify error: %s", err)
	}

	if !valid {
		t.Fatal("Password should be valid.")
	}
}

func TestBCryptSHA265Verify4(t *testing.T) {
	valid, err := NewBCryptSHA256Hasher().Verify("this$is#my@PASSWORD", "bcrypt_sha256$$2b$12$32j.pIs5XjE9sbEcHRKHW./6llXm9QgpXIX8jbG21hHQmOgAPRhx.")

	if err != nil {
		t.Fatalf("Verify error: %s", err)
	}

	if !valid {
		t.Fatal("Password should be valid.")
	}
}

func TestBCryptSHA265VerifyInvalidPassword(t *testing.T) {
	valid, err := NewBCryptSHA256Hasher().Verify("wrongpassword", "bcrypt_sha256$$2b$12$kXm66dejMbp4YV7AfxOhpOFxm1FggUmu52MU24gRvQwqfXxSu.7Li")

	if err != nil {
		t.Fatalf("Verify error: %s", err)
	}

	if valid {
		t.Fatal("Password should not be valid.")
	}
}
