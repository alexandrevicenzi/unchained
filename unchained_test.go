package unchained

import (
	"testing"
)

func TestMakePasswordDefault(t *testing.T) {
	encoded, err := MakePassword("admin", "1TMOT0Rohg3g", "default")

	if err != nil {
		t.Fatalf("MakePassword error: %s", err)
	}

	expected := "pbkdf2_sha256$180000$1TMOT0Rohg3g$yWmK6dJrGjnpIyllslJ9vlyiXP3WOGNQ74hjEofWJu4="

	if encoded != expected {
		t.Fatalf("Encoded hash %s does not match %s.", encoded, expected)
	}
}

func TestMakePasswordEmptySaltDefault(t *testing.T) {
	encoded, err := MakePassword("admin", "", "default")

	if err != nil {
		t.Fatalf("MakePassword error: %s", err)
	}

	hasher := IdentifyHasher(encoded)

	if hasher != DefaultHasher {
		t.Fatalf("Hasher %s is not %s.", hasher, DefaultHasher)
	}
}

func TestCheckPasswordArgon2(t *testing.T) {
	valid, err := CheckPassword("admin", "argon2$argon2i$v=19$m=512,t=2,p=2$NnFZNGxmQTE1bmFV$kPPGrqD6dnRllcQeksFN+w")

	if err != nil {
		t.Fatalf("CheckPassword error: %s", err)
	}

	if !valid {
		t.Fatal("Password should be valid.")
	}
}

func TestCheckPasswordPBKDF2SHA1(t *testing.T) {
	valid, err := CheckPassword("admin", "pbkdf2_sha1$120000$1TMOT0Rohg3g$zVJ4+gcRcano9Qks+kcsgKeRnVs=")

	if err != nil {
		t.Fatalf("CheckPassword error: %s", err)
	}

	if !valid {
		t.Fatal("Password should be valid.")
	}
}

func TestCheckPasswordPBKDF2SHA256(t *testing.T) {
	valid, err := CheckPassword("admin", "pbkdf2_sha256$120000$WZrFZhpl3wOU$yPimyWN658IuAu0XErvg1Nowfd55k60hu4o+eDUlBDM=")

	if err != nil {
		t.Fatalf("CheckPassword error: %s", err)
	}

	if !valid {
		t.Fatal("Password should be valid.")
	}
}

func TestCheckPasswordBCrypto(t *testing.T) {
	valid, err := CheckPassword("admin", "bcrypt$$2b$12$qcNExitVe89wMG.nmRD4Qupn2hFm0pxvnu6VC.w6LShOx30l.F9/.")

	if err != nil {
		t.Fatalf("CheckPassword error: %s", err)
	}

	if !valid {
		t.Fatal("Password should be valid.")
	}
}

func TestCheckPasswordBCryptoSHA256(t *testing.T) {
	valid, err := CheckPassword("admin", "bcrypt_sha256$$2b$12$WZK9cb9qKN.Q5LCYPq/gj.6gvry1b37HUsJER6KhQBnIWmPyyaaqi")

	if err != nil {
		t.Fatalf("CheckPassword error: %s", err)
	}

	if !valid {
		t.Fatal("Password should be valid.")
	}
}

func TestIsPasswordUsableWithValidPassword(t *testing.T) {
	usable := IsPasswordUsable("pbkdf2_sha256$24000$JMO9TJawIXB1$5iz40fwwc+QW6lZY+TuNciua3YVMV3GXdgkhXrcvWag=")

	if !usable {
		t.Fatal("Password should be usable.")
	}
}

func TestIsPasswordUsableWithUnusablePassword1(t *testing.T) {
	usable := IsPasswordUsable("!")

	if usable {
		t.Fatal("Password should be unusable.")
	}
}

func TestIsPasswordUsableWithUnusablePassword2(t *testing.T) {
	usable := IsPasswordUsable("!password")

	if usable {
		t.Fatal("Password should be unusable.")
	}
}

func TestIsPasswordUsableWithEmptyPassword(t *testing.T) {
	usable := IsPasswordUsable("")

	if usable {
		t.Fatal("Password should be unusable.")
	}
}
