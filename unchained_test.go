package unchained

import (
	"fmt"
	"strings"
	"testing"
)

func TestMakePasswordDefault(t *testing.T) {
	encoded, err := MakePassword("admin", "1TMOT0Rohg3g", "default")

	if err != nil {
		t.Fatalf("MakePassword error: %s", err)
	}

	expected := "pbkdf2_sha256$216000$1TMOT0Rohg3g$N+wIigWW4zpxnFBwXTWK1Qt8C9aduBIAayDS2ee8KxI="

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

func TestMakePasswordArgon2Hasher(t *testing.T) {
	encoded, err := MakePassword("admin", "", Argon2Hasher)

	if err != nil {
		t.Fatalf("Make password error: %s", err)
	}

	if !strings.HasPrefix(encoded, fmt.Sprintf("%s$", Argon2Hasher)) {
		t.Fatalf("Encoded password doesn't match algorithm (%s): %s", Argon2Hasher, encoded)
	}
}

func TestMakePasswordBCryptHasher(t *testing.T) {
	encoded, err := MakePassword("admin", "", BCryptHasher)

	if err != nil {
		t.Fatalf("Make password error: %s", err)
	}

	if !strings.HasPrefix(encoded, fmt.Sprintf("%s$", BCryptHasher)) {
		t.Fatalf("Encoded password doesn't match algorithm (%s): %s", BCryptHasher, encoded)
	}
}

func TestMakePasswordBCryptSHA256Hasher(t *testing.T) {
	encoded, err := MakePassword("admin", "", BCryptSHA256Hasher)

	if err != nil {
		t.Fatalf("Make password error: %s", err)
	}

	if !strings.HasPrefix(encoded, fmt.Sprintf("%s$", BCryptSHA256Hasher)) {
		t.Fatalf("Encoded password doesn't match algorithm (%s): %s", BCryptSHA256Hasher, encoded)
	}
}

func TestMakePasswordMD5Hasher(t *testing.T) {
	encoded, err := MakePassword("admin", "", MD5Hasher)

	if err != nil {
		t.Fatalf("Make password error: %s", err)
	}

	if !strings.HasPrefix(encoded, fmt.Sprintf("%s$", MD5Hasher)) {
		t.Fatalf("Encoded password doesn't match algorithm (%s): %s", MD5Hasher, encoded)
	}
}

func TestMakePasswordPBKDF2SHA1Hasher(t *testing.T) {
	encoded, err := MakePassword("admin", "", PBKDF2SHA1Hasher)

	if err != nil {
		t.Fatalf("Make password error: %s", err)
	}

	if !strings.HasPrefix(encoded, fmt.Sprintf("%s$", PBKDF2SHA1Hasher)) {
		t.Fatalf("Encoded password doesn't match algorithm (%s): %s", PBKDF2SHA1Hasher, encoded)
	}
}

func TestMakePasswordPBKDF2SHA256Hasher(t *testing.T) {
	encoded, err := MakePassword("admin", "", PBKDF2SHA256Hasher)

	if err != nil {
		t.Fatalf("Make password error: %s", err)
	}

	if !strings.HasPrefix(encoded, fmt.Sprintf("%s$", PBKDF2SHA256Hasher)) {
		t.Fatalf("Encoded password doesn't match algorithm (%s): %s", PBKDF2SHA256Hasher, encoded)
	}
}

func TestMakePasswordSHA1Hasher(t *testing.T) {
	encoded, err := MakePassword("admin", "", SHA1Hasher)

	if err != nil {
		t.Fatalf("Make password error: %s", err)
	}

	if !strings.HasPrefix(encoded, fmt.Sprintf("%s$", SHA1Hasher)) {
		t.Fatalf("Encoded password doesn't match algorithm (%s): %s", SHA1Hasher, encoded)
	}
}

func TestMakePasswordUnsaltedMD5Hasher(t *testing.T) {
	encoded, err := MakePassword("admin", "", UnsaltedMD5Hasher)

	if err != nil {
		t.Fatalf("Make password error: %s", err)
	}

	expected := "21232f297a57a5a743894a0e4a801fc3"

	if encoded != expected {
		t.Fatalf("Encoded hash %s does not match %s.", encoded, expected)
	}
}

func TestMakePasswordUnsaltedSHA1Hasher(t *testing.T) {
	encoded, err := MakePassword("admin", "", UnsaltedSHA1Hasher)

	if err != nil {
		t.Fatalf("Make password error: %s", err)
	}

	expected := "sha1$$d033e22ae348aeb5660fc2140aec35850c4da997"

	if encoded != expected {
		t.Fatalf("Encoded hash %s does not match %s.", encoded, expected)
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

func TestCheckPasswordMD5Hasher(t *testing.T) {
	valid, err := CheckPassword("admin", "md5$8CjhcHYaEGZQ$c7f218365947cecaac46415390d5cb6a")

	if err != nil {
		t.Fatalf("CheckPassword error: %s", err)
	}

	if !valid {
		t.Fatal("Password should be valid.")
	}
}

func TestCheckPasswordSHA1Hasher(t *testing.T) {
	valid, err := CheckPassword("admin", "sha1$7E3eUiuxfTHG$154faafaf5455924ad853c5f1630eaf062c135a7")

	if err != nil {
		t.Fatalf("CheckPassword error: %s", err)
	}

	if !valid {
		t.Fatal("Password should be valid.")
	}
}

func TestCheckPasswordUnsaltedMD5Hasher(t *testing.T) {
	valid, err := CheckPassword("admin", "21232f297a57a5a743894a0e4a801fc3")

	if err != nil {
		t.Fatalf("CheckPassword error: %s", err)
	}

	if !valid {
		t.Fatal("Password should be valid.")
	}
}

func TestCheckPasswordUnsaltedSHA1Hasher(t *testing.T) {
	valid, err := CheckPassword("admin", "sha1$$d033e22ae348aeb5660fc2140aec35850c4da997")

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
