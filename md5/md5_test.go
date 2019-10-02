package md5

import (
	"testing"
)

func TestUnsaltedMD5PasswordEncode(t *testing.T) {
	encoded, err := NewUnsaltedMD5PasswordHasher().Encode("this-is-my-password")

	if err != nil {
		t.Fatalf("Encode error: %s", err)
	}

	expected := "d24c80177269fb85874b1361e6b71fb4"

	if encoded != expected {
		t.Fatalf("Encoded hash %s does not match %s.", encoded, expected)
	}
}

func TestUnsaltedMD5PasswordVerify1(t *testing.T) {
	valid, err := NewUnsaltedMD5PasswordHasher().Verify("this-is-my-password", "d24c80177269fb85874b1361e6b71fb4")

	if err != nil {
		t.Fatalf("Verify error: %s", err)
	}

	if !valid {
		t.Fatal("Password should be valid.")
	}
}

func TestUnsaltedMD5PasswordVerify2(t *testing.T) {
	valid, err := NewUnsaltedMD5PasswordHasher().Verify("this-is-my-password", "md5$$d24c80177269fb85874b1361e6b71fb4")

	if err != nil {
		t.Fatalf("Verify error: %s", err)
	}

	if !valid {
		t.Fatal("Password should be valid.")
	}
}

func TestMD5PasswordEncode(t *testing.T) {
	encoded, err := NewMD5PasswordHasher().Encode("this-is-my-password", "NMxMaHPlUEr7")

	if err != nil {
		t.Fatalf("Encode error: %s", err)
	}

	expected := "md5$NMxMaHPlUEr7$5b7913a35d0cfbbd3e5ef243c84eadd1"

	if encoded != expected {
		t.Fatalf("Encoded hash %s does not match %s.", encoded, expected)
	}
}

func TestMD5PasswordVerify(t *testing.T) {
	valid, err := NewMD5PasswordHasher().Verify("this-is-my-password", "md5$NMxMaHPlUEr7$5b7913a35d0cfbbd3e5ef243c84eadd1")

	if err != nil {
		t.Fatalf("Verify error: %s", err)
	}

	if !valid {
		t.Fatal("Password should be valid.")
	}
}
