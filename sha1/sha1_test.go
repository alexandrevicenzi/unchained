package sha1

import (
	"testing"
)

func TestUnsaltedSHA1PasswordEncode(t *testing.T) {
	encoded, err := NewUnsaltedSHA1PasswordHasher().Encode("this-is-my-password", "")

	if err != nil {
		t.Fatalf("Encode error: %s", err)
	}

	expected := "sha1$$47a0caaf95db24a7f6701f0681610b9eed7e880f"

	if encoded != expected {
		t.Fatalf("Encoded hash %s does not match %s.", encoded, expected)
	}
}

func TestUnsaltedSHA1PasswordVerify(t *testing.T) {
	valid, err := NewUnsaltedSHA1PasswordHasher().Verify("this-is-my-password", "sha1$$47a0caaf95db24a7f6701f0681610b9eed7e880f")

	if err != nil {
		t.Fatalf("Verify error: %s", err)
	}

	if !valid {
		t.Fatal("Password should be valid.")
	}
}

func TestSHA1PasswordEncode(t *testing.T) {
	encoded, err := NewSHA1PasswordHasher().Encode("this-is-my-password", "FJkZbdAmXSDF")

	if err != nil {
		t.Fatalf("Encode error: %s", err)
	}

	expected := "sha1$FJkZbdAmXSDF$972db6461472a5345bab667d0255d120e06a3415"

	if encoded != expected {
		t.Fatalf("Encoded hash %s does not match %s.", encoded, expected)
	}
}

func TestSHA1PasswordVerify(t *testing.T) {
	valid, err := NewSHA1PasswordHasher().Verify("this-is-my-password", "sha1$FJkZbdAmXSDF$972db6461472a5345bab667d0255d120e06a3415")

	if err != nil {
		t.Fatalf("Verify error: %s", err)
	}

	if !valid {
		t.Fatal("Password should be valid.")
	}
}
