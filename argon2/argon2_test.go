package argon2

import (
	"testing"
)

func TestArgon2Encode1(t *testing.T) {
	encoded, err := NewArgon2Hasher().Encode("admin", "6qY4lfA15naU")

	if err != nil {
		t.Fatalf("Encode error: %s", err)
	}

	expected := "argon2$argon2i$v=19$m=512,t=2,p=2$NnFZNGxmQTE1bmFV$kPPGrqD6dnRllcQeksFN+w"

	if encoded != expected {
		t.Fatalf("Encoded hash %s does not match %s.", encoded, expected)
	}
}

func TestArgon2Encode2(t *testing.T) {
	encoded, err := NewArgon2Hasher().Encode("this-is-my-password", "h8lI73ohfXug")

	if err != nil {
		t.Fatalf("Encode error: %s", err)
	}

	expected := "argon2$argon2i$v=19$m=512,t=2,p=2$aDhsSTczb2hmWHVn$TPhJYMg9pKQauvPF4RPH8A"

	if encoded != expected {
		t.Fatalf("Encoded hash %s does not match %s.", encoded, expected)
	}
}

func TestArgon2Encode3(t *testing.T) {
	encoded, err := NewArgon2Hasher().Encode("Th1S1sMYp4ssw0rd", "HUxfcH4lx2SP")

	if err != nil {
		t.Fatalf("Encode error: %s", err)
	}

	expected := "argon2$argon2i$v=19$m=512,t=2,p=2$SFV4ZmNINGx4MlNQ$fEh86SVdKL6mqx+pRDHOlg"

	if encoded != expected {
		t.Fatalf("Encoded hash %s does not match %s.", encoded, expected)
	}
}

func TestArgon2Encode4(t *testing.T) {
	encoded, err := NewArgon2Hasher().Encode("this$is#my@PASSWORD", "0iHb4EQbyJzL")

	if err != nil {
		t.Fatalf("Encode error: %s", err)
	}

	expected := "argon2$argon2i$v=19$m=512,t=2,p=2$MGlIYjRFUWJ5SnpM$NMBj1EpUCdu+TGsTLdAyfw"

	if encoded != expected {
		t.Fatalf("Encoded hash %s does not match %s.", encoded, expected)
	}
}

func TestArgon2Verify1(t *testing.T) {
	valid, err := NewArgon2Hasher().Verify("admin", "argon2$argon2i$v=19$m=512,t=2,p=2$NnFZNGxmQTE1bmFV$kPPGrqD6dnRllcQeksFN+w")

	if err != nil {
		t.Fatalf("Verify error: %s", err)
	}

	if !valid {
		t.Fatal("Password should be valid.")
	}
}

func TestArgon2Verify2(t *testing.T) {
	valid, err := NewArgon2Hasher().Verify("this-is-my-password", "argon2$argon2i$v=19$m=512,t=2,p=2$aDhsSTczb2hmWHVn$TPhJYMg9pKQauvPF4RPH8A")

	if err != nil {
		t.Fatalf("Verify error: %s", err)
	}

	if !valid {
		t.Fatal("Password should be valid.")
	}
}

func TestArgon2Verify3(t *testing.T) {
	valid, err := NewArgon2Hasher().Verify("Th1S1sMYp4ssw0rd", "argon2$argon2i$v=19$m=512,t=2,p=2$SFV4ZmNINGx4MlNQ$fEh86SVdKL6mqx+pRDHOlg")

	if err != nil {
		t.Fatalf("Verify error: %s", err)
	}

	if !valid {
		t.Fatal("Password should be valid.")
	}
}

func TestArgon2Verify4(t *testing.T) {
	valid, err := NewArgon2Hasher().Verify("this$is#my@PASSWORD", "argon2$argon2i$v=19$m=512,t=2,p=2$MGlIYjRFUWJ5SnpM$NMBj1EpUCdu+TGsTLdAyfw")

	if err != nil {
		t.Fatalf("Verify error: %s", err)
	}

	if !valid {
		t.Fatal("Password should be valid.")
	}
}

func TestArgon2VerifyInvalidPassword(t *testing.T) {
	valid, err := NewArgon2Hasher().Verify("wrongpassword", "argon2$argon2i$v=19$m=512,t=2,p=2$NnFZNGxmQTE1bmFV$kPPGrqD6dnRllcQeksFN+w")

	if err != nil {
		t.Fatalf("Verify error: %s", err)
	}

	if valid {
		t.Fatal("Password should not be valid.")
	}
}
