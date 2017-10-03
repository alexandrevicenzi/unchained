package bcrypt

import "testing"

func TestBcryptVerifyPassword(t *testing.T) {
	hashedPassword, err := NewBcryptHasher().Encode("FooBar", 10)
	if err != nil {
		t.Errorf("Error hashing password: %v", err)
	}
	t.Logf("Hashed password is: %s", hashedPassword)

	res, err := NewBcryptHasher().Verify("FooBar", hashedPassword)

	if res == false {
		if err != nil {
			t.Errorf("Error comparing passwords: %v", err)
		} else {
			t.Error("Passwords do not match")
		}
	}
}
