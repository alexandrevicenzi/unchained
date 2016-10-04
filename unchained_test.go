package unchained

import "testing"

func TestCheckPasswordPBKDF2SHA256WithValidPassword(t *testing.T) {
	valid, err := CheckPassword("admin", "pbkdf2_sha256$24000$JMO9TJawIXB1$5iz40fwwc+QW6lZY+TuNciua3YVMV3GXdgkhXrcvWag=")

	if err != nil {
		t.Fatal(err)
	} else if !valid {
		t.Fatal("Password should be valid.")
	}
}

func TestCheckPasswordPBKDF2SHA256WithInvalidPassword(t *testing.T) {
	valid, err := CheckPassword("wrongpassword", "pbkdf2_sha256$24000$JMO9TJawIXB1$5iz40fwwc+QW6lZY+TuNciua3YVMV3GXdgkhXrcvWag=")

	if err != nil {
		t.Fatal(err)
	} else if valid {
		t.Fatal("Password should be invalid.")
	}
}

func TestCheckPasswordPBKDF2SHA1WithValidPassword(t *testing.T) {
	valid, err := CheckPassword("test", "pbkdf2_sha1$24000$zX573SspyROA$eqWjJBui5kY/TRXg2TwvSwA+2wk=")

	if err != nil {
		t.Fatal(err)
	} else if !valid {
		t.Fatal("Password should be valid.")
	}
}

func TestCheckPasswordPBKDF2SHA1WithInvalidPassword(t *testing.T) {
	valid, err := CheckPassword("wrongpassword", "pbkdf2_sha1$24000$zX573SspyROA$eqWjJBui5kY/TRXg2TwvSwA+2wk=")

	if err != nil {
		t.Fatal(err)
	} else if valid {
		t.Fatal("Password should be invalid.")
	}
}

func TestIsPasswordUsableWithValidPassword(t *testing.T) {
	usabe := IsPasswordUsable("pbkdf2_sha256$24000$JMO9TJawIXB1$5iz40fwwc+QW6lZY+TuNciua3YVMV3GXdgkhXrcvWag=")

	if !usabe {
		t.Fatal("Password should be usable.")
	}
}

func TestIsPasswordUsableWithUnusablePassword(t *testing.T) {
	usabe := IsPasswordUsable("!")

	if usabe {
		t.Fatal("Password should be unusable.")
	}
}
