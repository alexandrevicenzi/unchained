package unchained

import "testing"

func TestVerifyWithValidPassword(t *testing.T) {
    valid, err := Verify("admin", "pbkdf2_sha256$24000$JMO9TJawIXB1$5iz40fwwc+QW6lZY+TuNciua3YVMV3GXdgkhXrcvWag=")

    if (err != nil) {
        t.Fatal(err)
    } else if (!valid) {
        t.Fatal("Password should be valid.")
    }
}

func TestVerifyWithInvalidPassword(t *testing.T) {
    valid, err := Verify("wrongpassword", "pbkdf2_sha256$24000$JMO9TJawIXB1$5iz40fwwc+QW6lZY+TuNciua3YVMV3GXdgkhXrcvWag=")

    if (err != nil) {
        t.Fatal(err)
    } else if (valid) {
        t.Fatal("Password should be invalid.")
    }
}

func TestIsPasswordUsableWithValidPassword(t *testing.T) {
    usabe := IsPasswordUsable("pbkdf2_sha256$24000$JMO9TJawIXB1$5iz40fwwc+QW6lZY+TuNciua3YVMV3GXdgkhXrcvWag=")

    if (!usabe) {
        t.Fatal("Password should be usable.")
    }
}

func TestIsPasswordUsableWithUnusablePassword(t *testing.T) {
    usabe := IsPasswordUsable("!")

    if (usabe) {
        t.Fatal("Password should be unusable.")
    }
}
