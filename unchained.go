package unchained

import (
    "encoding/base64"
    "fmt"
    "crypto/sha256"
    "golang.org/x/crypto/pbkdf2"
    "strconv"
    "strings"
)

func b64encode(bytes []byte) string {
    return base64.StdEncoding.EncodeToString(bytes)
}

func verify_pbkdf2_sha256(password string, encoded string) (bool, error) {
    s := strings.Split(encoded, "$")
    algorithm, iterations, salt, hash := s[0], s[1], s[2], s[3]

    if (algorithm != "pbkdf2_sha256") {
        return false, fmt.Errorf("Algorithm encoder mismatch: %s != pbkdf2_sha256", algorithm)
    }

    i, err := strconv.Atoi(iterations)

    if (err != nil) {
        return false, err
    }

    dk := pbkdf2.Key([]byte(password), []byte(salt), i, sha256.Size, sha256.New)
    newhash := b64encode(dk)
    return newhash == hash, nil
}

func IsPasswordUsable(encoded string) bool {
    return !strings.HasPrefix("!", encoded)
}

func Verify(password string, encoded string) (bool, error) {
    algorithm := strings.Split(encoded, "$")[0]

    if (algorithm == "pbkdf2_sha256") {
        return verify_pbkdf2_sha256(password, encoded)
    } else {
        return false, fmt.Errorf("Hasher not implemented: %s", algorithm)
    }
}
