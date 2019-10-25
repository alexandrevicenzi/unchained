// Package unchained provides Django password hashers in Go.
//
// These hashers can be used to perform validation against
// legacy databases. It can also be used as a standard for
// newer applications.
//
// Django provides a flexible password storage system and
// uses PBKDF2 by default.
//
// The default password used in Django is a string in this format:
//
//    <algorithm>$<iterations>$<salt>$<hash>
//
// This library supports Argon2, BCrypt, PBKDF2, MD5 and SHA1 algorithms.
//
package unchained
