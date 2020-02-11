// Package unchained provides password hashers that are compatible with Django.
//
// These hashers can be also used to perform validation against
// legacy and shared Django databases.
//
// Django provides a flexible password storage system and
// uses PBKDF2 by default.
//
// The password format/representation is the same as the one used in Django:
//
//    <algorithm>$<iterations>$<salt>$<hash>
//
// This library supports Argon2, BCrypt, PBKDF2, MD5 and SHA1 algorithms.
//
package unchained
