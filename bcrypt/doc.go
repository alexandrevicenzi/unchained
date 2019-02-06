// Package bcrypt implements a Django compatible bcrypt algorithm.
//
// This is considered by many to be the most secure algorithm.
//
// This library does not allow to set custom salt as in the Django algorithm.
// If you encode the same password multiple times you will get different hashes.
// This limitation comes from [golang.org/x/crypto/bcrypt](golang.org/x/crypto/bcrypt) library.
package bcrypt
