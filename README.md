# Unchained [![Build Status](https://travis-ci.org/alexandrevicenzi/unchained.svg?branch=master)](https://travis-ci.org/alexandrevicenzi/unchained) [![GoDoc](https://godoc.org/github.com/alexandrevicenzi/unchained?status.svg)](http://godoc.org/github.com/alexandrevicenzi/unchained) [![Go Report Card](https://goreportcard.com/badge/github.com/alexandrevicenzi/unchained)](https://goreportcard.com/report/github.com/alexandrevicenzi/unchained)

Django password hashers for Go

## About

This project aims to implement [Django Hashers](https://github.com/django/django/blob/master/django/contrib/auth/hashers.py) in Go to perform user validation against Django legacy databases.

If you're looking for a port of Django's auth application check [djinn](https://godoc.org/github.com/aodin/djinn).

## Install

```
go get github.com/alexandrevicenzi/unchained
```

## Supported Hashers

| Hasher | Encode | Decode | Dependencies |
|:-------|:------:|:------:|:------------:|
| Argon2        | ✘ | ✘ |  |
| BCrypt        | ✔ | ✔ | [golang.org/x/crypto/bcrypt](golang.org/x/crypto/bcrypt) |
| BCrypt SHA256 | ✔ | ✔ | [golang.org/x/crypto/bcrypt](golang.org/x/crypto/bcrypt) |
| Crypt         | ✘ | ✘ |  |
| MD5           | ✘ | ✘ |  |
| PBKDF2        | ✔ | ✔ | [golang.org/x/crypto/pbkdf2](golang.org/x/crypto/pbkdf2) |
| PBKDF2 SHA1   | ✔ | ✔ | [golang.org/x/crypto/pbkdf2](golang.org/x/crypto/pbkdf2) |
| SHA1          | ✘ | ✘ |  |
| Unsalted MD5  | ✘ | ✘ |  |
| Unsalted SHA1 | ✘ | ✘ |  |

## Notes

Crypt support is not planned because it's UNIX only.

BCrypt hashers do not allow to set custom salt as in Django.
If you encode the same password multiple times you will get different hashes.
This limitation comes from [golang.org/x/crypto/bcrypt](golang.org/x/crypto/bcrypt) library.

## Example

```go
package main

import "github.com/alexandrevicenzi/unchained"

func main() {
    valid, err := unchained.CheckPassword("admin", "pbkdf2_sha256$24000$JMO9TJawIXB1$5iz40fwwc+QW6lZY+TuNciua3YVMV3GXdgkhXrcvWag=")

    if (valid) {
        // do something
    } else {
        // error
    }
}
```

## TODO

- Argon2 support
- Weak hashers support

## Reference

- [Password management in Django](https://docs.djangoproject.com/en/dev/topics/auth/passwords/)
- [Django Unchained](http://www.imdb.com/title/tt1853728/) :trollface:
