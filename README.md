# Unchained

[![Build Status](https://travis-ci.org/alexandrevicenzi/unchained.svg?branch=master)](https://travis-ci.org/alexandrevicenzi/unchained)
[![GoDoc](https://godoc.org/github.com/alexandrevicenzi/unchained?status.svg)](http://godoc.org/github.com/alexandrevicenzi/unchained)
[![Go Report Card](https://goreportcard.com/badge/github.com/alexandrevicenzi/unchained)](https://goreportcard.com/report/github.com/alexandrevicenzi/unchained)

Secure password hashers for Go compatible with [Django Password Hashers](https://docs.djangoproject.com/en/3.0/topics/auth/passwords/).

Unchained can also be used to perform password validation against legacy or shared Django databases.

## Install

Requires Go 1.9 or higher.

```
go get github.com/alexandrevicenzi/unchained
```

## Supported Hashers

| Hasher | Encode | Decode | Dependencies |
|:-------|:------:|:------:|:------------:|
| Argon2        | ✔ | ✔ | [golang.org/x/crypto/argon2](https://godoc.org/golang.org/x/crypto/argon2) |
| BCrypt        | ✔ | ✔ | [golang.org/x/crypto/bcrypt](https://godoc.org/golang.org/x/crypto/bcrypt) |
| BCrypt SHA256 | ✔ | ✔ | [golang.org/x/crypto/bcrypt](https://godoc.org/golang.org/x/crypto/bcrypt) |
| Crypt         | ✘ | ✘ |  |
| MD5           | ✔ | ✔ |  |
| PBKDF2 SHA1   | ✔ | ✔ | [golang.org/x/crypto/pbkdf2](https://godoc.org/golang.org/x/crypto/pbkdf2) |
| PBKDF2 SHA256 | ✔ | ✔ | [golang.org/x/crypto/pbkdf2](https://godoc.org/golang.org/x/crypto/pbkdf2) |
| SHA1          | ✔ | ✔ |  |
| Unsalted MD5  | ✔ | ✔ |  |
| Unsalted SHA1 | ✔ | ✔ |  |

## Notes

Crypt support is not planned because it's UNIX only.

BCrypt hasher does not allow to set custom salt as in Django.
If you encode the same password multiple times you will get different hashes.
This limitation comes from [golang.org/x/crypto/bcrypt](https://godoc.org/golang.org/x/crypto/bcrypt) library.

## Examples

### Encode password

```go
package main

import "github.com/alexandrevicenzi/unchained"

func main() {
    hash, err := unchained.MakePassword("my-password", unchained.GetRandomString(12), "default")

    if err == nil {
        fmt.Println(hash)
    } else {
        fmt.Printf("Error encoding password: %s\n", err)
    }
}
```

### Validate password

```go
package main

import "github.com/alexandrevicenzi/unchained"

func main() {
    valid, err := unchained.CheckPassword("admin", "pbkdf2_sha256$24000$JMO9TJawIXB1$5iz40fwwc+QW6lZY+TuNciua3YVMV3GXdgkhXrcvWag=")

    if valid {
        fmt.Println("Password is valid.")
    } else {
        if err == nil {
            fmt.Println("Password is invalid.")
        } else {
            fmt.Printf("Error decoding password: %s\n", err)
        }
    }
}
```

## License

BSD

## Reference

- [Password management in Django](https://docs.djangoproject.com/en/3.0/topics/auth/passwords/)
- [Django Unchained](http://www.imdb.com/title/tt1853728/) :trollface:

## Related Links

- [Django compatible signing for Go](https://gitlab.com/pennersr/djgo/) (`django.core.signing`)
