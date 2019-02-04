# Unchained [![Build Status](https://travis-ci.org/alexandrevicenzi/unchained.svg?branch=master)](https://travis-ci.org/alexandrevicenzi/unchained) [![GoDoc](https://godoc.org/github.com/alexandrevicenzi/unchained?status.svg)](http://godoc.org/github.com/alexandrevicenzi/unchained) [![Go Report Card](https://goreportcard.com/badge/github.com/alexandrevicenzi/unchained)](https://goreportcard.com/report/github.com/alexandrevicenzi/unchained)

Django password hashers for Go

## About

This project aims to implement [Django Hashers](https://github.com/django/django/blob/master/django/contrib/auth/hashers.py) in Go to perform user validation against Django legacy databases.

If you're looking for a port of Django's auth application check [djinn](https://godoc.org/github.com/aodin/djinn).

## Install

```
go get github.com/alexandrevicenzi/unchained
go get golang.org/x/crypto/pbkdf2
```

## Supported Hashers

| Hasher | Encode | Decode |
|:-------|:------:|:------:|
| argon2        | ✘ | ✘ |
| bcrypt        | ✘ | ✘ |
| bcrypt_sha256 | ✘ | ✘ |
| crypt         | ✘ | ✘ |
| md5           | ✘ | ✘ |
| pbkdf2_sha1   | ✔ | ✔ |
| pbkdf2_sha256 | ✔ | ✔ |
| sha1          | ✘ | ✘ |
| unsalted_md5  | ✘ | ✘ |
| unsalted_sha1 | ✘ | ✘ |

Others hashers are planned to be implemented.

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

## Reference

- [Password management in Django](https://docs.djangoproject.com/en/dev/topics/auth/passwords/)
- [Django Unchained](http://www.imdb.com/title/tt1853728/) :trollface:
