# Unchained

Django password hashers for Go

## About

This project aims to implement [Django Hashers](https://github.com/django/django/blob/master/django/contrib/auth/hashers.py) in Go to perform user validation against Django legacy databases.

## Install

```
go get github.com/alexandrevicenzi/unchained
go get golang.org/x/crypto/pbkdf2
```

## Supported Hashers

| Hasher | Encode | Decode |
|:-------|:------:|:------:|
| argon2        | ✘ || ✘ |
| bcrypt        | ✘ || ✘ |
| bcrypt_sha256 | ✘ || ✘ |
| crypt         | ✘ || ✘ |
| md5           | ✘ || ✘ |
| pbkdf2_sha1   | ✔ || ✔ |
| pbkdf2_sha256 | ✔ || ✔ |
| sha1          | ✘ || ✘ |
| unsalted_md5  | ✘ || ✘ |
| unsalted_sha1 | ✘ || ✘ |

Others hashers are planned to be implemented.

## Reference

- [Password management in Django](https://docs.djangoproject.com/en/1.9/topics/auth/passwords/)
- [Django Unchained](http://www.imdb.com/title/tt1853728/) :trollface: