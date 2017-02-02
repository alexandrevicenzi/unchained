FROM golang:1.7

RUN mkdir -p /go/src/github.com/alexandrevicenzi/unchained

WORKDIR /go/src/github.com/alexandrevicenzi/unchained

RUN go get github.com/stretchr/testify
RUN go get golang.org/x/crypto/pbkdf2
