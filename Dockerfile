FROM golang:1.13

RUN mkdir -p /go/src/github.com/alexandrevicenzi/unchained

WORKDIR /go/src/github.com/alexandrevicenzi/unchained

ENV GO111MODULE on
ENV GOPRIVATE on
ENV GONOPROXY on
