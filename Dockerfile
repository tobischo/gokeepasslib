FROM golang:1.19.1

# Don't run tests as root so we can play with permissions
RUN useradd --create-home --user-group app

ENV GOPACKAGE github.com/tobischo/gokeepasslib

ADD . /go/src/$GOPACKAGE
RUN chown -R app /go

WORKDIR /go/src/$GOPACKAGE

USER app
RUN go build
