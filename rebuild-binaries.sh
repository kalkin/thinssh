#!/bin/sh

GOARCH=386 go build && mv thinssh bin/thinssh-"386"
GOARCH=amd64 go build && mv thinssh bin/thinssh-"amd64"
