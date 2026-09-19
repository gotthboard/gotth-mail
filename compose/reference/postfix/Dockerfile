FROM golang:1.26.6-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY . .
RUN go build -o /out/gotth-mail-postfix-gate ./cmd/gotth-mail-postfix-gate

FROM alpine:3.22
RUN apk add --no-cache postfix busybox-extras curl jq
COPY --from=build /out/gotth-mail-postfix-gate /usr/local/bin/gotth-mail-postfix-gate
