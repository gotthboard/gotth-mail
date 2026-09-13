FROM golang:1.25-alpine AS build
RUN adduser -D -h /home/gotthmail gotthmail \
    && mkdir -p /src /out /go \
    && chown -R gotthmail:gotthmail /src /out /go /home/gotthmail
WORKDIR /src
COPY --chown=gotthmail:gotthmail go.mod go.sum ./
COPY --chown=gotthmail:gotthmail . .
USER gotthmail
RUN go test ./... && go build -o /out/gotth-mail ./cmd/gotth-mail && go build -o /out/gotth-mailctl ./cmd/gotth-mailctl && go build -o /out/gotth-mail-plugin ./cmd/gotth-mail-plugin
FROM alpine:3.22
COPY --from=build /out/gotth-mail /usr/local/bin/gotth-mail
COPY --from=build /out/gotth-mailctl /usr/local/bin/gotth-mailctl
COPY --from=build /out/gotth-mail-plugin /usr/local/bin/gotth-mail-plugin
EXPOSE 8080 9443
ENTRYPOINT ["/usr/local/bin/gotth-mail"]
