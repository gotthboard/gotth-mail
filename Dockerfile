FROM golang:1.25-alpine AS build
RUN adduser -D -h /home/gmf gmf \
    && mkdir -p /src /out /go \
    && chown -R gmf:gmf /src /out /go /home/gmf
WORKDIR /src
COPY --chown=gmf:gmf go.mod go.sum ./
COPY --chown=gmf:gmf . .
USER gmf
RUN go test ./... && go build -o /out/gophermailforge ./cmd/gophermailforge && go build -o /out/gmf ./cmd/gmf
FROM alpine:3.22
COPY --from=build /out/gophermailforge /usr/local/bin/gophermailforge
COPY --from=build /out/gmf /usr/local/bin/gmf
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/gophermailforge"]
