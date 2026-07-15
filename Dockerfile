FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN go test ./... && go build -o /out/gophermailforge ./cmd/gophermailforge && go build -o /out/gmf ./cmd/gmf
FROM alpine:3.22
COPY --from=build /out/gophermailforge /usr/local/bin/gophermailforge
COPY --from=build /out/gmf /usr/local/bin/gmf
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/gophermailforge"]
