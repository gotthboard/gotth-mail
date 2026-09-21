# syntax=docker/dockerfile:1.7

ARG GO_IMAGE=golang@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83
ARG RUNTIME_IMAGE=alpine@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8

FROM --platform=linux/amd64 ${GO_IMAGE} AS source
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION
ARG SOURCE_COMMIT
ARG BUILD_DATE_EPOCH
ARG SOURCE_DATE_EPOCH
ARG SOURCE_STATE
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64
RUN printf '%s\n' "${VERSION}" | grep -Eq '^dev$|^1\.0\.0$|^1\.0\.0-(alpha|beta)\.[1-9][0-9]*$' && \
    printf '%s\n' "${SOURCE_COMMIT}" | grep -Eq '^[0-9a-f]{40}$' && \
    printf '%s\n' "${SOURCE_STATE}" | grep -Eq '^[0-9a-f]{64}$' && \
    printf '%s\n' "${BUILD_DATE_EPOCH}" | grep -Eq '^[1-9][0-9]*$' && \
    test "${BUILD_DATE_EPOCH}" = "${SOURCE_DATE_EPOCH}" && \
    go build -trimpath -buildvcs=false -ldflags="-s -w -buildid= -X forgejo/gotthboard/gotth-mail/internal/version.Version=${VERSION}" -o /out/gotth-mail ./cmd/gotth-mail && \
    go build -trimpath -buildvcs=false -ldflags="-s -w -buildid= -X forgejo/gotthboard/gotth-mail/internal/version.Version=${VERSION}" -o /out/gotth-mail-postfix-gate ./cmd/gotth-mail-postfix-gate

FROM source AS binaries-control
RUN go build -trimpath -buildvcs=false -ldflags="-s -w -buildid= -X main.role=control-plane -X forgejo/gotthboard/gotth-mail/internal/version.Version=${VERSION}" -o /out/gotth-mail-entrypoint ./cmd/gotth-mail-entrypoint && \
    go build -trimpath -buildvcs=false -ldflags="-s -w -buildid= -X main.role=control-plane -X forgejo/gotthboard/gotth-mail/internal/version.Version=${VERSION}" -o /out/gotth-mail-health ./cmd/gotth-mail-health

FROM source AS binaries-front
RUN go build -trimpath -buildvcs=false -ldflags="-s -w -buildid= -X main.role=front -X forgejo/gotthboard/gotth-mail/internal/version.Version=${VERSION}" -o /out/gotth-mail-entrypoint ./cmd/gotth-mail-entrypoint && \
    go build -trimpath -buildvcs=false -ldflags="-s -w -buildid= -X main.role=front -X forgejo/gotthboard/gotth-mail/internal/version.Version=${VERSION}" -o /out/gotth-mail-health ./cmd/gotth-mail-health

FROM source AS binaries-postfix
RUN go build -trimpath -buildvcs=false -ldflags="-s -w -buildid= -X main.role=postfix -X forgejo/gotthboard/gotth-mail/internal/version.Version=${VERSION}" -o /out/gotth-mail-entrypoint ./cmd/gotth-mail-entrypoint && \
    go build -trimpath -buildvcs=false -ldflags="-s -w -buildid= -X main.role=postfix -X forgejo/gotthboard/gotth-mail/internal/version.Version=${VERSION}" -o /out/gotth-mail-health ./cmd/gotth-mail-health

FROM source AS binaries-dovecot
RUN go build -trimpath -buildvcs=false -ldflags="-s -w -buildid= -X main.role=dovecot -X forgejo/gotthboard/gotth-mail/internal/version.Version=${VERSION}" -o /out/gotth-mail-entrypoint ./cmd/gotth-mail-entrypoint && \
    go build -trimpath -buildvcs=false -ldflags="-s -w -buildid= -X main.role=dovecot -X forgejo/gotthboard/gotth-mail/internal/version.Version=${VERSION}" -o /out/gotth-mail-health ./cmd/gotth-mail-health

FROM source AS binaries-rspamd
RUN go build -trimpath -buildvcs=false -ldflags="-s -w -buildid= -X main.role=rspamd -X forgejo/gotthboard/gotth-mail/internal/version.Version=${VERSION}" -o /out/gotth-mail-entrypoint ./cmd/gotth-mail-entrypoint && \
    go build -trimpath -buildvcs=false -ldflags="-s -w -buildid= -X main.role=rspamd -X forgejo/gotthboard/gotth-mail/internal/version.Version=${VERSION}" -o /out/gotth-mail-health ./cmd/gotth-mail-health

FROM ${RUNTIME_IMAGE} AS control-plane
RUN apk add --no-cache ca-certificates=20260909-r0 tzdata=2026d-r0 && \
    addgroup -S -g 1000 gotth && adduser -S -D -H -u 1000 -G gotth gotth
COPY --from=source --chown=1000:1000 /out/gotth-mail /usr/local/bin/gotth-mail
COPY --from=binaries-control --chown=1000:1000 /out/gotth-mail-entrypoint /out/gotth-mail-health /usr/local/bin/
ARG VERSION SOURCE_COMMIT SOURCE_STATE
LABEL org.opencontainers.image.version="${VERSION}" org.opencontainers.image.revision="${SOURCE_COMMIT}" com.gotth.mail.source-state="${SOURCE_STATE}" com.gotth.mail.role="control-plane"
USER 1000:1000
ENTRYPOINT ["/usr/local/bin/gotth-mail-entrypoint"]

FROM ${RUNTIME_IMAGE} AS front
RUN apk add --no-cache ca-certificates=20260909-r0 tzdata=2026d-r0 nginx=1.28.3-r7 nginx-mod-mail=1.28.3-r7 && \
    addgroup -S -g 1000 gotth && adduser -S -D -H -u 1000 -G gotth gotth
COPY --from=binaries-front --chown=1000:1000 /out/gotth-mail-entrypoint /out/gotth-mail-health /usr/local/bin/
ARG VERSION SOURCE_COMMIT SOURCE_STATE
LABEL org.opencontainers.image.version="${VERSION}" org.opencontainers.image.revision="${SOURCE_COMMIT}" com.gotth.mail.source-state="${SOURCE_STATE}" com.gotth.mail.role="front"
USER 1000:1000
ENTRYPOINT ["/usr/local/bin/gotth-mail-entrypoint"]

FROM ${RUNTIME_IMAGE} AS postfix
RUN apk add --no-cache ca-certificates=20260909-r0 tzdata=2026d-r0 postfix=3.10.13-r0 postfix-pcre=3.10.13-r0 postfix-pgsql=3.10.13-r0
COPY --from=binaries-postfix /out/gotth-mail-entrypoint /out/gotth-mail-health /usr/local/bin/
COPY --from=source /out/gotth-mail-postfix-gate /usr/local/bin/gotth-mail-postfix-gate
ARG VERSION SOURCE_COMMIT SOURCE_STATE
LABEL org.opencontainers.image.version="${VERSION}" org.opencontainers.image.revision="${SOURCE_COMMIT}" com.gotth.mail.source-state="${SOURCE_STATE}" com.gotth.mail.role="postfix"
USER 0:0
ENTRYPOINT ["/usr/local/bin/gotth-mail-entrypoint"]

FROM ${RUNTIME_IMAGE} AS dovecot
RUN apk add --no-cache ca-certificates=20260909-r0 tzdata=2026d-r0 dovecot=2.4.1-r2 dovecot-lmtpd=2.4.1-r2 dovecot-pgsql=2.4.1-r2 dovecot-pigeonhole-plugin=2.4.1-r2
COPY --from=binaries-dovecot /out/gotth-mail-entrypoint /out/gotth-mail-health /usr/local/bin/
ARG VERSION SOURCE_COMMIT SOURCE_STATE
LABEL org.opencontainers.image.version="${VERSION}" org.opencontainers.image.revision="${SOURCE_COMMIT}" com.gotth.mail.source-state="${SOURCE_STATE}" com.gotth.mail.role="dovecot"
USER 0:0
ENTRYPOINT ["/usr/local/bin/gotth-mail-entrypoint"]

FROM ${RUNTIME_IMAGE} AS rspamd
RUN apk add --no-cache ca-certificates=20260909-r0 tzdata=2026d-r0 rspamd=3.11.1-r2 && \
    addgroup -S -g 1000 gotth && adduser -S -D -H -u 1000 -G gotth gotth
COPY --from=binaries-rspamd --chown=1000:1000 /out/gotth-mail-entrypoint /out/gotth-mail-health /usr/local/bin/
ARG VERSION SOURCE_COMMIT SOURCE_STATE
LABEL org.opencontainers.image.version="${VERSION}" org.opencontainers.image.revision="${SOURCE_COMMIT}" com.gotth.mail.source-state="${SOURCE_STATE}" com.gotth.mail.role="rspamd"
USER 1000:1000
ENTRYPOINT ["/usr/local/bin/gotth-mail-entrypoint"]
