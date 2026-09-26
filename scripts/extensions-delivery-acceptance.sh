#!/usr/bin/env bash
# Test equipment: precompiled Mail test binary, immutable alpha.1 archive, native PG16.
# No builds/downloads, host trust changes, or writable source/cache mounts here.
set -euo pipefail
if [[ $# != 3 ]]; then echo "usage: $0 TEST_BINARY ALPHA1_ARCHIVE PG16_BIN" >&2; exit 2; fi
binary=$(realpath -e "$1")
archive=$(realpath -e "$2")
pgbin=$(realpath -e "$3")
[[ -x "$binary" && -f "$archive" && -x "$pgbin/postgres" ]]
"$pgbin/postgres" --version
bwrap --version
# Entire fixture, CA and private keys exist only in a private tmpfs mount.
# readonly / preserves shared-library/toolchain paths without writable broad binds.
bwrap --unshare-user --unshare-pid --unshare-ipc --unshare-uts --unshare-net \
 --die-with-parent --new-session --ro-bind / / --tmpfs /tmp --proc /proc --dev /dev \
 --tmpfs /etc/ssl/certs --clearenv \
 --setenv PATH "$pgbin:/usr/bin:/bin" --setenv HOME /tmp --setenv TMPDIR /tmp \
 --setenv GOMAXPROCS 4 --setenv GOTTH_MAIL_ACCEPTANCE_NAMESPACE 1 \
 --setenv GOTTH_MAIL_ACCEPTANCE_ARCHIVE "$archive" \
 --setenv GOTTH_MAIL_ACCEPTANCE_CERT /tmp/tls/server.crt \
 --setenv GOTTH_MAIL_ACCEPTANCE_KEY /tmp/tls/server.key \
 --chdir /tmp -- /bin/bash -eu -o pipefail -c '
 umask 077
 mkdir /tmp/tls
 openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -subj /CN=GOTTH-Mail-acceptance-CA -keyout /tmp/tls/ca.key \
  -out /etc/ssl/certs/ca-certificates.crt >/dev/null 2>&1
 openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj /CN=127.0.0.1 -keyout /tmp/tls/server.key -out /tmp/tls/server.csr >/dev/null 2>&1
 printf "%s\n" "subjectAltName=IP:127.0.0.1" "extendedKeyUsage=serverAuth" > /tmp/tls/server.ext
 openssl x509 -req -in /tmp/tls/server.csr -CA /etc/ssl/certs/ca-certificates.crt \
  -CAkey /tmp/tls/ca.key -CAcreateserial -days 1 -extfile /tmp/tls/server.ext \
  -out /tmp/tls/server.crt >/dev/null 2>&1
 "$1" -test.v -test.timeout=10m -test.run="^(TestExtensionRealArchiveDelivery|TestExtensionAcceptanceReceiverBounds)$"
 # Test cleanup must have removed PG, staging and runtime directories.
 test "$(find /tmp -mindepth 1 -maxdepth 1 ! -name tls | wc -l)" -eq 0
 echo "namespace cleanup: only ephemeral TLS fixture remains; destroyed on namespace exit"
 ' acceptance "$binary"
