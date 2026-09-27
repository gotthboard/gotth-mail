#!/usr/bin/env bash
# Bounded native gates; all writes are task evidence or private namespace state.
set -euo pipefail
[[ $# == 4 || $# == 5 || $# == 6 ]] || { echo 'usage: TEST_BINARY ALPHA1_ARCHIVE PG16_BIN NEW_EVIDENCE_DIR [navigation|audit|configuration|connection-test|activation|update|rollback] [ALPHA2_FOR_UPDATE_OR_ROLLBACK]' >&2; exit 2; }
mode=${5:-navigation}
archive_b=""
if [[ "$mode" == update || "$mode" == rollback ]]; then
 [[ $# == 6 && -f "$6" ]] || exit 2
 archive_b=$(realpath -e "$6")
else
 [[ $# == 4 || $# == 5 ]] || exit 2
 [[ "$mode" == navigation || "$mode" == audit || "$mode" == configuration || "$mode" == connection-test || "$mode" == activation ]] || exit 2
fi
binary=$(realpath -e "$1"); archive=$(realpath -e "$2"); pgbin=$(realpath -e "$3")
driver=$(realpath -e "$(dirname "$0")/extensions-browser-smoke.mjs")
[[ -x "$binary" && -f "$archive" && -x "$pgbin/postgres" && -x "$pgbin/initdb" && -x "$pgbin/createdb" ]]
mkdir -m 700 "$4"; output=$(realpath -e "$4")
"$pgbin/postgres" --version
bwrap --unshare-user --unshare-pid --unshare-ipc --unshare-uts --unshare-net \
 --die-with-parent --new-session --ro-bind / / --tmpfs /tmp --proc /proc --dev /dev \
 --tmpfs /etc/ssl/certs --bind "$output" "$output" --clearenv \
 --setenv PATH "$pgbin:/usr/bin:/bin" --setenv HOME /tmp/browser-home \
 --setenv TMPDIR /tmp --setenv GOTMPDIR /tmp --setenv GOMAXPROCS 4 \
 --setenv GOTTH_MAIL_ACCEPTANCE_ARCHIVE_B "$archive_b" \
 --setenv GOTTH_MAIL_ACCEPTANCE_NAMESPACE 1 --setenv GOTTH_MAIL_ACCEPTANCE_ARCHIVE "$archive" \
 --setenv GOTTH_MAIL_ACCEPTANCE_CERT /tmp/tls/server.crt --setenv GOTTH_MAIL_ACCEPTANCE_KEY /tmp/tls/server.key \
 --setenv GOTTH_MAIL_BROWSER_MODE "$mode" --setenv GOTTH_MAIL_BROWSER_DRIVER "$driver" --setenv GOTTH_MAIL_BROWSER_OUTPUT "$output/browser" \
 --chdir /tmp -- /bin/bash -eu -o pipefail -c '
 umask 077
 mkdir /tmp/tls /tmp/browser-home
 openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -subj /CN=GOTTH-Mail-acceptance-CA -keyout /tmp/tls/ca.key \
  -out /etc/ssl/certs/ca-certificates.crt >/dev/null 2>&1
 openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj /CN=127.0.0.1 -keyout /tmp/tls/server.key -out /tmp/tls/server.csr >/dev/null 2>&1
 printf "%s\n" "subjectAltName=IP:127.0.0.1" "extendedKeyUsage=serverAuth" > /tmp/tls/server.ext
 openssl x509 -req -in /tmp/tls/server.csr -CA /etc/ssl/certs/ca-certificates.crt \
  -CAkey /tmp/tls/ca.key -CAcreateserial -days 1 -extfile /tmp/tls/server.ext \
  -out /tmp/tls/server.crt >/dev/null 2>&1
 set +e
 "$1" -test.v -test.timeout=3m -test.run="^TestExtensionAcceptanceBrowserFixture$"
 result=$?
 set -e
 # Check live descendants independently before namespace final containment.
 alive=$(ps -eo stat=,comm= | awk '\''$1 !~ /^Z/ && ($2=="chromium" || $2=="chrome_crashpad" || $2=="postgres" || $2=="gotth-extension") {n++} END {print n+0}'\'')
 leftovers=$(find /tmp -mindepth 1 -maxdepth 1 ! -name tls ! -name browser-home | wc -l)
 printf "namespace closeout: live fixture processes=%s residual paths=%s\n" "$alive" "$leftovers"
 if [[ "$alive" != 0 || "$leftovers" != 0 ]]; then exit 2; fi
 exit "$result"
 ' browser-acceptance "$binary"
