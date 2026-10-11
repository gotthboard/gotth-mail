#!/bin/sh
set -eu

image="${GOTTH_RETRY_TRANSPORT_POSTFIX_IMAGE:-gotth-mail-release-postfix:1.0.0-alpha.3}"
docker_command="${DOCKER:-docker}"
if ! $docker_command info >/dev/null 2>&1; then
  docker_command="sudo -n docker"
fi
stamp=$(date -u +%Y%m%dT%H%M%SZ)
project="gotth-retry-transport-red-${USER:-test}-$$"
network="$project-net"
postfix_container="$project-postfix"
remote_container="$project-remote"
root="${GOTTH_RETRY_TRANSPORT_EVIDENCE_ROOT:-/tmp/$project}"
mkdir -p "$root/fixture" "$root/evidence"
chmod 777 "$root/fixture" "$root/evidence"
cleanup_done=0

cleanup() {
  status=$?
  if [ "$cleanup_done" = 1 ]; then
    return 0
  fi
  cleanup_done=1
  {
    echo "cleanup_started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    $docker_command rm -f "$postfix_container" "$remote_container" 2>&1 || true
    $docker_command network rm "$network" 2>&1 || true
    echo 'remaining_containers:'
    $docker_command ps -a --filter "name=$project" --format '{{.Names}} {{.ID}} {{.Status}}' 2>&1 || true
    echo 'remaining_networks:'
    $docker_command network ls --filter "name=$network" --format '{{.Name}} {{.ID}}' 2>&1 || true
    echo "cleanup_finished_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "cleanup_status=$status"
  } > "$root/evidence/cleanup.txt"
  chmod -R a+r "$root/evidence" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

cat > "$root/fixture/main.cf" <<'EOF_MAIN'
compatibility_level = 3.10
myhostname = retry-red.local
mydomain = retry-red.local
myorigin = $mydomain
inet_interfaces = loopback-only
inet_protocols = ipv4
mynetworks = 127.0.0.0/8
mydestination = localhost
local_transport = error:local delivery disabled
alias_maps =
alias_database =
default_transport = gotth_policy:
relay_transport = gotth_policy:
enable_long_queue_ids = yes
append_dot_mydomain = no
biff = no
readme_directory = no
html_directory = no
meta_directory = /etc/postfix
shlib_directory = /usr/lib/postfix
queue_directory = /var/spool/postfix
data_directory = /var/spool/postfix/data
command_directory = /usr/sbin
daemon_directory = /usr/libexec/postfix
mail_owner = postfix
setgid_group = postdrop
smtpd_relay_restrictions = permit_mynetworks,reject
smtpd_recipient_restrictions = permit_mynetworks,reject
smtpd_milters =
non_smtpd_milters =
message_size_limit = 52428800
mailbox_size_limit = 0
maillog_file = /evidence/maillog.txt
maillog_file_prefixes = /evidence
EOF_MAIN

cat > "$root/fixture/master.cf" <<'EOF_MASTER'
127.0.0.1:2526 inet n -       n       -       -       smtpd
127.0.0.1:10027 inet n -       n       -       -       smtpd
  -o smtpd_sasl_auth_enable=no
  -o smtpd_milters=
  -o non_smtpd_milters=
  -o smtpd_tls_security_level=none
  -o smtpd_relay_restrictions=permit_mynetworks,reject
  -o smtpd_recipient_restrictions=permit_mynetworks,reject
  -o receive_override_options=no_unknown_recipient_checks,no_header_body_checks
  -o content_filter=smtp:
pickup    unix  n       -       n       60      1       pickup
cleanup   unix  n       -       n       -       0       cleanup
qmgr      unix  n       -       n       300     1       qmgr
tlsmgr    unix  -       -       n       1000?   1       tlsmgr
rewrite   unix  -       -       n       -       -       trivial-rewrite
bounce    unix  -       -       n       -       0       bounce
defer     unix  -       -       n       -       0       bounce
trace     unix  -       -       n       -       0       bounce
verify    unix  -       -       n       -       1       verify
flush     unix  n       -       n       1000?   0       flush
proxymap  unix  -       -       n       -       -       proxymap
proxywrite unix -       -       n       -       1       proxymap
smtp      unix  -       -       n       -       -       smtp
relay     unix  -       -       n       -       -       smtp
showq     unix  n       -       n       -       -       showq
error     unix  -       -       n       -       -       error
retry     unix  -       -       n       -       -       error
discard   unix  -       -       n       -       -       discard
local     unix  -       n       n       -       -       local
virtual   unix  -       n       n       -       -       virtual
lmtp      unix  -       -       n       -       -       lmtp
anvil     unix  -       -       n       -       1       anvil
scache    unix  -       -       n       -       1       scache
postlog   unix-dgram n  -       n       -       1       postlogd
gotth_policy unix -     n       n       -       -       pipe
  flags=q user=nobody null_sender= argv=/fixture/gate.sh --queue-id=${queue_id} --sender=${sender} --recipient=${recipient}
EOF_MASTER

cat > "$root/fixture/gate.sh" <<'EOF_GATE'
#!/bin/sh
set -eu
qid=""; sender=""; recip=""
while [ $# -gt 0 ]; do
  case "$1" in
    --queue-id=*) qid=${1#*=} ;;
    --sender=*) sender=${1#*=} ;;
    --recipient=*) recip=${1#*=} ;;
  esac
  shift
done
[ -n "$qid" ] && [ -n "$recip" ] || exit 75
state=$(cat /fixture/policy_state 2>/dev/null || echo deny)
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
if [ "$state" != allow ]; then
  echo "$now decision=defer queueA=$qid recipient=$recip state=$state" >> /evidence/policy-ledger.txt
  exit 75
fi
msg=/tmp/gate-$qid.eml
cat > "$msg"
hash=$(sha256sum "$msg" | awk '{print $1}')
msgid=$(grep -im1 '^Message-ID:' "$msg" | sed 's/[\r]$//' || true)
echo "$now decision=allow queueA=$qid recipient=$recip sender=$sender hash=$hash $msgid" >> /evidence/policy-ledger.txt
{
  sleep 1
  printf 'EHLO gotth-gate\r\n'
  sleep 0.3
  printf 'MAIL FROM:<forwarder@retry-red.local>\r\n'
  sleep 0.3
  printf 'RCPT TO:<%s>\r\n' "$recip"
  sleep 0.3
  printf 'DATA\r\n'
  sleep 0.3
  cat "$msg"
  printf '\r\n.\r\nQUIT\r\n'
} | nc 127.0.0.1 10027 > "/evidence/private10027-$qid.smtp" 2>&1 || exit 75
queueB=$(sed -n 's/.*queued as \([A-Za-z0-9]*\).*/\1/p' "/evidence/private10027-$qid.smtp" | tail -n 1)
[ -n "$queueB" ] || exit 75
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) queueA=$qid private10027_queueB=$queueB input_hash=$hash" >> /evidence/queue-bindings.txt
exit 0
EOF_GATE
chmod 755 "$root/fixture/gate.sh"
echo allow > "$root/fixture/policy_state"
chmod 666 "$root/fixture/policy_state"

cat > "$root/fixture/remote-session.sh" <<'EOF_REMOTE_SESSION'
#!/bin/sh
set -eu
attempt_file=/evidence/remote-attempt.count
attempt=$(($(cat "$attempt_file" 2>/dev/null || echo 0) + 1))
echo "$attempt" > "$attempt_file"
msg=/evidence/remote-message-$attempt.eml
: > "$msg"
printf '220 retry-red-remote ESMTP\r\n'
indata=0
while IFS= read -r line; do
  clean=$(printf '%s' "$line" | sed 's/\r$//')
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) attempt=$attempt line=$clean" >> /evidence/remote-ledger.txt
  if [ "$indata" = 1 ]; then
    if [ "$clean" = "." ]; then
      hash=$(sha256sum "$msg" | awk '{print $1}')
      msgid=$(grep -im1 '^Message-ID:' "$msg" | sed 's/[\r]$//' || true)
      if [ "$attempt" = 1 ]; then
        echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) attempt=$attempt result=tempfail hash=$hash $msgid" >> /evidence/remote-ledger.txt
        printf '451 4.3.0 deliberate first-attempt tempfail\r\n'
      else
        echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) attempt=$attempt result=accepted hash=$hash $msgid" >> /evidence/remote-ledger.txt
        printf '250 2.0.0 accepted retry-red-remote-2\r\n'
      fi
      indata=0
    else
      printf '%s\r\n' "$clean" >> "$msg"
    fi
    continue
  fi
  case "$clean" in
    EHLO*|HELO*) printf '250-retry-red-remote\r\n250 OK\r\n' ;;
    MAIL*) printf '250 2.1.0 ok\r\n' ;;
    RCPT*) printf '250 2.1.5 ok\r\n' ;;
    DATA*) printf '354 end with dot\r\n'; indata=1 ;;
    QUIT*) printf '221 bye\r\n'; exit 0 ;;
    *) printf '250 ok\r\n' ;;
  esac
done
EOF_REMOTE_SESSION
chmod 755 "$root/fixture/remote-session.sh"

cat > "$root/fixture/run-remote.sh" <<'EOF_REMOTE'
#!/bin/sh
set -eu
chmod 777 /evidence /fixture
: > /evidence/remote-ledger.txt
chmod 666 /evidence/remote-ledger.txt
cat /etc/hosts > /evidence/remote-hosts.txt
cat /etc/resolv.conf > /evidence/remote-resolv.conf
nc -lk -p 25 -e /fixture/remote-session.sh
EOF_REMOTE
chmod 755 "$root/fixture/run-remote.sh"

cat > "$root/fixture/run-postfix.sh" <<'EOF_POSTFIX'
#!/bin/sh
set -eu
mkdir -p /evidence
chmod 777 /evidence /fixture
cp /fixture/main.cf /etc/postfix/main.cf
cp /fixture/master.cf /etc/postfix/master.cf
mkdir -p /var/spool/postfix/etc
cp /etc/resolv.conf /var/spool/postfix/etc/resolv.conf 2>/dev/null || true
cp /etc/hosts /var/spool/postfix/etc/hosts 2>/dev/null || true
cat /etc/hosts > /evidence/postfix-hosts.txt
cat /etc/resolv.conf > /evidence/postfix-resolv.conf
cat /var/spool/postfix/etc/hosts > /evidence/postfix-chroot-hosts.txt 2>/dev/null || true
cat /var/spool/postfix/etc/resolv.conf > /evidence/postfix-chroot-resolv.conf 2>/dev/null || true
postconf -n > /evidence/postconf-n.txt
postconf -M > /evidence/postconf-M.txt
postconf mail_version > /evidence/postfix-version.txt
sha256sum /etc/postfix/main.cf /etc/postfix/master.cf /fixture/gate.sh /fixture/remote-session.sh /fixture/run-remote.sh > /evidence/config-hashes.txt
: > /evidence/policy-ledger.txt
: > /evidence/queue-bindings.txt
chmod 666 /evidence/policy-ledger.txt /evidence/queue-bindings.txt
postfix start > /evidence/postfix-start.stdout 2> /evidence/postfix-start.stderr
sleep 2
postfix status > /evidence/postfix-status-initial.txt 2>&1 || true
cat > /tmp/red-message.eml <<'MSG'
Message-ID: <retry-transport-red@example.test>
Date: Wed, 07 Oct 2026 12:00:00 +0000
From: Remote Author <author@remote.example>
To: Forward Target <outside@remote.test>
Subject: retry transport policy bypass red

retry transport red body
MSG
sha256sum /tmp/red-message.eml > /evidence/input-message.sha256
{
  sleep 1
  printf 'EHLO retry-red-client\r\n'
  sleep 0.3
  printf 'MAIL FROM:<remote-author@remote.example>\r\n'
  sleep 0.3
  printf 'RCPT TO:<outside@remote.test>\r\n'
  sleep 0.3
  printf 'DATA\r\n'
  sleep 0.3
  cat /tmp/red-message.eml
  printf '\r\n.\r\nQUIT\r\n'
} | nc 127.0.0.1 2526 > /evidence/public-submit.smtp 2>&1
sed -n 's/.*queued as \([A-Za-z0-9]*\).*/public_queueA=\1/p' /evidence/public-submit.smtp > /evidence/public-queueA.txt || true
i=0
while ! grep -q 'private10027_queueB=' /evidence/queue-bindings.txt 2>/dev/null; do
  i=$((i+1)); [ "$i" -lt 80 ] || { postqueue -p > /evidence/postqueue-timeout-a.txt || true; exit 2; }
  sleep 0.25
done
i=0
while ! grep -q 'attempt=1 result=tempfail' /evidence/remote-ledger.txt 2>/dev/null; do
  i=$((i+1)); [ "$i" -lt 120 ] || { postqueue -p > /evidence/postqueue-timeout-tempfail.txt || true; exit 2; }
  sleep 0.25
done
postqueue -j > /evidence/postqueue-after-tempfail.jsonl 2>/evidence/postqueue-after-tempfail.err || true
queueA=$(sed -n 's/.*queueA=\([A-Za-z0-9]*\).*/\1/p' /evidence/policy-ledger.txt | head -n 1)
queueB=$(sed -n 's/.*private10027_queueB=\([A-Za-z0-9]*\).*/\1/p' /evidence/queue-bindings.txt | head -n 1)
echo deny > /fixture/policy_state
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) revoked_policy queueB=$queueB" >> /evidence/revocation-ledger.txt
before=$(grep -c 'decision=allow' /evidence/policy-ledger.txt || true)
echo "$before" > /evidence/policy-allow-count-before-flush.txt
postqueue -f > /evidence/postqueue-flush.stdout 2> /evidence/postqueue-flush.stderr
i=0
while ! grep -q 'attempt=2 result=accepted' /evidence/remote-ledger.txt 2>/dev/null; do
  i=$((i+1)); [ "$i" -lt 160 ] || { postqueue -p > /evidence/postqueue-timeout-accept.txt || true; exit 2; }
  sleep 0.25
done
after=$(grep -c 'decision=allow' /evidence/policy-ledger.txt || true)
echo "$after" > /evidence/policy-allow-count-after-flush.txt
postqueue -j > /evidence/postqueue-after-accept.jsonl 2>/evidence/postqueue-after-accept.err || true
sha256sum /evidence/remote-message-1.eml /evidence/remote-message-2.eml > /evidence/remote-message.sha256
hash1=$(awk 'NR==1 {print $1}' /evidence/remote-message.sha256)
hash2=$(awk 'NR==2 {print $1}' /evidence/remote-message.sha256)
msgid1=$(grep -im1 '^Message-ID:' /evidence/remote-message-1.eml | sed 's/[\r]$//' || true)
msgid2=$(grep -im1 '^Message-ID:' /evidence/remote-message-2.eml | sed 's/[\r]$//' || true)
{
  echo "queueA=$queueA"
  echo "queueB=$queueB"
  echo "policy_allows_before=$before"
  echo "policy_allows_after=$after"
  echo "remote_hash_1=$hash1"
  echo "remote_hash_2=$hash2"
  echo "remote_msgid_1=$msgid1"
  echo "remote_msgid_2=$msgid2"
  grep 'attempt=1 result=tempfail' /evidence/remote-ledger.txt
  grep 'attempt=2 result=accepted' /evidence/remote-ledger.txt
} > /evidence/red-summary.txt
if [ -n "$queueA" ] && [ -n "$queueB" ] && [ "$queueA" != "$queueB" ] && [ "$before" = 1 ] && [ "$after" = 1 ] && [ "$hash1" = "$hash2" ] && [ -n "$hash1" ] && [ "$msgid1" = "$msgid2" ] && [ "$msgid1" = 'Message-ID: <retry-transport-red@example.test>' ] && grep -q 'attempt=1 result=tempfail' /evidence/remote-ledger.txt && grep -q 'attempt=2 result=accepted' /evidence/remote-ledger.txt; then
  echo 'RED: queueB retried and was accepted after policy revocation without a fresh policy allow' >&2
  exit 1
fi
echo 'STRUCTURAL BLOCKER: fixture did not prove the complete RED' >&2
exit 2
EOF_POSTFIX
chmod 755 "$root/fixture/run-postfix.sh"

{
  echo "started_utc=$stamp"
  echo "image=$image"
  $docker_command image inspect "$image" --format 'image_id={{.Id}} repo_digests={{json .RepoDigests}}'
  $docker_command version --format 'docker_client={{.Client.Version}} docker_server={{.Server.Version}}'
} > "$root/evidence/host-preflight.txt"

$docker_command network create --internal "$network" > "$root/evidence/network-create.txt"
$docker_command run -d --name "$remote_container" --network "$network" --network-alias remote.test \
  -v "$root/fixture:/fixture:rw" -v "$root/evidence:/evidence:rw" \
  --entrypoint /bin/sh "$image" /fixture/run-remote.sh > "$root/evidence/remote-container-id.txt"
$docker_command run -d --name "$postfix_container" --network "$network" \
  -v "$root/fixture:/fixture:rw" -v "$root/evidence:/evidence:rw" \
  --entrypoint /bin/sh "$image" -c 'sleep 600' > "$root/evidence/postfix-container-id.txt"
sleep 2
$docker_command inspect "$remote_container" > "$root/evidence/remote-container.inspect.json"
$docker_command inspect "$postfix_container" > "$root/evidence/postfix-container.inspect.json"
$docker_command network inspect "$network" > "$root/evidence/network.inspect.json"
$docker_command exec "$remote_container" /bin/sh -c 'hostname -i; cat /etc/hosts; echo ---; cat /etc/resolv.conf' > "$root/evidence/remote-runtime-network.txt" 2>&1 || true
$docker_command exec "$postfix_container" /bin/sh -c 'hostname -i; cat /etc/hosts; echo ---; cat /etc/resolv.conf' > "$root/evidence/postfix-runtime-network.txt" 2>&1 || true

set +e
$docker_command exec "$postfix_container" /bin/sh /fixture/run-postfix.sh > "$root/evidence/run.stdout" 2> "$root/evidence/run.stderr"
rc=$?
set -e
echo "$rc" > "$root/evidence/run.exit"
$docker_command logs "$remote_container" > "$root/evidence/remote-container.log" 2>&1 || true
$docker_command logs "$postfix_container" > "$root/evidence/postfix-container.log" 2>&1 || true
$docker_command exec "$postfix_container" postqueue -p > "$root/evidence/postqueue-final.txt" 2>&1 || true
$docker_command exec "$postfix_container" postfix stop > "$root/evidence/postfix-stop.txt" 2>&1 || true
$docker_command exec "$postfix_container" /bin/sh -c 'chmod -R a+r /evidence 2>/dev/null || true' >/dev/null 2>&1 || true
$docker_command exec "$remote_container" /bin/sh -c 'chmod -R a+r /evidence 2>/dev/null || true' >/dev/null 2>&1 || true
cleanup
trap - EXIT INT TERM
find "$root" -maxdepth 3 -type f -print0 | sort -z | xargs -0 sha256sum > "$root/evidence/evidence.sha256"
if [ "$rc" -eq 1 ] && [ -s "$root/evidence/red-summary.txt" ]; then
  echo "expected RED reproduced; evidence at $root/evidence" >&2
  exit 1
fi
echo "retry topology smoke did not produce expected RED; exit=$rc evidence=$root/evidence" >&2
exit 2
