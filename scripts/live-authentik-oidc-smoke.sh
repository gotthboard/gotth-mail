#!/usr/bin/env bash
set -euo pipefail

issuer="${GOTTH_MAIL_AUTHENTIK_ISSUER:-https://auth.dannyhunn.com/application/o/gotth-mail/}"
client_id="${GOTTH_MAIL_AUTHENTIK_CLIENT_ID:?GOTTH_MAIL_AUTHENTIK_CLIENT_ID required}"
redirect_uri="${GOTTH_MAIL_AUTHENTIK_REDIRECT_URI:-http://127.0.0.1:18080/api/v1/oidc/callback}"
state="${GOTTH_MAIL_AUTHENTIK_STATE:-gotth-mail-live-smoke-state}"
nonce="${GOTTH_MAIL_AUTHENTIK_NONCE:-gotth-mail-live-smoke-nonce}"

issuer="${issuer%/}/"
discovery_url="${issuer}.well-known/openid-configuration"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl -fsS --max-time 15 "$discovery_url" > "$tmp/discovery.json"
python3 - "$tmp/discovery.json" "$issuer" <<'PY'
import json,sys
path, expected = sys.argv[1], sys.argv[2]
d = json.load(open(path))
for k in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"):
    if not d.get(k):
        raise SystemExit(f"missing discovery field {k}")
if d["issuer"] != expected:
    raise SystemExit(f"issuer mismatch {d['issuer']!r} != {expected!r}")
PY
mapfile -t endpoints < <(python3 - "$tmp/discovery.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
print(d["authorization_endpoint"])
print(d["jwks_uri"])
PY
)
authorize_endpoint="${endpoints[0]}"
jwks_uri="${endpoints[1]}"

curl -fsS --max-time 15 "$jwks_uri" > "$tmp/jwks.json"
python3 - "$tmp/jwks.json" <<'PY'
import json,sys
j=json.load(open(sys.argv[1]))
keys=j.get("keys") or []
if not keys:
    raise SystemExit("jwks contains no keys")
if not any(k.get("kty") == "RSA" and k.get("kid") for k in keys):
    raise SystemExit("jwks contains no RSA key with kid")
PY

location="$(python3 - "$authorize_endpoint" "$client_id" "$redirect_uri" "$state" "$nonce" <<'PY' | xargs -0 curl -ksS -o /dev/null -w '%{http_code} %{redirect_url}' --max-time 15
import sys, urllib.parse
base, client_id, redirect_uri, state, nonce = sys.argv[1:]
q = urllib.parse.urlencode({
    "response_type": "code",
    "client_id": client_id,
    "redirect_uri": redirect_uri,
    "scope": "openid email profile",
    "state": state,
    "nonce": nonce,
})
print(base + "?" + q, end="\0")
PY
)"
code="${location%% *}"
redirect="${location#* }"
case "$code" in
  30*) ;;
  *) echo "expected authorize redirect, got HTTP $code" >&2; exit 1 ;;
esac
case "$redirect" in
  *"state=$state"*|*"state%3D$state"*) ;;
  *) echo "authorize redirect did not preserve state: $redirect" >&2; exit 1 ;;
esac

echo "live Authentik OIDC smoke passed"
echo "issuer=$issuer"
echo "redirect_uri=$redirect_uri"
