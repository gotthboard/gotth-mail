#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
renderer_dir=${GOTTH_AUTHENTIK_DIR:?set GOTTH_AUTHENTIK_DIR to the pinned gotth-authentik checkout}
expected_revision=77c811c18fe3c107f6f3e97ce3f9a3850a685300
manifest="$repo_root/deploy/authentik/gotth-mail/manifest.json"
blueprint="$repo_root/deploy/authentik/gotth-mail/blueprint.yaml"

actual_revision=$(git -C "$renderer_dir" rev-parse HEAD)
if [ "$actual_revision" != "$expected_revision" ]; then
	echo "gotth-authentik revision mismatch: $actual_revision" >&2
	exit 1
fi
if ! git -C "$renderer_dir" diff --quiet -- . ||
	! git -C "$renderer_dir" diff --cached --quiet -- .; then
	echo "gotth-authentik checkout is dirty" >&2
	exit 1
fi

(
	cd "$renderer_dir"
	go run ./cmd/gotth-authentik check "$manifest" "$blueprint"
)

python3 - "$manifest" "$blueprint" <<'PY'
import json
import pathlib
import re
import sys

manifest_path, blueprint_path = map(pathlib.Path, sys.argv[1:])
manifest = json.loads(manifest_path.read_text())
expected = {
    "slug": "gotth-mail",
    "access_group": "gotth-mail-users",
}
for key, value in expected.items():
    if manifest.get(key) != value:
        raise SystemExit(f"unexpected {key}: {manifest.get(key)!r}")
provider = manifest.get("provider") or {}
if provider.get("name") != "gotth-mail-oidc" or provider.get("client_id") != "gotth-mail":
    raise SystemExit("unexpected provider identity")
if provider.get("redirect_uris") != ["http://127.0.0.1:18080/api/v1/oidc/callback"]:
    raise SystemExit("unexpected pre-production callback")

forbidden_keys = {"client_secret", "token", "password_value", "private_key"}
def walk(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in forbidden_keys:
                raise SystemExit(f"secret-bearing manifest key: {key}")
            walk(child)
    elif isinstance(value, list):
        for child in value:
            walk(child)
walk(manifest)

blueprint = blueprint_path.read_text()
secret_field = re.search(
    r"(?im)^\s*(client_secret|token|password_value|private_key)\s*:",
    blueprint,
)
if secret_field:
    raise SystemExit(f"secret-bearing blueprint field: {secret_field.group(1)}")
PY

echo "GOTTH Mail Authentik profile verified at $expected_revision"
