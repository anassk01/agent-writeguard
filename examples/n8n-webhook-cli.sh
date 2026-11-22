#!/usr/bin/env bash
# Example: Guarding an n8n webhook or CI/CD PR deploy via the writeguard CLI.
set -euo pipefail

WG_BIN="$(cd "$(dirname "$0")/.." && pwd)/bin/writeguard.mjs"
STATE_DIR="$(mktemp -d)"
trap 'rm -rf "$STATE_DIR"' EXIT

# 1. Initialize state dir with daily caps and tenant identity binding
node "$WG_BIN" init \
  --dir "$STATE_DIR" \
  --cap "deploy.release=3" \
  --identity "org:acme:prod" \
  --label "acme-prod"

# 2. Create a fingerprint-bound dry-run attestation (valid for 2h)
PAYLOAD='{"service":"billing-api","version":"2.14.0","region":"us-east-1"}'
ATT_ID="$(node "$WG_BIN" attest \
  --dir "$STATE_DIR" \
  --action "deploy.release" \
  --target "n8n:webhook/deploy-prod" \
  --payload "$PAYLOAD" \
  --ttl "2h" \
  --json | node -e "const d = JSON.parse(require('fs').readFileSync(0,'utf8')); console.log(d.attestationId);")"

echo "Attestation ID: $ATT_ID"

# 3. Execute under atomic O_EXCL lock + mandatory read-back check
MARKER_FILE="$STATE_DIR/deployed-2.14.0.ok"
node "$WG_BIN" guard \
  --dir "$STATE_DIR" \
  --key "deploy-billing-2.14.0" \
  --action "deploy.release" \
  --target "n8n:webhook/deploy-prod" \
  --attestation "$ATT_ID" \
  --identity "org:acme:prod" \
  --payload "$PAYLOAD" \
  --verify-cmd "test -f '$MARKER_FILE'" \
  -- bash -c "echo 'Deployed 2.14.0' > '$MARKER_FILE' && echo 'release=2.14.0'"

# 4. Inspect status
node "$WG_BIN" status --dir "$STATE_DIR"
