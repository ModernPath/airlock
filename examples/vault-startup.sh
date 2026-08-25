#!/usr/bin/env bash
# Start airlock daemon with secrets sourced from HashiCorp Vault.
#
# Prerequisites:
#   - Vault CLI installed and configured
#   - Authenticated: vault login
#
# Usage:
#   chmod +x examples/vault-startup.sh
#   ./examples/vault-startup.sh

set -euo pipefail

export GH_TOKEN
GH_TOKEN=$(vault kv get -field=token secret/github)

export CLOUDFLARE_API_TOKEN
CLOUDFLARE_API_TOKEN=$(vault kv get -field=api_token secret/cloudflare)

airlock daemon start

echo "Airlock daemon started with Vault secrets."
echo "Check status: airlock status"
echo "List tools:   airlock list"
