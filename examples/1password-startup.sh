#!/usr/bin/env bash
# Start airlock daemon with secrets sourced from 1Password.
#
# Prerequisites:
#   - 1Password CLI installed (https://developer.1password.com/docs/cli/)
#   - Signed in: eval $(op signin)
#
# Usage:
#   chmod +x examples/1password-startup.sh
#   ./examples/1password-startup.sh

set -euo pipefail

GH_TOKEN="op://Employee/GH_TOKEN/value" \
CLOUDFLARE_API_TOKEN="op://Infrastructure/Cloudflare/api_token" \
  op run -- airlock daemon start

echo "Airlock daemon started with 1Password secrets."
echo "Check status: airlock status"
echo "List tools:   airlock list"
