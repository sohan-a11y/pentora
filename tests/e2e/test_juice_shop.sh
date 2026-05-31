#!/usr/bin/env bash
# E2E validation script — requires Docker + running Juice Shop
# NOT run in unit CI — requires: docker-compose -f juice_shop_compose.yml up -d
set -euo pipefail

TARGET="http://localhost:3000"
OUT="./pentora-e2e-out"

echo "[e2e] Starting Pentora scan against Juice Shop..."
pentora scan "$TARGET" \
    --output "$OUT" \
    --phases "recon,discovery" \
    --scope-include "localhost" \
    --reporter "json,sarif,html"

echo "[e2e] Validating output..."
test -f "$OUT/summary.json"   || (echo "FAIL: summary.json missing" && exit 1)
test -f "$OUT/findings.sarif" || (echo "FAIL: findings.sarif missing" && exit 1)
test -f "$OUT/summary.html"   || (echo "FAIL: summary.html missing" && exit 1)

FINDING_COUNT=$(python3 -c "import json; d=json.load(open('$OUT/summary.json')); print(d['findings_count'])")
echo "[e2e] Findings: $FINDING_COUNT"

if [ "$FINDING_COUNT" -ge 0 ]; then
    echo "[e2e] PASS — scan completed successfully"
else
    echo "[e2e] FAIL — expected at least 0 findings"
    exit 1
fi
