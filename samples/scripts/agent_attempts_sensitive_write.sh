#!/usr/bin/env bash
# agent_attempts_sensitive_write.sh — simulates an agent that attempts both
# safe and policy-violating writes in the same run.
#
# Airlock governance outcome (with --policy-pack strict):
#   src/output.txt       → ALLOWED   (within allow_write: src/**)
#   .env                 → BLOCKED   (touchesSensitivePath: always HardBlocked)
#   deploy_config.yaml   → BLOCKED   ("deploy" + "config" in one path component: HardBlocked)
#
# The blocked writes are reverted in the workspace. POLICY_DENY events are
# recorded in events.jsonl with the attempted diff.
# The run exits 0 because the shell command itself completed.
#
# Use in Airlock:
#   ./airlock run --agent generic-shell \
#     --cmd "$(cat samples/scripts/agent_attempts_sensitive_write.sh)" \
#     --repo . --policy-pack strict --approval deny-high-risk

set -euo pipefail

mkdir -p src

# Allowed write
echo "agent output data" > src/output.txt

# Blocked: .env is a HardBlocked sensitive path
echo "SECRET_KEY=abc123" > .env

# Blocked: "deploy" paired with "config" in one path component — HardBlocked by the governance risk classifier
echo "server: prod" > deploy_config.yaml

echo "Agent attempted all writes. Airlock enforced policy on .env and deploy_config.yaml."
