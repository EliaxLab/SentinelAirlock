#!/usr/bin/env bash
# Real-binary acceptance test for `airlock ci` in a disposable workspace.
# Usage: AIRLOCK=./airlock samples/ci-acceptance.sh
# Emulates a CI job in plain shell; the "workload" is an external writer that
# never invokes Airlock. Requires python3 (JSON parsing only).
set -u
AIRLOCK="$(cd "$(dirname "${AIRLOCK:-./airlock}")" && pwd)/$(basename "${AIRLOCK:-./airlock}")"
WS="$(mktemp -d)"; WS="$(cd "$WS" && pwd -P)"
FOREIGN="$(mktemp -d)"; FOREIGN="$(cd "$FOREIGN" && pwd -P)"
fails=0
ok()   { echo "PASS: $*"; }
bad()  { echo "FAIL: $*"; fails=$((fails+1)); }
check(){ if eval "$2"; then ok "$1"; else bad "$1"; fi; }
jget() { python3 -c "import sys,json; d=json.load(sys.stdin)
for k in sys.argv[1].split('.'): d=d[k]
print(d)" "$1"; }
cleanup() { "$AIRLOCK" sentinel --repo "$WS" --stop >/dev/null 2>&1; "$AIRLOCK" sentinel --repo "$FOREIGN" --stop >/dev/null 2>&1; rm -rf "$WS" "$FOREIGN"; }
trap cleanup EXIT

policy='version: 1
policy:
  deny_write:
    - "**/.env"
    - "secrets/**"
  allow_write:
    - "allow.txt"
    - "newdir/**"
network:
  mode: "off"
'
printf '%s' "$policy" > "$WS/airlock.yaml"
printf '%s' "$policy" > "$FOREIGN/airlock.yaml"

echo "== ci start"
START=$("$AIRLOCK" ci start --workspace "$WS" --json); rc=$?
check "start exit 0" "[ $rc -eq 0 ]"
SID=$(echo "$START" | jget session_id)
check "start owned" "[ \"\$(echo '$START' | jget owned)\" = True ]"

echo "== ci status"
ST=$("$AIRLOCK" ci status --workspace "$WS" --json)
check "status running, same session" "[ \"\$(echo '$ST' | jget status)\" = running ] && [ \"\$(echo '$ST' | jget session_id)\" = \"$SID\" ]"

echo "== duplicate start is idempotent"
S2=$("$AIRLOCK" ci start --workspace "$WS" --json); rc=$?
check "second start ok, same session" "[ $rc -eq 0 ] && [ \"\$(echo '$S2' | jget session_id)\" = \"$SID\" ]"

echo "== external writer (no airlock involved)"
echo ok > "$WS/allow.txt"
mkdir "$WS/newdir" && echo child > "$WS/newdir/child.txt"
echo secret > "$WS/.env"
for _ in $(seq 1 100); do [ ! -e "$WS/.env" ] && break; sleep 0.2; done
check "denied .env reverted"     "[ ! -e '$WS/.env' ]"
check "allowed file survives"    "[ -f '$WS/allow.txt' ]"
check "new dir child survives"   "[ -f '$WS/newdir/child.txt' ]"

echo "== ci finalize"
FIN=$("$AIRLOCK" ci finalize --workspace "$WS" --json); rc=$?
check "finalize exit 20 (policy violation, reverted)" "[ $rc -eq 20 ]"
check "finalize denied>=1" "[ \"\$(echo '$FIN' | jget governance.denied)\" -ge 1 ]"
check "finalize reverted>=1" "[ \"\$(echo '$FIN' | jget governance.reverted)\" -ge 1 ]"
RUN=$(echo "$FIN" | jget evidence.run_dir)
check "evidence events present" "grep -q 'newdir/child.txt' '$RUN/events.jsonl'"
check "digest + report present" "[ -f '$RUN/run_digest.json' ] && [ -f '$RUN/report/index.html' ]"
check "sentinel actually stopped" "! \"$AIRLOCK\" sentinel --repo '$WS' --status 2>&1 | grep -q '^Sentinel: running'"
check "verify section present" "[ \"\$(echo '$FIN' | jget verify.run_id)\" = \"$SID\" ]"
( cd "$WS" && "$AIRLOCK" verify "$SID" --json >/dev/null 2>&1 ); check "airlock verify works on evidence" "[ $? -eq 0 ]"

echo "== finalize idempotent"
FIN2=$("$AIRLOCK" ci finalize --workspace "$WS" --json); rc=$?
check "second finalize returns same result" "[ $rc -eq 20 ] && [ \"\$(echo '$FIN2' | jget session_id)\" = \"$SID\" ]"

echo "== foreign-Sentinel ownership invariant"
"$AIRLOCK" sentinel --repo "$FOREIGN" --managed >/dev/null 2>&1 &
for _ in $(seq 1 50); do [ -f "$FOREIGN/.airlock/sentinel.json" ] && break; sleep 0.2; done
"$AIRLOCK" ci start --workspace "$FOREIGN" --json >/dev/null 2>&1; rc=$?
check "start refuses foreign sentinel (exit 30)" "[ $rc -eq 30 ]"
"$AIRLOCK" ci finalize --workspace "$FOREIGN" --json >/dev/null 2>&1; rc=$?
check "finalize without lifecycle refuses (exit 30)" "[ $rc -eq 30 ]"
check "foreign sentinel still running" "[ -f '$FOREIGN/.airlock/sentinel.json' ]"
"$AIRLOCK" ci start --workspace "$FOREIGN" --attach-existing --json >/dev/null 2>&1
"$AIRLOCK" ci finalize --workspace "$FOREIGN" --json >/dev/null 2>&1
check "attached finalize did not stop foreign sentinel" "[ -f '$FOREIGN/.airlock/sentinel.json' ]"

echo "== ci exec"
"$AIRLOCK" ci exec --workspace "$WS" --json -- sh -c 'echo ok > allow.txt' >/dev/null 2>&1; check "exec success -> 0" "[ $? -eq 0 ]"
"$AIRLOCK" ci exec --workspace "$WS" --json -- sh -c 'exit 7' >/dev/null 2>&1;             check "exec failing child -> 10" "[ $? -eq 10 ]"
"$AIRLOCK" ci exec --workspace "$WS" --json -- sh -c 'echo x > .env; exit 3' >/dev/null 2>&1; check "exec violation outranks failure -> 20" "[ $? -eq 20 ]"

echo
[ $fails -eq 0 ] && echo "ALL PASSED" || echo "$fails FAILED"
exit $fails
