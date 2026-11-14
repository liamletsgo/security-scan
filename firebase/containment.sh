#!/usr/bin/env bash
# Post-deploy containment check for a Firebase (Cloud Functions gen2) HTTPS function: fails unless the function's
# Cloud Run service grants no public invoker and an anonymous request is refused (401/403).
# Scope: this checks the service's own invoker policy and one anonymous request. It does not prove inherited IAM,
# authenticated authorization or tenant isolation; run the release tests for those.
# Requires gcloud authenticated as the deployer (roles/cloudfunctions.developer + roles/run.viewer suffice).
# Usage: containment.sh <function> <region> <project> [path for the anonymous request, default /]
set -euo pipefail
FN=$1; REGION=$2; PROJECT=$3; REQ_PATH=${4:-/}
SVC=$(gcloud functions describe "$FN" --region="$REGION" --project="$PROJECT" --format='value(serviceConfig.service)')
URI=$(gcloud functions describe "$FN" --region="$REGION" --project="$PROJECT" --format='value(serviceConfig.uri)')
[ -n "$SVC" ] && [ -n "$URI" ] || { echo "containment: could not read the deployed function" >&2; exit 1; }
gcloud run services get-iam-policy "${SVC##*/}" --region="$REGION" --project="$PROJECT" --format=json >"${TMPDIR:-/tmp}/containment-policy.$$"
# parse the policy: 0 = no public member, 1 = public member, anything else (malformed) = error
rc=0
python3 - "${TMPDIR:-/tmp}/containment-policy.$$" <<'PY' || rc=$?
import json, sys
try:
    p = json.load(open(sys.argv[1]))
    if not isinstance(p, dict) or not isinstance(p.get("bindings", []), list):
        raise ValueError("not an IAM policy")
    members = [m for b in p.get("bindings", []) for m in b["members"]]
except Exception as e:
    print(f"containment: could not parse the IAM policy: {e}", file=sys.stderr); sys.exit(2)
sys.exit(1 if any(m in ("all" "Users", "all" "AuthenticatedUsers") for m in members) else 0)
PY
rm -f "${TMPDIR:-/tmp}/containment-policy.$$"
case $rc in
  0) ;;
  1) echo "containment: the function is publicly invokable" >&2; exit 1 ;;
  *) echo "containment: invoker policy check failed" >&2; exit 1 ;;
esac
CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 -X POST "$URI$REQ_PATH")
case "$CODE" in
  401|403) echo "containment: no public invoker; anonymous call refused ($CODE)" ;;
  *) echo "containment: anonymous call returned $CODE (expected 401 or 403)" >&2; exit 1 ;;
esac
