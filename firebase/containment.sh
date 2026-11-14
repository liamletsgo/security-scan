#!/usr/bin/env bash
# Post-deploy containment check for a Firebase (Cloud Functions gen2) HTTPS function: fails unless the function's
# Cloud Run service grants no public invoker and an anonymous request is refused (401/403).
# Requires gcloud authenticated as the deployer (roles/cloudfunctions.developer + roles/run.viewer suffice).
# Usage: containment.sh <function> <region> <project> [path for the anonymous request, default /]
set -euo pipefail
FN=$1; REGION=$2; PROJECT=$3; REQ_PATH=${4:-/}
SVC=$(gcloud functions describe "$FN" --region="$REGION" --project="$PROJECT" --format='value(serviceConfig.service)')
URI=$(gcloud functions describe "$FN" --region="$REGION" --project="$PROJECT" --format='value(serviceConfig.uri)')
[ -n "$SVC" ] && [ -n "$URI" ] || { echo "containment: could not read the deployed function" >&2; exit 1; }
POLICY=$(gcloud run services get-iam-policy "${SVC##*/}" --region="$REGION" --project="$PROJECT" --format=json)
PUBLIC_MEMBERS='all''Users|all''AuthenticatedUsers'
if printf '%s' "$POLICY" | grep -qE "$PUBLIC_MEMBERS"; then
  echo "containment: the function is publicly invokable" >&2; exit 1
fi
CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 -X POST "$URI$REQ_PATH")
case "$CODE" in
  401|403) echo "containment: no public invoker; anonymous call refused ($CODE)" ;;
  *) echo "containment: anonymous call returned $CODE (expected 401 or 403)" >&2; exit 1 ;;
esac
