#!/usr/bin/env bash
set -euo pipefail

# ---- CONFIG (edit once) ----
PROJECT_ID="pgdn-464506"
REGION="europe-west1"
REPO="pgdn"
NAME="pgdn-api-discord"
DEPLOY="pgdn-api-discord"
CONTAINER="$(kubectl get deploy ${DEPLOY} -o jsonpath='{.spec.template.spec.containers[0].name}')"
PLATFORM="linux/amd64"

branch="$(git rev-parse --abbrev-ref HEAD)"
if [[ "$branch" != "main" ]]; then
  echo "You're on '$branch'. This script deploys 'main'."
  exit 1
fi

echo "Pushing branch 'main' to origin…"
git push origin main

TS="$(date +%s)"
SHORT_SHA="$(git rev-parse --short=7 HEAD)"
IMG="${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO}/${NAME}:${TS}-${SHORT_SHA}"

echo "Building and pushing ${IMG}…"
docker buildx build --platform "${PLATFORM}" -t "${IMG}" --push .

echo "Setting image on deployment ${DEPLOY} (container: ${CONTAINER})…"
kubectl set image "deploy/${DEPLOY}" "${CONTAINER}=${IMG}" --record

echo "Waiting for rollout…"
kubectl rollout status "deploy/${DEPLOY}" --timeout=120s

echo "Deployed ${IMG} ✅"
