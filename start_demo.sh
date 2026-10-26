#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

# Load .env if present
if [ -f ".env" ]; then
  set -a
  # shellcheck disable=SC1091
  source ".env"
  set +a
fi

export GOOGLE_CLOUD_PROJECT="${GOOGLE_CLOUD_PROJECT:-your-gcp-project-id}"
export BQ_LOCATION="${BQ_LOCATION:-us-central1}"
export BQ_DATASET="${BQ_DATASET:-data_policies_example}"
export HOST="${HOST:-127.0.0.1}"
export PORT="${PORT:-8088}"
export CLOUDSDK_METRICS_ENVIRONMENT="${CLOUDSDK_METRICS_ENVIRONMENT:+$CLOUDSDK_METRICS_ENVIRONMENT }datacloud.antigravity"

echo "================================================================================"
echo "🚀 Starting BigQuery Multi-Policy PK/FK Dynamic Data Masking Live Workbench"
echo "   URL     : http://${HOST}:${PORT}"
echo "   Project : ${GOOGLE_CLOUD_PROJECT} | Dataset: ${BQ_DATASET} (${BQ_LOCATION})"
echo "================================================================================"

exec python3.12 -m uvicorn backend.app.main:app --host "${HOST}" --port "${PORT}"
