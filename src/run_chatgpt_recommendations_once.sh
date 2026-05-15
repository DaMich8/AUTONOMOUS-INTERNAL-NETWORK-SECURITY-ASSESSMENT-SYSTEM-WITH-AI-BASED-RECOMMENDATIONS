#!/usr/bin/env bash
set -euo pipefail

cd "$HOME/network-thesis-GIT/src"

if [ -f "$HOME/network-thesis-GIT/.env" ]; then
  set -a
  # shellcheck disable=SC1090
  source "$HOME/network-thesis-GIT/.env"
  set +a
fi

if [ -z "${OPENAI_API_KEY:-}" ]; then
  echo "[KLAIDA] OPENAI_API_KEY nenustatytas. Įrašyk jį į ~/network-thesis-GIT/.env arba eksportuok prieš paleidimą."
  exit 1
fi

export RECOMMENDATION_DELIVERY_ENABLED=1
export OPENAI_API_FALLBACK_ENABLED=1
export OPENAI_API_REQUIRE_MANUAL_APPROVAL=1
export OPENAI_API_ALLOW_RUN=1
export OPENAI_API_SKIP_IF_EVIDENCE_UNCHANGED="${OPENAI_API_SKIP_IF_EVIDENCE_UNCHANGED:-1}"
export OPENAI_API_ONLY_WHEN_NEEDED="${OPENAI_API_ONLY_WHEN_NEEDED:-1}"
export OPENAI_API_MAX_CALLS_PER_DAY="${OPENAI_API_MAX_CALLS_PER_DAY:-1}"
export OPENAI_API_MAX_CALLS_PER_MONTH="${OPENAI_API_MAX_CALLS_PER_MONTH:-5}"
export OPENAI_API_MIN_RISK_SCORE="${OPENAI_API_MIN_RISK_SCORE:-70}"
export OPENAI_API_DELETE_UPLOADED_FILE="${OPENAI_API_DELETE_UPLOADED_FILE:-1}"

# Modelį gali keisti .env faile. Numatytasis paliekamas toks pats kaip recommendation_delivery.py.
export OPENAI_API_MODEL="${OPENAI_API_MODEL:-gpt-4.1-mini}"

python3 recommendation_delivery.py
