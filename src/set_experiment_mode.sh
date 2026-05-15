#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-}"
ENV_FILE="${2:-$HOME/network-thesis-GIT/.env}"

if [[ ! "$MODE" =~ ^[1-4]$ ]]; then
  echo "Naudojimas: $0 <1|2|3|4> [env_failas]"
  echo "1 - bazinė taisyklinė analizė"
  echo "2 - vietinis LLM / Ollama"
  echo "3 - ChatGPT / OpenAI API"
  echo "4 - rankinio AI įkėlimo paketas el. paštu"
  exit 1
fi

mkdir -p "$(dirname "$ENV_FILE")"
if [[ -f "$ENV_FILE" ]] && grep -q '^export EXPERIMENT_MODE=' "$ENV_FILE"; then
  sed -i "s/^export EXPERIMENT_MODE=.*/export EXPERIMENT_MODE=$MODE/" "$ENV_FILE"
else
  printf '\n# Vienos eilutės eksperimento pasirinkimas\nexport EXPERIMENT_MODE=%s\n' "$MODE" >> "$ENV_FILE"
fi

echo "[GERAI] $ENV_FILE nustatyta: EXPERIMENT_MODE=$MODE"
