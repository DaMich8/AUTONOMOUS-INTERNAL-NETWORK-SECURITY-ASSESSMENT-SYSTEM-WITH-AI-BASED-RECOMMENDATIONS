#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
export PROJECT_DIR="$(cd .. && pwd)"

# Įkeliami aplinkos kintamieji iš projekto .env failo.
if [[ -f ../.env ]]; then
  set -a
  # shellcheck source=/dev/null
  . ../.env
  set +a
elif [[ -f .env ]]; then
  set -a
  # shellcheck source=/dev/null
  . ./.env
  set +a
fi

# LLM etapas pagal nutylėjimą įjungiamas, jeigu .env faile nebuvo nurodyta kitaip.
export LOCAL_LLM_ENABLED="${LOCAL_LLM_ENABLED:-1}"
export LOCAL_LLM_MODEL="${LOCAL_LLM_MODEL:-qwen2.5:7b-instruct}"

# Senas automatinis siuntimas laikinai išjungiamas, kad nebūtų išsiųstas painus techninis paketas.
ORIGINAL_EMAIL_ENABLED="${EMAIL_ENABLED:-0}"
export EMAIL_ENABLED=0

python3 full_assessment.py

# PDF sugeneruojamas atskirai, jeigu įmanoma. Jei reportlab dar neįdiegtas, laiškas bus siunčiamas su Markdown ataskaita.
if [[ -f recommendation_pdf.py ]]; then
  python3 recommendation_pdf.py || echo "[WARN] PDF sugeneruoti nepavyko; bus siunčiama tekstinė ataskaita, jei ji yra."
fi

# Atstatomas vartotojo pasirinktas el. pašto siuntimo nustatymas ir siunčiamas tik sutvarkytas administratoriui skirtas laiškas.
export EMAIL_ENABLED="$ORIGINAL_EMAIL_ENABLED"
python3 admin_email_delivery.py

