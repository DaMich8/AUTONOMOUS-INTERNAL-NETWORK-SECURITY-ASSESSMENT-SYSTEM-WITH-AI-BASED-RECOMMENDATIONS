#!/usr/bin/env python3
from __future__ import annotations

import os
from typing import Mapping

TRUE_VALUES = {"1", "true", "yes", "y", "on"}

SCENARIO_NAMES = {
    "1": "1 bandymas – bazinė taisyklinė analizė be LLM ir be el. pašto",
    "2": "2 bandymas – vietinis LLM / Ollama rekomendacijos",
    "3": "3 bandymas – ChatGPT / OpenAI API rekomendacijos",
    "4": "4 bandymas – rankinio AI įkėlimo paketas el. paštu",
}


def _truthy(value: object) -> bool:
    return str(value or "").strip().lower() in TRUE_VALUES


def _set(env: dict[str, str], key: str, value: object) -> None:
    env[key] = str(value)


def _setdefault(env: dict[str, str], key: str, value: object) -> None:
    if not str(env.get(key, "")).strip():
        env[key] = str(value)


def _apply_email_aliases(env: dict[str, str]) -> None:
    """Suderina senus SMTP_* kintamuosius su recommendation_delivery.py naudojamais kintamaisiais."""
    _set(env, "RECOMMENDATION_EMAIL_FROM", env.get("RECOMMENDATION_EMAIL_FROM") or env.get("EMAIL_FROM", ""))
    _set(env, "RECOMMENDATION_EMAIL_TO", env.get("RECOMMENDATION_EMAIL_TO") or env.get("SMTP_TO", ""))
    _set(env, "RECOMMENDATION_SMTP_HOST", env.get("RECOMMENDATION_SMTP_HOST") or env.get("SMTP_HOST", ""))
    _set(env, "RECOMMENDATION_SMTP_PORT", env.get("RECOMMENDATION_SMTP_PORT") or env.get("SMTP_PORT", ""))
    _set(env, "RECOMMENDATION_SMTP_USER", env.get("RECOMMENDATION_SMTP_USER") or env.get("SMTP_USER", ""))
    _set(env, "RECOMMENDATION_SMTP_PASSWORD", env.get("RECOMMENDATION_SMTP_PASSWORD") or env.get("SMTP_PASSWORD", ""))


def _apply_compat_aliases(env: dict[str, str]) -> None:
    _set(env, "USE_RECOMMENDATION_DELIVERY", env.get("RECOMMENDATION_DELIVERY_ENABLED", "0"))
    _set(env, "USE_EMAIL_SEND", env.get("EMAIL_SEND_ENABLED", "0"))
    _set(env, "USE_CHATGPT_MANUAL_PACKAGE", env.get("CHATGPT_PACKAGE_EMAIL_ENABLED", "0"))
    _set(env, "USE_LOCAL_LLM", env.get("LOCAL_LLM_ENABLED", "0"))
    _set(env, "USE_OPENAI_API", env.get("OPENAI_API_ENABLED", "0"))


def _apply_defaults(env: dict[str, str]) -> None:
    _setdefault(env, "LOCAL_LLM_MODEL", "qwen2.5:7b-instruct")
    _setdefault(env, "LOCAL_LLM_TIMEOUT", "3600")
    _setdefault(env, "LOCAL_LLM_MAX_INPUT_CHARS", "18000")
    _setdefault(env, "LOCAL_LLM_HARD_INPUT_CHARS", "26000")

    _setdefault(env, "OPENAI_API_MODEL", "gpt-5.4-mini")
    _setdefault(env, "OPENAI_API_MAX_CALLS_PER_DAY", "1")
    _setdefault(env, "OPENAI_API_MAX_CALLS_PER_MONTH", "5")
    _setdefault(env, "OPENAI_API_MAX_INPUT_CHARS", "220000")
    _setdefault(env, "OPENAI_API_MAX_OUTPUT_TOKENS", "7000")
    _setdefault(env, "OPENAI_API_DELETE_UPLOADED_FILE", "1")
    _setdefault(env, "OPENAI_API_REQUIRE_MANUAL_APPROVAL", "1")
    _setdefault(env, "OPENAI_API_SKIP_IF_EVIDENCE_UNCHANGED", "1")
    _setdefault(env, "OPENAI_API_ONLY_WHEN_NEEDED", "1")
    _setdefault(env, "OPENAI_API_MIN_RISK_SCORE", "70")


def apply_experiment_mode(source_env: Mapping[str, str] | None = None) -> dict[str, str]:
    """Pritaiko vienos eilutės EXPERIMENT_MODE konfigūraciją.

    EXPERIMENT_MODE:
      1 – bazinė taisyklinė analizė be LLM ir be el. pašto
      2 – vietinis LLM / Ollama rekomendacijos
      3 – ChatGPT / OpenAI API rekomendacijos
      4 – rankinio AI įkėlimo paketas el. paštu

    Jei EXPERIMENT_MODE nenurodytas, funkcija tik pritaiko suderinamumo alias'us
    ir nekeičia esamų veikimo režimų.
    """
    env = dict(source_env or os.environ)
    _apply_defaults(env)

    mode = str(env.get("EXPERIMENT_MODE", "")).strip()
    if not mode:
        _apply_email_aliases(env)
        _apply_compat_aliases(env)
        return env

    if mode not in SCENARIO_NAMES:
        raise ValueError(f"Netinkamas EXPERIMENT_MODE={mode!r}. Naudok 1, 2, 3 arba 4.")

    # Bendros saugios pradinės reikšmės – kiekvienas scenarijus toliau įjungia tik tai, ko reikia.
    for key in [
        "LOCAL_LLM_ENABLED",
        "OPENAI_API_ENABLED",
        "OPENAI_API_ALLOW_RUN",
        "OPENAI_API_FALLBACK_ENABLED",
        "OPENAI_API_FORCE",
        "RECOMMENDATION_DELIVERY_ENABLED",
        "EMAIL_ENABLED",
        "EMAIL_SEND_ENABLED",
        "CHATGPT_PACKAGE_EMAIL_ENABLED",
    ]:
        _set(env, key, "0")

    _set(env, "OPENAI_API_MODE", "off")
    _set(env, "OPENAI_API_REQUIRE_MANUAL_APPROVAL", "1")
    _set(env, "OPENAI_API_SKIP_IF_EVIDENCE_UNCHANGED", "1")
    _set(env, "OPENAI_API_ONLY_WHEN_NEEDED", "1")
    _set(env, "OPENAI_API_MIN_RISK_SCORE", "70")
    _set(env, "CHATGPT_MANUAL_PACKAGE_DISABLED", "1")

    if mode == "1":
        # Bazinė taisyklinė analizė. Nėra LLM, API, PDF pristatymo ir laiškų.
        pass

    elif mode == "2":
        # Vietinis LLM. ChatGPT API nenaudojamas, bet PDF ir el. pašto pristatymas gali veikti.
        _set(env, "LOCAL_LLM_ENABLED", "1")
        _set(env, "RECOMMENDATION_DELIVERY_ENABLED", "1")
        _set(env, "EMAIL_ENABLED", "1")
        _set(env, "EMAIL_SEND_ENABLED", "1")

    elif mode == "3":
        # ChatGPT / OpenAI API rekomendacijos. Rankinio paketo laiškas nesiunčiamas.
        _set(env, "OPENAI_API_ENABLED", "1")
        _set(env, "OPENAI_API_ALLOW_RUN", "1")
        # Suderinamumas su senesniais recommendation_delivery.py variantais.
        _set(env, "OPENAI_API_FALLBACK_ENABLED", "1")
        _set(env, "OPENAI_API_FORCE", "1")
        _set(env, "OPENAI_API_MODE", "when_needed")
        _set(env, "OPENAI_API_SKIP_IF_EVIDENCE_UNCHANGED", "0")
        _set(env, "OPENAI_API_ONLY_WHEN_NEEDED", "0")
        _set(env, "OPENAI_API_MIN_RISK_SCORE", "0")
        _set(env, "RECOMMENDATION_DELIVERY_ENABLED", "1")
        _set(env, "EMAIL_ENABLED", "1")
        _set(env, "EMAIL_SEND_ENABLED", "1")

    elif mode == "4":
        # Rankinio AI įkėlimo paketas. Nėra vietinio LLM, nėra OpenAI API, nėra galutinio PDF pristatymo.
        _set(env, "EMAIL_ENABLED", "1")
        _set(env, "EMAIL_SEND_ENABLED", "1")
        _set(env, "CHATGPT_PACKAGE_EMAIL_ENABLED", "1")
        _set(env, "CHATGPT_MANUAL_PACKAGE_DISABLED", "0")

    _apply_email_aliases(env)
    _apply_compat_aliases(env)
    env["EXPERIMENT_MODE_NAME"] = SCENARIO_NAMES[mode]
    return env


def print_experiment_mode_summary(env: Mapping[str, str]) -> None:
    mode = str(env.get("EXPERIMENT_MODE", "")).strip() or "nenustatytas"
    name = env.get("EXPERIMENT_MODE_NAME") or SCENARIO_NAMES.get(mode, "rankinė konfigūracija")
    print(f"[INFO] Eksperimento režimas: {mode} – {name}", flush=True)
    print(f"[INFO] LOCAL_LLM_ENABLED={env.get('LOCAL_LLM_ENABLED', '')}", flush=True)
    print(f"[INFO] OPENAI_API_ENABLED={env.get('OPENAI_API_ENABLED', '')}; OPENAI_API_ALLOW_RUN={env.get('OPENAI_API_ALLOW_RUN', '')}", flush=True)
    print(f"[INFO] RECOMMENDATION_DELIVERY_ENABLED={env.get('RECOMMENDATION_DELIVERY_ENABLED', '')}", flush=True)
    print(f"[INFO] CHATGPT_PACKAGE_EMAIL_ENABLED={env.get('CHATGPT_PACKAGE_EMAIL_ENABLED', '')}; EMAIL_ENABLED={env.get('EMAIL_ENABLED', '')}", flush=True)
