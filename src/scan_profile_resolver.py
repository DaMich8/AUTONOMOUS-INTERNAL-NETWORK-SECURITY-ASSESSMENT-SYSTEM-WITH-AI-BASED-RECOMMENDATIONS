import json
import os
from datetime import datetime, time
from pathlib import Path

try:
    from common import get_run_paths, save_json, timestamp_now
except Exception:  # pragma: no cover - fallback for standalone test
    get_run_paths = None
    save_json = None
    timestamp_now = lambda: datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

BASE_DIR = Path(os.getenv("NETWORK_THESIS_BASE", "/home/kali/network-thesis-GIT"))
CONFIG_FILE = Path(os.getenv("SCAN_SCHEDULE_CONFIG", str(BASE_DIR / "config" / "scan_schedule.json")))
VALID_PROFILES = {"balanced", "deep"}
PATCH_MARKER_ENV = "NETWORK_THESIS_RESOLVED_PROFILE"


def _parse_hhmm(value: str) -> time:
    parts = value.strip().split(":")
    if len(parts) != 2:
        raise ValueError(f"Neteisingas laiko formatas: {value}. Turi būti HH:MM")
    hour = int(parts[0])
    minute = int(parts[1])
    if hour < 0 or hour > 23 or minute < 0 or minute > 59:
        raise ValueError(f"Neteisingas laikas: {value}")
    return time(hour=hour, minute=minute)


def _time_in_range(current: time, start: time, end: time) -> bool:
    # Normal same-day interval, e.g. 04:00-23:00
    if start <= end:
        return start <= current < end
    # Overnight interval, e.g. 23:00-04:00
    return current >= start or current < end


def load_schedule(config_file: Path = CONFIG_FILE) -> dict:
    if not config_file.exists():
        return {
            "default_profile": "balanced",
            "rules": [
                {"name": "night_deep", "start": "23:00", "end": "04:00", "profile": "deep"},
                {"name": "day_balanced", "start": "04:00", "end": "23:00", "profile": "balanced"},
            ],
            "profiles": {
                "balanced": {},
                "deep": {},
            },
        }
    with open(config_file, "r", encoding="utf-8") as f:
        return json.load(f)


def resolve_scan_profile(now: datetime | None = None, schedule: dict | None = None) -> dict:
    """Return resolved profile metadata without mutating environment."""
    now = now or datetime.now()
    schedule = schedule or load_schedule()

    forced = os.getenv("FORCE_SCAN_PROFILE", "").strip().lower()
    if forced:
        if forced not in VALID_PROFILES:
            raise ValueError(f"FORCE_SCAN_PROFILE={forced} neteisingas. Galimos reikšmės: balanced, deep")
        return {
            "profile": forced,
            "source": "FORCE_SCAN_PROFILE",
            "rule": "manual_override",
            "current_time": now.strftime("%H:%M"),
            "timestamp": now.isoformat(timespec="seconds"),
        }

    current = now.time().replace(second=0, microsecond=0)
    for rule in schedule.get("rules", []):
        start = _parse_hhmm(rule["start"])
        end = _parse_hhmm(rule["end"])
        profile = str(rule.get("profile", "balanced")).lower()
        if profile not in VALID_PROFILES:
            continue
        if _time_in_range(current, start, end):
            return {
                "profile": profile,
                "source": "scan_schedule.json",
                "rule": rule.get("name"),
                "rule_start": rule.get("start"),
                "rule_end": rule.get("end"),
                "current_time": now.strftime("%H:%M"),
                "timestamp": now.isoformat(timespec="seconds"),
            }

    default_profile = str(schedule.get("default_profile", "balanced")).lower()
    if default_profile not in VALID_PROFILES:
        default_profile = "balanced"
    return {
        "profile": default_profile,
        "source": "default_profile",
        "rule": "default",
        "current_time": now.strftime("%H:%M"),
        "timestamp": now.isoformat(timespec="seconds"),
    }


def _apply_env_values(env_values: dict) -> dict:
    applied = {}
    previous = {}
    for key, value in env_values.items():
        if value is None:
            continue
        previous[key] = os.environ.get(key)
        # We intentionally set these variables so that old terminal exports do not accidentally keep deep/balanced stale.
        os.environ[key] = str(value)
        applied[key] = str(value)
    return {"applied": applied, "previous": previous}


def apply_profile_environment(write_context: bool = True) -> dict:
    """Resolve profile, set environment variables in the current Python process, and optionally save context."""
    if os.getenv("DISABLE_AUTO_PROFILE") == "1":
        info = {
            "profile": os.getenv("SERVICE_SCAN_PROFILE") or os.getenv("WEB_DEEP_PROFILE") or "manual",
            "source": "DISABLE_AUTO_PROFILE=1",
            "rule": "disabled",
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "environment_applied": {},
            "environment_previous": {},
        }
        os.environ[PATCH_MARKER_ENV] = info["profile"]
        return info

    schedule = load_schedule()
    resolved = resolve_scan_profile(schedule=schedule)
    profile = resolved["profile"]
    profile_env = (schedule.get("profiles", {}) or {}).get(profile, {}) or {}
    env_result = _apply_env_values(profile_env)

    os.environ[PATCH_MARKER_ENV] = profile
    info = {
        **resolved,
        "config_file": str(CONFIG_FILE),
        "environment_applied": env_result["applied"],
        "environment_previous": env_result["previous"],
    }

    if write_context:
        try:
            if get_run_paths and save_json:
                paths = get_run_paths()
                output = paths["logs_dir"] / f"auto_profile_{timestamp_now()}.json"
                save_json(output, info)
                info["context_file"] = str(output)
        except Exception as exc:
            info["context_write_warning"] = str(exc)

    return info


if __name__ == "__main__":
    result = apply_profile_environment(write_context=False)
    print(json.dumps(result, indent=2, ensure_ascii=False))
