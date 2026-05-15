#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MAC_RE = re.compile(r"\b[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
WINDOWS_USER_RE = re.compile(r"\b[A-Za-z0-9_.-]+\\[A-Za-z0-9_.-]+\b")


def pseudonym(prefix: str, value: str) -> str:
    return f"{prefix}_{hashlib.sha256(value.encode('utf-8', errors='replace')).hexdigest()[:10]}"


def mask_text(text: str) -> str:
    text = IP_RE.sub(lambda m: pseudonym("ip", m.group(0)), text)
    text = MAC_RE.sub(lambda m: pseudonym("mac", m.group(0)), text)
    text = EMAIL_RE.sub(lambda m: pseudonym("email", m.group(0)), text)
    text = WINDOWS_USER_RE.sub(lambda m: pseudonym("user", m.group(0)), text)
    return text


def mask_obj(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: mask_obj(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [mask_obj(v) for v in obj]
    if isinstance(obj, str):
        return mask_text(obj)
    return obj


def main() -> None:
    parser = argparse.ArgumentParser(description="Ataskaitų privatumo filtras.")
    parser.add_argument("input")
    parser.add_argument("output")
    args = parser.parse_args()
    inp = Path(args.input)
    out = Path(args.output)
    if inp.suffix.lower() == ".json":
        data = json.loads(inp.read_text(encoding="utf-8"))
        out.write_text(json.dumps(mask_obj(data), ensure_ascii=False, indent=4), encoding="utf-8")
    else:
        out.write_text(mask_text(inp.read_text(encoding="utf-8", errors="ignore")), encoding="utf-8")
    print(f"[GERAI] Privatumo filtruotas failas sukurtas: {out}")


if __name__ == "__main__":
    main()
