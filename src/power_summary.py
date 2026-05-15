import csv
import sys
from pathlib import Path
from statistics import mean

from common import get_run_paths

paths = get_run_paths()
LOG_DIR = paths["power_dir"]
REPORT_DIR = paths["reports_dir"]
REPORT_DIR.mkdir(parents=True, exist_ok=True)

OUTPUT_VOLTAGE_V = 5.0
POWERBANK_CELL_VOLTAGE_V = 3.7
POWERBANK_EFFICIENCY = 0.85
POWERBANK_CAPACITY_MAH = 20000


def interpret_throttled(hex_value: str) -> list[str]:
    if not hex_value or hex_value == "0x0":
        return []

    value = int(hex_value, 16)
    flags = []
    if value & 0x1:
        flags.append("undervoltage_now")
    if value & 0x2:
        flags.append("freq_capped_now")
    if value & 0x4:
        flags.append("throttled_now")
    if value & 0x8:
        flags.append("temp_limit_now")
    if value & 0x10000:
        flags.append("undervoltage_past")
    if value & 0x20000:
        flags.append("freq_capped_past")
    if value & 0x40000:
        flags.append("throttled_past")
    if value & 0x80000:
        flags.append("temp_limit_past")
    return flags


def main():
    if len(sys.argv) > 1:
        csv_file = Path(sys.argv[1])
    else:
        csv_files = sorted(LOG_DIR.glob("*.csv"))
        if not csv_files:
            raise FileNotFoundError("Nerastas nei vienas power log CSV failas.")
        csv_file = csv_files[-1]

    rows = list(csv.DictReader(open(csv_file, encoding="utf-8")))
    if not rows:
        raise RuntimeError("CSV failas tuščias.")

    power = [float(r["est_board_power_w"]) for r in rows if r["est_board_power_w"]]
    temp = [float(r["temp_c"]) for r in rows if r["temp_c"]]
    ext5v = [float(r["ext5v_v"]) for r in rows if r["ext5v_v"]]

    sample_interval = 2.0
    duration_s = len(rows) * sample_interval
    energy_wh = sum(power) * (sample_interval / 3600.0)

    throttled_values = [r["throttled_hex"] for r in rows if r["throttled_hex"]]
    unique_flags = sorted({flag for value in throttled_values for flag in interpret_throttled(value)})

    estimated_mah_5v = round(energy_wh * 1000 / OUTPUT_VOLTAGE_V, 2)
    estimated_powerbank_cell_mah = round(
        energy_wh * 1000 / (POWERBANK_CELL_VOLTAGE_V * POWERBANK_EFFICIENCY), 2
    )

    usable_powerbank_wh = (
        POWERBANK_CAPACITY_MAH / 1000 * POWERBANK_CELL_VOLTAGE_V * POWERBANK_EFFICIENCY
    )
    estimated_powerbank_used_percent = round(
        (energy_wh / usable_powerbank_wh) * 100, 2
    )

    summary = {
        "source_csv": csv_file.name,
        "samples": len(rows),
        "duration_s": duration_s,
        "avg_est_board_power_w": round(mean(power), 4),
        "max_est_board_power_w": round(max(power), 4),
        "min_ext5v_v": round(min(ext5v), 4) if ext5v else None,
        "avg_temp_c": round(mean(temp), 2),
        "max_temp_c": round(max(temp), 2),
        "estimated_energy_wh": round(energy_wh, 4),
        "estimated_mah_5v": estimated_mah_5v,
        "estimated_powerbank_cell_mah": estimated_powerbank_cell_mah,
        "estimated_powerbank_used_percent": estimated_powerbank_used_percent,
        "powerbank_capacity_mah": POWERBANK_CAPACITY_MAH,
        "powerbank_efficiency_assumed": POWERBANK_EFFICIENCY,
        "throttled_flags": unique_flags
    }

    report_path = REPORT_DIR / f"power_summary_{csv_file.stem}.csv"
    with open(report_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(summary.keys())
        writer.writerow(summary.values())

    print(f"Power summary: {report_path}")
    print(summary)


if __name__ == "__main__":
    main()
