import csv
import re
import subprocess
import sys
import time
from datetime import datetime

from common import get_run_paths

paths = get_run_paths()
LOG_DIR = paths["power_dir"]
LOG_DIR.mkdir(parents=True, exist_ok=True)

SAMPLE_INTERVAL = 2.0
TEST_NAME = sys.argv[1] if len(sys.argv) > 1 else "assessment"

timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
csv_file = LOG_DIR / f"power_{TEST_NAME}_{timestamp}.csv"

line_re = re.compile(r'^\s*([A-Z0-9_]+)\s+(current|volt)\(\d+\)=([0-9.]+)(A|V)$')


def run_cmd(cmd):
    return subprocess.check_output(cmd, text=True).strip()


def read_pmic():
    out = run_cmd(["vcgencmd", "pmic_read_adc"])
    currents = {}
    voltages = {}
    ext5v_v = None

    for line in out.splitlines():
        line = line.strip()
        m = line_re.match(line)
        if not m:
            continue

        rail, kind, value, _unit = m.groups()
        value = float(value)

        if kind == "current":
            currents[rail.replace("_A", "")] = value
        elif kind == "volt":
            voltages[rail.replace("_V", "")] = value

        if rail == "EXT5V_V":
            ext5v_v = value

    est_power = 0.0
    for rail, current in currents.items():
        if rail in voltages:
            est_power += voltages[rail] * current

    return ext5v_v, est_power


def read_temp():
    out = run_cmd(["vcgencmd", "measure_temp"])
    return float(out.split("=")[1].replace("'C", ""))


def read_throttled():
    out = run_cmd(["vcgencmd", "get_throttled"])
    return out.split("=")[1]


def read_arm_clock():
    out = run_cmd(["vcgencmd", "measure_clock", "arm"])
    return int(out.split("=")[1])


with open(csv_file, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow([
        "timestamp",
        "ext5v_v",
        "est_board_power_w",
        "temp_c",
        "arm_clock_hz",
        "throttled_hex"
    ])

    try:
        while True:
            now = datetime.now().isoformat(timespec="seconds")
            ext5v_v, est_power = read_pmic()
            temp_c = read_temp()
            arm_clock = read_arm_clock()
            throttled = read_throttled()

            writer.writerow([
                now,
                f"{ext5v_v:.4f}" if ext5v_v is not None else "",
                f"{est_power:.4f}",
                f"{temp_c:.2f}",
                arm_clock,
                throttled
            ])
            f.flush()
            time.sleep(SAMPLE_INTERVAL)
    except KeyboardInterrupt:
        pass
