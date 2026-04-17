from __future__ import annotations

import csv
import random
from pathlib import Path


ROOT = Path(__file__).resolve().parent
DATASET_PATH = ROOT / "ids_dataset.csv"

CLASS_COUNTS = {
    "normal": 1222,
    "brute_force": 678,
    "ddos": 700,
}

FIELDNAMES = [
    "request_rate",
    "failure_count",
    "fail_ratio",
    "hour_of_day",
    "endpoint_type",
    "suspicious_user_agent",
    "payload_flag",
    "status_code",
    "request_interval_ms",
    "unique_targets",
    "same_ip_requests",
    "response_bytes_kb",
    "method_code",
    "label",
]

ENDPOINT_PAGE = 0
ENDPOINT_AUTH = 1
ENDPOINT_API = 2
ENDPOINT_ADMIN = 3

METHOD_GET = 0
METHOD_POST = 1
METHOD_PUT = 2
METHOD_DELETE = 3


def clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(maximum, value))


def weighted_choice(rng: random.Random, pairs: list[tuple[int, float]]) -> int:
    values = [value for value, _ in pairs]
    weights = [weight for _, weight in pairs]
    return rng.choices(values, weights=weights, k=1)[0]


def round_row(row: dict[str, float | int | str]) -> dict[str, float | int | str]:
    rounded: dict[str, float | int | str] = {}
    for key, value in row.items():
        if isinstance(value, float):
            rounded[key] = round(value, 4)
        else:
            rounded[key] = value
    return rounded


def normal_hour(rng: random.Random) -> int:
    return weighted_choice(
        rng,
        [
            (7, 2),
            (8, 4),
            (9, 7),
            (10, 8),
            (11, 8),
            (12, 7),
            (13, 7),
            (14, 8),
            (15, 8),
            (16, 7),
            (17, 5),
            (18, 3),
            (19, 2),
            (20, 1),
        ],
    )


def attack_hour(rng: random.Random) -> int:
    return weighted_choice(
        rng,
        [
            (0, 4),
            (1, 4),
            (2, 4),
            (3, 4),
            (4, 4),
            (5, 4),
            (6, 3),
            (7, 2),
            (8, 2),
            (9, 2),
            (10, 2),
            (11, 2),
            (12, 2),
            (13, 2),
            (14, 2),
            (15, 2),
            (16, 2),
            (17, 2),
            (18, 2),
            (19, 2),
            (20, 3),
            (21, 3),
            (22, 4),
            (23, 4),
        ],
    )


def make_normal_row(rng: random.Random) -> dict[str, float | int | str]:
    request_rate = clamp(rng.gauss(2.1, 1.0), 0.1, 6.0)
    failure_count = weighted_choice(rng, [(0, 46), (1, 28), (2, 12), (3, 4), (4, 1)])
    fail_ratio = clamp(rng.uniform(0.0, 0.16) + (failure_count * 0.02), 0.0, 0.24)
    endpoint_type = weighted_choice(
        rng,
        [
            (ENDPOINT_PAGE, 36),
            (ENDPOINT_AUTH, 24),
            (ENDPOINT_API, 34),
            (ENDPOINT_ADMIN, 6),
        ],
    )
    method_code = weighted_choice(
        rng,
        [
            (METHOD_GET, 58 if endpoint_type != ENDPOINT_AUTH else 18),
            (METHOD_POST, 28 if endpoint_type != ENDPOINT_PAGE else 12),
            (METHOD_PUT, 10 if endpoint_type == ENDPOINT_API else 5),
            (METHOD_DELETE, 4 if endpoint_type == ENDPOINT_API else 2),
        ],
    )
    status_code = weighted_choice(rng, [(200, 62), (201, 10), (204, 8), (304, 12), (401, 4), (404, 4)])
    suspicious_user_agent = 1 if rng.random() < 0.015 else 0
    payload_flag = 1 if rng.random() < 0.01 else 0
    request_interval_ms = clamp((1000 / request_rate) * rng.uniform(1.2, 4.6), 180, 4500)
    unique_targets = weighted_choice(rng, [(1, 18), (2, 28), (3, 24), (4, 14), (5, 10), (6, 6)])
    same_ip_requests = int(clamp(rng.gauss(18, 9), 1, 55))
    response_bytes_kb = clamp(rng.gauss(42, 18), 3.0, 180.0)

    return round_row(
        {
            "request_rate": request_rate,
            "failure_count": failure_count,
            "fail_ratio": fail_ratio,
            "hour_of_day": normal_hour(rng),
            "endpoint_type": endpoint_type,
            "suspicious_user_agent": suspicious_user_agent,
            "payload_flag": payload_flag,
            "status_code": status_code,
            "request_interval_ms": request_interval_ms,
            "unique_targets": unique_targets,
            "same_ip_requests": same_ip_requests,
            "response_bytes_kb": response_bytes_kb,
            "method_code": method_code,
            "label": "normal",
        }
    )


def make_brute_force_row(rng: random.Random) -> dict[str, float | int | str]:
    request_rate = clamp(rng.gauss(4.6, 1.4), 1.1, 10.5)
    failure_count = int(clamp(rng.gauss(16, 7), 5, 44))
    fail_ratio = clamp(rng.uniform(0.76, 0.98) + (failure_count / 250), 0.78, 1.0)
    endpoint_type = weighted_choice(rng, [(ENDPOINT_AUTH, 82), (ENDPOINT_ADMIN, 18)])
    status_code = weighted_choice(rng, [(401, 70), (403, 18), (429, 12)])
    suspicious_user_agent = 1 if rng.random() < 0.86 else 0
    payload_flag = 1 if rng.random() < 0.08 else 0
    request_interval_ms = clamp((1000 / request_rate) * rng.uniform(0.35, 1.15), 60, 950)
    unique_targets = int(clamp(rng.gauss(8, 3), 1, 18))
    same_ip_requests = int(clamp(rng.gauss(130, 45), 22, 260))
    response_bytes_kb = clamp(rng.gauss(8, 3), 1.2, 24.0)

    return round_row(
        {
            "request_rate": request_rate,
            "failure_count": failure_count,
            "fail_ratio": fail_ratio,
            "hour_of_day": attack_hour(rng),
            "endpoint_type": endpoint_type,
            "suspicious_user_agent": suspicious_user_agent,
            "payload_flag": payload_flag,
            "status_code": status_code,
            "request_interval_ms": request_interval_ms,
            "unique_targets": unique_targets,
            "same_ip_requests": same_ip_requests,
            "response_bytes_kb": response_bytes_kb,
            "method_code": METHOD_POST,
            "label": "brute_force",
        }
    )


def make_ddos_row(rng: random.Random) -> dict[str, float | int | str]:
    request_rate = clamp(rng.gauss(58, 28), 12, 220)
    failure_count = weighted_choice(rng, [(0, 32), (1, 26), (2, 18), (3, 12), (4, 8), (5, 4)])
    fail_ratio = clamp(rng.uniform(0.04, 0.48) + (failure_count * 0.015), 0.02, 0.62)
    endpoint_type = weighted_choice(rng, [(ENDPOINT_API, 82), (ENDPOINT_PAGE, 12), (ENDPOINT_AUTH, 6)])
    status_code = weighted_choice(rng, [(200, 42), (202, 6), (429, 24), (503, 18), (504, 10)])
    suspicious_user_agent = 1 if rng.random() < 0.42 else 0
    payload_flag = 1 if rng.random() < 0.05 else 0
    request_interval_ms = clamp((1000 / request_rate) * rng.uniform(0.18, 0.92), 4, 95)
    unique_targets = weighted_choice(rng, [(1, 38), (2, 34), (3, 18), (4, 8), (5, 2)])
    same_ip_requests = int(clamp(rng.gauss(680, 250), 140, 1800))
    response_bytes_kb = clamp(rng.gauss(6.5, 3.2), 0.4, 20.0)
    method_code = METHOD_GET if rng.random() < 0.78 else METHOD_POST

    return round_row(
        {
            "request_rate": request_rate,
            "failure_count": failure_count,
            "fail_ratio": fail_ratio,
            "hour_of_day": attack_hour(rng),
            "endpoint_type": endpoint_type,
            "suspicious_user_agent": suspicious_user_agent,
            "payload_flag": payload_flag,
            "status_code": status_code,
            "request_interval_ms": request_interval_ms,
            "unique_targets": unique_targets,
            "same_ip_requests": same_ip_requests,
            "response_bytes_kb": response_bytes_kb,
            "method_code": method_code,
            "label": "ddos",
        }
    )


def generate_dataset(path: Path = DATASET_PATH, seed: int = 42) -> list[dict[str, float | int | str]]:
    rng = random.Random(seed)
    rows: list[dict[str, float | int | str]] = []

    for _ in range(CLASS_COUNTS["normal"]):
        rows.append(make_normal_row(rng))
    for _ in range(CLASS_COUNTS["brute_force"]):
        rows.append(make_brute_force_row(rng))
    for _ in range(CLASS_COUNTS["ddos"]):
        rows.append(make_ddos_row(rng))

    rng.shuffle(rows)

    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)

    return rows


def main() -> None:
    rows = generate_dataset()
    print(f"Wrote {len(rows)} rows to {DATASET_PATH.name}")
    print(
        "Class distribution:",
        ", ".join(f"{label}={count}" for label, count in CLASS_COUNTS.items()),
    )


if __name__ == "__main__":
    main()
