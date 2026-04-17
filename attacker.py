from __future__ import annotations

import argparse
import random
import threading
import time

import requests


def brute_force_attack(
    base_url: str,
    source_ip: str,
    *,
    attempts: int = 14,
    delay: float = 0.28,
    usernames: list[str] | None = None,
) -> None:
    candidates = usernames or ["analyst", "admin", "manager", "finance"]
    session = requests.Session()
    headers = {
        "X-Forwarded-For": source_ip,
        "X-Simulated-Attack": "1",
        "User-Agent": "hydra-sim/1.0",
    }

    for index in range(attempts):
        username = candidates[index % len(candidates)]
        password = f"guess-{random.randint(1000, 9999)}"
        try:
            session.post(
                f"{base_url}/auth/login",
                json={"username": username, "password": password},
                headers=headers,
                timeout=4,
            )
        except requests.RequestException:
            return
        time.sleep(delay)


def ddos_attack(
    base_url: str,
    source_ip: str,
    *,
    bursts: int = 64,
    delay: float = 0.06,
) -> None:
    session = requests.Session()
    headers = {
        "X-Forwarded-For": source_ip,
        "X-Simulated-Attack": "1",
        "User-Agent": "loadstorm-sim/3.4",
    }

    for index in range(bursts):
        try:
            session.get(
                f"{base_url}/api/public/feed?tick={index}",
                headers=headers,
                timeout=4,
            )
        except requests.RequestException:
            return
        time.sleep(delay)


def launch_profile(profile: str, base_url: str, source_ip: str) -> None:
    if profile == "bruteforce":
        brute_force_attack(base_url, source_ip)
        return

    if profile == "ddos":
        ddos_attack(base_url, source_ip)
        return

    threads = [
        threading.Thread(target=brute_force_attack, args=(base_url, source_ip), daemon=True),
        threading.Thread(target=ddos_attack, args=(base_url, source_ip), daemon=True),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


def main() -> None:
    parser = argparse.ArgumentParser(description="Launch simulated attacks against the Todo IDS demo.")
    parser.add_argument("--mode", choices=["bruteforce", "ddos", "both"], default="both")
    parser.add_argument("--base-url", default="http://127.0.0.1:5000")
    parser.add_argument("--ip", default="185.234.219.12")
    args = parser.parse_args()

    launch_profile(args.mode, args.base_url.rstrip("/"), args.ip)


if __name__ == "__main__":
    main()
