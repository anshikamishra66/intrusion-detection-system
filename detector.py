from __future__ import annotations

import csv
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
import threading

import numpy as np

try:
    from sklearn.ensemble import RandomForestClassifier
except Exception:  # pragma: no cover
    RandomForestClassifier = None


SEVERITY_RANK = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


COUNTRY_POOL = [
    "Germany",
    "Netherlands",
    "India",
    "Singapore",
    "United States",
    "Brazil",
    "Canada",
    "United Kingdom",
]

DATASET_PATH = Path("data/ids_training_dataset.csv")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def label_time(moment: datetime) -> str:
    return moment.astimezone().strftime("%H:%M:%S")


class HybridIDSEngine:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.ip_history: dict[str, deque[dict[str, Any]]] = defaultdict(deque)
        self.recent_events: deque[dict[str, Any]] = deque(maxlen=700)
        self.recent_alerts: deque[dict[str, Any]] = deque(maxlen=140)
        self.mitigations: dict[str, dict[str, Any]] = {}
        self.alert_cooldowns: dict[tuple[str, str, str], datetime] = {}
        self.model = self._train_model()

    def reset(self) -> None:
        with self.lock:
            self.ip_history.clear()
            self.recent_events.clear()
            self.recent_alerts.clear()
            self.mitigations.clear()
            self.alert_cooldowns.clear()

    def peek_mitigation(self, ip: str) -> dict[str, Any] | None:
        with self.lock:
            self._prune_locked(utcnow())
            mitigation = self.mitigations.get(ip)
            if mitigation is None:
                return None
            return {
                "mode": mitigation["mode"],
                "reason": mitigation["reason"],
                "severity": mitigation["severity"],
                "expires_in": max(0, int((mitigation["expires_at"] - utcnow()).total_seconds())),
            }

    def ingest_event(
        self,
        *,
        ip: str,
        endpoint: str,
        method: str,
        status_code: int,
        username: str | None = None,
        success: bool | None = None,
        blocked: bool = False,
        synthetic: bool = False,
        detail: str = "",
        attack_hint: str | None = None,
        mitigation_context: dict[str, Any] | None = None,
        latency_ms: float = 0.0,
    ) -> dict[str, Any]:
        now = utcnow()
        ts_value = now.timestamp()

        with self.lock:
            self._prune_locked(now)

            self.ip_history[ip].append(
                {
                    "ts": ts_value,
                    "endpoint": endpoint,
                    "status_code": status_code,
                    "username": username,
                    "success": success,
                    "blocked": blocked,
                }
            )

            features = self._features_locked(ip, now)
            ml_score = self._ml_score(features)
            rule = self._rules_locked(ip, endpoint, features)
            outcome = self._resolve_outcome(
                blocked=blocked,
                ml_score=ml_score,
                rule=rule,
                attack_hint=attack_hint,
                mitigation_context=mitigation_context,
                features=features,
            )

            event = {
                "ts": ts_value,
                "timestamp": now.isoformat(),
                "time_label": label_time(now),
                "ip": ip,
                "endpoint": endpoint,
                "method": method,
                "status_code": status_code,
                "username": username,
                "success": success,
                "blocked": blocked,
                "synthetic": synthetic,
                "detail": detail or outcome["detail"],
                "kind": outcome["kind"],
                "severity": outcome["severity"],
                "attack_type": outcome["attack_type"],
                "action": outcome["action"],
                "ml_score": round(ml_score, 3),
                "latency_ms": round(latency_ms, 2),
                "request_rate_10s": round(features["request_rate_10s"], 2),
                "failed_logins_60s": features["failed_logins_60s"],
            }
            self.recent_events.append(event)

            alerts: list[dict[str, Any]] = []
            if outcome["attack_type"] is not None and outcome["kind"] != "safe":
                if outcome["mitigation_mode"] is not None:
                    self._apply_mitigation_locked(
                        ip=ip,
                        mode=outcome["mitigation_mode"],
                        reason=outcome["attack_type"],
                        severity=outcome["severity"],
                        duration_seconds=outcome["mitigation_seconds"],
                    )
                alert = self._maybe_alert_locked(
                    ip=ip,
                    attack_type=outcome["attack_type"],
                    severity=outcome["severity"],
                    action=outcome["action"],
                    detail=event["detail"],
                    confidence=max(rule["confidence"], ml_score),
                    now=now,
                )
                if alert is not None:
                    alerts.append(alert)

            return {"event": event, "alerts": alerts}

    def snapshot(self) -> dict[str, Any]:
        now = utcnow()
        with self.lock:
            self._prune_locked(now)
            events = list(self.recent_events)
            alerts = list(self.recent_alerts)
            active_mitigations = self._active_mitigations_locked(now)

        recent_10 = [event for event in events if now.timestamp() - event["ts"] <= 10]
        recent_60 = [event for event in events if now.timestamp() - event["ts"] <= 60]
        recent_300 = [event for event in events if now.timestamp() - event["ts"] <= 300]

        active_threat_ips = {
            event["ip"] for event in recent_60 if event["kind"] in {"warning", "threat"}
        }
        active_threat_ips.update(item["ip"] for item in active_mitigations)

        blocked_count = sum(1 for item in active_mitigations if item["mode"] == "blocked")
        rate_limit_count = sum(1 for item in active_mitigations if item["mode"] == "rate_limited")
        failed_logins = sum(
            1
            for event in recent_60
            if event["endpoint"] == "/auth/login" and event["success"] is False
        )

        threat_level = min(
            100,
            (len(active_threat_ips) * 18)
            + (blocked_count * 14)
            + int((len(recent_10) / 10) * 12),
        )

        terminal_feed = []
        for alert in alerts[-10:]:
            terminal_feed.append(
                f"[{alert['time_label']}] {alert['action']} {alert['ip']} "
                f"for {alert['attack_type']} ({alert['severity']}, {int(alert['confidence'] * 100)}%)"
            )

        return {
            "metrics": {
                "active_threats": len(active_threat_ips),
                "blocked_ips": blocked_count,
                "rate_limited": rate_limit_count,
                "request_rate": round(len(recent_10) / 10, 1),
                "failed_logins": failed_logins,
                "threat_level": threat_level,
            },
            "mitigations": active_mitigations,
            "traffic_series": self._traffic_series(events),
            "attack_distribution": self._attack_distribution(recent_300),
            "recent_alerts": [self._public_copy(item) for item in alerts[-8:]][::-1],
            "recent_events": [self._public_copy(item) for item in events[-16:]][::-1],
            "top_offenders": self._top_offenders(recent_300),
            "terminal_feed": terminal_feed[::-1],
        }

    def _train_model(self) -> RandomForestClassifier | None:
        if RandomForestClassifier is None:
            return None

        dataset = self._load_dataset()
        if dataset is None:
            X, y = self._synthetic_training_data()
        else:
            X, y = dataset

        model = RandomForestClassifier(n_estimators=140, max_depth=7, random_state=7)
        model.fit(X, y)
        return model

    def _load_dataset(self) -> tuple[np.ndarray, np.ndarray] | None:
        if not DATASET_PATH.exists():
            return None

        feature_rows: list[list[float]] = []
        labels: list[int] = []
        with DATASET_PATH.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                try:
                    feature_rows.append(
                        [
                            float(row["request_rate_10s"]),
                            float(row["failed_logins_60s"]),
                            float(row["unique_endpoints_60s"]),
                            float(row["avg_interval_ms"]),
                            float(row["error_ratio_60s"]),
                            float(row["blocked_ratio_60s"]),
                        ]
                    )
                    labels.append(int(row["label"]))
                except (KeyError, TypeError, ValueError):
                    continue

        if len(feature_rows) < 12:
            return None

        return np.array(feature_rows, dtype=float), np.array(labels, dtype=int)

    def _synthetic_training_data(self) -> tuple[np.ndarray, np.ndarray]:
        rng = np.random.default_rng(7)

        normal = np.column_stack(
            [
                rng.normal(0.4, 0.2, 320).clip(0.05, 1.5),
                rng.normal(0.4, 0.8, 320).clip(0, 3),
                rng.normal(2.2, 0.8, 320).clip(1, 5),
                rng.normal(1800, 650, 320).clip(220, 5000),
                rng.normal(0.08, 0.06, 320).clip(0, 0.35),
                rng.normal(0.0, 0.02, 320).clip(0, 0.2),
            ]
        )

        brute_force = np.column_stack(
            [
                rng.normal(1.5, 0.4, 220).clip(0.6, 3.5),
                rng.normal(7.0, 2.2, 220).clip(3, 16),
                rng.normal(1.3, 0.5, 220).clip(1, 4),
                rng.normal(650, 180, 220).clip(120, 1400),
                rng.normal(0.88, 0.09, 220).clip(0.45, 1.0),
                rng.normal(0.05, 0.03, 220).clip(0, 0.25),
            ]
        )

        ddos = np.column_stack(
            [
                rng.normal(4.8, 1.6, 240).clip(2.2, 10.5),
                rng.normal(0.5, 0.7, 240).clip(0, 3),
                rng.normal(1.1, 0.4, 240).clip(1, 3),
                rng.normal(140, 80, 240).clip(20, 450),
                rng.normal(0.42, 0.18, 240).clip(0.05, 0.9),
                rng.normal(0.1, 0.08, 240).clip(0, 0.4),
            ]
        )

        X = np.vstack([normal, brute_force, ddos])
        y = np.array([0] * len(normal) + [1] * len(brute_force) + [1] * len(ddos))
        return X, y

    def _features_locked(self, ip: str, now: datetime) -> dict[str, Any]:
        history = self.ip_history[ip]
        cutoff_10 = now.timestamp() - 10
        cutoff_60 = now.timestamp() - 60

        last_10 = [item for item in history if item["ts"] >= cutoff_10]
        last_60 = [item for item in history if item["ts"] >= cutoff_60]

        timestamps = [item["ts"] for item in last_10]
        intervals_ms = []
        for index in range(1, len(timestamps)):
            intervals_ms.append((timestamps[index] - timestamps[index - 1]) * 1000)

        failed_logins = [
            item
            for item in last_60
            if item["endpoint"] == "/auth/login" and item["success"] is False
        ]
        errors = [item for item in last_60 if item["status_code"] >= 400]
        blocked_hits = [item for item in last_60 if item["blocked"]]

        return {
            "request_rate_10s": len(last_10) / 10,
            "failed_logins_60s": len(failed_logins),
            "unique_endpoints_60s": len({item["endpoint"] for item in last_60}) or 1,
            "avg_interval_ms": (sum(intervals_ms) / len(intervals_ms)) if intervals_ms else 2400,
            "error_ratio_60s": len(errors) / max(1, len(last_60)),
            "blocked_ratio_60s": len(blocked_hits) / max(1, len(last_60)),
            "unique_usernames_60s": len(
                {item["username"] for item in failed_logins if item["username"]}
            ),
            "window_10_count": len(last_10),
            "window_60_count": len(last_60),
        }

    def _ml_score(self, features: dict[str, Any]) -> float:
        vector = np.array(
            [
                features["request_rate_10s"],
                features["failed_logins_60s"],
                features["unique_endpoints_60s"],
                features["avg_interval_ms"],
                features["error_ratio_60s"],
                features["blocked_ratio_60s"],
            ]
        ).reshape(1, -1)

        if self.model is not None:
            return float(self.model.predict_proba(vector)[0][1])

        score = 0.0
        score += min(1.0, features["request_rate_10s"] / 5.5) * 0.45
        score += min(1.0, features["failed_logins_60s"] / 8.0) * 0.4
        score += min(1.0, features["error_ratio_60s"] / 0.8) * 0.15
        return min(1.0, score)

    def _rules_locked(self, ip: str, endpoint: str, features: dict[str, Any]) -> dict[str, Any]:
        failed_logins = features["failed_logins_60s"]
        request_burst = features["window_10_count"]
        unique_users = features["unique_usernames_60s"]

        if failed_logins >= 9:
            attack_type = "credential_stuffing" if unique_users >= 4 else "brute_force"
            return {
                "attack_type": attack_type,
                "severity": "CRITICAL",
                "action": "BLOCKED",
                "mitigation_mode": "blocked",
                "mitigation_seconds": 180,
                "confidence": 0.98,
                "detail": f"{failed_logins} failed logins from {ip} in the last 60 seconds.",
            }

        if failed_logins >= 5 and endpoint == "/auth/login":
            return {
                "attack_type": "brute_force",
                "severity": "HIGH",
                "action": "RATE LIMITED",
                "mitigation_mode": "rate_limited",
                "mitigation_seconds": 90,
                "confidence": 0.88,
                "detail": f"Repeated login failures from {ip} triggered step-up controls.",
            }

        if request_burst >= 42:
            return {
                "attack_type": "ddos",
                "severity": "CRITICAL",
                "action": "BLOCKED",
                "mitigation_mode": "blocked",
                "mitigation_seconds": 120,
                "confidence": 0.97,
                "detail": f"{request_burst} requests landed from {ip} in 10 seconds.",
            }

        if request_burst >= 24:
            return {
                "attack_type": "ddos",
                "severity": "HIGH",
                "action": "RATE LIMITED",
                "mitigation_mode": "rate_limited",
                "mitigation_seconds": 60,
                "confidence": 0.9,
                "detail": f"Elevated request burst detected from {ip}.",
            }

        return {
            "attack_type": None,
            "severity": "LOW",
            "action": "ALLOWED",
            "mitigation_mode": None,
            "mitigation_seconds": 0,
            "confidence": 0.0,
            "detail": "No active threat signature.",
        }

    def _resolve_outcome(
        self,
        *,
        blocked: bool,
        ml_score: float,
        rule: dict[str, Any],
        attack_hint: str | None,
        mitigation_context: dict[str, Any] | None,
        features: dict[str, Any],
    ) -> dict[str, Any]:
        if blocked and mitigation_context is not None:
            if mitigation_context["mode"] == "rate_limited":
                if features["failed_logins_60s"] >= 9:
                    return {
                        "kind": "threat",
                        "severity": "CRITICAL",
                        "attack_type": attack_hint or mitigation_context["reason"],
                        "action": "BLOCKED",
                        "detail": "Attacker persisted through rate limiting; escalation to temporary block applied.",
                        "mitigation_mode": "blocked",
                        "mitigation_seconds": 180,
                    }

                if features["window_10_count"] >= 42:
                    return {
                        "kind": "threat",
                        "severity": "CRITICAL",
                        "attack_type": attack_hint or mitigation_context["reason"],
                        "action": "BLOCKED",
                        "detail": "DDoS pressure continued during rate limiting; block promoted automatically.",
                        "mitigation_mode": "blocked",
                        "mitigation_seconds": 120,
                    }

            action = "BLOCKED" if mitigation_context["mode"] == "blocked" else "RATE LIMITED"
            return {
                "kind": "threat",
                "severity": mitigation_context["severity"],
                "attack_type": attack_hint or mitigation_context["reason"],
                "action": action,
                "detail": "IDS mitigation intercepted the request before application logic.",
                "mitigation_mode": None,
                "mitigation_seconds": 0,
            }

        if rule["attack_type"] is not None:
            return {
                "kind": "threat" if rule["severity"] in {"HIGH", "CRITICAL"} else "warning",
                "severity": rule["severity"],
                "attack_type": attack_hint or rule["attack_type"],
                "action": rule["action"],
                "detail": rule["detail"],
                "mitigation_mode": rule["mitigation_mode"],
                "mitigation_seconds": rule["mitigation_seconds"],
            }

        if ml_score >= 0.76 and features["window_60_count"] >= 8:
            return {
                "kind": "warning",
                "severity": "MEDIUM",
                "attack_type": attack_hint or "behavioral_anomaly",
                "action": "FLAGGED",
                "detail": f"Behavioral model scored this pattern at {int(ml_score * 100)}%.",
                "mitigation_mode": None,
                "mitigation_seconds": 0,
            }

        return {
            "kind": "safe",
            "severity": "LOW",
            "attack_type": None,
            "action": "ALLOWED",
            "detail": "Request accepted as normal traffic.",
            "mitigation_mode": None,
            "mitigation_seconds": 0,
        }

    def _apply_mitigation_locked(
        self,
        *,
        ip: str,
        mode: str,
        reason: str,
        severity: str,
        duration_seconds: int,
    ) -> None:
        candidate = {
            "ip": ip,
            "mode": mode,
            "reason": reason,
            "severity": severity,
            "expires_at": utcnow() + timedelta(seconds=duration_seconds),
        }

        current = self.mitigations.get(ip)
        if current is None:
            self.mitigations[ip] = candidate
            return

        current_rank = (SEVERITY_RANK[current["severity"]], 1 if current["mode"] == "blocked" else 0)
        candidate_rank = (SEVERITY_RANK[severity], 1 if mode == "blocked" else 0)
        if candidate_rank >= current_rank or candidate["expires_at"] > current["expires_at"]:
            self.mitigations[ip] = candidate

    def _maybe_alert_locked(
        self,
        *,
        ip: str,
        attack_type: str,
        severity: str,
        action: str,
        detail: str,
        confidence: float,
        now: datetime,
    ) -> dict[str, Any] | None:
        key = (ip, attack_type, action)
        previous = self.alert_cooldowns.get(key)
        if previous is not None and (now - previous).total_seconds() < 10:
            return None

        alert = {
            "timestamp": now.isoformat(),
            "time_label": label_time(now),
            "ip": ip,
            "attack_type": attack_type,
            "severity": severity,
            "action": action,
            "detail": detail,
            "confidence": round(confidence, 3),
            "ts": now.timestamp(),
        }
        self.alert_cooldowns[key] = now
        self.recent_alerts.append(alert)
        return alert

    def _prune_locked(self, now: datetime) -> None:
        cutoff = now.timestamp() - 600
        for ip, items in list(self.ip_history.items()):
            while items and items[0]["ts"] < cutoff:
                items.popleft()
            if not items:
                del self.ip_history[ip]

        for ip, mitigation in list(self.mitigations.items()):
            if mitigation["expires_at"] <= now:
                del self.mitigations[ip]

        for key, moment in list(self.alert_cooldowns.items()):
            if (now - moment).total_seconds() > 180:
                del self.alert_cooldowns[key]

    def _traffic_series(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        now_ts = utcnow().timestamp()
        bucket_size = 10
        bucket_count = 24
        start = now_ts - (bucket_size * bucket_count)

        buckets = [
            {"label": f"-{(bucket_count - index - 1) * bucket_size:02d}s", "normal": 0, "attack": 0}
            for index in range(bucket_count)
        ]

        for event in events:
            if event["ts"] < start:
                continue
            offset = int((event["ts"] - start) // bucket_size)
            if offset < 0 or offset >= bucket_count:
                continue
            lane = "attack" if event["kind"] in {"warning", "threat"} else "normal"
            buckets[offset][lane] += 1

        return buckets

    def _attack_distribution(self, recent_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        counter = Counter()
        for event in recent_events:
            if event["attack_type"] is not None:
                counter[event["attack_type"]] += 1

        total = sum(counter.values()) or 1
        ordered = []
        for attack_type in ["brute_force", "credential_stuffing", "ddos", "behavioral_anomaly"]:
            count = counter.get(attack_type, 0)
            ordered.append(
                {
                    "attack_type": attack_type,
                    "count": count,
                    "percentage": round((count / total) * 100, 1),
                }
            )
        return ordered

    def _top_offenders(self, recent_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        per_ip: dict[str, dict[str, Any]] = {}
        for event in recent_events:
            if event["kind"] == "safe":
                continue
            row = per_ip.setdefault(
                event["ip"],
                {
                    "ip": event["ip"],
                    "hits": 0,
                    "last_attack_type": event["attack_type"] or "behavioral_anomaly",
                    "country": self._country_for_ip(event["ip"]),
                },
            )
            row["hits"] += 1
            if event["attack_type"]:
                row["last_attack_type"] = event["attack_type"]

        offenders = list(per_ip.values())
        offenders.sort(key=lambda item: item["hits"], reverse=True)
        return offenders[:5]

    def _active_mitigations_locked(self, now: datetime) -> list[dict[str, Any]]:
        rows = []
        for ip, mitigation in self.mitigations.items():
            rows.append(
                {
                    "ip": ip,
                    "mode": mitigation["mode"],
                    "reason": mitigation["reason"],
                    "severity": mitigation["severity"],
                    "expires_in": max(0, int((mitigation["expires_at"] - now).total_seconds())),
                }
            )
        rows.sort(key=lambda item: (item["mode"] != "blocked", -item["expires_in"]))
        return rows

    def _country_for_ip(self, ip: str) -> str:
        return COUNTRY_POOL[sum(ord(char) for char in ip) % len(COUNTRY_POOL)]

    def _public_copy(self, row: dict[str, Any]) -> dict[str, Any]:
        public = dict(row)
        public.pop("ts", None)
        return public
