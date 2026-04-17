from __future__ import annotations

import json
import os
import threading
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class LocalJSONStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        if not self.path.exists():
            self._write(self._default_state())

    def _default_state(self) -> dict[str, Any]:
        return {
            "users": [],
            "todos": [],
            "events": [],
            "alerts": [],
        }

    def _read(self) -> dict[str, Any]:
        with self.lock:
            try:
                with self.path.open("r", encoding="utf-8") as handle:
                    return json.load(handle)
            except (json.JSONDecodeError, OSError):
                fallback = self._default_state()
                self._write(fallback)
                return fallback

    def _write(self, data: dict[str, Any]) -> None:
        with self.lock:
            temp_path = self.path.with_suffix(f"{self.path.suffix}.tmp")
            with temp_path.open("w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2)
            temp_path.replace(self.path)

    def get_user_by_username(self, username: str) -> dict[str, Any] | None:
        data = self._read()
        for user in data["users"]:
            if user["username"] == username:
                return deepcopy(user)
        return None

    def create_user(self, username: str, password_hash: str) -> dict[str, Any]:
        data = self._read()
        if any(user["username"] == username for user in data["users"]):
            raise ValueError("Username already exists.")

        user = {
            "id": str(uuid.uuid4()),
            "username": username,
            "password_hash": password_hash,
            "created_at": utcnow_iso(),
        }
        data["users"].append(user)
        self._write(data)
        return deepcopy(user)

    def list_todos(self, user_id: str) -> list[dict[str, Any]]:
        data = self._read()
        todos = [todo for todo in data["todos"] if todo["user_id"] == user_id]
        todos.sort(key=lambda item: item["created_at"], reverse=True)
        return deepcopy(todos)

    def create_todo(self, user_id: str, task: str) -> dict[str, Any]:
        data = self._read()
        todo = {
            "id": str(uuid.uuid4()),
            "user_id": user_id,
            "task": task,
            "completed": False,
            "created_at": utcnow_iso(),
        }
        data["todos"].append(todo)
        self._write(data)
        return deepcopy(todo)

    def update_todo(self, todo_id: str, fields: dict[str, Any]) -> dict[str, Any] | None:
        data = self._read()
        updated = None
        for todo in data["todos"]:
            if todo["id"] == todo_id:
                todo.update(fields)
                updated = deepcopy(todo)
                break
        if updated is not None:
            self._write(data)
        return updated

    def delete_todo(self, todo_id: str) -> bool:
        data = self._read()
        original_count = len(data["todos"])
        data["todos"] = [todo for todo in data["todos"] if todo["id"] != todo_id]
        if len(data["todos"]) != original_count:
            self._write(data)
            return True
        return False

    def log_event(self, event: dict[str, Any]) -> None:
        data = self._read()
        row = deepcopy(event)
        row["id"] = str(uuid.uuid4())
        data["events"].append(row)
        data["events"] = data["events"][-1500:]
        self._write(data)

    def log_alert(self, alert: dict[str, Any]) -> None:
        data = self._read()
        row = deepcopy(alert)
        row["id"] = str(uuid.uuid4())
        data["alerts"].append(row)
        data["alerts"] = data["alerts"][-500:]
        self._write(data)

    def reset_ids_demo_data(self) -> None:
        data = self._read()
        data["events"] = []
        data["alerts"] = []
        self._write(data)


class SupabaseStore:
    def __init__(self, url: str, key: str, timeout: int = 5) -> None:
        self.url = url.rstrip("/")
        self.key = key
        self.timeout = timeout
        self.base_url = f"{self.url}/rest/v1"
        self.session = requests.Session()
        self.session.headers.update(
            {
                "apikey": self.key,
                "Authorization": f"Bearer {self.key}",
                "Content-Type": "application/json",
            }
        )

    def _request(
        self,
        method: str,
        table: str,
        *,
        params: dict[str, Any] | None = None,
        payload: dict[str, Any] | list[dict[str, Any]] | None = None,
        prefer: str | None = None,
    ) -> Any:
        headers: dict[str, str] = {}
        if prefer:
            headers["Prefer"] = prefer

        response = self.session.request(
            method=method,
            url=f"{self.base_url}/{table}",
            params=params,
            json=payload,
            headers=headers,
            timeout=self.timeout,
        )
        response.raise_for_status()
        if not response.text:
            return None
        return response.json()

    def status(self) -> dict[str, Any]:
        self._request("GET", "users", params={"select": "id", "limit": 1})
        return {"mode": "supabase", "healthy": True}

    def get_user_by_username(self, username: str) -> dict[str, Any] | None:
        rows = self._request(
            "GET",
            "users",
            params={"select": "*", "username": f"eq.{username}", "limit": 1},
        )
        return rows[0] if rows else None

    def create_user(self, username: str, password_hash: str) -> dict[str, Any]:
        rows = self._request(
            "POST",
            "users",
            payload={
                "id": str(uuid.uuid4()),
                "username": username,
                "password_hash": password_hash,
            },
            prefer="return=representation",
        )
        return rows[0]

    def list_todos(self, user_id: str) -> list[dict[str, Any]]:
        rows = self._request(
            "GET",
            "todos",
            params={"select": "*", "user_id": f"eq.{user_id}", "order": "created_at.desc"},
        )
        return rows or []

    def create_todo(self, user_id: str, task: str) -> dict[str, Any]:
        rows = self._request(
            "POST",
            "todos",
            payload={"id": str(uuid.uuid4()), "user_id": user_id, "task": task, "completed": False},
            prefer="return=representation",
        )
        return rows[0]

    def update_todo(self, todo_id: str, fields: dict[str, Any]) -> dict[str, Any] | None:
        rows = self._request(
            "PATCH",
            "todos",
            params={"id": f"eq.{todo_id}", "select": "*"},
            payload=fields,
            prefer="return=representation",
        )
        return rows[0] if rows else None

    def delete_todo(self, todo_id: str) -> bool:
        self._request("DELETE", "todos", params={"id": f"eq.{todo_id}"})
        return True

    def log_event(self, event: dict[str, Any]) -> None:
        payload = {
            "timestamp": event["timestamp"],
            "ip": event["ip"],
            "endpoint": event["endpoint"],
            "method": event["method"],
            "status_code": event["status_code"],
            "latency_ms": event["latency_ms"],
            "username": event.get("username"),
            "kind": event["kind"],
            "severity": event["severity"],
            "attack_type": event.get("attack_type"),
            "action": event["action"],
            "detail": event["detail"],
            "blocked": event["blocked"],
            "synthetic": event["synthetic"],
            "ml_score": event["ml_score"],
        }
        self._request("POST", "events", payload=payload)

    def log_alert(self, alert: dict[str, Any]) -> None:
        payload = {
            "timestamp": alert["timestamp"],
            "ip": alert["ip"],
            "attack_type": alert["attack_type"],
            "severity": alert["severity"],
            "action": alert["action"],
            "detail": alert["detail"],
            "confidence": alert["confidence"],
        }
        self._request("POST", "alerts", payload=payload)

    def reset_ids_demo_data(self) -> None:
        self._request("DELETE", "events", params={"id": "gte.0"})
        self._request("DELETE", "alerts", params={"id": "gte.0"})


class ProjectStore:
    def __init__(self, local_path: str | Path = "data/local_store.json") -> None:
        self.local = LocalJSONStore(local_path)
        self.remote: SupabaseStore | None = None
        self.last_error = ""
        self.preferred_mode = "local"

        url = os.getenv("SUPABASE_URL", "").strip()
        key = (
            os.getenv("SUPABASE_KEY", "").strip()
            or os.getenv("SUPABASE_ANON_KEY", "").strip()
            or os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
        )

        if url and key:
            self.preferred_mode = "supabase"
            try:
                candidate = SupabaseStore(url, key)
                candidate.status()
                self.remote = candidate
            except Exception as exc:
                self.last_error = str(exc)

    def _run(self, method_name: str, *args: Any, **kwargs: Any) -> Any:
        if self.remote is not None:
            try:
                method = getattr(self.remote, method_name)
                return method(*args, **kwargs)
            except Exception as exc:
                self.last_error = str(exc)

        method = getattr(self.local, method_name)
        return method(*args, **kwargs)

    def status(self) -> dict[str, Any]:
        if self.remote is not None:
            return {
                "mode": "supabase",
                "healthy": True,
                "detail": "Supabase is active for users, todos, alerts, and telemetry.",
                "last_error": self.last_error,
            }

        detail = "Supabase is not configured." if self.preferred_mode == "local" else "Supabase unreachable, local fallback active."
        return {
            "mode": "local",
            "healthy": True,
            "detail": detail,
            "last_error": self.last_error,
        }

    def get_user_by_username(self, username: str) -> dict[str, Any] | None:
        return self._run("get_user_by_username", username)

    def create_user(self, username: str, password_hash: str) -> dict[str, Any]:
        return self._run("create_user", username, password_hash)

    def list_todos(self, user_id: str) -> list[dict[str, Any]]:
        return self._run("list_todos", user_id)

    def create_todo(self, user_id: str, task: str) -> dict[str, Any]:
        return self._run("create_todo", user_id, task)

    def update_todo(self, todo_id: str, fields: dict[str, Any]) -> dict[str, Any] | None:
        return self._run("update_todo", todo_id, fields)

    def delete_todo(self, todo_id: str) -> bool:
        return self._run("delete_todo", todo_id)

    def log_event(self, event: dict[str, Any]) -> None:
        self._run("log_event", event)

    def log_alert(self, alert: dict[str, Any]) -> None:
        self._run("log_alert", alert)

    def reset_ids_demo_data(self) -> None:
        self._run("reset_ids_demo_data")
