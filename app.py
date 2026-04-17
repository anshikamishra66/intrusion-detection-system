from __future__ import annotations

import atexit
import os
import queue
import random
import threading
import time
from pathlib import Path
from typing import Any

from flask import Flask, flash, g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from attacker import launch_profile
from detector import HybridIDSEngine
from supabase_db import ProjectStore


def load_env_file(path: str | Path = ".env") -> None:
    env_path = Path(path)
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


load_env_file()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "change-this-demo-secret")
app.config["JSON_SORT_KEYS"] = False

store = ProjectStore()
engine = HybridIDSEngine()

demo_credentials = {
    "username": os.getenv("DEMO_USERNAME", "analyst"),
    "password": os.getenv("DEMO_PASSWORD", "Defend123!"),
}

audit_queue: queue.Queue[tuple[str, dict[str, Any]]] = queue.Queue()
stop_event = threading.Event()
background_threads_started = False

TRACK_EXCLUSIONS = {
    "/api/state",
    "/api/reset-demo",
    "/api/simulate/bruteforce",
    "/api/simulate/ddos",
    "/api/simulate/both",
    "/actions/reset-demo",
    "/actions/simulate/bruteforce",
    "/actions/simulate/ddos",
    "/actions/simulate/both",
}


def should_track(path: str) -> bool:
    return not path.startswith("/static/") and path not in TRACK_EXCLUSIONS


def client_ip_from_request() -> str:
    for header in ("X-Forwarded-For", "X-Demo-IP", "CF-Connecting-IP"):
        value = request.headers.get(header, "").strip()
        if value:
            return value.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"


def enqueue_ids_result(result: dict[str, Any]) -> None:
    audit_queue.put(("event", result["event"]))
    for alert in result["alerts"]:
        audit_queue.put(("alert", alert))


def audit_worker() -> None:
    while not stop_event.is_set():
        try:
            kind, payload = audit_queue.get(timeout=0.5)
        except queue.Empty:
            continue

        try:
            if kind == "event":
                store.log_event(payload)
            elif kind == "alert":
                store.log_alert(payload)
        except Exception:
            pass
        finally:
            audit_queue.task_done()


def baseline_traffic_worker() -> None:
    safe_ips = ["192.168.10.21", "10.0.0.15", "172.16.1.8", "192.168.10.33"]
    endpoints = ["/", "/api/public/feed", "/api/public/feed", "/"]

    while not stop_event.is_set():
        time.sleep(random.uniform(2.5, 4.5))
        result = engine.ingest_event(
            ip=random.choice(safe_ips),
            endpoint=random.choice(endpoints),
            method="GET",
            status_code=200,
            username="employee",
            success=True,
            blocked=False,
            synthetic=True,
            detail="Baseline business traffic from legitimate workspace users.",
            latency_ms=random.randint(15, 90),
        )
        enqueue_ids_result(result)


def ensure_demo_user() -> None:
    existing = store.get_user_by_username(demo_credentials["username"])
    if existing is None:
        store.create_user(
            demo_credentials["username"],
            generate_password_hash(demo_credentials["password"]),
        )


def start_background_threads() -> None:
    global background_threads_started
    if background_threads_started:
        return

    ensure_demo_user()

    threading.Thread(target=audit_worker, daemon=True).start()
    threading.Thread(target=baseline_traffic_worker, daemon=True).start()
    background_threads_started = True


def shutdown_runtime() -> None:
    stop_event.set()


start_background_threads()
atexit.register(shutdown_runtime)


def current_session_payload() -> dict[str, Any]:
    if "user_id" not in session:
        return {"authenticated": False, "username": None}
    return {
        "authenticated": True,
        "username": session.get("username"),
        "user_id": session.get("user_id"),
    }


def current_todos() -> list[dict[str, Any]]:
    user_id = session.get("user_id")
    if not user_id:
        return []
    return store.list_todos(user_id)


def json_payload() -> dict[str, Any]:
    if request.is_json:
        return request.get_json(silent=True) or {}
    return request.form.to_dict() or {}


def wants_json_response() -> bool:
    if request.path.startswith("/api/"):
        return True
    if request.is_json:
        return True
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return True

    accept = request.accept_mimetypes
    best = accept.best_match(["application/json", "text/html"])
    return best == "application/json" and accept[best] > accept["text/html"]


def todo_stats(todos: list[dict[str, Any]]) -> dict[str, int]:
    completed = sum(1 for todo in todos if todo.get("completed"))
    return {
        "total": len(todos),
        "completed": completed,
        "pending": len(todos) - completed,
    }


def report_summary(snapshot: dict[str, Any]) -> list[str]:
    metrics = snapshot["metrics"]
    lines = [
        f"Active threats currently visible: {metrics['active_threats']}.",
        f"Blocked IPs right now: {metrics['blocked_ips']}.",
        f"Rate-limited attackers: {metrics['rate_limited']}.",
        f"Current request rate: {metrics['request_rate']} req/sec.",
        f"Failed logins in the active window: {metrics['failed_logins']}.",
    ]
    return lines


def require_authentication() -> tuple[dict[str, Any], int] | None:
    if "user_id" in session:
        return None
    g.ids_context = {
        "detail": "Unauthenticated access attempt against the Todo API.",
        "success": False,
    }
    return {"ok": False, "message": "Please log in first."}, 401


def start_attack(profile: str, source_ip: str | None = None) -> dict[str, Any]:
    ip_address = source_ip or {
        "bruteforce": "185.234.219.12",
        "ddos": "198.51.100.24",
        "both": "203.0.113.90",
    }[profile]
    base_url = request.host_url.rstrip("/")

    threading.Thread(
        target=launch_profile,
        args=(profile, base_url, ip_address),
        daemon=True,
    ).start()

    return {"ok": True, "message": f"{profile.upper()} simulation launched.", "ip": ip_address}


@app.before_request
def enforce_active_mitigations() -> tuple[Any, int] | None:
    g.track_request = should_track(request.path)
    g.request_started = time.perf_counter()
    g.ids_context = {}

    if not g.track_request:
        return None

    ip = client_ip_from_request()
    mitigation = engine.peek_mitigation(ip)
    if mitigation is None:
        return None

    g.ids_context = {
        "blocked": True,
        "attack_hint": mitigation["reason"],
        "detail": "Request stopped by active IDS mitigation policy.",
        "success": False,
        "mitigation_context": mitigation,
    }
    status_code = 403 if mitigation["mode"] == "blocked" else 429
    return (
        jsonify(
            {
                "ok": False,
                "message": "IDS mitigation is active for this IP address.",
                "mitigation": mitigation,
            }
        ),
        status_code,
    )


@app.after_request
def record_traffic(response: Any) -> Any:
    if not getattr(g, "track_request", False):
        return response

    elapsed_ms = (time.perf_counter() - getattr(g, "request_started", time.perf_counter())) * 1000
    context = getattr(g, "ids_context", {})

    result = engine.ingest_event(
        ip=client_ip_from_request(),
        endpoint=request.path,
        method=request.method,
        status_code=response.status_code,
        username=context.get("username"),
        success=context.get("success"),
        blocked=context.get("blocked", False),
        synthetic=request.headers.get("X-Simulated-Attack") == "1",
        detail=context.get("detail", ""),
        attack_hint=context.get("attack_hint"),
        mitigation_context=context.get("mitigation_context"),
        latency_ms=elapsed_ms,
    )
    enqueue_ids_result(result)
    return response


@app.get("/")
def home_page() -> str:
    snapshot = engine.snapshot()
    return render_template(
        "home.html",
        ids=snapshot,
        summary_lines=report_summary(snapshot),
        demo_credentials=demo_credentials,
        storage_status=store.status(),
        session_payload=current_session_payload(),
    )


@app.get("/todo")
def todo_page() -> str:
    todos = current_todos()
    return render_template(
        "todo.html",
        demo_credentials=demo_credentials,
        storage_status=store.status(),
        session_payload=current_session_payload(),
        todos=todos,
        stats=todo_stats(todos),
    )


@app.get("/monitor")
def monitor_page() -> str:
    return render_template(
        "monitor.html",
        storage_status=store.status(),
        ids=engine.snapshot(),
        session_payload=current_session_payload(),
    )


@app.get("/reports")
def reports_page() -> str:
    snapshot = engine.snapshot()
    return render_template(
        "report.html",
        storage_status=store.status(),
        ids=snapshot,
        summary_lines=report_summary(snapshot),
        session_payload=current_session_payload(),
    )


@app.get("/lab")
def lab_page() -> str:
    return render_template(
        "index.html",
        demo_credentials=demo_credentials,
        storage_status=store.status(),
    )


@app.get("/api/state")
def api_state() -> Any:
    session_payload = current_session_payload()
    return jsonify(
        {
            "storage": store.status(),
            "session": session_payload,
            "todos": current_todos() if session_payload["authenticated"] else [],
            "demo_credentials": demo_credentials,
            "ids": engine.snapshot(),
        }
    )


@app.get("/api/public/feed")
def public_feed() -> Any:
    ids_snapshot = engine.snapshot()
    return jsonify(
        {
            "service": "todo-public-feed",
            "status": "green",
            "request_rate": ids_snapshot["metrics"]["request_rate"],
            "active_threats": ids_snapshot["metrics"]["active_threats"],
            "blocked_ips": ids_snapshot["metrics"]["blocked_ips"],
        }
    )


@app.post("/auth/register")
def register() -> Any:
    data = json_payload()
    username = data.get("username", "").strip().lower()
    password = data.get("password", "").strip()

    if len(username) < 3 or len(password) < 6:
        g.ids_context = {
            "username": username or None,
            "success": False,
            "detail": "Registration rejected because the submitted credentials were too short.",
        }
        message = "Username must be 3+ chars and password 6+ chars."
        if wants_json_response():
            return jsonify({"ok": False, "message": message}), 400
        flash(message, "danger")
        return redirect(url_for("todo_page"))

    if store.get_user_by_username(username) is not None:
        g.ids_context = {
            "username": username,
            "success": False,
            "detail": "Registration failed because the username already exists.",
        }
        message = "Username already exists."
        if wants_json_response():
            return jsonify({"ok": False, "message": message}), 409
        flash(message, "warning")
        return redirect(url_for("todo_page"))

    user = store.create_user(username, generate_password_hash(password))
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    g.ids_context = {
        "username": username,
        "success": True,
        "detail": "New Todo user registered successfully.",
    }
    if wants_json_response():
        return jsonify({"ok": True, "message": "Account created.", "session": current_session_payload()})
    flash("Account created. You are now logged in.", "success")
    return redirect(url_for("todo_page"))


@app.post("/auth/login")
def login() -> Any:
    data = json_payload()
    username = data.get("username", "").strip().lower()
    password = data.get("password", "").strip()

    user = store.get_user_by_username(username)
    if user is None or not check_password_hash(user["password_hash"], password):
        g.ids_context = {
            "username": username or None,
            "success": False,
            "detail": "Invalid password submitted to the login endpoint.",
        }
        message = "Invalid username or password."
        if wants_json_response():
            return jsonify({"ok": False, "message": message}), 401
        flash(message, "danger")
        return redirect(url_for("todo_page"))

    session["user_id"] = user["id"]
    session["username"] = user["username"]
    g.ids_context = {
        "username": username,
        "success": True,
        "detail": "Interactive operator login accepted.",
    }
    if wants_json_response():
        return jsonify({"ok": True, "message": "Logged in.", "session": current_session_payload()})
    flash("Logged in successfully.", "success")
    return redirect(url_for("todo_page"))


@app.post("/auth/logout")
def logout() -> Any:
    g.ids_context = {
        "username": session.get("username"),
        "success": True,
        "detail": "Operator logged out from the Todo workspace.",
    }
    session.clear()
    if wants_json_response():
        return jsonify({"ok": True, "message": "Logged out."})
    flash("Logged out.", "success")
    return redirect(url_for("todo_page"))


@app.get("/api/todos")
def list_todos() -> Any:
    auth_error = require_authentication()
    if auth_error is not None:
        payload, status = auth_error
        return jsonify(payload), status
    return jsonify({"ok": True, "todos": current_todos()})


@app.post("/api/todos")
def create_todo() -> Any:
    auth_error = require_authentication()
    if auth_error is not None:
        payload, status = auth_error
        return jsonify(payload), status

    task = json_payload().get("task", "").strip()
    if len(task) < 3:
        g.ids_context = {
            "username": session.get("username"),
            "success": False,
            "detail": "Todo creation failed because the task text was too short.",
        }
        return jsonify({"ok": False, "message": "Task must be at least 3 characters."}), 400

    todo = store.create_todo(session["user_id"], task)
    g.ids_context = {
        "username": session.get("username"),
        "success": True,
        "detail": "Todo item created successfully.",
    }
    return jsonify({"ok": True, "todo": todo})


@app.patch("/api/todos/<todo_id>")
def update_todo(todo_id: str) -> Any:
    auth_error = require_authentication()
    if auth_error is not None:
        payload, status = auth_error
        return jsonify(payload), status

    data = json_payload()
    fields: dict[str, Any] = {}
    if "completed" in data:
        fields["completed"] = bool(data["completed"])
    if "task" in data:
        task = str(data["task"]).strip()
        if len(task) < 3:
            g.ids_context = {
                "username": session.get("username"),
                "success": False,
                "detail": "Todo update failed because the task text was too short.",
            }
            return jsonify({"ok": False, "message": "Task must be at least 3 characters."}), 400
        fields["task"] = task

    todo = store.update_todo(todo_id, fields)
    if todo is None:
        return jsonify({"ok": False, "message": "Todo not found."}), 404

    g.ids_context = {
        "username": session.get("username"),
        "success": True,
        "detail": "Todo item updated successfully.",
    }
    return jsonify({"ok": True, "todo": todo})


@app.delete("/api/todos/<todo_id>")
def delete_todo(todo_id: str) -> Any:
    auth_error = require_authentication()
    if auth_error is not None:
        payload, status = auth_error
        return jsonify(payload), status

    deleted = store.delete_todo(todo_id)
    if not deleted:
        return jsonify({"ok": False, "message": "Todo not found."}), 404

    g.ids_context = {
        "username": session.get("username"),
        "success": True,
        "detail": "Todo item deleted successfully.",
    }
    return jsonify({"ok": True, "message": "Todo removed."})


@app.post("/todo/create")
def create_todo_form() -> Any:
    if "user_id" not in session:
        g.ids_context = {
            "detail": "Unauthenticated form submission targeted Todo creation.",
            "success": False,
        }
        flash("Please log in before adding tasks.", "danger")
        return redirect(url_for("todo_page"))

    task = request.form.get("task", "").strip()
    if len(task) < 3:
        g.ids_context = {
            "username": session.get("username"),
            "success": False,
            "detail": "Todo creation failed because the task text was too short.",
        }
        flash("Task must be at least 3 characters.", "danger")
        return redirect(url_for("todo_page"))

    store.create_todo(session["user_id"], task)
    g.ids_context = {
        "username": session.get("username"),
        "success": True,
        "detail": "Todo item created from the HTML workflow.",
    }
    flash("Task added to the Todo board.", "success")
    return redirect(url_for("todo_page"))


@app.post("/todo/<todo_id>/toggle")
def toggle_todo_form(todo_id: str) -> Any:
    if "user_id" not in session:
        g.ids_context = {
            "detail": "Unauthenticated task status change attempt.",
            "success": False,
        }
        flash("Please log in before changing tasks.", "danger")
        return redirect(url_for("todo_page"))

    completed = request.form.get("completed", "0") == "1"
    todo = store.update_todo(todo_id, {"completed": completed})
    if todo is None:
        g.ids_context = {
            "username": session.get("username"),
            "success": False,
            "detail": "Task toggle failed because the task no longer existed.",
        }
        flash("Task not found.", "warning")
        return redirect(url_for("todo_page"))

    g.ids_context = {
        "username": session.get("username"),
        "success": True,
        "detail": "Todo item status updated from the HTML workflow.",
    }
    flash("Task status updated.", "success")
    return redirect(url_for("todo_page"))


@app.post("/todo/<todo_id>/delete")
def delete_todo_form(todo_id: str) -> Any:
    if "user_id" not in session:
        g.ids_context = {
            "detail": "Unauthenticated task deletion attempt.",
            "success": False,
        }
        flash("Please log in before deleting tasks.", "danger")
        return redirect(url_for("todo_page"))

    if not store.delete_todo(todo_id):
        g.ids_context = {
            "username": session.get("username"),
            "success": False,
            "detail": "Task deletion failed because the task was missing.",
        }
        flash("Task not found.", "warning")
        return redirect(url_for("todo_page"))

    g.ids_context = {
        "username": session.get("username"),
        "success": True,
        "detail": "Todo item deleted from the HTML workflow.",
    }
    flash("Task removed.", "success")
    return redirect(url_for("todo_page"))


@app.post("/actions/simulate/<profile>")
def simulate_action(profile: str) -> Any:
    if profile not in {"bruteforce", "ddos", "both"}:
        flash("Unknown attack profile.", "danger")
        return redirect(url_for("monitor_page"))

    payload = start_attack(profile)
    if wants_json_response():
        return jsonify(payload)
    flash(f"{payload['message']} Source IP: {payload['ip']}", "warning")
    return redirect(url_for("monitor_page"))


@app.post("/actions/reset-demo")
def reset_demo_action() -> Any:
    engine.reset()
    store.reset_ids_demo_data()
    ensure_demo_user()
    if wants_json_response():
        return jsonify({"ok": True, "message": "IDS alerts and telemetry were reset."})
    flash("IDS alerts and telemetry were reset.", "success")
    return redirect(url_for("monitor_page"))


@app.post("/api/simulate/bruteforce")
def simulate_bruteforce() -> Any:
    return jsonify(start_attack("bruteforce"))


@app.post("/api/simulate/ddos")
def simulate_ddos() -> Any:
    return jsonify(start_attack("ddos"))


@app.post("/api/simulate/both")
def simulate_both() -> Any:
    return jsonify(start_attack("both"))


@app.post("/api/reset-demo")
def reset_demo() -> Any:
    engine.reset()
    store.reset_ids_demo_data()
    ensure_demo_user()
    return jsonify({"ok": True, "message": "IDS alerts and telemetry were reset."})


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, threaded=True, debug=False)
