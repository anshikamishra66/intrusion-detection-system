const state = {
    filter: "all",
    refreshInFlight: false,
};

function setBanner(message, tone = "neutral") {
    const banner = document.getElementById("statusBanner");
    banner.textContent = message;
    banner.className = "status-banner";
    if (tone === "warning") banner.classList.add("warning");
    if (tone === "danger") banner.classList.add("danger");
}

async function api(path, options = {}) {
    const response = await fetch(path, {
        headers: { "Content-Type": "application/json" },
        ...options,
    });

    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
        throw new Error(payload.message || "Request failed.");
    }
    return payload;
}

async function refreshState() {
    if (state.refreshInFlight) return;
    state.refreshInFlight = true;
    try {
        const payload = await api("/api/state");
        renderApp(payload);
    } catch (error) {
        setBanner(error.message, "danger");
    } finally {
        state.refreshInFlight = false;
    }
}

function renderApp(payload) {
    renderStorage(payload.storage);
    renderSession(payload.session, payload.demo_credentials);
    renderTodos(payload.todos || []);
    renderIDS(payload.ids);
}

function renderStorage(storage) {
    document.getElementById("storageModeBadge").textContent = storage.mode.toUpperCase();
    document.getElementById("metricStorageMode").textContent = storage.mode.toUpperCase();
    document.getElementById("storageHeadline").textContent = storage.mode === "supabase" ? "Supabase Connected" : "Local Fallback Active";
    document.getElementById("storageDetail").textContent = storage.detail || "Monitoring database connection.";
}

function renderSession(sessionPayload, demoCredentials) {
    const authCard = document.getElementById("authCard");
    const todoCard = document.getElementById("todoCard");
    const sessionBadge = document.getElementById("sessionBadge");

    if (sessionPayload.authenticated) {
        authCard.classList.add("hidden");
        todoCard.classList.remove("hidden");
        sessionBadge.textContent = `${sessionPayload.username} active`;
    } else {
        authCard.classList.remove("hidden");
        todoCard.classList.add("hidden");
        sessionBadge.textContent = "Guest session";
        document.getElementById("usernameInput").placeholder = demoCredentials.username;
        document.getElementById("passwordInput").placeholder = demoCredentials.password;
    }
}

function renderTodos(todos) {
    const todoSummary = document.getElementById("todoSummary");
    const todoList = document.getElementById("todoList");

    if (!Array.isArray(todos) || todos.length === 0) {
        todoSummary.textContent = "0 tasks tracked.";
        todoList.innerHTML = `<div class="todo-item"><span class="muted">No tasks yet. Add one to create normal app traffic.</span></div>`;
        return;
    }

    const completed = todos.filter((todo) => todo.completed).length;
    todoSummary.textContent = `${todos.length} tasks tracked, ${completed} completed.`;
    todoList.innerHTML = todos
        .map((todo) => {
            const doneClass = todo.completed ? "done" : "";
            return `
                <article class="todo-item ${doneClass}">
                    <input type="checkbox" data-action="toggle-todo" data-id="${todo.id}" ${todo.completed ? "checked" : ""}>
                    <div>
                        <div class="todo-text">${escapeHtml(todo.task)}</div>
                        <div class="muted">${new Date(todo.created_at).toLocaleString()}</div>
                    </div>
                    <div class="todo-actions">
                        <button class="mini-button" data-action="delete-todo" data-id="${todo.id}">Delete</button>
                    </div>
                </article>
            `;
        })
        .join("");
}

function renderIDS(ids) {
    const metrics = ids.metrics;
    document.getElementById("metricActiveThreats").textContent = metrics.active_threats;
    document.getElementById("metricBlockedIps").textContent = metrics.blocked_ips;
    document.getElementById("metricRateLimited").textContent = metrics.rate_limited;
    document.getElementById("metricRequestRate").textContent = metrics.request_rate.toFixed(1);
    document.getElementById("metricFailedLogins").textContent = metrics.failed_logins;
    document.getElementById("threatMeterFill").style.width = `${metrics.threat_level}%`;
    document.getElementById("threatMeterValue").textContent = `${metrics.threat_level}%`;

    const topMitigation = ids.mitigations[0];
    document.getElementById("mitigationHeadline").textContent = topMitigation
        ? `${topMitigation.mode.replace("_", " ").toUpperCase()} - ${topMitigation.ip}`
        : "Monitoring";
    document.getElementById("mitigationDetail").textContent = topMitigation
        ? `${topMitigation.reason} expires in ${topMitigation.expires_in}s.`
        : "No active blocks yet.";

    renderDistribution(ids.attack_distribution);
    renderTerminal(ids.terminal_feed);
    renderOffenders(ids.top_offenders);
    renderEvents(ids.recent_events);
    drawTraffic(ids.traffic_series);
}

function renderDistribution(rows) {
    const container = document.getElementById("distributionBars");
    container.innerHTML = rows
        .map(
            (row) => `
                <div class="distribution-row">
                    <div class="panel-split">
                        <strong>${humanizeAttack(row.attack_type)}</strong>
                        <span>${row.percentage}%</span>
                    </div>
                    <div class="distribution-track">
                        <div class="distribution-fill" style="width: ${row.percentage}%"></div>
                    </div>
                </div>
            `
        )
        .join("");
}

function renderTerminal(lines) {
    const container = document.getElementById("terminalFeed");
    if (!lines.length) {
        container.innerHTML = `<div class="terminal-line">[idle] Awaiting new telemetry from the monitor.</div>`;
        return;
    }
    container.innerHTML = lines
        .map((line) => `<div class="terminal-line">${escapeHtml(line)}</div>`)
        .join("");
}

function renderOffenders(offenders) {
    const container = document.getElementById("offenderList");
    if (!offenders.length) {
        container.innerHTML = `<div class="offender-item"><span class="muted">No suspicious IPs yet.</span></div>`;
        return;
    }

    container.innerHTML = offenders
        .map(
            (item) => `
                <div class="offender-item">
                    <div>
                        <strong>${item.ip}</strong>
                        <div class="muted">${item.country} · ${humanizeAttack(item.last_attack_type)}</div>
                    </div>
                    <span class="severity-pill severity-high">${item.hits} hits</span>
                </div>
            `
        )
        .join("");
}

function renderEvents(events) {
    const container = document.getElementById("eventTable");
    const filtered = events.filter((event) => state.filter === "all" || event.kind === state.filter);

    if (!filtered.length) {
        container.innerHTML = `<div class="event-row"><span class="muted">No events match the current filter.</span></div>`;
        return;
    }

    container.innerHTML = filtered
        .map(
            (event) => `
                <div class="event-row">
                    <div>${event.time_label}</div>
                    <div><span class="event-kind kind-${event.kind}">${event.kind.toUpperCase()}</span></div>
                    <div>
                        <strong>${event.ip}</strong>
                        <div class="muted">${escapeHtml(event.endpoint)} · ${escapeHtml(event.detail)}</div>
                    </div>
                    <div><span class="severity-pill severity-${event.severity.toLowerCase()}">${event.severity}</span></div>
                    <div>${event.action}</div>
                </div>
            `
        )
        .join("");
}

function drawTraffic(series) {
    const canvas = document.getElementById("trafficChart");
    const ctx = canvas.getContext("2d");
    const dpr = window.devicePixelRatio || 1;
    const width = canvas.clientWidth * dpr;
    const height = 260 * dpr;

    if (canvas.width !== width || canvas.height !== height) {
        canvas.width = width;
        canvas.height = height;
    }

    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.clearRect(0, 0, width, height);
    ctx.scale(dpr, dpr);

    const logicalWidth = canvas.width / dpr;
    const logicalHeight = canvas.height / dpr;

    ctx.clearRect(0, 0, logicalWidth, logicalHeight);
    ctx.strokeStyle = "rgba(20, 44, 56, 0.08)";
    ctx.lineWidth = 1;
    for (let index = 0; index < 5; index += 1) {
        const y = 20 + ((logicalHeight - 40) / 4) * index;
        ctx.beginPath();
        ctx.moveTo(14, y);
        ctx.lineTo(logicalWidth - 14, y);
        ctx.stroke();
    }

    const maxValue = Math.max(
        2,
        ...series.map((point) => Math.max(point.normal, point.attack))
    );
    const plotWidth = logicalWidth - 40;
    const step = plotWidth / Math.max(series.length - 1, 1);

    drawLine(ctx, series, {
        color: "#147d74",
        value: "normal",
        maxValue,
        height: logicalHeight,
        step,
    });

    drawLine(ctx, series, {
        color: "#b2452d",
        value: "attack",
        maxValue,
        height: logicalHeight,
        step,
    });

    ctx.fillStyle = "#5c6b74";
    ctx.font = '12px "Trebuchet MS", sans-serif';
    ctx.fillText("Normal", 16, 18);
    ctx.fillStyle = "#b2452d";
    ctx.fillText("Threat", 80, 18);
}

function drawLine(ctx, series, options) {
    ctx.beginPath();
    ctx.strokeStyle = options.color;
    ctx.lineWidth = 3;

    series.forEach((point, index) => {
        const x = 20 + index * options.step;
        const y = options.height - 24 - ((point[options.value] / options.maxValue) * (options.height - 56));
        if (index === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    });

    ctx.stroke();
}

function humanizeAttack(value) {
    return value
        .replaceAll("_", " ")
        .replace(/\b\w/g, (char) => char.toUpperCase());
}

function escapeHtml(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
}

async function submitAuth(mode) {
    const username = document.getElementById("usernameInput").value.trim();
    const password = document.getElementById("passwordInput").value.trim();
    try {
        const payload = await api(`/auth/${mode}`, {
            method: "POST",
            body: JSON.stringify({ username, password }),
        });
        setBanner(payload.message);
        document.getElementById("passwordInput").value = "";
        await refreshState();
    } catch (error) {
        setBanner(error.message, "danger");
    }
}

async function logout() {
    try {
        const payload = await api("/auth/logout", { method: "POST" });
        setBanner(payload.message);
        await refreshState();
    } catch (error) {
        setBanner(error.message, "danger");
    }
}

async function addTodo(event) {
    event.preventDefault();
    const task = document.getElementById("todoInput").value.trim();
    if (!task) return;
    try {
        const payload = await api("/api/todos", {
            method: "POST",
            body: JSON.stringify({ task }),
        });
        document.getElementById("todoInput").value = "";
        setBanner(payload.todo ? "Todo created and logged as safe traffic." : payload.message);
        await refreshState();
    } catch (error) {
        setBanner(error.message, "danger");
    }
}

async function toggleTodo(id, completed) {
    try {
        await api(`/api/todos/${id}`, {
            method: "PATCH",
            body: JSON.stringify({ completed }),
        });
        await refreshState();
    } catch (error) {
        setBanner(error.message, "danger");
    }
}

async function deleteTodo(id) {
    try {
        await api(`/api/todos/${id}`, { method: "DELETE" });
        setBanner("Todo removed.");
        await refreshState();
    } catch (error) {
        setBanner(error.message, "danger");
    }
}

async function runAttack(kind) {
    try {
        const payload = await api(`/api/simulate/${kind}`, { method: "POST" });
        setBanner(`${payload.message} Source IP: ${payload.ip}`, "warning");
        await refreshState();
    } catch (error) {
        setBanner(error.message, "danger");
    }
}

async function resetDemo() {
    try {
        const payload = await api("/api/reset-demo", { method: "POST" });
        setBanner(payload.message);
        await refreshState();
    } catch (error) {
        setBanner(error.message, "danger");
    }
}

function bindEvents() {
    document.getElementById("loginButton").addEventListener("click", () => submitAuth("login"));
    document.getElementById("registerButton").addEventListener("click", () => submitAuth("register"));
    document.getElementById("logoutButton").addEventListener("click", logout);
    document.getElementById("todoForm").addEventListener("submit", addTodo);
    document.getElementById("resetDemoButton").addEventListener("click", resetDemo);

    document.querySelectorAll("[data-attack]").forEach((button) => {
        button.addEventListener("click", () => runAttack(button.dataset.attack));
    });

    document.querySelectorAll(".filter-chip").forEach((chip) => {
        chip.addEventListener("click", () => {
            state.filter = chip.dataset.filter;
            document.querySelectorAll(".filter-chip").forEach((item) => item.classList.remove("active"));
            chip.classList.add("active");
            refreshState();
        });
    });

    document.getElementById("todoList").addEventListener("click", (event) => {
        const target = event.target;
        if (!(target instanceof HTMLElement)) return;
        if (target.dataset.action === "delete-todo") {
            deleteTodo(target.dataset.id);
        }
    });

    document.getElementById("todoList").addEventListener("change", (event) => {
        const target = event.target;
        if (!(target instanceof HTMLInputElement)) return;
        if (target.dataset.action === "toggle-todo") {
            toggleTodo(target.dataset.id, target.checked);
        }
    });

    window.addEventListener("resize", refreshState);
}

bindEvents();
refreshState();
window.setInterval(refreshState, 2000);
