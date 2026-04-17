const monitorState = {
    filter: "all",
    refreshing: false,
};

async function fetchMonitorState() {
    if (monitorState.refreshing) return;
    monitorState.refreshing = true;
    try {
        const response = await fetch("/api/state", {
            headers: { Accept: "application/json" },
        });
        const payload = await response.json();
        renderMonitor(payload);
    } catch (error) {
        console.error("Monitor refresh failed", error);
    } finally {
        monitorState.refreshing = false;
    }
}

function renderMonitor(payload) {
    const ids = payload.ids;
    const metrics = ids.metrics;

    setText("metricActiveThreats", metrics.active_threats);
    setText("metricBlockedIps", metrics.blocked_ips);
    setText("metricRateLimited", metrics.rate_limited);
    setText("metricRequestRate", metrics.request_rate.toFixed(1));
    setText("metricFailedLogins", metrics.failed_logins);
    setText("metricStorageMode", payload.storage.mode.toUpperCase());

    const fill = document.getElementById("threatMeterFill");
    const label = document.getElementById("threatMeterValue");
    if (fill) fill.style.width = `${metrics.threat_level}%`;
    if (label) label.textContent = `${metrics.threat_level}%`;

    const topMitigation = ids.mitigations[0];
    setText(
        "mitigationHeadline",
        topMitigation ? `${topMitigation.mode.replace("_", " ").toUpperCase()} - ${topMitigation.ip}` : "Monitoring"
    );
    setText(
        "mitigationDetail",
        topMitigation
            ? `${humanize(topMitigation.reason)} mitigation expires in ${topMitigation.expires_in}s.`
            : "No active blocks yet."
    );

    renderDistribution(ids.attack_distribution);
    renderTerminal(ids.terminal_feed);
    renderOffenders(ids.top_offenders);
    renderEvents(ids.recent_events);
    drawTraffic(ids.traffic_series);
}

function setText(id, value) {
    const node = document.getElementById(id);
    if (node) node.textContent = value;
}

function renderDistribution(rows) {
    const container = document.getElementById("distributionBars");
    if (!container) return;

    container.innerHTML = rows
        .map(
            (row) => `
                <div class="distribution-row">
                    <div class="panel-split">
                        <strong>${humanize(row.attack_type)}</strong>
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
    if (!container) return;

    if (!lines.length) {
        container.innerHTML = `<div class="terminal-line">[idle] Awaiting telemetry.</div>`;
        return;
    }

    container.innerHTML = lines.map((line) => `<div class="terminal-line">${escapeHtml(line)}</div>`).join("");
}

function renderOffenders(rows) {
    const container = document.getElementById("offenderList");
    if (!container) return;

    if (!rows.length) {
        container.innerHTML = `<div class="offender-item"><span class="muted">No suspicious IPs yet.</span></div>`;
        return;
    }

    container.innerHTML = rows
        .map(
            (row) => `
                <div class="offender-item">
                    <div>
                        <strong>${row.ip}</strong>
                        <div class="muted">${row.country} · ${humanize(row.last_attack_type)}</div>
                    </div>
                    <span class="severity-pill severity-high">${row.hits} hits</span>
                </div>
            `
        )
        .join("");
}

function renderEvents(rows) {
    const container = document.getElementById("eventTable");
    if (!container) return;

    const filtered = rows.filter((row) => monitorState.filter === "all" || row.kind === monitorState.filter);
    if (!filtered.length) {
        container.innerHTML = `<div class="event-row"><span class="muted">No events match the current filter.</span></div>`;
        return;
    }

    container.innerHTML = filtered
        .map(
            (row) => `
                <div class="event-row">
                    <div>${row.time_label}</div>
                    <div><span class="event-kind kind-${row.kind}">${row.kind.toUpperCase()}</span></div>
                    <div>
                        <strong>${row.ip}</strong>
                        <div class="muted">${escapeHtml(row.endpoint)} · ${escapeHtml(row.detail)}</div>
                    </div>
                    <div><span class="severity-pill severity-${row.severity.toLowerCase()}">${row.severity}</span></div>
                    <div>${row.action}</div>
                </div>
            `
        )
        .join("");
}

function drawTraffic(series) {
    const canvas = document.getElementById("trafficChart");
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    const dpr = window.devicePixelRatio || 1;
    const width = Math.max(320, canvas.clientWidth) * dpr;
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

    ctx.strokeStyle = "rgba(20, 44, 56, 0.08)";
    ctx.lineWidth = 1;
    for (let index = 0; index < 5; index += 1) {
        const y = 20 + ((logicalHeight - 40) / 4) * index;
        ctx.beginPath();
        ctx.moveTo(14, y);
        ctx.lineTo(logicalWidth - 14, y);
        ctx.stroke();
    }

    const maxValue = Math.max(2, ...series.map((point) => Math.max(point.normal, point.attack)));
    const plotWidth = logicalWidth - 40;
    const step = plotWidth / Math.max(series.length - 1, 1);

    drawLine(ctx, series, { color: "#147d74", value: "normal", maxValue, height: logicalHeight, step });
    drawLine(ctx, series, { color: "#b2452d", value: "attack", maxValue, height: logicalHeight, step });

    ctx.fillStyle = "#147d74";
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

function humanize(value) {
    return String(value)
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

function bindFilters() {
    document.querySelectorAll(".filter-chip").forEach((chip) => {
        chip.addEventListener("click", () => {
            monitorState.filter = chip.dataset.filter;
            document.querySelectorAll(".filter-chip").forEach((item) => item.classList.remove("active"));
            chip.classList.add("active");
            fetchMonitorState();
        });
    });
}

bindFilters();
fetchMonitorState();
window.setInterval(fetchMonitorState, 2000);
window.addEventListener("resize", fetchMonitorState);
