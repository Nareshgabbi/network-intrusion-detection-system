const byId = (id) => document.getElementById(id);
let currentMonitoringStatus = "stopped";
let monitoringActionInProgress = false;

function setText(id, value) {
    byId(id).textContent = value === null || value === undefined || value === "" ? "N/A" : String(value);
}

function renderStatus(status) {
    const isRunning = status === "running";
    currentMonitoringStatus = isRunning ? "running" : "stopped";
    setText("nids-status", isRunning ? "MONITORING ACTIVE" : "MONITORING STOPPED");
    byId("status-dot").className = `status-dot ${isRunning ? "running" : "stopped"}`;
    byId("start-monitoring").disabled = monitoringActionInProgress || isRunning;
    byId("stop-monitoring").disabled = monitoringActionInProgress || !isRunning;
    byId("clear-session").disabled = monitoringActionInProgress || isRunning;
}

async function clearSession() {
    if (currentMonitoringStatus !== "stopped" || monitoringActionInProgress) {
        return;
    }
    if (!window.confirm("Are you sure you want to clear the current session data and logs? This cannot be undone.")) {
        return;
    }

    monitoringActionInProgress = true;
    byId("start-monitoring").disabled = true;
    byId("stop-monitoring").disabled = true;
    byId("clear-session").disabled = true;
    const message = byId("monitor-action-message");
    message.textContent = "";

    try {
        const response = await fetch("/api/clear", {
            method: "POST",
            headers: { "Accept": "application/json" },
            cache: "no-store"
        });
        const result = await response.json();
        message.textContent = result.message || "Session data clear completed.";
        message.classList.toggle("control-error", !response.ok);
    } catch (error) {
        message.textContent = "Unable to contact the NIDS monitoring API.";
        message.classList.add("control-error");
    } finally {
        monitoringActionInProgress = false;
        renderStatus(currentMonitoringStatus);
        await refreshDashboard();
    }
}

async function refreshDashboard() {
    try {
        const [statusResponse, statisticsResponse, alertsResponse] = await Promise.all([
            fetch("/api/status", { cache: "no-store" }),
            fetch("/api/statistics", { cache: "no-store" }),
            fetch("/api/alerts", { cache: "no-store" })
        ]);
        if (!statusResponse.ok || !statisticsResponse.ok || !alertsResponse.ok) {
            throw new Error("Dashboard data is unavailable.");
        }

        const [status, statistics, alertData] = await Promise.all([
            statusResponse.json(),
            statisticsResponse.json(),
            alertsResponse.json()
        ]);

        if (!Array.isArray(alertData.alerts)) {
            throw new Error("Dashboard alert data is unavailable.");
        }

        renderDashboard(status, statistics, alertData.alerts);
    } catch (error) {
        showError();
    }
}

function renderDashboard(status, statistics, alerts) {
    const currentStatus = typeof status.status === "string" ? status.status : "stopped";
    renderStatus(currentStatus);
    if (typeof status.error === "string" && status.error) {
        byId("monitor-action-message").textContent = status.error;
        byId("monitor-action-message").classList.add("control-error");
    }

    ["packets", "detections", "low", "medium", "high", "port-scans", "dos-alerts", "logged-detections", "log-file"]
        .forEach((id) => {
            const key = id === "port-scans" ? "port_scans"
                : id === "dos-alerts" ? "dos_alerts"
                    : id === "logged-detections" ? "logged_detections"
                        : id.replace("-", "_");
            setText(id, statistics[key] ?? 0);
        });

    renderAlerts(alerts);
    byId("api-error").hidden = true;
}

async function sendMonitoringAction(action) {
    const startButton = byId("start-monitoring");
    const stopButton = byId("stop-monitoring");
    const message = byId("monitor-action-message");
    monitoringActionInProgress = true;
    startButton.disabled = true;
    stopButton.disabled = true;
    message.textContent = "";

    try {
        const response = await fetch(`/api/${action}`, {
            method: "POST",
            headers: { "Accept": "application/json" },
            cache: "no-store"
        });
        const result = await response.json();
        message.textContent = result.message || "NIDS monitoring action completed.";
        message.classList.toggle("control-error", !response.ok);
        if (typeof result.status === "string") {
            renderStatus(result.status);
        }
    } catch (error) {
        message.textContent = "Unable to contact the NIDS monitoring API.";
        message.classList.add("control-error");
    } finally {
        monitoringActionInProgress = false;
        renderStatus(currentMonitoringStatus);
        await refreshDashboard();
    }
}

function showError() {
    byId("api-error").hidden = false;
    if (byId("alerts-body").textContent.includes("Loading alerts")) {
        showEmptyState("Unable to retrieve NIDS data.");
    }
}

function renderAlerts(alerts) {
    const body = byId("alerts-body");
    body.replaceChildren();
    if (!alerts.length) {
        showEmptyState("No alerts detected");
        return;
    }

    for (const alert of alerts) {
        const row = document.createElement("tr");
        const time = alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : "N/A";
        const severity = alert.severity || "N/A";
        const values = [
            time,
            alert.type,
            severity,
            alert.source_ip,
            alert.destination_ip,
            alert.message
        ];
        values.forEach((value, index) => {
            const cell = document.createElement("td");
            cell.textContent = value ?? "N/A";
            if (index === 2) {
                const tag = document.createElement("span");
                tag.className = `severity-tag ${String(severity).toLowerCase()}`;
                tag.textContent = severity;
                cell.replaceChildren(tag);
            }
            row.appendChild(cell);
        });
        body.appendChild(row);
    }
}

function showEmptyState(message) {
    const body = byId("alerts-body");
    body.replaceChildren();
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 6;
    cell.className = "empty-state";
    cell.textContent = message;
    row.appendChild(cell);
    body.appendChild(row);
}

byId("start-monitoring").addEventListener("click", () => sendMonitoringAction("start"));
byId("stop-monitoring").addEventListener("click", () => sendMonitoringAction("stop"));
byId("clear-session").addEventListener("click", clearSession);
refreshDashboard();
window.setInterval(refreshDashboard, 3000);
