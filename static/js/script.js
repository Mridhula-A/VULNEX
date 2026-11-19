
/* ==========================================================
   VULNEX - SECURITY INTELLIGENCE CENTER
   FRONTEND APPLICATION CONTROLLER
   STAGE 4.4 - REPORT PREVIEW INTEGRATION
========================================================== */

const API = {
    health: "/api/health",
    dashboard: "/api/dashboard",
    scan: "/api/scan",
    history: "/api/history",
    reports: "/api/reports",
    preview: "/api/reports/preview"
};

let currentJobId = null;
let currentScanTarget = null;
let latestScanId = null;
let currentPreviewScanId = null;

let pollingTimer = null;
let isPolling = false;

let riskChart = null;
let activityChart = null;


/* ================= UTILITIES ================= */

const $ = id => document.getElementById(id);

function setText(id, value) {
    const element = $(id);
    if (element) element.textContent = value ?? "";
}

function escapeHTML(value) {
    return String(value ?? "").replace(/[&<>"']/g, char => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
    })[char]);
}

async function apiRequest(url, options = {}) {
    const response = await fetch(url, {
        ...options,
        headers: {
            ...(options.body ? {
                "Content-Type": "application/json"
            } : {}),
            ...(options.headers || {})
        }
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
        throw new Error(
            data.error ||
            data.message ||
            `Request failed (${response.status})`
        );
    }

    return data;
}


/* ================= CLOCK ================= */

function updateClock() {
    setText(
        "systemClock",
        new Date().toLocaleTimeString("en-IN", {
            hour12: false
        })
    );
}

updateClock();
setInterval(updateClock, 1000);

setText("footerYear", new Date().getFullYear());


/* ================= NAVIGATION ================= */

function showPage(page) {
    document.querySelectorAll(".page-section").forEach(section => {
        section.classList.remove("active");
    });

    document.querySelectorAll(".nav-item").forEach(button => {
        button.classList.remove("active");
    });

    const section = $(`page-${page}`);

    const button = document.querySelector(
        `.nav-item[data-page="${page}"]`
    );

    if (!section || !button) return;

    section.classList.add("active");
    button.classList.add("active");

    if (page === "history") {
        loadHistory();
    }

    if (page === "cve") {
        copyCveResultsToIntelligence();
    }

    if (page === "reports") {
        updateReportAvailability();
    }
}

document.querySelectorAll(".nav-item").forEach(button => {
    button.addEventListener("click", () => {
        showPage(button.dataset.page);
    });
});

document.querySelectorAll("[data-go]").forEach(button => {
    button.addEventListener("click", () => {
        showPage(button.dataset.go);
    });
});


/* ================= BACKEND STATUS ================= */

async function checkBackend() {
    try {
        const data = await apiRequest(API.health);

        setText("engineStatus", "SECURITY ENGINE ONLINE");
        setText("settingsBackend", "CONNECTED");

        const dot = document.querySelector(".live-dot");

        if (dot) {
            dot.style.background = "var(--green)";
        }

        return data;

    } catch (error) {
        setText("engineStatus", "ENGINE OFFLINE");
        setText("settingsBackend", "DISCONNECTED");

        const dot = document.querySelector(".live-dot");

        if (dot) {
            dot.style.background = "var(--red)";
        }

        console.error("Backend connection:", error.message);

        return null;
    }
}


/* ================= CHARTS ================= */

function createRiskChart() {
    const canvas = $("riskChart");

    if (!canvas || typeof Chart === "undefined") return;

    riskChart = new Chart(canvas, {
        type: "doughnut",

        data: {
            labels: ["Critical", "High", "Medium", "Low"],

            datasets: [{
                data: [0, 0, 0, 0],

                backgroundColor: [
                    "#FF647C",
                    "#FFAC67",
                    "#F2D078",
                    "#4ED6A0"
                ],

                borderColor: "#171321",
                borderWidth: 5,
                hoverOffset: 5
            }]
        },

        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: "76%",

            plugins: {
                legend: {
                    display: false
                }
            }
        }
    });
}


function createActivityChart() {
    const canvas = $("activityChart");

    if (!canvas || typeof Chart === "undefined") return;

    activityChart = new Chart(canvas, {
        type: "line",

        data: {
            labels: [
                "Day 1", "Day 2", "Day 3", "Day 4",
                "Day 5", "Day 6", "Day 7"
            ],

            datasets: [{
                label: "Completed scans",
                data: [0, 0, 0, 0, 0, 0, 0],

                borderColor: "#A970F0",
                backgroundColor: "rgba(169,112,240,.10)",

                fill: true,
                tension: .4,

                pointRadius: 3,
                pointBackgroundColor: "#C49AFF"
            }]
        },

        options: {
            responsive: true,
            maintainAspectRatio: false,

            plugins: {
                legend: {
                    display: false
                }
            },

            scales: {
                x: {
                    grid: {
                        color: "rgba(255,255,255,.035)"
                    },

                    ticks: {
                        color: "#8E849D",
                        font: {
                            size: 10
                        }
                    }
                },

                y: {
                    beginAtZero: true,

                    ticks: {
                        precision: 0,
                        color: "#8E849D",
                        font: {
                            size: 10
                        }
                    },

                    grid: {
                        color: "rgba(255,255,255,.06)"
                    }
                }
            }
        }
    });
}


function updateRiskChart(summary = {}) {
    const values = [
        Number(summary.Critical || 0),
        Number(summary.High || 0),
        Number(summary.Medium || 0),
        Number(summary.Low || 0)
    ];

    if (riskChart) {
        riskChart.data.datasets[0].data = values;
        riskChart.update();
    }

    setText("criticalLegend", values[0]);
    setText("highLegend", values[1]);
    setText("mediumLegend", values[2]);
    setText("lowLegend", values[3]);

    setText(
        "totalCves",
        values.reduce((a, b) => a + b, 0)
    );
}


/* ================= DASHBOARD ================= */

async function loadDashboard() {
    try {
        const data = await apiRequest(API.dashboard);

        setText("totalScans", data.total_scans ?? 0);
        setText("openPorts", data.open_ports ?? 0);
        setText("criticalRisks", data.critical_risks ?? 0);
        setText("highRisks", data.high_risks ?? 0);

        updateRiskChart(data.severity_summary || {});

        renderRecentActivity(data.recent_scans || []);

        if (activityChart && Array.isArray(data.activity)) {
            activityChart.data.labels = data.activity.map(
                item => item.date
            );

            activityChart.data.datasets[0].data =
                data.activity.map(item => Number(item.count || 0));

            activityChart.update();
        }

    } catch (error) {
        console.warn("Dashboard API:", error.message);
    }
}


function renderRecentActivity(records) {
    const tbody = $("recentActivity");

    if (!tbody) return;

    if (!records.length) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" class="empty-cell">
                    No scan activity recorded yet.
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = records.map(record => `
        <tr>
            <td>${escapeHTML(record.id)}</td>
            <td>${escapeHTML(record.scanned_at || "-")}</td>
            <td>${escapeHTML(record.target)}</td>
            <td>${escapeHTML(record.open_ports)}</td>
            <td>${escapeHTML(record.cve_count)}</td>
            <td>
                <button type="button"
                        class="vulnex-preview-button"
                        data-preview="${escapeHTML(record.id)}">
                    Preview
                </button>
            </td>
        </tr>
    `).join("");
}


/* ================= SCAN MESSAGES ================= */

function showScanMessage(message, type = "") {
    const element = $("scanMessage");

    if (!element) return;

    element.textContent = message;
    element.className = `scan-message ${type}`;
}


function setScanProgress(percent, message) {
    const progress = Math.max(
        0,
        Math.min(100, Number(percent) || 0)
    );

    $("scanProgress")?.classList.add("visible");

    setText("progressPercent", `${progress}%`);

    setText(
        "progressMessage",
        message || "Scanning..."
    );

    const fill = $("progressFill");

    if (fill) {
        fill.style.width = `${progress}%`;
    }
}


function setScanControls(disabled) {
    [
        "launchButton",
        "targetInput",
        "portsInput",
        "useNmap",
        "useScapy",
        "useCve"
    ].forEach(id => {
        if ($(id)) {
            $(id).disabled = disabled;
        }
    });
}


/* ================= SCAN SUBMISSION ================= */

$("scanForm")?.addEventListener("submit", async event => {
    event.preventDefault();

    if (!$("authorized").checked) {
        showScanMessage(
            "Please confirm that you are authorized to scan this target.",
            "error"
        );
        return;
    }

    const target = $("targetInput").value.trim();
    const ports = $("portsInput").value.trim();

    if (!target || !ports) {
        showScanMessage(
            "Enter a target and port configuration.",
            "error"
        );
        return;
    }

    const payload = {
        target,
        ports,
        use_nmap: $("useNmap").checked,
        use_scapy: $("useScapy").checked,
        use_cve: $("useCve").checked,
        authorized: true
    };

    setScanControls(true);

    setScanProgress(0, "Submitting scan request...");

    showScanMessage(
        "Connecting to VULNEX scanning engine..."
    );

    currentScanTarget = target;
    currentJobId = null;

    try {
        const result = await apiRequest(API.scan, {
            method: "POST",
            body: JSON.stringify(payload)
        });

        currentJobId = result.job_id || result.id;

        if (!currentJobId) {
            throw new Error(
                "The backend did not return a scan job ID."
            );
        }

        showScanMessage(
            "Scan accepted. Monitoring scan progress..."
        );

        setScanProgress(1, "Scan accepted");

        startPolling();

    } catch (error) {
        setScanControls(false);

        $("scanProgress")?.classList.remove("visible");

        showScanMessage(error.message, "error");
    }
});


/* ================= SCAN PROGRESS ================= */

function startPolling() {
    stopPolling();

    pollScanStatus();

    pollingTimer = setInterval(
        pollScanStatus,
        1500
    );
}


function stopPolling() {
    if (pollingTimer) {
        clearInterval(pollingTimer);
        pollingTimer = null;
    }

    isPolling = false;
}


async function pollScanStatus() {
    if (!currentJobId || isPolling) return;

    isPolling = true;

    try {
        const data = await apiRequest(
            `${API.scan}/${encodeURIComponent(currentJobId)}`
        );

        setScanProgress(
            data.progress ?? 0,
            data.message || data.status || "Scanning..."
        );

        if (data.status === "completed") {
            stopPolling();

            setScanControls(false);

            setScanProgress(
                100,
                "Assessment completed"
            );

            showScanMessage(
                "Security assessment completed successfully.",
                "success"
            );

            if (data.results) {
                renderScanResults(data.results);
            }

            await loadDashboard();

            const records = await loadHistory();

            if (records.length && records[0].id != null) {
                latestScanId = records[0].id;
            }

            updateReportAvailability();

            showReportMessage(
                latestScanId
                    ? `Scan #${latestScanId} is ready for report export.`
                    : "Scan completed, but no saved scan ID was returned.",
                latestScanId ? "success" : "error"
            );

        } else if (data.status === "failed") {
            stopPolling();

            setScanControls(false);

            showScanMessage(
                data.error || "The scan could not be completed.",
                "error"
            );
        }

    } catch (error) {
        stopPolling();

        setScanControls(false);

        showScanMessage(
            `Unable to retrieve scan status: ${error.message}`,
            "error"
        );

    } finally {
        isPolling = false;
    }
}


/* ================= SCAN RESULTS ================= */

function renderScanResults(results) {
    const services = results.services || [];
    const cves = results.cves || [];

    renderServices(services);
    renderCves(cves);

    setText("openPorts", services.length);

    setText(
        "networkStatus",
        `${services.length} OPEN SERVICE(S)`
    );

    const summary = {
        Critical: 0,
        High: 0,
        Medium: 0,
        Low: 0
    };

    cves.forEach(item => {
        const severity = String(item.severity || "Unknown");

        if (
            Object.prototype.hasOwnProperty.call(
                summary,
                severity
            )
        ) {
            summary[severity]++;
        }
    });

    updateRiskChart(summary);
}


function renderServices(services) {
    const tbody = $("servicesTable");

    if (!tbody) return;

    if (!services.length) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" class="empty-cell">
                    No open services discovered.
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = services.map(item => `
        <tr>
            <td>${escapeHTML(item.host || "-")}</td>
            <td>${escapeHTML(item.port)}</td>
            <td>${escapeHTML(item.protocol || "tcp")}</td>
            <td>${escapeHTML(item.service || "Unknown")}</td>
            <td>${escapeHTML(item.product || "-")}</td>
            <td>${escapeHTML(item.version || "-")}</td>
            <td>${escapeHTML(item.method || "-")}</td>
        </tr>
    `).join("");
}


function renderCves(cves) {
    const tbody = $("cveTable");

    if (!tbody) return;

    if (!cves.length) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" class="empty-cell">
                    No CVE candidates found.
                </td>
            </tr>
        `;
    } else {
        tbody.innerHTML = cves.map(item => `
            <tr>
                <td>${escapeHTML(item.cve_id)}</td>
                <td>${escapeHTML(item.severity || "Unknown")}</td>
                <td>${escapeHTML(item.score ?? "-")}</td>
                <td>${escapeHTML(item.product || "-")}</td>
                <td>${escapeHTML(item.port ?? "-")}</td>
                <td>${escapeHTML(item.priority || "-")}</td>
                <td>${safeNvdLink(item.url)}</td>
            </tr>
        `).join("");
    }

    copyCveResultsToIntelligence();
}


function safeNvdLink(url) {
    try {
        const parsed = new URL(url);

        if (
            parsed.protocol !== "https:" ||
            parsed.hostname !== "nvd.nist.gov"
        ) {
            return "-";
        }

        return `
            <a href="${escapeHTML(parsed.href)}"
               target="_blank"
               rel="noopener noreferrer">
                NVD ↗
            </a>
        `;

    } catch {
        return "-";
    }
}


function copyCveResultsToIntelligence() {
    const source = $("cveTable");
    const destination = $("cveIntelligenceTable");

    if (source && destination) {
        destination.innerHTML = source.innerHTML;
    }
}


/* ================= HISTORY ================= */

async function loadHistory() {
    try {
        const data = await apiRequest(API.history);

        const records = Array.isArray(data)
            ? data
            : (data.scans || []);

        const tbody = $("historyTable");

        if (records.length && records[0].id != null) {
            latestScanId = records[0].id;
        } else if (!records.length) {
            latestScanId = null;
        }

        if (tbody) {
            if (!records.length) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="7" class="empty-cell">
                            No scan history available.
                        </td>
                    </tr>
                `;
            } else {
                tbody.innerHTML = records.map(record => `
                    <tr>
                        <td>${escapeHTML(record.id)}</td>
                        <td>${escapeHTML(record.scanned_at || "-")}</td>
                        <td>${escapeHTML(record.target)}</td>
                        <td>${escapeHTML(record.ports_scanned)}</td>
                        <td>${escapeHTML(record.open_ports)}</td>
                        <td>${escapeHTML(record.cve_count)}</td>
                        <td>
                            <button type="button"
                                    class="vulnex-preview-button"
                                    data-preview="${escapeHTML(record.id)}">
                                Preview
                            </button>
                        </td>
                    </tr>
                `).join("");
            }
        }

        updateReportAvailability();

        return records;

    } catch (error) {
        console.error("History API:", error.message);

        showReportMessage(
            `Unable to load scan history: ${error.message}`,
            "error"
        );

        return [];
    }
}


$("refreshHistory")?.addEventListener(
    "click",
    loadHistory
);


/* ================= REPORT MESSAGES ================= */

function showReportMessage(message, type = "") {
    const notice = $("reportMessage");

    if (!notice) return;

    notice.textContent = message;
    notice.className = `report-notice ${type}`;
}


/* ================= REPORT AVAILABILITY ================= */

function updateReportAvailability() {
    const buttons = document.querySelectorAll("[data-export]");

    const available = latestScanId !== null &&
                      latestScanId !== undefined &&
                      latestScanId !== "";

    buttons.forEach(button => {
        button.disabled = !available;

        button.title = available
            ? `Export scan #${latestScanId}`
            : "Complete a scan before exporting a report";
    });
}


/* ================= DOWNLOAD FILENAME ================= */

function getDownloadFilename(response, format, scanId) {
    const disposition = response.headers.get(
        "Content-Disposition"
    );

    if (disposition) {
        const match =
            disposition.match(/filename\*=UTF-8''([^;]+)/i) ||
            disposition.match(/filename="?([^";]+)"?/i);

        if (match) {
            try {
                return decodeURIComponent(match[1].trim());
            } catch {
                return match[1].trim();
            }
        }
    }

    return `VULNEX_Scan_${scanId}.${format}`;
}


/* ================= REPORT EXPORT ================= */

async function exportReport(format, button, scanIdOverride = null) {
    const allowedFormats = ["pdf", "csv", "json"];

    if (!allowedFormats.includes(format)) {
        showReportMessage(
            "Unsupported report format.",
            "error"
        );
        return;
    }

    const scanId = scanIdOverride ?? latestScanId;

    if (scanId == null || scanId === "") {
        showReportMessage(
            "No completed scan is available. Complete a scan before exporting.",
            "error"
        );
        return;
    }

    const originalText = button.textContent;
    const wasDisabled = button.disabled;

    button.disabled = true;
    button.textContent = "GENERATING...";

    showReportMessage(
        `Generating ${format.toUpperCase()} report for scan #${scanId}...`
    );

    let downloadUrl = null;

    try {
        const response = await fetch(
            `${API.reports}/${format}/${encodeURIComponent(scanId)}`
        );

        if (!response.ok) {
            const contentType =
                response.headers.get("Content-Type") || "";

            let errorMessage =
                `Report generation failed (${response.status}).`;

            if (contentType.includes("application/json")) {
                const errorData = await response.json().catch(() => ({}));

                errorMessage =
                    errorData.error ||
                    errorData.message ||
                    errorMessage;

            } else {
                const errorText = await response.text().catch(() => "");

                if (errorText) {
                    errorMessage = errorText.slice(0, 250);
                }
            }

            throw new Error(errorMessage);
        }

        const blob = await response.blob();

        if (!blob.size) {
            throw new Error("The generated report is empty.");
        }

        const filename = getDownloadFilename(
            response,
            format,
            scanId
        );

        downloadUrl = window.URL.createObjectURL(blob);

        const anchor = document.createElement("a");

        anchor.href = downloadUrl;
        anchor.download = filename;

        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();

        showReportMessage(
            `${format.toUpperCase()} report downloaded successfully: ${filename}`,
            "success"
        );

    } catch (error) {
        console.error("Report export error:", error);

        showReportMessage(
            `Unable to export ${format.toUpperCase()}: ${error.message}`,
            "error"
        );

    } finally {
        if (downloadUrl) {
            setTimeout(() => {
                window.URL.revokeObjectURL(downloadUrl);
            }, 1000);
        }

        button.disabled = wasDisabled;
        button.textContent = originalText;

        updateReportAvailability();
    }
}


document.querySelectorAll("[data-export]").forEach(button => {
    button.addEventListener("click", () => {
        exportReport(button.dataset.export, button);
    });
});


/* ==========================================================
   STAGE 4.4 - REPORT PREVIEW
========================================================== */


/* ================= PREVIEW API ================= */

async function previewReport(scanId) {
    if (!Number.isInteger(scanId) || scanId <= 0) {
        showReportMessage("Invalid scan ID.", "error");
        return;
    }

    currentPreviewScanId = scanId;

    showReportMessage(
        `Loading report preview for scan #${scanId}...`
    );

    try {
        const data = await apiRequest(
            `${API.preview}/${encodeURIComponent(scanId)}`
        );

        if (!data || Number(data.scan_id) !== scanId) {
            throw new Error("The returned scan report does not match the selected scan.");
        }

        renderReportPreview(data);

        showReportMessage(
            `Report preview loaded for scan #${scanId}.`,
            "success"
        );

    } catch (error) {
        console.error("Report preview error:", error);

        showReportMessage(
            `Unable to load preview: ${error.message}`,
            "error"
        );
    }
}


/* ================= PREVIEW RENDERING ================= */

function renderReportPreview(data) {
    let modal = $("vulnexPreviewModal");

    if (!modal) {
        modal = document.createElement("div");
        modal.id = "vulnexPreviewModal";

        document.body.appendChild(modal);
    }

    const severity = data.severity_summary || {};
    const risks = data.risk_summary || {};

    const services = Array.isArray(data.services)
        ? data.services
        : [];

    const cves = Array.isArray(data.cves)
        ? data.cves
        : [];

    const severityItems = [
        ["Critical", severity.Critical || 0],
        ["High", severity.High || 0],
        ["Medium", severity.Medium || 0],
        ["Low", severity.Low || 0],
        ["Unknown", severity.Unknown || 0]
    ];

    const severityHTML = severityItems.map(([name, count]) => `
        <div class="vulnex-preview-stat">
            <span>${escapeHTML(name)}</span>
            <strong>${escapeHTML(count)}</strong>
        </div>
    `).join("");

    const riskHTML = Object.entries(risks).map(([name, value]) => `
        <div class="vulnex-preview-stat">
            <span>${escapeHTML(name.replaceAll("_", " "))}</span>
            <strong>${escapeHTML(value)}</strong>
        </div>
    `).join("");

    const serviceHTML = services.length
        ? services.map(item => `
            <tr>
                <td>${escapeHTML(item.host || "-")}</td>
                <td>${escapeHTML(item.port ?? "-")}</td>
                <td>${escapeHTML(item.protocol || "tcp")}</td>
                <td>${escapeHTML(item.service || "Unknown")}</td>
                <td>${escapeHTML(item.product || "-")}</td>
                <td>${escapeHTML(item.version || "-")}</td>
            </tr>
        `).join("")
        : `
            <tr>
                <td colspan="6" class="empty-cell">
                    No exposed services found.
                </td>
            </tr>
        `;

    const cveHTML = cves.length
        ? cves.map(item => `
            <tr>
                <td>${escapeHTML(item.cve_id || "-")}</td>
                <td>${escapeHTML(item.severity || "Unknown")}</td>
                <td>${escapeHTML(item.score ?? "-")}</td>
                <td>${escapeHTML(item.product || "-")}</td>
                <td>${escapeHTML(item.port ?? "-")}</td>
            </tr>
        `).join("")
        : `
            <tr>
                <td colspan="5" class="empty-cell">
                    No CVE candidates found.
                </td>
            </tr>
        `;

    const scanId = Number(data.scan_id);

    modal.innerHTML = `
        <div class="vulnex-preview-backdrop">

            <section class="vulnex-preview-panel"
                     role="dialog"
                     aria-modal="true"
                     aria-labelledby="vulnexPreviewTitle">

                <header class="vulnex-preview-header">
                    <div>
                        <span class="vulnex-preview-eyebrow">
                            VULNEX SECURITY INTELLIGENCE
                        </span>

                        <h2 id="vulnexPreviewTitle">
                            Scan Report Preview
                        </h2>

                        <p>
                            Assessment Report #${escapeHTML(scanId)}
                        </p>
                    </div>

                    <button type="button"
                            class="vulnex-preview-close"
                            data-preview-close
                            aria-label="Close preview">
                        ✕
                    </button>
                </header>

                <div class="vulnex-preview-body">

                    <div class="vulnex-preview-target">
                        <span>SCAN TARGET</span>

                        <strong>
                            ${escapeHTML(data.target)}
                        </strong>

                        <small>
                            ${escapeHTML(data.scanned_at || "Date unavailable")}
                        </small>
                    </div>

                    <h3>Assessment Overview</h3>

                    <div class="vulnex-preview-grid">
                        <div class="vulnex-preview-card">
                            <span>Ports Scanned</span>
                            <strong>
                                ${escapeHTML(data.ports_scanned ?? 0)}
                            </strong>
                        </div>

                        <div class="vulnex-preview-card">
                            <span>Open Services</span>
                            <strong>
                                ${escapeHTML(data.open_ports ?? 0)}
                            </strong>
                        </div>

                        <div class="vulnex-preview-card">
                            <span>CVE Candidates</span>
                            <strong>
                                ${escapeHTML(data.cve_count ?? 0)}
                            </strong>
                        </div>
                    </div>

                    <h3>CVSS Severity Distribution</h3>

                    <div class="vulnex-preview-grid">
                        ${severityHTML}
                    </div>

                    <h3>Security Risk Summary</h3>

                    <div class="vulnex-preview-grid">
                        ${riskHTML || `
                            <p>No additional risk summary available.</p>
                        `}
                    </div>

                    <h3>Exposed Services</h3>

                    <div class="vulnex-preview-table-wrap">
                        <table>
                            <thead>
                                <tr>
                                    <th>Host</th>
                                    <th>Port</th>
                                    <th>Protocol</th>
                                    <th>Service</th>
                                    <th>Product</th>
                                    <th>Version</th>
                                </tr>
                            </thead>

                            <tbody>
                                ${serviceHTML}
                            </tbody>
                        </table>
                    </div>

                    <h3>CVE Intelligence</h3>

                    <p class="vulnex-preview-disclaimer">
                        CVE entries are potential matches based on
                        detected service information. They should be
                        independently verified before being treated
                        as confirmed vulnerabilities.
                    </p>

                    <div class="vulnex-preview-table-wrap">
                        <table>
                            <thead>
                                <tr>
                                    <th>CVE ID</th>
                                    <th>Severity</th>
                                    <th>Score</th>
                                    <th>Product</th>
                                    <th>Port</th>
                                </tr>
                            </thead>

                            <tbody>
                                ${cveHTML}
                            </tbody>
                        </table>
                    </div>

                </div>

                <footer class="vulnex-preview-footer">
                    <button type="button"
                            class="vulnex-preview-secondary"
                            data-preview-close>
                        Close Preview
                    </button>

                    <button type="button"
                            class="vulnex-preview-primary"
                            data-preview-pdf="${escapeHTML(scanId)}">
                        Export PDF
                    </button>
                </footer>

            </section>
        </div>
    `;

    modal.style.display = "block";
    modal.setAttribute("aria-hidden", "false");

    document.body.style.overflow = "hidden";

    $("vulnexPreviewModal")
        ?.querySelector("[data-preview-close]")
        ?.focus();
}


/* ================= PREVIEW EVENTS ================= */

document.addEventListener("click", event => {

    const previewButton = event.target.closest("[data-preview]");

    if (previewButton) {
        const scanId = Number(previewButton.dataset.preview);

        if (Number.isInteger(scanId) && scanId > 0) {
            previewReport(scanId);
        }

        return;
    }

    // Close only when clicking the backdrop itself.
    // Clicking inside the modal must not close it.
    if (event.target.classList.contains("vulnex-preview-backdrop")) {
        closeReportPreview();
        return;
    }

    // Close buttons.
    if (event.target.closest("[data-preview-close]")) {
        closeReportPreview();
        return;
    }

    // Export PDF for the selected scan.
    const pdfButton = event.target.closest("[data-preview-pdf]");

    if (pdfButton) {
        const scanId = Number(pdfButton.dataset.previewPdf);

        if (Number.isInteger(scanId) && scanId > 0) {
            exportReport("pdf", pdfButton, scanId);
        }
    }
});


/* ================= CLOSE PREVIEW ================= */

function closeReportPreview() {
    const modal = $("vulnexPreviewModal");

    if (modal) {
        modal.style.display = "none";
        modal.setAttribute("aria-hidden", "true");
    }

    document.body.style.overflow = "";
}


document.addEventListener("keydown", event => {
    if (event.key === "Escape") {
        closeReportPreview();
    }
});


/* ================= PREVIEW STYLES ================= */

(function addPreviewStyles() {
    if ($("vulnexPreviewStyles")) return;

    const style = document.createElement("style");

    style.id = "vulnexPreviewStyles";

    style.textContent = `

        .vulnex-preview-button {
            padding: 8px 14px;
            background: rgba(169,112,240,.14);
            color: #C49AFF;
            border: 1px solid rgba(169,112,240,.35);
            border-radius: 7px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            transition: .2s ease;
        }

        .vulnex-preview-button:hover {
            background: #8954D8;
            color: white;
            transform: translateY(-1px);
        }

        #vulnexPreviewModal {
            display: none;
            position: fixed;
            inset: 0;
            z-index: 99999;
        }

        .vulnex-preview-backdrop {
            position: fixed;
            inset: 0;
            background: rgba(8,6,15,.88);
            backdrop-filter: blur(8px);
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }

        .vulnex-preview-panel {
            width: min(1050px, 100%);
            max-height: 92vh;
            overflow: hidden;
            display: flex;
            flex-direction: column;
            background: #171321;
            color: #F5F0FF;
            border: 1px solid rgba(169,112,240,.35);
            border-radius: 16px;
            box-shadow: 0 25px 90px rgba(0,0,0,.5);
        }

        .vulnex-preview-header,
        .vulnex-preview-footer {
            padding: 20px 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 15px;
            flex-shrink: 0;
        }

        .vulnex-preview-header {
            border-bottom: 1px solid rgba(255,255,255,.08);
        }

        .vulnex-preview-header h2 {
            margin: 7px 0;
            font-size: 24px;
        }

        .vulnex-preview-header p {
            color: #A99BBD;
            margin: 0;
            font-size: 14px;
        }

        .vulnex-preview-eyebrow {
            color: #B98AFF;
            font-size: 11px;
            letter-spacing: 2px;
        }

        .vulnex-preview-close {
            background: #30243F;
            color: white;
            border: 0;
            padding: 10px 14px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 17px;
        }

        .vulnex-preview-close:hover {
            background: #8954D8;
        }

        .vulnex-preview-body {
            overflow-y: auto;
            padding: 24px;
        }

        .vulnex-preview-body h3 {
            font-size: 17px;
            margin: 27px 0 13px;
            color: #D8C3FA;
        }

        .vulnex-preview-target {
            background: #211A2E;
            padding: 20px;
            border: 1px solid rgba(169,112,240,.16);
            border-radius: 10px;
            display: grid;
            gap: 10px;
        }

        .vulnex-preview-target span {
            color: #A99BBD;
            font-size: 12px;
            letter-spacing: 1px;
        }

        .vulnex-preview-target strong {
            font-size: 20px;
            overflow-wrap: anywhere;
        }

        .vulnex-preview-target small {
            color: #A99BBD;
            font-size: 13px;
        }

        .vulnex-preview-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 12px;
        }

        .vulnex-preview-card,
        .vulnex-preview-stat {
            background: #211A2E;
            border: 1px solid rgba(255,255,255,.06);
            border-radius: 10px;
            padding: 16px;
        }

        .vulnex-preview-card {
            display: grid;
            gap: 12px;
        }

        .vulnex-preview-card span {
            color: #A99BBD;
            font-size: 13px;
        }

        .vulnex-preview-card strong {
            font-size: 28px;
        }

        .vulnex-preview-stat {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
        }

        .vulnex-preview-stat span {
            color: #C8BBD8;
            font-size: 14px;
        }

        .vulnex-preview-stat strong {
            color: #C49AFF;
            font-size: 18px;
        }

        .vulnex-preview-table-wrap {
            overflow-x: auto;
            border: 1px solid rgba(255,255,255,.07);
            border-radius: 9px;
        }

        .vulnex-preview-table-wrap table {
            width: 100%;
            border-collapse: collapse;
            min-width: 600px;
            font-size: 14px;
        }

        .vulnex-preview-table-wrap th,
        .vulnex-preview-table-wrap td {
            text-align: left;
            padding: 14px;
            border-bottom: 1px solid rgba(255,255,255,.08);
        }

        .vulnex-preview-table-wrap th {
            color: #B98AFF;
            background: #211A2E;
            font-weight: 600;
        }

        .vulnex-preview-table-wrap td {
            color: #E4DCEC;
        }

        .vulnex-preview-disclaimer {
            color: #A99BBD;
            font-size: 13px;
            line-height: 1.7;
            margin-bottom: 13px;
        }

        .vulnex-preview-footer {
            border-top: 1px solid rgba(255,255,255,.08);
            justify-content: flex-end;
        }

        .vulnex-preview-footer button {
            padding: 12px 18px;
            border: 0;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            font-size: 13px;
        }

        .vulnex-preview-secondary {
            background: #30243F;
            color: white;
        }

        .vulnex-preview-secondary:hover {
            background: #443253;
        }

        .vulnex-preview-primary {
            background: #8954D8;
            color: white;
        }

        .vulnex-preview-primary:hover {
            background: #A970F0;
        }

        .vulnex-preview-footer button:disabled {
            opacity: .6;
            cursor: not-allowed;
        }

        @media(max-width: 600px) {
            .vulnex-preview-backdrop {
                padding: 8px;
            }

            .vulnex-preview-panel {
                max-height: 96vh;
            }

            .vulnex-preview-header,
            .vulnex-preview-footer {
                padding: 15px;
            }

            .vulnex-preview-body {
                padding: 15px;
            }

            .vulnex-preview-header h2 {
                font-size: 19px;
            }

            .vulnex-preview-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }

            .vulnex-preview-card strong {
                font-size: 23px;
            }

            .vulnex-preview-footer button {
                padding: 10px 13px;
            }
        }
    `;

    document.head.appendChild(style);

})();


/* ================= INITIALIZATION ================= */

async function initializeApp() {
    createRiskChart();
    createActivityChart();

    updateReportAvailability();

    const backend = await checkBackend();

    if (backend) {
        await loadDashboard();
        await loadHistory();
    }
}

initializeApp();


/* ==========================================================
   END OF VULNEX FRONTEND CONTROLLER
========================================================== */
