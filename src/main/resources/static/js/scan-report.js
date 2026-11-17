/*
 * Behaviour for the scan report page: poll while a scan runs, draw the severity
 * and category charts, and drive the filter chips, search box and row expand.
 * All data is read from the rendered DOM, so no data is templated into script.
 */
(function () {
    "use strict";

    const main = document.querySelector("main[data-scan-id]");
    if (!main) {
        return;
    }

    const status = main.getAttribute("data-status");
    const id = main.getAttribute("data-scan-id");

    // While the scan is still running, poll its status and update the progress
    // bar and activity log; reload to render the report once it finishes.
    if (status === "PENDING" || status === "RUNNING") {
        const phaseEl = document.getElementById("phase");
        const pctEl = document.getElementById("percent-label");
        const fillEl = document.getElementById("progress-fill");
        const logEl = document.getElementById("scan-log");

        const poll = function () {
            fetch("/scan/" + id + "/status")
                .then(function (r) { return r.json(); })
                .then(function (d) {
                    if (phaseEl && d.phase) {
                        phaseEl.textContent = d.phase;
                    }
                    if (typeof d.percent === "number") {
                        if (fillEl) fillEl.style.width = d.percent + "%";
                        if (pctEl) pctEl.textContent = d.percent + "%";
                    }
                    if (logEl && Array.isArray(d.log) && d.log.length) {
                        logEl.textContent = d.log.join("\n");
                        logEl.scrollTop = logEl.scrollHeight;
                    }
                    if (d.status === "DONE" || d.status === "FAILED") {
                        clearInterval(timer);
                        location.reload();
                    }
                })
                .catch(function () { /* transient: try again next tick */ });
        };

        const timer = setInterval(poll, 1200);
        poll();
        return;
    }

    drawSeverityChart();
    drawCategoryChart();
    wireRowExpand();
    wireControls();
    wireCompletedLog(id);

    // --- charts ---------------------------------------------------------------

    function tileCount(severity) {
        const el = document.querySelector(".tile.sev-" + severity + " .num");
        return el ? parseInt(el.textContent.trim(), 10) || 0 : 0;
    }

    function drawSeverityChart() {
        const canvas = document.getElementById("sevChart");
        if (!canvas || !window.Chart) {
            return;
        }
        const data = [tileCount("HIGH"), tileCount("MEDIUM"), tileCount("LOW"), tileCount("INFO")];
        new Chart(canvas, {
            type: "doughnut",
            data: {
                labels: ["High", "Medium", "Low", "Info"],
                datasets: [{ data: data, backgroundColor: ["#dc2626", "#d97706", "#2563eb", "#64748b"], borderWidth: 0 }]
            },
            options: { cutout: "70%", plugins: { legend: { display: false } }, responsive: false }
        });
    }

    function drawCategoryChart() {
        const canvas = document.getElementById("catChart");
        if (!canvas || !window.Chart) {
            return;
        }
        const counts = new Map();
        document.querySelectorAll(".finding-row").forEach(function (row) {
            const cat = row.getAttribute("data-cat") || "Other";
            counts.set(cat, (counts.get(cat) || 0) + 1);
        });
        const sorted = Array.from(counts.entries()).sort(function (a, b) { return b[1] - a[1]; });
        if (!sorted.length) {
            return;
        }
        new Chart(canvas, {
            type: "bar",
            data: {
                labels: sorted.map(function (e) { return e[0]; }),
                datasets: [{ data: sorted.map(function (e) { return e[1]; }), backgroundColor: "#2563eb", borderRadius: 4, barThickness: 18 }]
            },
            options: {
                indexAxis: "y",
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { beginAtZero: true, ticks: { precision: 0 }, grid: { color: "#eef2f7" } },
                    y: { grid: { display: false } }
                }
            }
        });
    }

    // Loads the retained activity log when the "Activity log" section is opened.
    function wireCompletedLog(scanId) {
        const card = document.querySelector(".log-card");
        const pre = document.getElementById("completed-log");
        if (!card || !pre) {
            return;
        }
        card.addEventListener("toggle", function () {
            if (!card.open || card.dataset.loaded) {
                return;
            }
            card.dataset.loaded = "1";
            fetch("/scan/" + scanId + "/status")
                .then(function (r) { return r.json(); })
                .then(function (d) {
                    pre.textContent = Array.isArray(d.log) && d.log.length
                        ? d.log.join("\n")
                        : "Activity log is no longer available — it is kept in memory and cleared when the app restarts.";
                    pre.scrollTop = pre.scrollHeight;
                })
                .catch(function () { pre.textContent = "Could not load the activity log."; });
        });
    }

    // --- interaction ----------------------------------------------------------

    function wireRowExpand() {
        document.querySelectorAll(".finding-row").forEach(function (row) {
            row.addEventListener("click", function () {
                const detail = row.nextElementSibling;
                if (!detail || !detail.classList.contains("detail-row")) {
                    return;
                }
                const opening = detail.hasAttribute("hidden");
                if (opening) {
                    detail.removeAttribute("hidden");
                } else {
                    detail.setAttribute("hidden", "");
                }
                row.classList.toggle("open", opening);
            });
        });
    }

    // Combined severity/search filtering and pagination over the filtered rows.
    function wireControls() {
        const filter = document.getElementById("filter");
        const chips = document.querySelectorAll(".chip");
        const pageSizeSel = document.getElementById("page-size");
        const prevBtn = document.getElementById("prev-page");
        const nextBtn = document.getElementById("next-page");
        const pageLabel = document.getElementById("page-label");
        const pageInfo = document.getElementById("page-info");
        const rows = Array.from(document.querySelectorAll(".finding-row"));

        let activeSev = "ALL";
        let pageSize = pageSizeSel ? parsePageSize(pageSizeSel.value) : 10;
        let currentPage = 1;

        function parsePageSize(value) {
            return value === "all" ? Infinity : parseInt(value, 10);
        }

        function detailOf(row) {
            const d = row.nextElementSibling;
            return d && d.classList.contains("detail-row") ? d : null;
        }

        function matchedRows() {
            const q = (filter && filter.value || "").toLowerCase();
            return rows.filter(function (row) {
                const sev = row.getAttribute("data-sev");
                const text = row.getAttribute("data-text") || "";
                return (activeSev === "ALL" || sev === activeSev) && text.includes(q);
            });
        }

        function render() {
            const list = matchedRows();
            const total = list.length;
            const size = pageSize === Infinity ? Math.max(total, 1) : pageSize;
            const pages = Math.max(1, Math.ceil(total / size));
            if (currentPage > pages) {
                currentPage = pages;
            }
            const start = (currentPage - 1) * size;
            const end = start + size;

            // Hide and collapse every row, then reveal the current page's matches.
            rows.forEach(function (row) {
                row.style.display = "none";
                row.classList.remove("open");
                const detail = detailOf(row);
                if (detail) {
                    detail.setAttribute("hidden", "");
                }
            });
            list.slice(start, end).forEach(function (row) {
                row.style.display = "";
            });

            if (pageInfo) {
                pageInfo.textContent = total === 0
                    ? "No findings match"
                    : "Showing " + (start + 1) + "–" + Math.min(end, total) + " of " + total;
            }
            if (pageLabel) {
                pageLabel.textContent = "Page " + currentPage + " of " + pages;
            }
            if (prevBtn) {
                prevBtn.disabled = currentPage <= 1;
            }
            if (nextBtn) {
                nextBtn.disabled = currentPage >= pages;
            }
        }

        if (filter) {
            filter.addEventListener("input", function () { currentPage = 1; render(); });
        }
        chips.forEach(function (chip) {
            chip.addEventListener("click", function () {
                chips.forEach(function (c) { c.classList.remove("active"); });
                chip.classList.add("active");
                activeSev = chip.getAttribute("data-sev");
                currentPage = 1;
                render();
            });
        });
        if (pageSizeSel) {
            pageSizeSel.addEventListener("change", function () {
                pageSize = parsePageSize(pageSizeSel.value);
                currentPage = 1;
                render();
            });
        }
        if (prevBtn) {
            prevBtn.addEventListener("click", function () {
                if (currentPage > 1) { currentPage--; render(); }
            });
        }
        if (nextBtn) {
            nextBtn.addEventListener("click", function () {
                currentPage++;
                render();
            });
        }

        render();
    }
})();
