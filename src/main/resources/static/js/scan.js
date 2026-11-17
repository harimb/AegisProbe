/*
 * Scan list page: select-all, a live "Delete selected" state, and a confirmation
 * before scans (including running ones) are permanently deleted.
 */
(function () {
    "use strict";

    const form = document.getElementById("scan-list-form");
    if (!form) {
        return;
    }

    const selectAll = document.getElementById("select-all");
    const deleteBtn = document.getElementById("delete-selected");
    const countLabel = document.getElementById("selected-count");
    const rowChecks = function () {
        return Array.from(form.querySelectorAll(".row-check"));
    };

    function refresh() {
        const checked = rowChecks().filter(function (c) { return c.checked; });
        const n = checked.length;
        if (deleteBtn) {
            deleteBtn.disabled = n === 0;
            deleteBtn.textContent = n === 0 ? "Delete selected" : "Delete selected (" + n + ")";
        }
        if (countLabel) {
            countLabel.textContent = n === 0 ? "None selected"
                : n + (n === 1 ? " scan selected" : " scans selected");
        }
        if (selectAll) {
            const all = rowChecks();
            selectAll.checked = n > 0 && n === all.length;
            selectAll.indeterminate = n > 0 && n < all.length;
        }
    }

    if (selectAll) {
        selectAll.addEventListener("change", function () {
            rowChecks().forEach(function (c) { c.checked = selectAll.checked; });
            refresh();
        });
    }
    rowChecks().forEach(function (c) {
        c.addEventListener("change", refresh);
    });

    form.addEventListener("submit", function (e) {
        const n = rowChecks().filter(function (c) { return c.checked; }).length;
        if (n === 0) {
            e.preventDefault();
            return;
        }
        const msg = "Permanently delete " + n + (n === 1 ? " scan" : " scans")
            + " and all their findings? Running scans will be cancelled. This cannot be undone.";
        if (!window.confirm(msg)) {
            e.preventDefault();
        }
    });

    refresh();
})();
