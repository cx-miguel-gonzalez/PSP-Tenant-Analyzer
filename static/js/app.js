// POSTs from fetch() carry the session's CSRF token (rendered into base.html)
// in the header Flask-WTF checks, the same way forms send it as a field.
function postWithCsrf(url) {
  const meta = document.querySelector('meta[name="csrf-token"]');
  return fetch(url, { method: "POST", headers: { "X-CSRFToken": meta ? meta.content : "" } });
}

function csvEscape(value) {
  const str = String(value ?? "");
  return /[",\r\n]/.test(str) ? `"${str.replace(/"/g, '""')}"` : str;
}

function buildCsv(headers, rows) {
  const lines = [headers.map(csvEscape).join(",")];
  rows.forEach((cells) => lines.push(cells.map(csvEscape).join(",")));
  return lines.join("\r\n");
}

function downloadCsv(filename, csvText) {
  const blob = new Blob([csvText], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

function pollStatus(url, onUpdate, intervalMs) {
  const poll = () => {
    fetch(url)
      .then((r) => r.json())
      .then((data) => {
        onUpdate(data);
        if (data.state === "running") {
          setTimeout(poll, intervalMs);
        }
      })
      .catch(() => {});
  };
  poll();
}

function wireSectionSync() {
  document.querySelectorAll(".section-sync-btn").forEach((btn) => {
    const key = btn.dataset.sectionKey;
    const progressEl = document.querySelector(
      `.sync-strip-progress[data-section-key="${key}"]`
    );
    const progressTrack = document.querySelector(
      `.sync-progress-track[data-section-key="${key}"]`
    );
    const progressBar = document.querySelector(
      `.sync-progress-bar[data-section-key="${key}"]`
    );
    btn.addEventListener("click", () => {
      btn.disabled = true;
      const originalLabel = btn.textContent;
      btn.textContent = "Syncing...";
      if (progressTrack) progressTrack.hidden = false;
      if (progressBar) {
        progressBar.style.width = "35%";
        progressBar.classList.add("is-indeterminate");
      }
      if (progressEl) progressEl.textContent = "Starting sync...";

      const params = new URLSearchParams();
      if (btn.dataset.refreshCatalog) params.set("refresh_catalog", "1");
      const query = params.toString();
      const startUrl = `/sync/${key}/start${query ? `?${query}` : ""}`;

      postWithCsrf(startUrl).then(() => {
        pollStatus(
          `/sync/${key}/status`,
          (data) => {
            if (progressEl) progressEl.textContent = data.message || "";
            if (progressTrack && progressBar) {
              progressTrack.hidden = false;
              if (data.total) {
                progressBar.classList.remove("is-indeterminate");
                const pct = Math.min(100, Math.round(((data.current || 0) / data.total) * 100));
                progressBar.style.width = `${pct}%`;
                progressTrack.setAttribute("aria-valuenow", String(pct));
                progressTrack.setAttribute("aria-valuetext", data.message || `${pct}% complete`);
              } else if (data.state === "running") {
                progressBar.classList.add("is-indeterminate");
                progressBar.style.width = "35%";
                progressTrack.removeAttribute("aria-valuenow");
                progressTrack.setAttribute("aria-valuetext", data.message || "Sync in progress");
              } else {
                progressBar.classList.remove("is-indeterminate");
                progressBar.style.width = data.state === "done" ? "100%" : "0%";
                progressTrack.setAttribute("aria-valuenow", data.state === "done" ? "100" : "0");
                progressTrack.setAttribute("aria-valuetext", data.message || "Sync complete");
              }
            }
            if (data.state === "done" || data.state === "error") {
              window.location.reload();
            }
          },
          900
        );
      }).catch(() => {
        btn.disabled = false;
        btn.textContent = originalLabel;
        if (progressTrack) progressTrack.hidden = true;
        if (progressBar) progressBar.classList.remove("is-indeterminate");
        if (progressEl) progressEl.textContent = "Could not start sync.";
      });
    });
  });
}

function wireSyncAll() {
  const btn = document.getElementById("sync-all-btn");
  if (!btn) return;
  const statusEl = document.getElementById("sync-all-status");

  btn.addEventListener("click", () => {
    btn.disabled = true;
    btn.textContent = "Syncing All...";
    postWithCsrf("/sync/all/start").then(() => {
      pollStatus(
        "/sync/all/status",
        (data) => {
          if (statusEl) statusEl.textContent = data.message || "";
          if (data.state === "done" || data.state === "error") {
            window.location.reload();
          }
        },
        1200
      );
    });
  });
}

function wireCategoryToggles() {
  const expandBtn = document.getElementById("expand-all-btn");
  const collapseBtn = document.getElementById("collapse-all-btn");
  if (!expandBtn && !collapseBtn) return;

  const setAll = (open) => {
    document.querySelectorAll(".category-block").forEach((details) => {
      details.open = open;
    });
  };

  if (expandBtn) expandBtn.addEventListener("click", () => setAll(true));
  if (collapseBtn) collapseBtn.addEventListener("click", () => setAll(false));
}

function initCompareSelection() {
  const checkboxes = Array.from(document.querySelectorAll(".compare-checkbox"));
  const button = document.getElementById("compare-submit-button");
  const inputA = document.getElementById("compare-input-a");
  const inputB = document.getElementById("compare-input-b");
  if (!checkboxes.length || !button || !inputA || !inputB) return;

  function selectedIds() {
    return checkboxes.filter((c) => c.checked).map((c) => c.dataset.id);
  }

  function refresh() {
    const ids = selectedIds();
    checkboxes.forEach((c) => {
      c.disabled = !c.checked && ids.length >= 2;
    });
    button.disabled = ids.length !== 2;
    button.textContent = `Compare selected (${ids.length}/2)`;
    button.classList.toggle("compare-sticky", ids.length === 2);
    inputA.value = ids[0] || "";
    inputB.value = ids[1] || "";
  }

  checkboxes.forEach((c) => c.addEventListener("change", refresh));
  refresh();
}

function initPresetsTable() {
  const table = document.getElementById("presets-table");
  if (!table) return;
  const tbody = table.tBodies[0];
  const rows = Array.from(tbody.rows);
  const searchInput = document.getElementById("preset-search");
  const typeFilter = document.getElementById("type-filter");

  function applyFilters() {
    const term = ((searchInput && searchInput.value) || "").toLowerCase();
    const type = (typeFilter && typeFilter.value) || "all";
    rows.forEach((row) => {
      const name = (row.dataset.name || "").toLowerCase();
      const description = (row.dataset.description || "").toLowerCase();
      const rowType = row.dataset.type;
      const matchesTerm = !term || name.includes(term) || description.includes(term);
      const matchesType = type === "all" || !row.dataset.type || rowType === type;
      row.style.display = matchesTerm && matchesType ? "" : "none";
    });
    document.dispatchEvent(new Event("presets-filtered"));
  }

  if (searchInput) searchInput.addEventListener("input", applyFilters);
  if (typeFilter) typeFilter.addEventListener("change", applyFilters);

  const headers = Array.from(table.querySelectorAll("th[data-sort-key]"));
  let sortKey = null;
  let sortDir = 1;

  headers.forEach((th) => {
    th.addEventListener("click", () => {
      const key = th.dataset.sortKey;
      sortDir = sortKey === key ? -sortDir : 1;
      sortKey = key;

      headers.forEach((h) => h.classList.remove("sort-asc", "sort-desc"));
      th.classList.add(sortDir === 1 ? "sort-asc" : "sort-desc");

      const sorted = rows.slice().sort((a, b) => {
        if (key === "associated_projects") {
          const na = parseInt(a.dataset[key], 10) || 0;
          const nb = parseInt(b.dataset[key], 10) || 0;
          return (na - nb) * sortDir;
        }
        const va = (a.dataset[key] || "").toLowerCase();
        const vb = (b.dataset[key] || "").toLowerCase();
        if (va < vb) return -1 * sortDir;
        if (va > vb) return 1 * sortDir;
        return 0;
      });
      sorted.forEach((row) => tbody.appendChild(row));
    });
  });
}

function initFeedbackAppsTable() {
  const table = document.getElementById("feedback-apps-table");
  if (!table) return;
  const tbody = table.tBodies[0];
  const rows = Array.from(tbody.rows);
  const filters = Array.from(table.querySelectorAll(".feedback-apps-filter"));
  const headers = Array.from(table.querySelectorAll("th[data-sort-key]"));

  function applyFilters() {
    rows.forEach((row) => {
      const matches = filters.every((input) => {
        const term = input.value.trim().toLowerCase();
        const cell = row.cells[Number(input.dataset.filterColumn)];
        return !term || (cell && cell.textContent.toLowerCase().includes(term));
      });
      row.style.display = matches ? "" : "none";
    });
  }

  filters.forEach((input) => input.addEventListener("input", applyFilters));

  let sortKey = null;
  let sortDir = 1;
  headers.forEach((header) => {
    header.addEventListener("click", () => {
      const key = header.dataset.sortKey;
      sortDir = sortKey === key ? -sortDir : 1;
      sortKey = key;
      headers.forEach((item) => item.classList.remove("sort-asc", "sort-desc"));
      header.classList.add(sortDir === 1 ? "sort-asc" : "sort-desc");
      rows.sort((a, b) => {
        const left = a.cells[Number(key)].textContent.trim().toLowerCase();
        const right = b.cells[Number(key)].textContent.trim().toLowerCase();
        return left.localeCompare(right) * sortDir;
      }).forEach((row) => tbody.appendChild(row));
    });
  });
}

// Shared by Project Management's Projects/Applications tables and Stale
// Projects: filter (per-column search inputs) + sort (click a header) +
// paginate (a page-size select drives how many of the FILTERED, SORTED rows
// show at once). style.display is the single source of truth for
// visibility, set only inside render() -- filtering alone never hides a
// row; pagination decides which filtered rows are in view.
function initFilterableSortableTable(options) {
  const {
    tableId, filterSelector, pageSizeId, prevId, nextId, labelId,
    exportButtonId, exportFilename, defaultPageSize = "25", noMatchLabel = "No matching rows",
  } = options;
  const table = document.getElementById(tableId);
  if (!table) return;
  const tbody = table.tBodies[0];
  const rows = Array.from(tbody.rows);
  const filters = Array.from(table.querySelectorAll(filterSelector));
  const headers = Array.from(table.querySelectorAll("thead tr:first-child th[data-sort-key]"));
  const pageSizeSelect = pageSizeId ? document.getElementById(pageSizeId) : null;
  const prevBtn = prevId ? document.getElementById(prevId) : null;
  const nextBtn = nextId ? document.getElementById(nextId) : null;
  const label = labelId ? document.getElementById(labelId) : null;
  const exportButton = exportButtonId ? document.getElementById(exportButtonId) : null;

  let page = 0;

  // Rows in CURRENT DOM order (reflects the active sort, since sorting
  // re-appends rows to tbody) that match every active filter.
  function getMatchingRows() {
    return Array.from(tbody.rows).filter((row) =>
      filters.every((input) => {
        const term = input.value.trim().toLowerCase();
        const cell = row.cells[Number(input.dataset.filterColumn)];
        return !term || (cell && cell.textContent.toLowerCase().includes(term));
      })
    );
  }

  function render() {
    const matching = getMatchingRows();
    const matchSet = new Set(matching);

    const pageSizeRaw = pageSizeSelect ? pageSizeSelect.value : defaultPageSize;
    const pageSize = pageSizeRaw === "all" ? Math.max(matching.length, 1) : parseInt(pageSizeRaw, 10) || 25;
    const totalPages = Math.max(1, Math.ceil(matching.length / pageSize));
    if (page >= totalPages) page = totalPages - 1;
    if (page < 0) page = 0;
    const start = page * pageSize;
    const pageRows = matching.slice(start, start + pageSize);
    const pageSet = new Set(pageRows);

    rows.forEach((row) => {
      row.style.display = matchSet.has(row) && pageSet.has(row) ? "" : "none";
    });

    if (label) {
      label.textContent = matching.length === 0
        ? noMatchLabel
        : `Showing ${start + 1}-${start + pageRows.length} of ${matching.length}`;
    }
    if (prevBtn) prevBtn.disabled = page <= 0;
    if (nextBtn) nextBtn.disabled = start + pageRows.length >= matching.length;
  }

  filters.forEach((input) => input.addEventListener("input", () => { page = 0; render(); }));

  let sortKey = null;
  let sortDir = 1;
  headers.forEach((header) => {
    header.addEventListener("click", () => {
      const key = header.dataset.sortKey;
      sortDir = sortKey === key ? -sortDir : 1;
      sortKey = key;
      headers.forEach((item) => item.classList.remove("sort-asc", "sort-desc"));
      header.classList.add(sortDir === 1 ? "sort-asc" : "sort-desc");
      rows.sort((left, right) => {
        const a = left.cells[Number(key)].textContent.trim();
        const b = right.cells[Number(key)].textContent.trim();
        const numberA = Number(a);
        const numberB = Number(b);
        const bothNumeric = a !== "" && b !== "" && Number.isFinite(numberA) && Number.isFinite(numberB);
        const comparison = bothNumeric ? numberA - numberB : a.localeCompare(b, undefined, { numeric: true, sensitivity: "base" });
        return comparison * sortDir;
      });
      rows.forEach((row) => tbody.appendChild(row));
      page = 0;
      render();
    });
  });

  if (pageSizeSelect) pageSizeSelect.addEventListener("change", () => { page = 0; render(); });
  if (prevBtn) prevBtn.addEventListener("click", () => { page -= 1; render(); });
  if (nextBtn) nextBtn.addEventListener("click", () => { page += 1; render(); });

  if (exportButton) {
    exportButton.addEventListener("click", () => {
      // Every filtered row, not just the current page -- pagination is a
      // display convenience, not a data reduction.
      const exportHeaders = headers.map((header) => header.textContent.trim());
      const exportRows = getMatchingRows().map((row) =>
        Array.from(row.cells, (cell) => cell.textContent.trim().replace(/\s+/g, " "))
      );
      downloadCsv(exportFilename, buildCsv(exportHeaders, exportRows));
    });
  }

  render();
}

function initProjectManagementTables() {
  initFilterableSortableTable({
    tableId: "project-management-projects-table",
    filterSelector: ".project-management-filter",
    pageSizeId: "project-management-page-size",
    prevId: "project-management-prev",
    nextId: "project-management-next",
    labelId: "project-management-range-label",
    noMatchLabel: "No matching projects",
  });
  initFilterableSortableTable({
    tableId: "project-management-applications-table",
    filterSelector: ".project-management-filter",
    pageSizeId: "project-management-page-size",
    prevId: "project-management-prev",
    nextId: "project-management-next",
    labelId: "project-management-range-label",
    noMatchLabel: "No matching applications",
  });
}

function initStaleProjectsTable() {
  initFilterableSortableTable({
    tableId: "stale-projects-table",
    filterSelector: ".stale-project-filter",
    pageSizeId: "stale-projects-page-size",
    prevId: "stale-projects-prev",
    nextId: "stale-projects-next",
    labelId: "stale-projects-range-label",
    exportButtonId: "stale-projects-export-btn",
    exportFilename: "stale-projects.csv",
    noMatchLabel: "No matching stale projects",
  });
}

function initPresetPanel() {
  const panel = document.getElementById("preset-panel");
  const backdrop = document.getElementById("preset-panel-backdrop");
  const closeBtn = document.getElementById("preset-panel-close");
  const title = document.getElementById("preset-panel-title");
  const meta = document.getElementById("preset-panel-meta");
  const body = document.getElementById("preset-panel-body");
  const triggers = document.querySelectorAll(".preset-name-trigger");
  if (!panel || !backdrop || !closeBtn || !title || !meta || !body || !triggers.length) return;

  function openPanel() {
    backdrop.hidden = false;
    panel.classList.add("panel-open");
    panel.setAttribute("aria-hidden", "false");
  }

  function closePanel() {
    panel.classList.remove("panel-open");
    panel.setAttribute("aria-hidden", "true");
    backdrop.hidden = true;
  }

  function clearBody() {
    while (body.firstChild) body.removeChild(body.firstChild);
  }

  function renderMessage(message) {
    clearBody();
    const p = document.createElement("p");
    p.className = "section-note";
    p.textContent = message;
    body.appendChild(p);
  }

  function renderPreset(data) {
    title.textContent = data.name || `Preset ${data.id}`;
    meta.textContent = `${data.is_custom ? "Custom" : "Built-in"} · ${data.total_queries} queries`;
    clearBody();

    const languages = Object.keys(data.groups || {});
    if (!languages.length) {
      renderMessage("No queries in this preset.");
      return;
    }

    languages.forEach((language) => {
      const langSection = document.createElement("div");
      langSection.className = "panel-language";

      const langHeading = document.createElement("h3");
      langHeading.textContent = language;
      langSection.appendChild(langHeading);

      const categories = data.groups[language];
      Object.keys(categories).forEach((category) => {
        const catBlock = document.createElement("div");
        catBlock.className = "panel-category";

        const catHeading = document.createElement("h4");
        catHeading.textContent = category;
        catBlock.appendChild(catHeading);

        const list = document.createElement("ul");
        categories[category].forEach((name) => {
          const li = document.createElement("li");
          li.textContent = name;
          list.appendChild(li);
        });
        catBlock.appendChild(list);
        langSection.appendChild(catBlock);
      });

      body.appendChild(langSection);
    });
  }

  triggers.forEach((el) => {
    el.addEventListener("click", async () => {
      const id = el.dataset.presetId;
      title.textContent = "Loading...";
      meta.textContent = "";
      clearBody();
      openPanel();
      try {
        const resp = await fetch(`/presets/${encodeURIComponent(id)}/detail`);
        const data = await resp.json();
        if (!resp.ok) {
          renderMessage((data && data.error) || "Could not load preset.");
          return;
        }
        renderPreset(data);
      } catch (err) {
        renderMessage("Could not load preset.");
      }
    });
  });

  closeBtn.addEventListener("click", closePanel);
  backdrop.addEventListener("click", closePanel);
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closePanel();
  });
}

function wireSelectAll(selectAllId, checkboxClass) {
  const selectAll = document.getElementById(selectAllId);
  const checkboxes = Array.from(document.querySelectorAll(`.${checkboxClass}`));
  if (!selectAll || !checkboxes.length) return;

  function refreshSelectAllState() {
    selectAll.checked = checkboxes.every((c) => c.checked);
  }

  selectAll.addEventListener("change", () => {
    checkboxes.forEach((c) => (c.checked = selectAll.checked));
  });
  checkboxes.forEach((c) => c.addEventListener("change", refreshSelectAllState));
  refreshSelectAllState();
}

function initDeleteSelection() {
  const selectAll = document.getElementById("delete-select-all");
  const button = document.getElementById("delete-selected-button");
  const checkboxes = Array.from(document.querySelectorAll(".delete-checkbox"));
  if (!button || !checkboxes.length) return;

  function isRowVisible(checkbox) {
    const row = checkbox.closest("tr");
    return !row || row.style.display !== "none";
  }

  function visibleCheckboxes() {
    return checkboxes.filter(isRowVisible);
  }

  function refresh() {
    const count = checkboxes.filter((c) => c.checked).length;
    button.disabled = count === 0;
    button.textContent = `Delete selected (${count})`;
    if (selectAll) {
      const visible = visibleCheckboxes();
      selectAll.checked = visible.length > 0 && visible.every((c) => c.checked);
    }
  }

  if (selectAll) {
    selectAll.addEventListener("change", () => {
      // Only the currently filtered-in (visible) rows should be affected --
      // otherwise "select all" silently selects presets hidden by search too.
      visibleCheckboxes().forEach((c) => (c.checked = selectAll.checked));
      refresh();
    });
  }
  checkboxes.forEach((c) => c.addEventListener("change", refresh));
  document.addEventListener("presets-filtered", refresh);
  refresh();
}

function initUpdateCounts() {
  const groups = Array.from(document.querySelectorAll(".category-block"));
  const checkboxes = Array.from(document.querySelectorAll(".update-checkbox"));
  if (!groups.length || !checkboxes.length) return;

  function refreshCount(group) {
    const countEl = group.querySelector(":scope > summary .update-count");
    if (!countEl) return;
    const scoped = group.querySelectorAll(".update-checkbox");
    const checked = Array.from(scoped).filter((c) => c.checked).length;
    countEl.textContent = `${checked}/${scoped.length} enabled`;
  }

  function refreshAll() {
    groups.forEach(refreshCount);
  }

  checkboxes.forEach((cb) => cb.addEventListener("change", refreshAll));
  const selectAll = document.getElementById("update-select-all");
  if (selectAll) selectAll.addEventListener("change", refreshAll);
  refreshAll();
}

// Set by initScansExplorer once it runs, so the KPI widgets above it (pie
// legend, failure bars, project links) can drive its filters/highlighting
// without either side needing to know the other's internals.
let scansExplorerApi = null;

function initScansExplorer() {
  const table = document.getElementById("scans-table");
  if (!table) return;
  const tbody = table.tBodies[0];
  const allRows = Array.from(tbody.rows);

  const statusSelect = document.getElementById("scans-status-filter");
  const filterInputs = {
    project: document.getElementById("scans-filter-project"),
    branch: document.getElementById("scans-filter-branch"),
    origin: document.getElementById("scans-filter-origin"),
    initiator: document.getElementById("scans-filter-initiator"),
  };
  const pageSizeSelect = document.getElementById("scans-page-size");
  const prevBtn = document.getElementById("scans-prev");
  const nextBtn = document.getElementById("scans-next");
  const rangeLabel = document.getElementById("scans-range-label");
  const statTiles = Array.from(document.querySelectorAll(".stat-tile[data-status]"));
  const headers = Array.from(table.querySelectorAll("th[data-sort-key]"));

  let sortKey = "created_at";
  let sortDir = -1;
  let page = 0;
  // null, "long" (>=30 min, from the Long-Running KPI), or "variance" (red
  // above / green at-or-below that project's own average duration, from the
  // Inconsistent KPI). Cleared by any manual filter/sort change -- it's a
  // "how you arrived here" indicator, not a persistent view mode.
  let highlightMode = null;
  // Set only by the Long-Running KPI's project links: restricts the list to
  // scans that actually crossed the threshold, rather than every scan for
  // that project (highlighting alone doesn't remove the short ones).
  let minDurationThreshold = null;
  // Set only by the Top Error Categories KPI: the exact Failed/Partial scans
  // whose workflows hit that category (with its name, for the note).
  let scanIdFilter = null;
  let scanIdFilterLabel = "";

  function matchesFilters(row) {
    if (scanIdFilter && !scanIdFilter.has(row.dataset.scan_id)) return false;
    const status = statusSelect ? statusSelect.value : "";
    if (status) {
      const wanted = status.split(",");
      if (wanted.indexOf(row.dataset.status) === -1) return false;
    }
    if (minDurationThreshold !== null) {
      const mins = parseFloat(row.dataset.duration_minutes);
      if (isNaN(mins) || mins < minDurationThreshold) return false;
    }
    for (const [field, input] of Object.entries(filterInputs)) {
      if (!input) continue;
      const term = input.value.trim().toLowerCase();
      if (term && !(row.dataset[field] || "").toLowerCase().includes(term)) return false;
    }
    return true;
  }

  function syncStatTiles() {
    statTiles.forEach((tile) => {
      tile.classList.toggle(
        "stat-tile-active",
        !!statusSelect && !!statusSelect.value && statusSelect.value === tile.dataset.status
      );
    });
  }

  function applyHighlighting(filtered) {
    allRows.forEach((r) => {
      r.classList.remove("scan-row-long", "scan-row-high-duration", "scan-row-low-duration");
    });
    if (highlightMode === "long") {
      filtered.forEach((r) => {
        const mins = parseFloat(r.dataset.duration_minutes);
        if (!isNaN(mins) && mins >= 30) r.classList.add("scan-row-long");
      });
    } else if (highlightMode === "variance") {
      const durations = filtered
        .map((r) => parseFloat(r.dataset.duration_minutes))
        .filter((v) => !isNaN(v));
      if (durations.length) {
        const avg = durations.reduce((sum, v) => sum + v, 0) / durations.length;
        filtered.forEach((r) => {
          const mins = parseFloat(r.dataset.duration_minutes);
          if (isNaN(mins)) return;
          r.classList.add(mins > avg ? "scan-row-high-duration" : "scan-row-low-duration");
        });
      }
    }
  }

  function sortComparator(a, b) {
    if (sortKey === "duration_minutes" || sortKey === "loc") {
      const va = parseFloat(a.dataset[sortKey]);
      const vb = parseFloat(b.dataset[sortKey]);
      const na = isNaN(va) ? -Infinity : va;
      const nb = isNaN(vb) ? -Infinity : vb;
      return (na - nb) * sortDir;
    }
    const va = (a.dataset[sortKey] || "").toLowerCase();
    const vb = (b.dataset[sortKey] || "").toLowerCase();
    if (va < vb) return -1 * sortDir;
    if (va > vb) return 1 * sortDir;
    return 0;
  }

  function updateActiveFilterNote() {
    const note = document.getElementById("scans-active-filter-note");
    if (!note) return;
    if (scanIdFilter) {
      note.textContent = `Showing the ${scanIdFilter.size} failed/partial scan(s) with ${scanIdFilterLabel}. `;
      const clear = document.createElement("button");
      clear.type = "button";
      clear.className = "link-button";
      clear.textContent = "Clear";
      clear.addEventListener("click", () => applyExternalFilter());
      note.appendChild(clear);
      note.hidden = false;
    } else if (minDurationThreshold !== null) {
      const project = filterInputs.project && filterInputs.project.value;
      note.textContent = `Showing only scans of at least ${minDurationThreshold} minutes` +
        (project ? ` for ${project}.` : ".");
      note.hidden = false;
    } else {
      note.hidden = true;
    }
  }

  function render() {
    const filtered = allRows.filter(matchesFilters);
    applyHighlighting(filtered);
    updateActiveFilterNote();
    filtered.sort(sortComparator);

    allRows.forEach((r) => {
      if (r.parentNode) r.parentNode.removeChild(r);
    });

    const pageSizeRaw = pageSizeSelect ? pageSizeSelect.value : "50";
    const pageSize = pageSizeRaw === "all" ? filtered.length : parseInt(pageSizeRaw, 10) || 50;
    const totalPages = Math.max(1, Math.ceil(filtered.length / Math.max(pageSize, 1)));
    if (page >= totalPages) page = totalPages - 1;
    if (page < 0) page = 0;
    const start = page * pageSize;
    const pageRows = pageSize > 0 ? filtered.slice(start, start + pageSize) : filtered;

    pageRows.forEach((r) => tbody.appendChild(r));

    if (rangeLabel) {
      rangeLabel.textContent = filtered.length === 0
        ? "No matching scans"
        : `Showing ${start + 1}-${start + pageRows.length} of ${filtered.length}`;
    }
    if (prevBtn) prevBtn.disabled = page <= 0;
    if (nextBtn) nextBtn.disabled = start + pageRows.length >= filtered.length;
  }

  headers.forEach((th) => {
    th.addEventListener("click", () => {
      const key = th.dataset.sortKey;
      sortDir = sortKey === key ? -sortDir : 1;
      sortKey = key;
      headers.forEach((h) => h.classList.remove("sort-asc", "sort-desc"));
      th.classList.add(sortDir === 1 ? "sort-asc" : "sort-desc");
      page = 0;
      render();
    });
  });

  Object.values(filterInputs).forEach((input) => {
    if (input) {
      input.addEventListener("input", () => {
        highlightMode = null;
        minDurationThreshold = null;
        scanIdFilter = null;
        page = 0;
        render();
      });
    }
  });

  if (statusSelect) {
    statusSelect.addEventListener("change", () => {
      highlightMode = null;
      minDurationThreshold = null;
      scanIdFilter = null;
      page = 0;
      render();
      syncStatTiles();
    });
  }

  statTiles.forEach((tile) => {
    tile.addEventListener("click", () => {
      if (!statusSelect) return;
      statusSelect.value = statusSelect.value === tile.dataset.status ? "" : tile.dataset.status;
      highlightMode = null;
      minDurationThreshold = null;
      scanIdFilter = null;
      page = 0;
      render();
      syncStatTiles();
      const explorer = document.getElementById("scans-explorer");
      if (explorer) explorer.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  });

  if (pageSizeSelect) {
    pageSizeSelect.addEventListener("change", () => {
      page = 0;
      render();
    });
  }
  if (prevBtn) prevBtn.addEventListener("click", () => { page -= 1; render(); });
  if (nextBtn) nextBtn.addEventListener("click", () => { page += 1; render(); });

  // Driven by the KPI widgets above: sets whichever filters/highlight mode
  // are passed (anything omitted is cleared, so clicks never compound with
  // a stale filter left over from a previous click), then scrolls down.
  function applyExternalFilter({ status = "", project = "", highlight = null, minDuration = null, scanIds = null, label = "" } = {}) {
    if (statusSelect) statusSelect.value = status;
    if (filterInputs.project) filterInputs.project.value = project;
    if (filterInputs.branch) filterInputs.branch.value = "";
    if (filterInputs.origin) filterInputs.origin.value = "";
    if (filterInputs.initiator) filterInputs.initiator.value = "";
    highlightMode = highlight;
    minDurationThreshold = minDuration;
    scanIdFilter = scanIds ? new Set(scanIds) : null;
    scanIdFilterLabel = label;
    page = 0;
    render();
    syncStatTiles();
    const explorer = document.getElementById("scans-explorer");
    if (explorer) explorer.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  scansExplorerApi = { applyExternalFilter };

  const exportBtn = document.getElementById("scans-export-btn");
  const EXPORT_HEADERS = ["Scan ID", "Project", "Status", "Branch", "Origin", "Initiator", "Duration", "Created", "LOC"];
  if (exportBtn) {
    exportBtn.addEventListener("click", () => {
      // Every row matching the current filters, not just the current page --
      // pagination is a display convenience, not a data reduction.
      const filtered = allRows.filter(matchesFilters).sort(sortComparator);
      const rows = filtered.map((row) =>
        Array.from(row.cells)
          .slice(0, EXPORT_HEADERS.length)
          .map((cell) => cell.textContent.trim())
      );
      const stamp = new Date().toISOString().replace(/[:.]/g, "-");
      downloadCsv(`scans-export-${stamp}.csv`, buildCsv(EXPORT_HEADERS, rows));
    });
  }

  // Arriving from an Integrations origin box (?origin=Jenkins) -- pre-apply
  // that as the Origin filter so the link actually lands on a filtered view.
  const urlOrigin = new URLSearchParams(window.location.search).get("origin");
  if (urlOrigin && filterInputs.origin) {
    filterInputs.origin.value = urlOrigin;
    const explorer = document.getElementById("scans-explorer");
    if (explorer) explorer.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  render();
}

function initKpiInteractions() {
  document.querySelectorAll(".legend-item[data-status]").forEach((btn) => {
    btn.addEventListener("click", () => {
      if (scansExplorerApi) scansExplorerApi.applyExternalFilter({ status: btn.dataset.status });
    });
  });

  document.querySelectorAll(".bar-column[data-project]").forEach((btn) => {
    btn.addEventListener("click", () => {
      if (scansExplorerApi) {
        scansExplorerApi.applyExternalFilter({ status: "Failed,Partial", project: btn.dataset.project });
      }
    });
  });

  document.querySelectorAll(".error-category-link").forEach((btn) => {
    btn.addEventListener("click", () => {
      if (!scansExplorerApi) return;
      scansExplorerApi.applyExternalFilter({
        status: "Failed,Partial",
        scanIds: btn.dataset.scanIds.split(" ").filter(Boolean),
        label: btn.dataset.errorCategory,
      });
    });
  });

  document.querySelectorAll("[data-kpi-link]").forEach((btn) => {
    btn.addEventListener("click", () => {
      if (!scansExplorerApi) return;
      const kind = btn.dataset.kpiLink;
      // "long" means only the scans that actually crossed the threshold --
      // "variance" means every scan for the project, highlighted relative
      // to its own average, per how each KPI is actually defined.
      scansExplorerApi.applyExternalFilter({
        project: btn.dataset.project,
        highlight: kind,
        minDuration: kind === "long" ? 30 : null,
      });
    });
  });
}

// The workflow API has no dedicated error/status field (see
// cx_client.get_scan_workflow) -- a problem shows up as wording inside a
// step's own "info"/"source" text, so that's what gets scanned.
const WORKFLOW_ERROR_PATTERN = /\b(error|fail(?:ed|ure)?|exception|denied|rejected|invalid|timed?\s*out|abort(?:ed)?|unable to|not found)\b/i;

function initWorkflowPanel() {
  const panel = document.getElementById("workflow-panel");
  const backdrop = document.getElementById("workflow-panel-backdrop");
  const closeBtn = document.getElementById("workflow-panel-close");
  const title = document.getElementById("workflow-panel-title");
  const meta = document.getElementById("workflow-panel-meta");
  const body = document.getElementById("workflow-panel-body");
  const triggers = document.querySelectorAll(".workflow-btn");
  if (!panel || !backdrop || !closeBtn || !title || !meta || !body || !triggers.length) return;

  function openPanel() {
    backdrop.hidden = false;
    panel.classList.add("panel-open");
    panel.setAttribute("aria-hidden", "false");
  }

  function closePanel() {
    panel.classList.remove("panel-open");
    panel.setAttribute("aria-hidden", "true");
    backdrop.hidden = true;
  }

  function clearBody() {
    while (body.firstChild) body.removeChild(body.firstChild);
  }

  function renderMessage(message) {
    clearBody();
    const p = document.createElement("p");
    p.className = "section-note";
    p.textContent = message;
    body.appendChild(p);
  }

  function renderSteps(steps) {
    clearBody();
    if (!steps || !steps.length) {
      renderMessage("No workflow steps returned for this scan.");
      return;
    }

    const list = document.createElement("ol");
    list.className = "workflow-step-list";
    steps.forEach((step) => {
      const info = step.info || "";
      const source = step.source || "";
      const isError = WORKFLOW_ERROR_PATTERN.test(info) || WORKFLOW_ERROR_PATTERN.test(source);

      const item = document.createElement("li");
      item.className = "workflow-step" + (isError ? " workflow-step-error" : "");

      const head = document.createElement("div");
      head.className = "workflow-step-head";
      const sourceSpan = document.createElement("span");
      sourceSpan.className = "workflow-step-source";
      sourceSpan.textContent = source || "Unknown source";
      head.appendChild(sourceSpan);
      if (step.timestamp) {
        const timeSpan = document.createElement("span");
        timeSpan.className = "workflow-step-time";
        timeSpan.textContent = step.timestamp;
        head.appendChild(timeSpan);
      }
      item.appendChild(head);

      const infoP = document.createElement("p");
      infoP.className = "workflow-step-info";
      infoP.textContent = info;
      item.appendChild(infoP);

      list.appendChild(item);
    });
    body.appendChild(list);
  }

  triggers.forEach((btn) => {
    btn.addEventListener("click", async () => {
      const scanId = btn.dataset.scanId;
      title.textContent = "Scan Workflow";
      meta.textContent = `Scan ${scanId}`;
      renderMessage("Loading...");
      openPanel();
      try {
        const resp = await fetch(`/scans/${encodeURIComponent(scanId)}/workflow`);
        const data = await resp.json();
        if (!resp.ok) {
          renderMessage((data && data.error) || "Could not load the scan workflow.");
          return;
        }
        renderSteps(data.steps);
      } catch (err) {
        renderMessage("Could not load the scan workflow.");
      }
    });
  });

  closeBtn.addEventListener("click", closePanel);
  backdrop.addEventListener("click", closePanel);
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closePanel();
  });
}

// Known defaultRepositorySettings keys -> a readable label. Falls back to a
// camelCase-to-Title-Case split for any key added on the tenant side later.
const SCM_SETTING_LABELS = {
  sastScannerEnabled: "SAST Scanner",
  scaScannerEnabled: "SCA Scanner",
  kicsScannerEnabled: "KICS Scanner",
  apiSecScannerEnabled: "API Security Scanner",
  containerScannerEnabled: "Container Scanner",
  ossfScoreCardScannerEnabled: "OSSF Scorecard Scanner",
  secretsDetectionScannerEnabled: "Secrets Detection Scanner",
  aiscScannerEnabled: "AI Security (AISC) Scanner",
  sastIncrementalScan: "SAST Incremental Scan",
  prDecorationEnabled: "PR Decoration",
  scaAutoPrEnabled: "SCA Auto Pull Request",
  commitIdScanTagEnabled: "Commit ID Scan Tag",
  remediationSeverities: "Remediation Severities",
};

function humanizeScmSetting(key) {
  if (SCM_SETTING_LABELS[key]) return SCM_SETTING_LABELS[key];
  return key.replace(/([A-Z])/g, " $1").replace(/^./, (c) => c.toUpperCase()).trim();
}

function formatScmSettingValue(value) {
  if (Array.isArray(value)) return value.length ? value.join(", ") : "None";
  if (typeof value === "boolean") return value ? "Enabled" : "Disabled";
  return String(value);
}

function initScmOrgPanel() {
  const panel = document.getElementById("scm-org-panel");
  const backdrop = document.getElementById("scm-org-panel-backdrop");
  const closeBtn = document.getElementById("scm-org-panel-close");
  const title = document.getElementById("scm-org-panel-title");
  const meta = document.getElementById("scm-org-panel-meta");
  const body = document.getElementById("scm-org-panel-body");
  const triggers = document.querySelectorAll(".scm-org-box");
  if (!panel || !backdrop || !closeBtn || !title || !meta || !body || !triggers.length) return;

  function openPanel() {
    backdrop.hidden = false;
    panel.classList.add("panel-open");
    panel.setAttribute("aria-hidden", "false");
  }

  function closePanel() {
    panel.classList.remove("panel-open");
    panel.setAttribute("aria-hidden", "true");
    backdrop.hidden = true;
  }

  function clearBody() {
    while (body.firstChild) body.removeChild(body.firstChild);
  }

  function renderMessage(message) {
    clearBody();
    const p = document.createElement("p");
    p.className = "section-note";
    p.textContent = message;
    body.appendChild(p);
  }

  function renderOrg(data) {
    clearBody();
    const settingKeys = Object.keys(data.settings || {});
    if (!settingKeys.length) {
      renderMessage("No default repository settings returned for this org.");
      return;
    }
    settingKeys.forEach((key) => {
      const setting = data.settings[key];
      const row = document.createElement("div");
      row.className = "scm-setting-row";

      const name = document.createElement("span");
      name.className = "scm-setting-name";
      name.textContent = humanizeScmSetting(key);
      row.appendChild(name);

      const valueWrap = document.createElement("span");
      const value = document.createElement("span");
      value.textContent = formatScmSettingValue(setting.value);
      valueWrap.appendChild(value);
      const override = document.createElement("span");
      override.className = "scm-setting-override";
      override.textContent = setting.allowOverride ? " (override allowed)" : " (locked)";
      valueWrap.appendChild(override);
      row.appendChild(valueWrap);

      body.appendChild(row);
    });
  }

  triggers.forEach((btn) => {
    btn.addEventListener("click", async () => {
      const orgId = btn.dataset.orgId;
      title.textContent = "Org Settings";
      meta.textContent = "Loading...";
      renderMessage("Loading...");
      openPanel();
      try {
        const resp = await fetch(`/scm-orgs/${encodeURIComponent(orgId)}/detail`);
        const data = await resp.json();
        if (!resp.ok) {
          meta.textContent = "";
          renderMessage((data && data.error) || "Could not load org settings.");
          return;
        }
        title.textContent = data.org_identity;
        meta.textContent = `${data.is_user_org ? "Personal org" : "Organization"} -- webhook ${data.webhook_enabled ? "enabled" : "disabled"}${data.webhook_editable ? "" : " (not editable)"}`;
        renderOrg(data);
      } catch (err) {
        meta.textContent = "";
        renderMessage("Could not load org settings.");
      }
    });
  });

  closeBtn.addEventListener("click", closePanel);
  backdrop.addEventListener("click", closePanel);
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closePanel();
  });
}

// Pagination only (no sort/filter) for simple KPI tables like Long-Running
// Scans, where the row order from the server is already the right order.
function initSimplePagination(tableId, pageSize, prevId, nextId, labelId) {
  const table = document.getElementById(tableId);
  if (!table) return;
  const tbody = table.tBodies[0];
  const allRows = Array.from(tbody.rows);
  const prevBtn = document.getElementById(prevId);
  const nextBtn = document.getElementById(nextId);
  const label = document.getElementById(labelId);
  let page = 0;

  function render() {
    allRows.forEach((r) => {
      if (r.parentNode) r.parentNode.removeChild(r);
    });
    const totalPages = Math.max(1, Math.ceil(allRows.length / pageSize));
    if (page >= totalPages) page = totalPages - 1;
    if (page < 0) page = 0;
    const start = page * pageSize;
    const pageRows = allRows.slice(start, start + pageSize);
    pageRows.forEach((r) => tbody.appendChild(r));

    if (label) {
      label.textContent = allRows.length === 0
        ? "No matching projects"
        : `Showing ${start + 1}-${start + pageRows.length} of ${allRows.length}`;
    }
    if (prevBtn) prevBtn.disabled = page <= 0;
    if (nextBtn) nextBtn.disabled = start + pageRows.length >= allRows.length;
  }

  if (prevBtn) prevBtn.addEventListener("click", () => { page -= 1; render(); });
  if (nextBtn) nextBtn.addEventListener("click", () => { page += 1; render(); });
  render();
}

// Every multi-column .data-table gets a drag handle on each header cell's
// right edge. A drag trades width between that column and its right-hand
// neighbour, so the table (and the page) never changes overall width; widths
// are kept as percentages so the table still scales with the window.
const MIN_COLUMN_PX = 48;

function initResizableColumns() {
  document.querySelectorAll("table.data-table").forEach((table) => {
    const headerRow = table.tHead && table.tHead.rows[0];
    if (!headerRow || headerRow.cells.length < 2 || table.dataset.resizable) return;
    table.dataset.resizable = "1";
    const cells = Array.from(headerRow.cells);
    cells.slice(0, -1).forEach((th, index) => {
      const handle = document.createElement("span");
      handle.className = "col-resize-handle";
      handle.setAttribute("aria-hidden", "true");
      handle.addEventListener("click", (event) => event.stopPropagation());  // don't trigger column sort
      handle.addEventListener("dblclick", (event) => { event.stopPropagation(); resetColumnWidths(table, cells); });
      handle.addEventListener("pointerdown", (event) => startColumnResize(event, table, cells, index, handle));
      th.appendChild(handle);
    });
  });
}

function freezeColumnWidths(table, cells) {
  if (table.classList.contains("cols-resized")) return;
  const tableWidth = table.getBoundingClientRect().width;
  const widths = cells.map((cell) => cell.getBoundingClientRect().width);
  cells.forEach((cell, i) => { cell.style.width = `${(widths[i] / tableWidth) * 100}%`; });
  table.classList.add("cols-resized");
}

function resetColumnWidths(table, cells) {
  cells.forEach((cell) => { cell.style.width = ""; });
  table.classList.remove("cols-resized");
}

function startColumnResize(event, table, cells, index, handle) {
  if (event.button !== 0) return;
  event.preventDefault();
  event.stopPropagation();
  freezeColumnWidths(table, cells);

  const left = cells[index];
  const right = cells[index + 1];
  const tableWidth = table.getBoundingClientRect().width;
  const startX = event.clientX;
  const startLeft = left.getBoundingClientRect().width;
  const startRight = right.getBoundingClientRect().width;

  handle.setPointerCapture(event.pointerId);
  table.classList.add("col-resizing");

  const onMove = (moveEvent) => {
    const delta = Math.max(
      MIN_COLUMN_PX - startLeft,
      Math.min(moveEvent.clientX - startX, startRight - MIN_COLUMN_PX),
    );
    left.style.width = `${((startLeft + delta) / tableWidth) * 100}%`;
    right.style.width = `${((startRight - delta) / tableWidth) * 100}%`;
  };
  const onEnd = () => {
    handle.removeEventListener("pointermove", onMove);
    handle.removeEventListener("pointerup", onEnd);
    handle.removeEventListener("pointercancel", onEnd);
    table.classList.remove("col-resizing");
  };
  handle.addEventListener("pointermove", onMove);
  handle.addEventListener("pointerup", onEnd);
  handle.addEventListener("pointercancel", onEnd);
}

function initAnalyzerConfig() {
  document.querySelectorAll(".rule-enabled-toggle").forEach((checkbox) => {
    checkbox.addEventListener("change", () => {
      const row = checkbox.closest("tr");
      if (row) row.classList.toggle("rule-row-disabled", !checkbox.checked);
    });
  });
}

document.addEventListener("DOMContentLoaded", () => {
  wireSectionSync();
  wireSyncAll();
  wireCategoryToggles();
  initCompareSelection();
  initPresetsTable();
  initFeedbackAppsTable();
  initProjectManagementTables();
  initStaleProjectsTable();
  initPresetPanel();
  wireSelectAll("combine-select-all", "diff-checkbox");
  wireSelectAll("update-select-all", "update-checkbox");
  initDeleteSelection();
  initUpdateCounts();
  initScansExplorer();
  initKpiInteractions();
  initWorkflowPanel();
  initScmOrgPanel();
  initSimplePagination("long-running-table", 10, "long-running-prev", "long-running-next", "long-running-range-label");
  initAnalyzerConfig();
  initResizableColumns();
});
