// MCP Guard dashboard — polls the proxy's API and fills the static
// markup in index.html with live data. Plain vanilla JS, no build step.

const POLL_INTERVAL_MS = 1500;

// Module-level state: DOM template nodes (captured once, then the
// visible copies are cleared), which tool_id the manifest panel /
// approve-reject buttons currently refer to, and the "stages" object
// from the most recent /api/demo/* call (captured here for a later step
// that will use it to drive a pipeline stepper visualization).
const state = {
  eventTemplate: null,
  toolTemplate: null,
  currentAlertToolId: null,
  currentHeroAlert: null,
  lastDemoStages: null,
  lastEventKeys: null, // `${id}:${status}` per currently-rendered event row, for diffed re-rendering
  paused: false, // when true, the poll loop's setInterval tick is a no-op
};

// ---------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------

async function fetchJSON(url, options) {
  const res = await fetch(url, options);
  if (!res.ok) throw new Error(`${url} responded ${res.status}`);
  return res.json();
}

function timeAgo(isoTimestamp) {
  if (!isoTimestamp) return "";
  const then = new Date(isoTimestamp).getTime();
  if (Number.isNaN(then)) return "";
  const seconds = Math.max(0, Math.floor((Date.now() - then) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ago`;
}

function formatHash(hash) {
  if (!hash) return "";
  if (hash.length <= 20) return hash;
  return `${hash.slice(0, 16)}...${hash.slice(-4)}`;
}

const TYPE_TITLES = {
  silent_mutation: "Manifest Mutation Detected",
  cross_server_hijacking: "Cross-Server Instruction Detected",
  poisoned_description: "Poisoned Description Detected",
  poisoned_output: "Poisoned Output Detected",
  manifest_changed: "Manifest Changed",
  tool_registered: "Tool Registered",
  traffic: "Traffic Event",
};

function titleForAlert(alert) {
  return TYPE_TITLES[alert.type] || alert.message || "Security Event";
}

// Maps an alert to the small status pill shown on its event row:
// blocked -> rose, pending / sanitized output -> amber, else -> emerald.
function badgeForAlert(alert) {
  if (alert.status === "blocked") {
    if (alert.type === "poisoned_output") {
      return { label: "Sanitized", dot: "bg-amber-500", pill: "bg-amber-50 text-amber-800 border border-amber-200/60" };
    }
    return { label: "Blocked", dot: "bg-rose-500", pill: "bg-rose-50 text-rose-700 border border-rose-200/60" };
  }
  if (alert.status === "pending") {
    return { label: "Pending", dot: "bg-amber-500", pill: "bg-amber-50 text-amber-800 border border-amber-200/60" };
  }
  return { label: "Passed", dot: "bg-emerald-500", pill: "bg-emerald-50 text-emerald-700 border border-emerald-200/60" };
}

const TOOL_ROW_STYLE = {
  approved: {
    label: "Trusted",
    rowClass: "flex items-center justify-between py-2.5 px-3.5 rounded-xl hover:bg-slate-50 transition-colors",
    dotClass: "w-2 h-2 rounded-full bg-emerald-500 pulse-glow-emerald",
    statusClass: "font-mono text-xs font-medium text-emerald-600",
  },
  pending: {
    label: "Under Review",
    rowClass: "flex items-center justify-between py-2.5 px-3.5 rounded-xl bg-amber-50/50 border border-amber-100/60 transition-colors",
    dotClass: "w-2 h-2 rounded-full bg-amber-500",
    statusClass: "font-mono text-xs font-semibold text-amber-700",
  },
  blocked: {
    label: "Suspended",
    rowClass: "flex items-center justify-between py-2.5 px-3.5 rounded-xl bg-rose-50/50 border border-rose-100/60 transition-colors",
    dotClass: "w-2 h-2 rounded-full bg-rose-500 pulse-glow-rose",
    statusClass: "font-mono text-xs font-semibold text-rose-700",
  },
};

const HIGHLIGHT_EVENT_ROW_CLASS =
  "py-4 px-3 my-1 -mx-3 rounded-xl ring-1 ring-violet-200/60 bg-violet-50/25 flex items-start justify-between gap-6 group transition-all duration-200 hover:bg-violet-50/50 hover:translate-x-1 cursor-pointer";
const NORMAL_EVENT_ROW_CLASS =
  "py-4 px-3 my-1 -mx-3 rounded-xl flex items-start justify-between gap-6 group transition-all duration-200 hover:bg-violet-50/40 hover:translate-x-1 cursor-pointer";

// ---------------------------------------------------------------------
// One-time setup: capture the two template rows, then clear the lists
// ---------------------------------------------------------------------

function initTemplates() {
  const eventsListEl = document.getElementById("events-list");
  const eventRow = eventsListEl.querySelector("div");
  state.eventTemplate = eventRow.cloneNode(true);
  eventsListEl.innerHTML = "";

  const toolsListEl = document.getElementById("tools-list");
  const toolRow = toolsListEl.querySelector("div");
  state.toolTemplate = toolRow.cloneNode(true);
  toolsListEl.innerHTML = "";
}

// ---------------------------------------------------------------------
// 2. Stats strip
// ---------------------------------------------------------------------

function updateStats(tools, events) {
  document.getElementById("stat-active-tools").textContent = tools.length;
  document.getElementById("stat-trusted").textContent =
    tools.filter((t) => t.status === "approved").length;
  document.getElementById("stat-under-review").textContent =
    tools.filter((t) => t.status === "pending").length;
  // "Threats Blocked" uses the alert feed's severity field (present on
  // every /api/events item) rather than tool status, since it's meant to
  // read as a cumulative security-event count, not a live tool count.
  document.getElementById("stat-threats-blocked").textContent =
    events.filter((e) => e.severity === "high").length;
}

// ---------------------------------------------------------------------
// 3. Proxy status pill
// ---------------------------------------------------------------------

function updateProxyStatus(healthy) {
  const statusEl = document.getElementById("proxy-status");
  const lastSeenEl = document.getElementById("proxy-last-seen");
  const dotEl = statusEl.previousElementSibling; // the small pulsing dot span

  if (healthy) {
    statusEl.textContent = "PROXY ACTIVE";
    lastSeenEl.textContent = "just now";
    if (dotEl) dotEl.className = "w-2 h-2 rounded-full bg-emerald-500 pulse-glow-emerald";
  } else {
    statusEl.textContent = "PROXY OFFLINE";
    lastSeenEl.textContent = "unreachable";
    if (dotEl) dotEl.className = "w-2 h-2 rounded-full bg-rose-500 pulse-glow-rose";
  }
}

// ---------------------------------------------------------------------
// 4. Recent Security Events list
// ---------------------------------------------------------------------

function fillEventRow(row, alert, index) {
  row.className = index === 0 ? HIGHLIGHT_EVENT_ROW_CLASS : NORMAL_EVENT_ROW_CLASS;

  const contentCol = row.children[0];
  const headerRow = contentCol.children[0];
  const titleEl = headerRow.children[0];
  const toolBadgeEl = headerRow.children[1];
  const hashBadgeEl = headerRow.children[2];
  const descEl = contentCol.children[1];
  const timeEl = contentCol.children[2];
  const statusPill = row.children[1];

  titleEl.textContent = titleForAlert(alert);
  toolBadgeEl.textContent = alert.tool_id || "unknown";

  const hash = alert.diff_report ? alert.diff_report.new_fingerprint : null;
  if (hashBadgeEl) {
    if (hash) {
      hashBadgeEl.textContent = `sha256:${formatHash(hash)}`;
    } else {
      hashBadgeEl.remove();
    }
  }

  descEl.textContent = alert.message || "";
  timeEl.textContent = timeAgo(alert.timestamp);

  const badge = badgeForAlert(alert);
  statusPill.className =
    `px-3 py-1 rounded-full text-[11px] font-mono font-medium ${badge.pill} shrink-0 inline-flex items-center gap-1.5`;
  statusPill.innerHTML = `<span class="w-1.5 h-1.5 rounded-full ${badge.dot}"></span>${badge.label}`;
}

// Cheap per-row identity: an alert's id never changes, but its status
// can (e.g. approve/reject) without a new id being issued, so both are
// part of the key — otherwise a status change on an existing row would
// be mistaken for "nothing changed" and silently not repaint.
function eventRowKey(alert) {
  return `${alert.id}:${alert.status}`;
}

// Re-applies just the "newest row" highlight styling across existing
// row elements, without touching their content or re-triggering the
// entrance animation (which is bound to element insertion, not to a
// className change on an element already in the DOM).
function reapplyEventRowEmphasis(container) {
  Array.from(container.children).forEach((row, index) => {
    row.className = index === 0 ? HIGHLIGHT_EVENT_ROW_CLASS : NORMAL_EVENT_ROW_CLASS;
  });
}

function renderAllEventRows(container, recent) {
  container.innerHTML = "";
  recent.forEach((alert, index) => {
    const row = state.eventTemplate.cloneNode(true);
    fillEventRow(row, alert, index);
    container.appendChild(row);
  });
}

function updateEventsList(events) {
  const container = document.getElementById("events-list");
  const recent = events.slice(0, 8);
  const newKeys = recent.map(eventRowKey);

  // Nothing changed since the last poll (the overwhelmingly common case
  // while idle) — skip the DOM entirely so the list stops visibly
  // flickering every 1.5s.
  if (state.lastEventKeys && newKeys.join("|") === state.lastEventKeys.join("|")) {
    return;
  }

  const oldKeys = state.lastEventKeys || [];
  const prependCount = newKeys.length - oldKeys.length;
  // True only when every retained row is unchanged and in the same
  // order — i.e. the new data is exactly N brand-new alerts stacked on
  // top of what was already rendered.
  const isPurePrepend = prependCount > 0 && newKeys.slice(prependCount).every((key, i) => key === oldKeys[i]);

  if (isPurePrepend) {
    // Insert only the new rows (newest first, so build back-to-front
    // to keep them in the right order), leaving every existing row
    // untouched — that's what lets the entrance animation play only
    // for genuinely new alerts instead of the whole list.
    for (let i = prependCount - 1; i >= 0; i--) {
      const row = state.eventTemplate.cloneNode(true);
      fillEventRow(row, recent[i], i);
      container.insertBefore(row, container.firstChild);
    }
    while (container.children.length > recent.length) {
      container.removeChild(container.lastChild);
    }
    reapplyEventRowEmphasis(container);
  } else {
    renderAllEventRows(container, recent);
  }

  state.lastEventKeys = newKeys;
}

// ---------------------------------------------------------------------
// 5. Tool Trust Status list
// ---------------------------------------------------------------------

function fillToolRow(row, tool) {
  const style = TOOL_ROW_STYLE[tool.status] || TOOL_ROW_STYLE.pending;

  row.className = style.rowClass;

  const left = row.children[0];
  const dotEl = left.children[0];
  const nameEl = left.children[1];
  const statusEl = row.children[1];

  dotEl.className = style.dotClass;
  nameEl.textContent = tool.name ? `${tool.name} MCP` : tool.tool_id;
  statusEl.className = style.statusClass;
  statusEl.textContent = style.label;
}

function updateToolsList(tools) {
  const container = document.getElementById("tools-list");
  container.innerHTML = "";

  tools.forEach((tool) => {
    const row = state.toolTemplate.cloneNode(true);
    fillToolRow(row, tool);
    container.appendChild(row);
  });
}

// ---------------------------------------------------------------------
// 6 & 7. Hero alert card + Manifest Inspection panel (share one alert)
// ---------------------------------------------------------------------

function findHeroAlert(events) {
  // /api/events already returns newest-first, so the first match here is
  // the most recent still-blocked alert. severity is deliberately NOT
  // part of this check: once approve/reject moves status off "blocked",
  // the card should disappear even though severity stays "high" forever.
  return events.find((e) => e.status === "blocked") || null;
}

function updateHeroCard(alert) {
  const card = document.getElementById("hero-alert-card");

  if (!alert) {
    card.style.display = "none";
    return;
  }

  card.style.display = "";
  document.getElementById("hero-alert-tool").textContent = alert.tool_id || "";
  document.getElementById("hero-alert-title").textContent = titleForAlert(alert);
  document.getElementById("hero-alert-description").textContent = alert.message || "";
  // #hero-alert-flow-steps is left as static markup per spec.
}

function updateManifestPanel(alert) {
  const panel = document.getElementById("manifest-inspection-panel");

  if (!alert || !alert.diff_report) {
    panel.style.display = "none";
    state.currentAlertToolId = null;
    return;
  }

  const diff = alert.diff_report;
  panel.style.display = "";
  state.currentAlertToolId = alert.tool_id;

  document.getElementById("manifest-hash").textContent = formatHash(diff.new_fingerprint);

  // diff_report.old_description is the trusted baseline's actual
  // description text, captured by differ.py at diff time.
  document.getElementById("manifest-baseline-text").textContent =
    diff.old_description || "(baseline text not included in this diff report)";

  document.getElementById("manifest-untrusted-text").textContent = diff.diff_text || "";

  const changedFields = (diff.changed_fields || []).join(", ");
  document.getElementById("manifest-block-reason").textContent =
    `Risk: ${diff.risk_level || "unknown"} • Changed: ${changedFields || "n/a"}`;
}

// Drops any removed_text snippet that is fully contained in another,
// longer snippet in the same list. scanner.py's regex and LLM layers
// both flag the same sentence in most poisoned-output alerts (with
// slightly different trimming), so without this a naive concatenation
// would duplicate that sentence.
function dedupeRemovedSnippets(removedList) {
  const list = removedList || [];
  return list.filter(
    (snippet, i) => !list.some((other, j) => j !== i && other.length > snippet.length && other.includes(snippet))
  );
}

function updateOutputPanel(alert) {
  const panel = document.getElementById("output-sanitization-panel");

  if (!alert || alert.diff_report || !alert.scan_result) {
    panel.style.display = "none";
    return;
  }

  const scan = alert.scan_result;
  panel.style.display = "";

  document.getElementById("output-panel-tool").textContent = alert.tool_id || "";
  document.getElementById("output-panel-status").textContent = (alert.status || "").toUpperCase();

  const removed = dedupeRemovedSnippets(scan.removed_text);

  // The polled Alert shape only stores cleaned_text + removed_text, not
  // the true original text, so "Original Output" is a best-effort
  // reconstruction (cleaned text with the removed snippets appended)
  // rather than a byte-exact replay of what the tool actually returned.
  document.getElementById("output-original-text").textContent =
    removed.length > 0 ? [scan.cleaned_text, ...removed].filter(Boolean).join(" ") : scan.cleaned_text || "";

  document.getElementById("output-cleaned-text").textContent = scan.cleaned_text || "";

  const removedListEl = document.getElementById("output-removed-list");
  removedListEl.innerHTML = "";
  if (removed.length === 0) {
    const li = document.createElement("li");
    li.className = "text-[11px] font-mono text-slate-400";
    li.textContent = "(nothing removed)";
    removedListEl.appendChild(li);
  } else {
    removed.forEach((snippet) => {
      const li = document.createElement("li");
      li.className =
        "text-[11px] font-mono text-rose-700 bg-rose-50/60 border border-rose-200/50 rounded-lg px-2.5 py-1.5 leading-relaxed line-through decoration-rose-400";
      li.textContent = snippet;
      removedListEl.appendChild(li);
    });
  }

  const patternsEl = document.getElementById("output-matched-patterns");
  patternsEl.innerHTML = "";
  (scan.matched_patterns || []).forEach((pattern) => {
    const chip = document.createElement("span");
    chip.className =
      "inline-flex items-center px-2 py-0.5 rounded-full bg-amber-50 text-amber-700 text-[10px] font-mono font-medium border border-amber-200/60";
    chip.textContent = pattern;
    patternsEl.appendChild(chip);
  });
}

// ---------------------------------------------------------------------
// 8. Approve / Reject buttons
// ---------------------------------------------------------------------

function wireActionButtons() {
  document.getElementById("btn-approve-update").addEventListener("click", async () => {
    if (!state.currentAlertToolId) return;
    try {
      await fetch(`/api/approve/${state.currentAlertToolId}`, { method: "POST" });
    } catch (err) {
      // ignore — next poll cycle will reflect whatever the real state is
    }
    await pollOnce();
  });

  document.getElementById("btn-reject-update").addEventListener("click", async () => {
    if (!state.currentAlertToolId) return;
    try {
      await fetch(`/api/reject/${state.currentAlertToolId}`, { method: "POST" });
    } catch (err) {
      // ignore
    }
    await pollOnce();
  });
}

// "Inspect Raw Payload" (hero card): for an output-type event (the
// current alert has a scan_result, no diff_report), scroll to and
// briefly highlight the Output Sanitization panel. For a manifest-type
// event, or when there's no current alert, it's a no-op — it wasn't
// wired to anything before this change either.
function wireInspectRawPayloadButton() {
  document.getElementById("btn-inspect-raw-payload").addEventListener("click", () => {
    const alert = state.currentHeroAlert;
    if (!alert) return;

    // Manifest-type alerts (have a diff_report) -> Manifest Inspection
    // panel; output-type alerts (scan_result only) -> Output
    // Sanitization panel. Either way this scrolls to and flashes
    // whichever detail panel is actually showing this alert's data, so
    // it's never a dead click regardless of alert type.
    const panel = document.getElementById(
      alert.diff_report ? "manifest-inspection-panel" : "output-sanitization-panel"
    );
    if (!panel || panel.style.display === "none") return;

    panel.scrollIntoView({ behavior: "smooth", block: "center" });
    panel.classList.remove("highlight-flash");
    // force reflow so re-adding the class restarts the animation on repeat clicks
    void panel.offsetWidth;
    panel.classList.add("highlight-flash");
  });
}

// SHA-256 hash "Copy" button in the Manifest Inspection panel.
function wireCopyHashButton() {
  const button = document.getElementById("btn-copy-hash");
  const icon = document.getElementById("copy-hash-icon");
  const label = document.getElementById("copy-hash-label");

  button.addEventListener("click", async () => {
    const hash = document.getElementById("manifest-hash").textContent;
    if (!hash) return;

    try {
      await navigator.clipboard.writeText(hash);
      icon.textContent = "check";
      label.textContent = "Copied";
    } catch (err) {
      icon.textContent = "error";
      label.textContent = "Failed";
    }

    setTimeout(() => {
      icon.textContent = "content_copy";
      label.textContent = "Copy";
    }, 1500);
  });
}

// "Pause Stream" header button: stops/resumes the 1.5s poll loop.
function wirePauseStreamButton() {
  const button = document.getElementById("btn-pause-stream");
  const icon = document.getElementById("pause-stream-icon");
  const label = document.getElementById("pause-stream-label");

  button.addEventListener("click", () => {
    state.paused = !state.paused;
    icon.textContent = state.paused ? "play_arrow" : "pause";
    label.textContent = state.paused ? "Resume Stream" : "Pause Stream";
  });
}

// Manifest Inspection panel's inline live test — read-only scan of
// arbitrary text via /api/demo/scan-description. Purely additive: it
// only touches its own small result line, never the diff/baseline
// content already shown above it in the panel, and has no side effects
// on tool state so it doesn't need to trigger a dashboard refresh.
function wireManifestLiveTest() {
  const input = document.getElementById("manifest-live-test-input");
  const button = document.getElementById("manifest-live-test-btn");
  const resultEl = document.getElementById("manifest-live-test-result");
  const dotEl = document.getElementById("manifest-live-test-dot");
  const textEl = document.getElementById("manifest-live-test-text");

  async function runTest() {
    const text = input.value.trim();
    if (!text) return;

    button.disabled = true;
    const originalLabel = button.textContent;
    button.textContent = "…";

    try {
      const result = await fetchJSON("/api/demo/scan-description", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text }),
      });

      resultEl.classList.remove("hidden");
      resultEl.classList.add("flex");
      if (result.flagged) {
        dotEl.className = "w-2 h-2 rounded-full shrink-0 bg-rose-500";
        textEl.textContent = `Flagged — ${(result.matched_patterns || []).join(", ") || "suspicious instruction"}`;
      } else {
        dotEl.className = "w-2 h-2 rounded-full shrink-0 bg-emerald-500";
        textEl.textContent = "Not flagged — looks benign";
      }
    } catch (err) {
      resultEl.classList.remove("hidden");
      resultEl.classList.add("flex");
      dotEl.className = "w-2 h-2 rounded-full shrink-0 bg-slate-400";
      textEl.textContent = "Could not reach the proxy.";
    }

    button.textContent = originalLabel;
    button.disabled = false;
  }

  button.addEventListener("click", runTest);
  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter") runTest();
  });
}

// ---------------------------------------------------------------------
// Demo Controls (sidebar buttons) — each calls its /api/demo/* endpoint,
// then triggers the same refresh the poll loop does so the dashboard
// updates immediately instead of waiting for the next tick. The
// "stages" object each endpoint returns is stashed on `state` for a
// later step to use (not rendered yet).
// ---------------------------------------------------------------------

function wireDemoButtons() {
  document.querySelectorAll(".demo-btn").forEach((button) => {
    button.addEventListener("click", async () => {
      const endpoint = button.dataset.endpoint;

      button.disabled = true;
      const label = button.querySelector(".demo-btn-label");
      const originalLabel = label.textContent;
      label.textContent = "Running…";

      try {
        const result = await fetchJSON(endpoint, { method: "POST" });
        state.lastDemoStages = result.stages || null;
      } catch (err) {
        // Ignore — pollOnce() below will just show whatever the real
        // backend state is (or silently no-op if the proxy is down).
      }

      // Await the refresh (stats, tools, events, manifest panel state
      // incl. state.currentAlertToolId) BEFORE re-enabling the button —
      // otherwise a fast follow-up click (e.g. Approve, right after an
      // attack finishes) can fire while currentAlertToolId is still
      // unset from the previous alert and silently no-op.
      await pollOnce();

      label.textContent = originalLabel;
      button.disabled = false;
    });
  });
}

// ---------------------------------------------------------------------
// Novel-attack live test (sidebar) — same /api/demo/novel-test endpoint
// the pipeline-stepper step will later visualize; for now just shows a
// one-line flagged/not-flagged result inline.
// ---------------------------------------------------------------------

function wireNovelTest() {
  const input = document.getElementById("novel-test-input");
  const button = document.getElementById("novel-test-btn");
  const resultEl = document.getElementById("novel-test-result");
  const dotEl = document.getElementById("novel-test-dot");
  const textEl = document.getElementById("novel-test-text");

  async function runTest() {
    const text = input.value.trim();
    if (!text) return;

    const originalLabel = button.textContent;
    button.disabled = true;
    button.textContent = "…";

    try {
      const result = await fetchJSON("/api/demo/novel-test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text }),
      });
      state.lastDemoStages = result.stages || null;

      resultEl.classList.remove("hidden");
      resultEl.classList.add("flex");
      if (result.flagged) {
        dotEl.className = "w-2 h-2 rounded-full shrink-0 bg-rose-500";
        textEl.textContent = "Flagged — instruction removed";
      } else {
        dotEl.className = "w-2 h-2 rounded-full shrink-0 bg-emerald-500";
        textEl.textContent = "Not flagged — passed through";
      }
    } catch (err) {
      resultEl.classList.remove("hidden");
      resultEl.classList.add("flex");
      dotEl.className = "w-2 h-2 rounded-full shrink-0 bg-slate-400";
      textEl.textContent = "Could not reach the proxy.";
    }

    await pollOnce();

    button.textContent = originalLabel;
    button.disabled = false;
  }

  button.addEventListener("click", runTest);
  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter") runTest();
  });
}

// ---------------------------------------------------------------------
// 1. Poll loop — fetches everything, then re-renders the whole page
// ---------------------------------------------------------------------

async function pollOnce() {
  let tools, events;
  try {
    [tools, events] = await Promise.all([
      fetchJSON("/api/tools"),
      fetchJSON("/api/events"),
    ]);
  } catch (err) {
    // A failed fetch just skips this update cycle; the page keeps
    // showing whatever it last successfully rendered.
    return;
  }

  updateStats(tools, events);
  updateToolsList(tools);
  updateEventsList(events);

  const heroAlert = findHeroAlert(events);
  state.currentHeroAlert = heroAlert;
  updateHeroCard(heroAlert);
  updateManifestPanel(heroAlert);
  updateOutputPanel(heroAlert);

  try {
    await fetchJSON("/health");
    updateProxyStatus(true);
  } catch (err) {
    updateProxyStatus(false);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  initTemplates();
  wireActionButtons();
  wireInspectRawPayloadButton();
  wireCopyHashButton();
  wirePauseStreamButton();
  wireDemoButtons();
  wireNovelTest();
  wireManifestLiveTest();
  pollOnce();
  setInterval(() => {
    if (!state.paused) pollOnce();
  }, POLL_INTERVAL_MS);
});
