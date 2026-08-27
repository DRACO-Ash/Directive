/* The console's behaviour.
 *
 * Every value from a record reaches the page through textContent, never through innerHTML
 * or string concatenation into markup, so a record field cannot become script however it
 * was stored. The server escapes too; this is the second of the two.
 *
 * There is no access decision here. The sidebar and the forms are a convenience: every
 * route behind them is gated server-side, and hiding a button has never stopped anybody.
 */
(() => {
  "use strict";

  const state = { registers: {}, counts: {}, states: {}, csrf: null };

  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => Array.from(document.querySelectorAll(selector));

  function notify(message, ok) {
    const box = $("#notice");
    box.textContent = message;
    box.className = `notice show ${ok ? "notice-ok" : "notice-bad"}`;
    if (ok) setTimeout(() => box.classList.remove("show"), 4000);
  }

  async function call(path, options = {}) {
    const headers = { "Content-Type": "application/json" };
    if (state.csrf) headers["X-CSRF-Token"] = state.csrf;
    const response = await fetch(path, { credentials: "same-origin", headers, ...options });
    const token = response.headers.get("X-CSRF-Token");
    if (token) state.csrf = token;
    if (response.status === 401) {
      window.location.href = "/sign-in";
      return null;
    }
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || `request failed (${response.status})`);
    return body;
  }

  function cell(text, className) {
    const td = document.createElement("td");
    td.textContent = text ?? "";
    if (className) td.className = className;
    return td;
  }

  function pill(value) {
    const td = document.createElement("td");
    const span = document.createElement("span");
    span.className = `pill pill-${String(value || "").toLowerCase()}`;
    span.textContent = String(value || "").replace(/_/g, " ");
    td.append(span);
    return td;
  }

  function transitionButtons(register, record) {
    const td = document.createElement("td");
    const wrap = document.createElement("div");
    wrap.className = "row-actions";
    for (const next of state.states[register] || []) {
      if (next === record.state) continue;
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = next.replace(/_/g, " ");
      button.addEventListener("click", () => move(register, record.id, next));
      wrap.append(button);
    }
    td.append(wrap);
    return td;
  }

  function renderRegister(register) {
    const body = document.querySelector(`[data-rows="${register}"]`);
    const empty = document.querySelector(`[data-empty="${register}"]`);
    const rows = state.registers[register] || [];
    body.replaceChildren();
    empty.classList.toggle("hidden", rows.length > 0);

    for (const record of rows) {
      const tr = document.createElement("tr");
      tr.append(cell(record.reference || record.id, "id"));
      tr.append(cell(record.title));
      tr.append(cell(record.owner || "unassigned"));
      tr.append(pill(record.state));
      tr.append(cell((record.updated || "").replace("T", " ").replace("Z", ""), "stamp"));
      tr.append(transitionButtons(register, record));
      body.append(tr);
    }
  }

  function renderCounts() {
    const cards = $("#cards");
    cards.replaceChildren();
    for (const [register, counts] of Object.entries(state.counts)) {
      const card = document.createElement("div");
      card.className = "card";
      const label = document.createElement("div");
      label.className = "card-label";
      label.textContent = register;
      const value = document.createElement("div");
      value.className = "card-value";
      value.textContent = String(counts.total ?? 0);
      const note = document.createElement("div");
      note.className = "card-note";
      note.textContent = Object.entries(counts)
        .filter(([key, count]) => key !== "total" && count > 0)
        .map(([key, count]) => `${count} ${key.toLowerCase().replace(/_/g, " ")}`)
        .join(" · ") || "nothing recorded";
      card.append(label, value, note);
      cards.append(card);

      const badge = document.querySelector(`[data-count="${register}"]`);
      if (badge) badge.textContent = String(counts.total ?? 0);
    }
  }

  function renderAudit(entries) {
    const body = $("#audit-rows");
    body.replaceChildren();
    $("#audit-empty").classList.toggle("hidden", entries.length > 0);
    for (const entry of entries) {
      const tr = document.createElement("tr");
      tr.className = "entry";
      tr.append(cell((entry.timestamp || "").replace("T", " ").replace("Z", ""), "stamp"));
      tr.append(cell(entry.actor));
      tr.append(cell(entry.action));
      tr.append(cell(`${entry.resource} ${entry.resource_id}`));
      tr.append(cell(entry.old_state && entry.new_state ? `${entry.old_state} → ${entry.new_state}` : "—"));
      tr.append(cell((entry.entry_hash || "").slice(0, 16), "entry-hash"));
      body.append(tr);
    }
  }

  async function refresh() {
    const data = await call("/api/registers");
    if (!data) return;
    state.registers = data.registers;
    state.counts = data.counts;
    state.states = data.states;
    renderCounts();
    for (const register of Object.keys(state.registers)) renderRegister(register);
  }

  async function refreshAudit() {
    const data = await call("/api/audit");
    if (data) renderAudit(data.entries);
  }

  async function move(register, id, next) {
    try {
      await call(`/api/registers/${register}/${id}`, {
        method: "PATCH",
        body: JSON.stringify({ state: next }),
      });
      notify(`${id} moved to ${next.replace(/_/g, " ").toLowerCase()}, and the audit entry is written.`, true);
      await refresh();
      await refreshAudit();
    } catch (error) {
      notify(error.message, false);
    }
  }

  function show(view) {
    $$("[id^='panel-']").forEach((panel) => panel.classList.add("hidden"));
    const panel = $(`#panel-${view}`);
    if (panel) panel.classList.remove("hidden");
    $$(".nav button").forEach((button) => {
      button.toggleAttribute("aria-current", button.dataset.view === view);
      if (button.dataset.view === view) button.setAttribute("aria-current", "page");
    });
    const button = document.querySelector(`.nav button[data-view="${view}"]`);
    $("#view-title").textContent = button ? button.textContent.trim().split("\n")[0] : "Dashboard";
    if (view === "audit") refreshAudit();
  }

  function wire() {
    $$(".nav button").forEach((button) =>
      button.addEventListener("click", () => show(button.dataset.view)),
    );

    $$("form.record").forEach((form) =>
      form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const register = form.dataset.register;
        const payload = Object.fromEntries(
          Array.from(new FormData(form).entries()).filter(([, value]) => String(value).trim() !== ""),
        );
        try {
          const body = await call(`/api/registers/${register}`, {
            method: "POST",
            body: JSON.stringify(payload),
          });
          form.reset();
          notify(`${body.record.id} recorded, with its audit entry.`, true);
          await refresh();
        } catch (error) {
          notify(error.message, false);
        }
      }),
    );

    $("#verify").addEventListener("click", async () => {
      try {
        const verdict = await call("/api/audit/verify", { method: "POST" });
        notify(verdict.summary, verdict.ok);
      } catch (error) {
        notify(error.message, false);
      }
    });
  }

  document.addEventListener("DOMContentLoaded", async () => {
    wire();
    try {
      await refresh();
    } catch (error) {
      notify(error.message, false);
    }
  });
})();
