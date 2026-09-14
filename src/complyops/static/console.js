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

  const state = { registers: {}, counts: {}, states: {}, fields: {}, titles: {}, csrf: null, open: null };

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

  function stamp(value) {
    // The `Z` used to be stripped, leaving `2026-09-14 21:38:08` on a screen an assessor
    // reads, in a country an hour off UTC for seven months of the year.
    if (!value) return "";
    return `${String(value).replace("T", " ").replace("Z", "")} UTC`;
  }

  function label(register, name) {
    const found = (state.fields[register] || []).find((field) => field.name === name);
    return found ? found.label : name.replace(/_/g, " ");
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
      // Without this a screen-reader user hears "approved button" forty times with no idea
      // which record each one belongs to.
      button.setAttribute("aria-label", `Move ${record.reference || record.id} to ${next.replace(/_/g, " ").toLowerCase()}`);
      button.addEventListener("click", () => move(register, record.id, next));
      wrap.append(button);
    }
    td.append(wrap);
    return td;
  }

  // The columns a register shows beyond the common ones. Derived from its schema, so a
  // field added to a register appears here without a second edit. `summary` and `notes`
  // are deliberately not columns: they are long, and they live in the drawer.
  function extraColumns(register) {
    return (state.fields[register] || [])
      .filter((field) => !["title", "owner", "reference", "summary", "notes"].includes(field.name))
      .slice(0, 3);
  }

  function renderHead(register) {
    const head = document.querySelector(`[data-head="${register}"]`);
    if (!head) return;
    head.replaceChildren();
    const names = ["Reference", "Title", "Owner", "State"];
    for (const field of extraColumns(register)) names.push(field.label);
    names.push("Updated", "Move to");
    for (const name of names) {
      const th = document.createElement("th");
      th.scope = "col";
      th.textContent = name;
      head.append(th);
    }
  }

  function renderRegister(register) {
    const body = document.querySelector(`[data-rows="${register}"]`);
    const empty = document.querySelector(`[data-empty="${register}"]`);
    const rows = state.registers[register] || [];
    renderHead(register);
    body.replaceChildren();
    empty.classList.toggle("hidden", rows.length > 0);

    for (const record of rows) {
      const tr = document.createElement("tr");
      tr.tabIndex = 0;
      tr.className = "row-open";
      // A row header, so a screen reader announces which record a row action belongs to.
      const th = document.createElement("th");
      th.scope = "row";
      th.className = "id";
      th.textContent = record.reference || record.id;
      tr.append(th);
      tr.append(cell(record.title));
      tr.append(cell(record.owner || "unassigned"));
      tr.append(pill(record.state));
      for (const field of extraColumns(register)) {
        const value = record[field.name] || "";
        tr.append(cell(String(value).replace(/_/g, " ") || "—"));
      }
      tr.append(cell(stamp(record.updated), "stamp"));
      tr.append(transitionButtons(register, record));
      const open = (event) => {
        if (event.target.closest("button")) return;
        openDrawer(register, record.id);
      };
      tr.addEventListener("click", open);
      tr.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          openDrawer(register, record.id);
        }
      });
      body.append(tr);
    }
  }

  // ---- The record drawer -------------------------------------------------------------
  // Before this existed a record was write-only: you could create one and move its state,
  // and there was no way to correct a typo, read back a 2,000 character summary, or see
  // any field the six table columns did not carry.

  function findRecord(register, id) {
    return (state.registers[register] || []).find((row) => row.id === id) || null;
  }

  function linkOptions(select, target, chosen) {
    select.replaceChildren();
    const none = document.createElement("option");
    none.value = "";
    none.textContent = "Choose a record";
    select.append(none);
    for (const row of state.registers[target] || []) {
      const option = document.createElement("option");
      option.value = row.id;
      // The identifier AND the title, because `IDTA-0001` alone tells the operator nothing.
      option.textContent = `${row.id} — ${row.title}`;
      if (row.id === chosen) option.selected = true;
      select.append(option);
    }
  }

  function editor(register, record, field) {
    const wrap = document.createElement("div");
    wrap.className = field.long ? "field field-wide" : "field";
    const id = `drawer-${field.name}`;
    const tag = document.createElement("label");
    tag.setAttribute("for", id);
    tag.textContent = field.label;
    let input;
    if (field.kind === "choice") {
      input = document.createElement("select");
      const none = document.createElement("option");
      none.value = "";
      none.textContent = "Not set";
      input.append(none);
      for (const choice of field.choices) {
        const option = document.createElement("option");
        option.value = choice;
        option.textContent = choice.replace(/_/g, " ");
        input.append(option);
      }
      input.value = record[field.name] || "";
    } else if (field.kind === "link") {
      input = document.createElement("select");
      linkOptions(input, field.target, record[field.name]);
    } else if (field.kind === "date") {
      input = document.createElement("input");
      input.type = "date";
      input.value = record[field.name] || "";
    } else if (field.long) {
      input = document.createElement("textarea");
      input.maxLength = field.cap;
      input.value = record[field.name] || "";
    } else {
      input = document.createElement("input");
      input.maxLength = field.cap;
      input.value = record[field.name] || "";
    }
    input.id = id;
    input.dataset.field = field.name;
    // Save on leaving the field, not on every keystroke: every write is an audit entry.
    input.addEventListener("change", () => saveField(register, record.id, field.name, input.value));
    wrap.append(tag, input);
    return wrap;
  }

  function openDrawer(register, id) {
    const record = findRecord(register, id);
    if (!record) return;
    state.open = { register, id };
    $("#drawer-ref").textContent = `${state.titles[register] || register} · ${record.id}`;
    $("#drawer-title").textContent = record.title || record.id;
    const body = $("#drawer-body");
    body.replaceChildren();
    for (const field of state.fields[register] || []) body.append(editor(register, record, field));

    const meta = document.createElement("div");
    meta.className = "drawer-meta";
    meta.textContent = `Created ${stamp(record.created)} · last changed ${stamp(record.updated)}`;
    body.append(meta);

    $("#drawer").classList.remove("hidden");
    $("#scrim").classList.remove("hidden");
    const first = body.querySelector("input, select, textarea");
    if (first) first.focus();
  }

  function closeDrawer() {
    state.open = null;
    $("#drawer").classList.add("hidden");
    $("#scrim").classList.add("hidden");
  }

  async function saveField(register, id, name, value) {
    const record = findRecord(register, id);
    if (record && String(record[name] || "") === String(value)) return;
    try {
      await call(`/api/registers/${register}/${id}`, {
        method: "PATCH",
        body: JSON.stringify({ [name]: value }),
      });
      notify(`${id}: ${label(register, name).toLowerCase()} saved, with its audit entry.`, true);
      await refresh();
      if (state.open) openDrawer(state.open.register, state.open.id);
    } catch (error) {
      notify(error.message, false);
    }
  }

  async function renderSystem() {
    const rows = $("#system-rows");
    rows.replaceChildren();
    try {
      const report = await call("/api/diagnostics");
      for (const [key, value] of Object.entries(report || {})) {
        const tr = document.createElement("tr");
        const th = document.createElement("th");
        th.scope = "row";
        th.textContent = key;
        tr.append(th, cell(typeof value === "object" ? JSON.stringify(value) : String(value)));
        rows.append(tr);
      }
    } catch (error) {
      rows.append(document.createElement("tr")).append(cell(error.message));
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
      tr.append(cell(stamp(entry.timestamp), "stamp"));
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
    state.fields = data.fields || {};
    state.titles = data.titles || {};
    renderCounts();
    for (const register of Object.keys(state.registers)) renderRegister(register);
    // The create forms' link pickers, filled from the records just loaded. A transfer risk
    // assessment could not be created through the interface at all before this: `agreement`
    // is required and no form offered it.
    for (const select of $$("select[data-link]")) linkOptions(select, select.dataset.link, select.value);
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
    // `data-title` rather than the button's text, which carried the count badge and broke
    // whenever the template was reflowed.
    $("#view-title").textContent = button ? button.dataset.title || view : "Dashboard";
    // The subtitle never updated, so every view carried the dashboard's description.
    $("#view-sub").textContent = button ? button.dataset.sub || "" : "";
    closeDrawer();
    if (view === "audit") refreshAudit();
    if (view === "system") renderSystem();
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

    $("#drawer-close").addEventListener("click", closeDrawer);
    $("#scrim").addEventListener("click", closeDrawer);
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") closeDrawer();
    });

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
