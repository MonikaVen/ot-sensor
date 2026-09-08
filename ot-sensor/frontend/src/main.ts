import { ack, control, fetchSnapshot } from "./api";
import { assetMapSvg } from "./map";
import type { Asset, Incident, Snapshot } from "./types";
import "./styles.css";

type Overlay = "comms" | "deps";

const state = {
  snap: null as Snapshot | null,
  error: null as string | null,
  overlay: "comms" as Overlay,
  selectedAsset: null as string | null,
  selectedIncident: null as string | null,
  toastId: null as string | null,
};

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] ?? c);
}

function hoursUntil(iso: string): string {
  const ms = new Date(iso).getTime() - Date.now();
  const h = ms / 3600000;
  if (h < 0) return "overdue";
  if (h < 1) return `${Math.round(h * 60)} min`;
  return `${h.toFixed(1)} h`;
}

function tone(status: string): string {
  if (status === "ok" || status === "fired") return "ok";
  if (status === "alert" || status === "llm_unavailable" || status === "model_unavailable") return "warn";
  return "idle";
}

function healthHtml(snap: Snapshot): string {
  return `<div class="health-row" aria-label="Service health">${snap.services
    .map(
      (s) => `<div class="health-pill ${tone(s.status)}" title="${esc(s.status)}">
        <span class="dot"></span><span class="health-label">${esc(s.label)}</span>
        <span class="health-status">${esc(s.status)}</span></div>`,
    )
    .join("")}</div>`;
}

function kv(rows: Array<[string, string]>): string {
  return `<dl class="kv">${rows
    .map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`)
    .join("")}</dl>`;
}

function caseHtml(inc: Incident, copilot: Snapshot["copilot"]): string {
  const nis2 = inc.nis2
    ? `<div class="nis2"><h3>NIS2 clocks</h3>
        <p>Early warning (24h): ${esc(hoursUntil(inc.nis2.early_warning_due))}</p>
        <p>Notification (72h): ${esc(hoursUntil(inc.nis2.notification_due))}</p>
        <p>Human confirm: ${inc.nis2.human_confirm ? "yes" : "required before CSIRT"}</p></div>`
    : "";
  const slm = copilot && copilot.incident_id === inc.incident_id ? `<p class="muted">SLM ${esc(copilot.status)}</p>` : "";
  return `<section class="case">
    <h2>${esc(inc.incident_id)}</h2>
    <p class="case-title">${esc(inc.title)}</p>
    ${kv([
      ["Criticality", String(inc.risk.max_criticality)],
      ["Risk", String(inc.risk.total)],
      ["Segment", inc.segment],
      ["Assets", inc.asset_ids.join(", ")],
      ["ATT&CK", inc.techniques.join(" ") || "—"],
      ["Impact", inc.impacts.join(" ") || "—"],
    ])}
    ${nis2}${slm}
  </section>`;
}

function assetCard(asset: Asset): string {
  return `<section>
    <h2>${esc(asset.name)}</h2>
    ${kv([
      ["SA", asset.asset_id],
      ["Segment", asset.segment],
      ["Criticality", String(asset.criticality)],
      ["NIS2 service", asset.nis2_service || "none"],
      ["Live", asset.live ? "talking" : "not seen"],
      ["PGNs", asset.channels_seen.join(", ") || "—"],
    ])}
  </section>`;
}

function sideHtml(snap: Snapshot): string {
  const inc =
    snap.incidents.find((i) => i.incident_id === state.selectedIncident) ?? snap.incidents[0] ?? null;
  const asset = snap.assets.find((a) => a.asset_id === state.selectedAsset) ?? null;
  const list =
    snap.incidents.length === 0
      ? `<p class="muted">No correlated cases. Detections join here, not as raw alerts.</p>`
      : `<ul class="inc-list">${snap.incidents
          .map(
            (i) => `<li><button type="button" class="inc-row ${state.selectedIncident === i.incident_id ? "sel" : ""}" data-incident="${esc(i.incident_id)}">
              <span class="inc-id">${esc(i.incident_id)}</span>
              <span class="inc-title">${esc(i.title)}</span>
              <span class="inc-risk">${esc(i.severity)} · ${i.risk.total}${i.risk.nis2_significant ? " · NIS2" : ""}</span>
            </button></li>`,
          )
          .join("")}</ul>`;
  return `<aside class="side">
    <section><h2>Incidents</h2>${list}</section>
    ${inc ? caseHtml(inc, snap.copilot) : ""}
    ${asset ? assetCard(asset) : ""}
  </aside>`;
}

function toastHtml(inc: Incident): string {
  return `<div class="toast-layer"><div class="toast" role="alertdialog" aria-labelledby="toast-title">
    <div class="toast-kicker">${inc.risk.nis2_significant ? "NIS2 significant" : "Incident"} · ${esc(inc.incident_id)}</div>
    <h2 id="toast-title">${esc(inc.title)}</h2>
    <p class="toast-meta">${esc(inc.severity.toUpperCase())} · risk ${inc.risk.total} · ${esc(inc.segment)} · ${esc(inc.techniques.join(", ") || "unclassified")}</p>
    ${inc.body ? `<p class="toast-body">${esc(inc.body)}</p>` : ""}
    <div class="toast-actions">
      <button type="button" class="btn primary" data-toast="open">Open case</button>
      <button type="button" class="btn" data-toast="dismiss">Dismiss</button>
    </div>
  </div></div>`;
}

function render(): void {
  const root = document.getElementById("root");
  if (!root) return;
  const snap = state.snap;
  const toast = snap?.incidents.find((i) => i.incident_id === state.toastId) ?? null;
  root.innerHTML = `<div class="shell">
    <header class="top">
      <div>
        <p class="kicker">Listen-only · NMEA 2000</p>
        <h1>OT sensor</h1>
      </div>
      <dl class="top-stats">
        <div><dt>Hull</dt><dd>${esc(snap?.hull ?? "—")}</dd></div>
        <div><dt>Mode</dt><dd>${esc(snap?.mode ?? "—")}</dd></div>
        <div><dt>Phase</dt><dd>${esc(snap?.plant?.phase ?? "idle")}</dd></div>
        <div><dt>SOG</dt><dd>${snap?.plant?.sog_kn != null ? `${snap.plant.sog_kn.toFixed(1)} kn` : "—"}</dd></div>
        <div><dt>Cases</dt><dd>${snap?.stats.open_incidents ?? 0}</dd></div>
      </dl>
      <div class="controls">
        <button type="button" class="btn primary" data-ctrl="${snap?.running ? "pause" : "start"}">${snap?.running ? "Pause" : "Start"}</button>
        <button type="button" class="btn" data-ctrl="reset-spoof">Reset spoof</button>
        <button type="button" class="btn" data-ctrl="reset-underway">Reset underway</button>
      </div>
    </header>
    ${snap ? healthHtml(snap) : ""}
    ${state.error ? `<p class="banner">${esc(state.error)} — start with ot-dashboard on :8443</p>` : ""}
    <div class="main">
      <div class="map-col">
        <div class="map-toolbar">
          <h2>Asset map</h2>
          <div class="seg">
            <button type="button" class="btn ${state.overlay === "comms" ? "active" : ""}" data-overlay="comms">Communications</button>
            <button type="button" class="btn ${state.overlay === "deps" ? "active" : ""}" data-overlay="deps">Dependencies</button>
          </div>
          <p class="legend"><span class="swatch ok"></span> expected <span class="swatch bad"></span> violation <span class="swatch dep"></span> depends_on</p>
        </div>
        ${
          snap
            ? assetMapSvg(snap.assets, snap.comms, snap.dependencies, state.overlay, state.selectedAsset)
            : `<p class="muted">Waiting for TAP snapshot…</p>`
        }
      </div>
      ${snap ? sideHtml(snap) : ""}
    </div>
    ${toast ? toastHtml(toast) : ""}
  </div>`;
}

async function dismissToast(): Promise<void> {
  const id = state.toastId;
  state.toastId = null;
  render();
  if (id) await ack([id]);
}

async function runControl(action: string, attack?: string): Promise<void> {
  try {
    state.snap = await control(action, attack);
    state.error = null;
    render();
  } catch (e) {
    state.error = e instanceof Error ? e.message : "control failed";
    render();
  }
}

function eventEl(ev: Event): Element | null {
  const n = ev.target;
  if (n instanceof Element) return n;
  if (n instanceof Node) return n.parentElement;
  return null;
}

function dataAttr(el: Element | null, name: string): string | null {
  return el?.getAttribute(`data-${name}`) ?? null;
}

function bind(): void {
  const root = document.getElementById("root");
  if (!root) return;
  root.addEventListener("click", (ev) => {
    const t = eventEl(ev);
    if (!t) return;
    const overlay = dataAttr(t.closest("[data-overlay]"), "overlay");
    if (overlay === "comms" || overlay === "deps") {
      state.overlay = overlay;
      render();
      return;
    }
    const ctrl = dataAttr(t.closest("[data-ctrl]"), "ctrl");
    if (ctrl === "start" || ctrl === "pause") {
      void runControl(ctrl);
      return;
    }
    if (ctrl === "reset-spoof") {
      void runControl("reset", "gps-spoof-primary");
      return;
    }
    if (ctrl === "reset-underway") {
      void runControl("reset", "");
      return;
    }
    const assetId = dataAttr(t.closest("[data-asset]"), "asset");
    if (assetId) {
      state.selectedAsset = assetId;
      const hit = state.snap?.assets.find((a) => a.asset_id === assetId);
      if (hit?.incident_ids[0]) state.selectedIncident = hit.incident_ids[0];
      render();
      return;
    }
    const incidentId = dataAttr(t.closest("[data-incident]"), "incident");
    if (incidentId) {
      state.selectedIncident = incidentId;
      render();
      return;
    }
    const toastAct = dataAttr(t.closest("[data-toast]"), "toast");
    if (toastAct === "open" && state.toastId) {
      state.selectedIncident = state.toastId;
      void dismissToast();
      return;
    }
    if (toastAct === "dismiss") {
      void dismissToast();
    }
  });
}

async function pull(): Promise<void> {
  try {
    const next = await fetchSnapshot();
    state.snap = next;
    state.error = null;
    state.toastId = state.toastId ?? next.new_incident_ids[0] ?? null;
    state.selectedIncident = state.selectedIncident ?? next.incidents[0]?.incident_id ?? null;
    render();
  } catch (e) {
    state.error = e instanceof Error ? e.message : "snapshot failed";
    render();
  }
}

bind();
void pull();
setInterval(() => void pull(), 800);
