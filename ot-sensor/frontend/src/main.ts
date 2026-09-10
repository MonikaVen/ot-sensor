import { downloadCsv, filterLogs, filterSeries, logId, logSource, logsCsv, plotsCsv, stampName, type ExplorerFilter, type LogSource } from "./explorer";
import { ack, askAssistant, control, fetchAssistant, fetchSnapshot, updateRule } from "./api";
import { assetMapSvg } from "./map";
import { histogramPlot, linePlot, plotColors } from "./plot";
import type { Alert, Asset, AssistantSession, FlowMessage, HistogramRow, HoneypotFeed, Incident, ModelPack, RuleClause, RulePack, Snapshot } from "./types";
import "./styles.css";

type Overlay = "comms" | "deps";
type Page = "map" | "rules" | "models" | "plots" | "correlation" | "honeypot" | "assistant";

const SUGGESTED = [
  "Why did this incident fire?",
  "Which assets are affected, and what depends on them?",
  "Is this more likely an attack or a sensor fault?",
  "What should I check next without writing the bus?",
];

const state = {
  snap: null as Snapshot | null,
  error: null as string | null,
  overlay: "comms" as Overlay,
  page: "map" as Page,
  selectedAsset: null as string | null,
  selectedIncident: null as string | null,
  toastId: null as string | null,
  assistant: null as AssistantSession | null,
  assistantDraft: "",
  assistantBusy: false,
  assistantError: null as string | null,
  plots: {
    from: "",
    to: "",
    source: "both" as LogSource,
    selectedLogs: new Set<string>(),
    selectedPlots: new Set<string>(),
  },
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
  if (status === "alert" || status === "llm_unavailable" || status === "model_unavailable" || status === "down") return "warn";
  if (status === "disabled") return "idle";
  return "idle";
}

function healthHtml(snap: Snapshot): string {
  return `<div class="health-row" aria-label="Service health">${snap.services
    .map((s) => {
      const shown = s.status === "ok" && s.detail ? s.detail : s.status;
      return `<div class="health-pill ${tone(s.status)}" title="${esc(s.label)} · ${esc(shown)}">
        <span class="dot"></span><span class="health-label">${esc(s.label)}</span>
        <span class="health-status">${esc(shown)}</span></div>`;
    })
    .join("")}</div>`;
}

function fmtLive(v: number | null | undefined, unit: string, type: string): string {
  if (v == null || Number.isNaN(v)) return "live —";
  if (type === "bool") return v >= 1 ? "live yes" : "live no";
  const n = Math.abs(v) >= 10 ? v.toFixed(1) : v.toFixed(2);
  return `live ${n}${unit ? " " + unit : ""}`;
}

function packStatus(pack: RulePack): string {
  if (!pack.enabled) return "off";
  if (pack.fired) return "fired";
  return "quiet";
}

function oneRuleWidget(pack: RulePack): string {
  const status = packStatus(pack);
  const groups = pack.groups
    .map((g) => {
      const rows = g.clauses
        .map((c) => {
          const control =
            c.type === "bool"
              ? `<label class="toggle compact"><input type="checkbox" data-clause="${esc(c.id)}" ${c.value ? "checked" : ""}/> require</label>`
              : `<input type="number" min="0" step="any" data-clause="${esc(c.id)}" value="${esc(String(c.value))}" />`;
          return `<div class="clause ${c.met ? "met" : ""} ${g.id === "not" ? "suppress" : ""}">
            <span class="clause-label">${esc(c.label)}</span>
            <span class="op">${esc(c.op)}</span>
            ${control}
            <span class="unit">${esc(c.unit)}</span>
            <span class="live" data-live="${esc(c.feature)}">${esc(fmtLive(c.live, c.unit, c.type))}</span>
          </div>`;
        })
        .join("");
      return `<div class="clause-group"><h3>${esc(g.label)}</h3>${rows}</div>`;
    })
    .join("");
  return `<section class="rules-widget" data-rule-id="${esc(pack.rule_id)}">
    <div class="rule-head">
      <div>
        <h2>${esc(pack.title)}</h2>
        <p class="rule-title">${esc(pack.rule_id)} · v${esc(pack.version)}</p>
        <p class="muted">${esc(pack.blurb)}</p>
        <p class="muted">ATT&amp;CK ${esc(pack.techniques.join(" ") || "—")} · impact ${esc(pack.impacts.join(" ") || "—")}</p>
      </div>
      <div class="rule-head-actions">
        <label class="toggle"><input type="checkbox" data-rule-enabled ${pack.enabled ? "checked" : ""}/> Enabled</label>
        <label class="sev">Severity
          <select data-rule-severity>
            ${["info", "warning", "critical"].map((s) => `<option value="${s}" ${pack.severity === s ? "selected" : ""}>${s}</option>`).join("")}
          </select>
        </label>
        <span class="rule-status ${status}">${status === "fired" ? "FIRED" : status === "off" ? "off" : "quiet"}</span>
      </div>
    </div>
    ${groups}
  </section>`;
}

function rulesPageHtml(snap: Snapshot): string {
  const packs = snap.rules?.packs ?? [];
  const body =
    packs.length === 0
      ? `<p class="muted">No rule packs available.</p>`
      : packs.map(oneRuleWidget).join("");
  return `<div class="map-col rules-col">
    <div class="map-toolbar">
      <h2>Rules</h2>
      <p class="muted">Same feature window as ONNX. Settings survive Reset.</p>
    </div>
    ${body}
  </div>`;
}

function fmtNum(v: number | null | undefined, digits = 2): string {
  if (v == null || Number.isNaN(v)) return "—";
  return Math.abs(v) >= 10 ? v.toFixed(1) : v.toFixed(digits);
}

function liveBox(live: boolean, fired?: boolean): string {
  const cls = fired ? "hot" : live ? "" : "off";
  const label = fired ? "detection" : live ? "live" : "not live";
  return `<span class="live-box ${cls}" title="${label}"></span><span class="live-caption">${label}</span>`;
}

function fmtCoord(v: number | null | undefined): string {
  if (v == null || Number.isNaN(v)) return "—";
  return v.toFixed(5);
}

function clauseById(pack: RulePack, id: string): RuleClause | undefined {
  for (const g of pack.groups) {
    const hit = g.clauses.find((c) => c.id === id || c.feature === id);
    if (hit) return hit;
  }
  return undefined;
}

function ruleMonitorPlot(pack: RulePack): string {
  if (pack.rule_id === "gps-spoof-nav") return gpsSpoofMonitorPlot(pack);
  const keys = pack.groups.flatMap((g) => g.clauses.filter((c) => c.type === "number").map((c) => ({ id: c.id, label: c.label, unit: c.unit })));
  const pick = keys.slice(0, 4);
  const rows = (pack.series ?? []).map((s) => {
    const row: Record<string, number> = { t: s.t };
    for (const k of pick) {
      const live = s.values[k.id];
      const thr = s.thresholds[k.id];
      if (live != null) row[k.id] = live;
      if (thr != null) row[`${k.id}__thr`] = thr;
    }
    return row;
  });
  const lines = pick.flatMap((k, i) => {
    const color = plotColors(i);
    return [
      { key: k.id, color, label: `${k.label}${k.unit ? " " + k.unit : ""}` },
      { key: `${k.id}__thr`, color, dash: true, label: `${k.label} thr` },
    ];
  });
  const latest = pack.series?.[pack.series.length - 1];
  const now = pick
    .map((k) => {
      const live = clauseById(pack, k.id)?.live ?? latest?.values[k.id];
      const thr = latest?.thresholds[k.id] ?? clauseById(pack, k.id)?.value;
      return `${esc(k.label)} ${fmtNum(live)}${k.unit} / thr ${fmtNum(typeof thr === "number" ? thr : Number(thr))}${k.unit}`;
    })
    .join(" · ");
  return `${linePlot(rows, lines)}
    <p class="plot-legend">${pick
      .map((k, i) => `<span><i class="swatch" style="background:${plotColors(i)}"></i>${esc(k.label)}</span><span class="swatch-dash" style="border-color:${plotColors(i)}"></span> thr`)
      .join("")}</p>
    <p class="muted score-line">${now || "no numeric clauses"}</p>`;
}

function gpsSpoofMonitorPlot(pack: RulePack): string {
  const splitC = clauseById(pack, "gnss1_gnss2_split_m");
  const resC = clauseById(pack, "gnss_dr_residual_m");
  const cogC = clauseById(pack, "cog_heading_residual_deg");
  const hdopC = clauseById(pack, "hdop_healthy");
  const satC = clauseById(pack, "sat_count_min");
  const latest = pack.series?.[pack.series.length - 1];
  const read = latest?.readings ?? {};
  const liveSplit = splitC?.live ?? latest?.values.gnss1_gnss2_split_m ?? read.gnss1_gnss2_split_m;
  const liveRes = resC?.live ?? latest?.values.gnss_dr_residual_m ?? read.gnss_dr_residual_m;
  const splitThr = Number(splitC?.value ?? latest?.thresholds.gnss1_gnss2_split_m ?? 30);
  const resThr = Number(resC?.value ?? latest?.thresholds.gnss_dr_residual_m ?? 50);
  const cogThr = Number(cogC?.value ?? latest?.thresholds.cog_heading_residual_deg ?? 15);
  const rows = (pack.series ?? []).map((s) => {
    const split = s.values.gnss1_gnss2_split_m ?? s.readings?.gnss1_gnss2_split_m;
    const residual = s.values.gnss_dr_residual_m ?? s.readings?.gnss_dr_residual_m;
    const cog = s.values.cog_heading_residual_deg ?? s.readings?.cog_heading_residual_deg;
    const crossed =
      s.fired ||
      (split != null && split > (s.thresholds.gnss1_gnss2_split_m ?? splitThr)) ||
      (residual != null && residual > (s.thresholds.gnss_dr_residual_m ?? resThr));
    return {
      t: s.t,
      split,
      residual,
      split_thr: s.thresholds.gnss1_gnss2_split_m ?? splitThr,
      residual_thr: s.thresholds.gnss_dr_residual_m ?? resThr,
      cog,
      cog_thr: s.thresholds.cog_heading_residual_deg ?? cogThr,
      detect: crossed ? split ?? residual : null,
    };
  });
  if (rows.length && liveSplit != null) {
    const last = rows[rows.length - 1];
    last.split = liveSplit;
    last.residual = liveRes ?? last.residual;
    last.cog = cogC?.live ?? last.cog;
    const crossed = pack.fired || (liveSplit > splitThr || (liveRes != null && liveRes > resThr));
    last.detect = crossed ? liveSplit : last.detect;
  }
  const distPlot = linePlot(rows, [
    { key: "split", color: "#3caf7a", label: "GNSS-1 vs GNSS-2" },
    { key: "residual", color: "#c9a227", label: "GNSS vs DR" },
    { key: "split_thr", color: "#3caf7a", dash: true, label: "split thr" },
    { key: "residual_thr", color: "#c9a227", dash: true, label: "DR thr" },
  ]);
  const cogPlot = linePlot(rows, [
    { key: "cog", color: "#3d8bfd", label: "COG vs heading" },
    { key: "cog_thr", color: "#3d8bfd", dash: true, label: "thr" },
  ]);
  const lat1 = latest?.readings?.gnss1_lat_deg;
  const lon1 = latest?.readings?.gnss1_lon_deg;
  const lat2 = latest?.readings?.gnss2_lat_deg;
  const lon2 = latest?.readings?.gnss2_lon_deg;
  return `<dl class="live-readings">
      <div><dt>GNSS-1</dt><dd>${fmtCoord(lat1)}, ${fmtCoord(lon1)}</dd></div>
      <div><dt>GNSS-2</dt><dd>${fmtCoord(lat2)}, ${fmtCoord(lon2)}</dd></div>
      <div><dt>Split</dt><dd>${fmtNum(liveSplit)} m / thr ${fmtNum(splitThr)} m</dd></div>
      <div><dt>DR residual</dt><dd>${fmtNum(liveRes)} m / thr ${fmtNum(resThr)} m</dd></div>
      <div><dt>HDOP</dt><dd>${fmtNum(hdopC?.live ?? latest?.readings?.hdop)} / &lt; ${fmtNum(Number(hdopC?.value))}</dd></div>
      <div><dt>Sats</dt><dd>${fmtNum(satC?.live ?? latest?.readings?.sat_count)} / ≥ ${fmtNum(Number(satC?.value))}</dd></div>
      <div><dt>COG vs heading</dt><dd>${fmtNum(cogC?.live ?? latest?.readings?.cog_heading_residual_deg)}° / thr ${fmtNum(cogThr)}°</dd></div>
    </dl>
    ${distPlot}
    <p class="plot-legend"><span><i class="swatch" style="background:#3caf7a"></i>GNSS-1 vs GNSS-2 split</span><span><i class="swatch" style="background:#c9a227"></i>GNSS vs DR</span><span class="swatch-dash" style="border-color:#8b97a8"></span> threshold<span><i class="swatch" style="background:#d45b4c"></i>detection</span></p>
    ${cogPlot}
    <p class="plot-legend"><span><i class="swatch" style="background:#3d8bfd"></i>COG vs heading</span><span class="swatch-dash" style="border-color:#3d8bfd"></span> threshold</p>`;
}

function ruleStatusCard(pack: RulePack): string {
  const live = Boolean(pack.live);
  const status = packStatus(pack);
  return `<section class="status-card ${live ? "live" : "idle"} ${pack.fired ? "detect" : ""}" data-monitor-rule="${esc(pack.rule_id)}">
    <div class="status-card-head">
      <div class="live-row">${liveBox(live, pack.fired)}</div>
      <div>
        <h2>${esc(pack.title)}</h2>
        <p class="rule-title">${esc(pack.rule_id)} · v${esc(pack.version)}</p>
      </div>
      <span class="rule-status ${status}">${status === "fired" ? "FIRED" : status === "off" ? "off" : "quiet"}</span>
    </div>
    <p class="muted">${esc(pack.blurb)}</p>
    ${ruleMonitorPlot(pack)}
  </section>`;
}

function modelStatusCard(pack: ModelPack): string {
  const live = Boolean(pack.live);
  const status = pack.detected || pack.status === "fired" ? "fired" : live ? "quiet" : "off";
  const rows = (pack.series ?? []).map((s) => {
    const thr = s.threshold_fps ?? s.predicted_fps;
    return {
      t: s.t,
      actual_fps: s.actual_fps,
      threshold_fps: thr,
      detect: s.fired || s.crossed ? s.actual_fps : null,
    };
  });
  const plot = linePlot(rows, [
    { key: "actual_fps", color: "#3caf7a", label: "actual" },
    { key: "threshold_fps", color: "#3d8bfd", dash: true, label: "LSTM threshold" },
  ]);
  const s = pack.scores || {};
  const thrNow = s.threshold_fps ?? s.predicted_fps ?? pack.thresholds.threshold_fps;
  return `<section class="status-card ${live ? "live" : "idle"} ${pack.detected ? "detect" : ""}" data-monitor-model="${esc(pack.model_id)}">
    <div class="status-card-head">
      <div class="live-row">${liveBox(live, pack.detected)}</div>
      <div>
        <h2>${esc(pack.title)}</h2>
        <p class="rule-title">${esc(pack.model_id)} · v${esc(pack.version)}${pack.onnx_loaded ? " · ONNX" : " · numpy LSTM"}</p>
      </div>
      <span class="rule-status ${status}">${pack.detected ? "FIRED" : live ? "live" : "idle"}</span>
    </div>
    <p class="muted">${esc(pack.blurb)}</p>
    ${plot}
    <p class="plot-legend"><span><i class="swatch" style="background:#3caf7a"></i>actual flow</span><span class="swatch-dash" style="border-color:#3d8bfd"></span> LSTM threshold<span><i class="swatch" style="background:#d45b4c"></i>detection</span></p>
    <p class="muted score-line">actual ${fmtNum(s.actual_fps)} fps · threshold ${fmtNum(thrNow)} fps (LSTM) ${pack.detected ? "· crossed" : ""}</p>
  </section>`;
}

function modelsPageHtml(snap: Snapshot): string {
  const rules = snap.rules?.packs ?? [];
  const models = snap.models?.packs ?? [];
  return `<div class="models-page">
    <div class="map-toolbar models-toolbar">
      <h2>Model status</h2>
      <p class="legend"><span class="swatch fill ok"></span> live <span class="swatch fill idle"></span> not live <span class="swatch fill bad"></span> detection</p>
    </div>
    <div class="models-grid">
      <div class="models-col">
        <h2>Rules applied</h2>
        ${rules.length ? rules.map(ruleStatusCard).join("") : `<p class="muted">No rule packs.</p>`}
      </div>
      <div class="models-col">
        <h2>ML models</h2>
        ${models.length ? models.map(modelStatusCard).join("") : `<p class="muted">No deployed ONNX models.</p>`}
      </div>
    </div>
  </div>`;
}

function plotsFilter(): ExplorerFilter {
  return { from: state.plots.from, to: state.plots.to, source: state.plots.source };
}

function explorerRows(snap: Snapshot): FlowMessage[] {
  return filterLogs(snap.log_archive?.length ? snap.log_archive : snap.message_flow ?? [], plotsFilter());
}

function plotsGridHtml(snap: Snapshot): string {
  const rows: HistogramRow[] = snap.histograms ?? [];
  const filter = plotsFilter();
  if (!rows.length) {
    return `<p class="muted">Start the injector. Each plot bins benign vs attack samples for that overlay and updates every TAP tick.</p>`;
  }
  return rows
    .map((h) => {
      const benign = filterSeries(h.benign, filter, "benign");
      const attack = filterSeries(h.attack, filter, "attack");
      const checked = state.plots.selectedPlots.size === 0 || state.plots.selectedPlots.has(h.key);
      return `<article class="hist-card ${h.active ? "detect" : ""}">
        <label class="hist-pick"><input type="checkbox" data-plot-key="${esc(h.key)}" ${checked ? "checked" : ""} /> ${esc(h.label)}</label>
        <p class="muted">${esc(h.technique || "")} · ${esc(h.unit || "")} · benign n=${benign.length} · attack n=${attack.length}${h.active ? " · live overlay" : ""}</p>
        ${histogramPlot(benign, attack)}
        <p class="plot-legend"><span><i class="swatch" style="background:#3caf7a"></i>benign</span><span><i class="swatch" style="background:#d45b4c"></i>attack</span></p>
      </article>`;
    })
    .join("");
}

function explorerBodyHtml(snap: Snapshot): string {
  const rows = explorerRows(snap);
  if (!rows.length) {
    return `<tr><td colspan="8" class="muted">No log rows in this window. Widen the datetime range or choose Both.</td></tr>`;
  }
  return rows
    .map((m, i) => {
      const id = logId(m, i);
      const src = logSource(m);
      const checked = state.plots.selectedLogs.has(id);
      return `<tr class="${src === "attack" ? "attack" : ""}" data-log-row="${esc(id)}">
        <td><input type="checkbox" data-log-id="${esc(id)}" ${checked ? "checked" : ""} /></td>
        <td>${esc(fmtClock(m.t))}</td>
        <td>${esc(src)}</td>
        <td>SA ${esc(m.sa)} ${esc(m.name)}</td>
        <td>PGN ${esc(String(m.pgn))}</td>
        <td>${esc(m.pgn_name)}</td>
        <td>${esc(m.technique || m.kind || "")}</td>
        <td class="hex">${esc(m.summary)}</td>
      </tr>`;
    })
    .join("");
}

function explorerCountHtml(snap: Snapshot): string {
  const n = explorerRows(snap).length;
  const sel = state.plots.selectedLogs.size;
  return `${n} row${n === 1 ? "" : "s"} in view · ${sel ? `${sel} selected` : "export uses all rows in view"} · plots ${sel ? "use checked overlays" : "export all overlays"}`;
}

function plotsPageHtml(snap: Snapshot): string {
  const live = snap.running ? "live" : "paused";
  return `<div class="models-page plots-page">
    <div class="map-toolbar models-toolbar">
      <h2>Plots</h2>
      <p class="muted">Histograms refresh every TAP tick. Attack series uses GNSS spoof red. Check overlays and log rows, then export CSV.</p>
      <span class="live-caption">${esc(live)} · tick ${snap.ticks}</span>
    </div>
    <form class="plots-explorer" data-plots-explorer>
      <label>From <input type="datetime-local" step="1" data-plots-from value="${esc(state.plots.from)}" /></label>
      <label>To <input type="datetime-local" step="1" data-plots-to value="${esc(state.plots.to)}" /></label>
      <label>Source <select data-plots-source>
        <option value="both" ${state.plots.source === "both" ? "selected" : ""}>Both</option>
        <option value="benign" ${state.plots.source === "benign" ? "selected" : ""}>Benign</option>
        <option value="attack" ${state.plots.source === "attack" ? "selected" : ""}>Attack</option>
      </select></label>
      <button type="button" class="btn" data-ctrl="plots-select-all">Select logs in view</button>
      <button type="button" class="btn" data-ctrl="plots-clear">Clear selection</button>
      <button type="button" class="btn" data-ctrl="export-csv">Export CSV</button>
    </form>
    <div class="plots-grid" id="plots-grid">${plotsGridHtml(snap)}</div>
    <section class="explorer-panel">
      <h2>Log explorer</h2>
      <p class="muted" id="explorer-count">${explorerCountHtml(snap)}</p>
      <div class="explorer-table-wrap">
        <table class="explorer-table">
          <thead>
            <tr><th></th><th>Time</th><th>Source</th><th>Talker</th><th>PGN</th><th>Name</th><th>Technique</th><th>Summary</th></tr>
          </thead>
          <tbody id="explorer-tbody">${explorerBodyHtml(snap)}</tbody>
        </table>
      </div>
    </section>
  </div>`;
}

function patchPlotsLive(snap: Snapshot): void {
  const grid = document.getElementById("plots-grid");
  if (grid) grid.innerHTML = plotsGridHtml(snap);
  const body = document.getElementById("explorer-tbody");
  if (body) body.innerHTML = explorerBodyHtml(snap);
  const count = document.getElementById("explorer-count");
  if (count) count.textContent = explorerCountHtml(snap);
}

function exportSelected(snap: Snapshot): void {
  const logs = explorerRows(snap);
  const chosenLogs = logs.filter((m, i) => state.plots.selectedLogs.has(logId(m, i)));
  const logRows = chosenLogs.length ? chosenLogs : logs;
  downloadCsv(stampName("ot-sensor-logs"), logsCsv(logRows));
  const plots = snap.histograms ?? [];
  window.setTimeout(() => {
    downloadCsv(stampName("ot-sensor-plots"), plotsCsv(plots, plotsFilter(), state.plots.selectedPlots));
  }, 120);
}

function scoreLine(scores: Record<string, number> | undefined): string {
  if (!scores) return "—";
  const keys = ["flood_score", "actual_fps", "threshold_fps", "predicted_fps", "residual_fps"];
  const parts = keys
    .filter((k) => scores[k] != null)
    .map((k) => `${k.replace(/_fps$/, "").replace(/_/g, " ")} ${fmtNum(scores[k])}`);
  const extra = Object.keys(scores)
    .filter((k) => !keys.includes(k))
    .slice(0, 4)
    .map((k) => `${k} ${fmtNum(scores[k])}`);
  return [...parts, ...extra].join(" · ") || "—";
}

function alertCard(alert: Alert): string {
  const rules = (alert.rules ?? [])
    .map(
      (r) =>
        `<li class="${r.fired ? "fired" : ""}"><span class="rule-status ${r.fired ? "fired" : "quiet"}">${r.fired ? "FIRED" : "quiet"}</span> ${esc(r.rule_id)}${r.severity ? ` · ${esc(r.severity)}` : ""}${r.clauses_fired?.length ? ` · ${esc(r.clauses_fired.join(", "))}` : ""}</li>`,
    )
    .join("");
  const models = (alert.models ?? [])
    .map(
      (m) =>
        `<li class="${m.fired ? "fired" : ""}"><span class="rule-status ${m.fired ? "fired" : "quiet"}">${m.fired ? "FIRED" : esc(m.status)}</span> ${esc(m.model_id)} v${esc(m.version)} · ${esc(scoreLine(m.scores))}</li>`,
    )
    .join("");
  const fired = [...(alert.fired_rules ?? []), ...(alert.fired_models ?? [])];
  return `<article class="alert-card ${fired.length ? "hot" : ""}">
    <div class="alert-head">
      <span class="inc-id">${esc(alert.event_id)}</span>
      <span class="inc-risk">${esc(fmtClock(alert.timestamp))} · ${esc(alert.segment || "—")}${alert.join_incomplete ? " · join incomplete" : ""}</span>
    </div>
    <p class="muted">${esc((alert.asset_ids || []).join(", ") || "no assets")} · ${fired.length ? esc(fired.join(" · ")) : "enrichment only"}</p>
    <h3>Rules</h3>
    ${rules ? `<ul class="alert-hits">${rules}</ul>` : `<p class="muted">No rule hits on this window.</p>`}
    <h3>Models</h3>
    ${models ? `<ul class="alert-hits">${models}</ul>` : `<p class="muted">No model scores on this window.</p>`}
  </article>`;
}

function correlationPageHtml(snap: Snapshot): string {
  const incidents = snap.incidents ?? [];
  const selected =
    incidents.find((i) => i.incident_id === state.selectedIncident) ?? incidents[0] ?? null;
  const list =
    incidents.length === 0
      ? `<p class="muted">No correlated cases yet. Alerts appear after ONNX and rules write the same event_id.</p>`
      : `<ul class="inc-list">${incidents
          .map(
            (i) => `<li><button type="button" class="inc-row ${selected?.incident_id === i.incident_id ? "sel" : ""} ${i.state === "closed" ? "idle" : ""}" data-incident="${esc(i.incident_id)}">
              <span class="inc-id">${esc(i.incident_id)} · ${esc(i.state)}${i.risk.nis2_significant ? " · NIS2" : ""}</span>
              <span class="inc-title">${esc(i.title)}</span>
              <span class="inc-risk">${esc(i.severity)} · risk ${i.risk.total} · ${i.alert_count} alert${i.alert_count === 1 ? "" : "s"} · ${(i.families || []).join(" · ") || i.segment}</span>
            </button></li>`,
          )
          .join("")}</ul>`;
  const memberAlerts = selected?.alerts ?? [];
  const feed = memberAlerts.length ? memberAlerts : snap.alerts ?? [];
  const alertBody =
    feed.length === 0
      ? `<p class="muted">No joined alerts. Correlation waits until enrichment finishes.</p>`
      : feed.map(alertCard).join("");
  return `<div class="models-page correlation-page">
    <div class="map-toolbar models-toolbar">
      <h2>Correlation</h2>
      <p class="muted">Join ONNX + rules by event_id, then fold alerts into incidents. SLM text is not a detection.</p>
    </div>
    <div class="models-grid">
      <div class="models-col">
        <h2>Incidents</h2>
        ${list}
        ${selected ? caseHtml(selected, snap.copilot) : ""}
      </div>
      <div class="models-col">
        <h2>${selected ? `Alerts in ${esc(selected.incident_id)}` : "Alerts"}</h2>
        ${alertBody}
      </div>
    </div>
  </div>`;
}

function fmtBytes(n: number | null | undefined): string {
  const v = Number(n) || 0;
  if (v < 1024) return `${v} B`;
  if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} KB`;
  return `${(v / (1024 * 1024)).toFixed(2)} MB`;
}

function canHex(id: number): string {
  return "0x" + (id >>> 0).toString(16).padStart(8, "0");
}

function honeypotPageHtml(snap: Snapshot): string {
  const hp = snap.honeypot;
  const feed = hp?.feed ?? [];
  const files = hp?.entries ?? [];
  const series = (hp?.series ?? []).map((s) => ({ t: s.t, bytes: s.bytes, files: s.files }));
  const filesPlot = linePlot(series, [{ key: "files", color: "#c9a227", label: "files" }], {
    formatY: (v) => String(Math.max(0, Math.round(v))),
  });
  const bytesPlot = linePlot(
    series,
    [{ key: "bytes", color: "#3d8bfd", label: "bytes" }],
    {
      formatY: (v) => {
        if (v >= 1024 * 1024) return `${(v / (1024 * 1024)).toFixed(1)}M`;
        if (v >= 1024) return `${(v / 1024).toFixed(1)}K`;
        return `${Math.round(v)}`;
      },
    },
  );
  const fileRows =
    files.length === 0
      ? `<p class="muted">No files on disk yet.</p>`
      : `<table class="hp-table"><thead><tr><th>When</th><th>File</th><th>Size</th><th></th></tr></thead><tbody>${files
          .slice()
          .reverse()
          .map(
            (f) => `<tr class="${f.open ? "open" : ""}">
              <td>${esc(fmtClock(f.t))}</td>
              <td class="hex">${esc(f.name)}</td>
              <td>${esc(fmtBytes(f.bytes))}</td>
              <td>${f.open ? "open" : "closed"}</td>
            </tr>`,
          )
          .join("")}</tbody></table>`;
  const feedRows =
    feed.length === 0
      ? `<p class="muted">No units yet. Collector writes every TAP inflow before N2K convert.</p>`
      : `<ol class="hp-feed">${feed
          .map((u) => feedItemHtml(u))
          .join("")}</ol>`;
  return `<div class="models-page honeypot-page">
    <div class="map-toolbar models-toolbar">
      <h2>Honeypot</h2>
      <p class="muted">Live collector feed. Rotate/retain cap applies. Delete removes logs only — not incidents.</p>
      <button type="button" class="btn danger" data-ctrl="clear-honeypot">Delete all data</button>
    </div>
    <dl class="hp-stats">
      <div><dt>Dataset</dt><dd>${esc(fmtBytes(hp?.bytes))}</dd></div>
      <div><dt>Open / closed</dt><dd>${esc(fmtBytes(hp?.bytes_open))} / ${esc(fmtBytes(hp?.bytes_closed))}</dd></div>
      <div><dt>Files</dt><dd>${hp?.files ?? 0}</dd></div>
      <div><dt>Units written</dt><dd>${hp?.written ?? 0}</dd></div>
      <div><dt>Rotations</dt><dd>${hp?.rotation ?? 0}</dd></div>
      <div><dt>Dropped</dt><dd>${hp?.dropped ?? 0}</dd></div>
    </dl>
    <div class="models-grid">
      <div class="models-col">
        <h2>File count</h2>
        ${filesPlot}
        <h2>Bytes</h2>
        ${bytesPlot}
        <h2>On disk</h2>
        ${fileRows}
      </div>
      <div class="models-col">
        <h2>Live feed</h2>
        ${feedRows}
      </div>
    </div>
  </div>`;
}

function feedItemHtml(u: HoneypotFeed): string {
  const kind = u.kind || "unknown";
  const id = u.can_id != null ? ` · ${canHex(u.can_id)}` : "";
  const hex = u.payload_hex || "";
  return `<li class="kind-${esc(kind)}${u.error ? " err" : ""}">
    <div class="meta">${esc(fmtClock(u.t))} · ${esc(u.segment)}${u.iface ? ` · ${esc(u.iface)}` : ""} · ${esc(kind)} · seq ${esc(String(u.seq))} · ${esc(String(u.nbytes))} B${id}</div>
    <div class="hex">${esc(hex)}</div>
  </li>`;
}

function kv(rows: Array<[string, string]>): string {
  return `<dl class="kv">${rows
    .map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`)
    .join("")}</dl>`;
}

function caseHtml(inc: Incident, copilot: Snapshot["copilot"]): string {
  const slmSrc = inc.copilot ?? (copilot && copilot.incident_id === inc.incident_id ? copilot : null);
  const nis2 = inc.nis2
    ? `<div class="nis2"><h3>NIS2 clocks</h3>
        <p>Early warning (24h): ${esc(hoursUntil(inc.nis2.early_warning_due))}</p>
        <p>Notification (72h): ${esc(hoursUntil(inc.nis2.notification_due))}</p>
        <p>Human confirm: ${inc.nis2.human_confirm ? "yes" : "required before CSIRT"}</p></div>`
    : "";
  const slm = slmSrc
    ? `<div class="slm-block"><p class="muted">SLM ${esc(slmSrc.status)}${slmSrc.runtime ? ` · ${esc(slmSrc.runtime)}` : ""}</p>${inc.body || slmSrc.alert_body ? `<p class="toast-body">${esc(inc.body || slmSrc.alert_body)}</p>` : ""}</div>`
    : "";
  return `<section class="case">
    <h2>${esc(inc.incident_id)}</h2>
    <p class="case-title">${esc(inc.title)}</p>
    ${kv([
      ["State", inc.state],
      ["Severity", inc.severity],
      ["Risk", `${inc.risk.total} (impact ${inc.risk.impact} · likelihood ${inc.risk.likelihood} · blast ${inc.risk.blast_radius} · control ${inc.risk.control_plane})`],
      ["Segment", inc.segment],
      ["Assets", inc.asset_ids.join(", ")],
      ["Alerts", String(inc.alert_count)],
      ["Family", (inc.families || []).join(" · ") || "—"],
      ["ATT&CK", inc.techniques.join(" ") || "—"],
      ["Impact", inc.impacts.join(" ") || "—"],
    ])}
    ${nis2}${slm}
  </section>`;
}

function assistantPageHtml(snap: Snapshot): string {
  const incidents = snap.incidents ?? [];
  const selected =
    incidents.find((i) => i.incident_id === state.selectedIncident) ?? incidents[0] ?? null;
  const list =
    incidents.length === 0
      ? `<p class="muted">No correlated cases yet. The assistant waits for the correlator.</p>`
      : `<ul class="inc-list">${incidents
          .map(
            (i) => `<li><button type="button" class="inc-row ${selected?.incident_id === i.incident_id ? "sel" : ""} ${i.state === "closed" ? "idle" : ""}" data-incident="${esc(i.incident_id)}">
              <span class="inc-id">${esc(i.incident_id)} · ${esc(i.state)}</span>
              <span class="inc-title">${esc(i.title)}</span>
              <span class="inc-risk">${esc(i.severity)} · risk ${i.risk.total} · ${i.alert_count} alert${i.alert_count === 1 ? "" : "s"}</span>
            </button></li>`,
          )
          .join("")}</ul>`;
  const sess = state.assistant && selected && state.assistant.incident_id === selected.incident_id ? state.assistant : null;
  const loaded = snap.assistant?.loaded || sess?.loaded;
  const status = sess?.status || snap.assistant?.status || "idle";
  const source = sess?.source ? ` · ${sess.source}` : "";
    const runtime = sess?.base_model || sess?.runtime || snap.assistant?.base_model || snap.assistant?.runtime || "qwen2:1.5b";
  const interp = sess?.interpretation
    ? `<div class="assistant-brief">${esc(sess.interpretation)}</div>`
    : `<p class="muted">${state.assistantBusy ? "Interpreting incident…" : "Select a case to load a CyberPal briefing."}</p>`;
  const chat = (sess?.messages ?? [])
    .map(
      (m) => `<li class="${m.role}"><div class="meta">${esc(m.role)}</div><div class="body">${esc(m.content)}</div></li>`,
    )
    .join("");
  const suggestions = SUGGESTED.map((q) => `<button type="button" class="btn" data-ask="${esc(q)}">${esc(q)}</button>`).join("");
  return `<div class="models-page assistant-page">
    <div class="map-toolbar models-toolbar">
      <h2>Assistant</h2>
      <p class="muted">CyberPal · ${esc(runtime)} · one session per incident · correlation JSON only · listen-only</p>
      <span class="rule-status ${loaded ? "" : "off"}">${esc(status)}${esc(source)}</span>
      <button type="button" class="btn" data-ctrl="assistant-refresh" ${selected ? "" : "disabled"}>Re-interpret</button>
    </div>
    ${sess?.last_error && sess.source === "heuristic" ? `<p class="banner">${esc(sess.last_error)}</p>` : ""}
    ${state.assistantError ? `<p class="banner">${esc(state.assistantError)}</p>` : ""}
    <div class="models-grid assistant-grid">
      <div class="models-col">
        <h2>Incidents</h2>
        ${list}
        ${selected ? caseHtml(selected, snap.copilot) : ""}
      </div>
      <div class="models-col assistant-col">
        <h2>Interpretation</h2>
        ${interp}
        <h2>Investigation</h2>
        <ol class="assistant-chat">${chat || `<li class="muted">Ask about this case. Session stays on ${esc(selected?.incident_id || "—")}.</li>`}</ol>
        <div class="assistant-suggest">${suggestions}</div>
        <form class="assistant-form" data-assistant-form>
          <textarea name="q" rows="3" placeholder="Investigation question…" ${selected ? "" : "disabled"}>${esc(state.assistantDraft)}</textarea>
          <button type="submit" class="btn primary" ${!selected || state.assistantBusy ? "disabled" : ""}>${state.assistantBusy ? "Thinking…" : "Ask"}</button>
        </form>
      </div>
    </div>
  </div>`;
}

function assetCard(asset: Asset): string {
  return `<section>
    <h2>${esc(asset.name)}</h2>
    ${kv([
      ["SA", asset.asset_id],
      ["Segment", asset.segment],
      ["Criticality", String(asset.criticality)],
      ["NIS2 service", asset.nis2_service || "none"],
      ["Live", asset.traffic === "attack" ? "attack" : asset.traffic === "benign" ? "talking" : "no communication"],
      ["Expected", asset.expected ? "OPV model" : "unexpected"],
      ["Detected", (asset.detected_via || []).join(", ") || "—"],
      ["PGNs", asset.channels_seen.join(", ") || "—"],
    ])}
  </section>`;
}

function fmtClock(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
}

function incidentsHtml(snap: Snapshot): string {
  const inc =
    snap.incidents.find((i) => i.incident_id === state.selectedIncident) ?? snap.incidents[0] ?? null;
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
  return `<section class="incidents-panel">
    <h2>Incidents</h2>
    ${list}
    ${inc ? caseHtml(inc, snap.copilot) : ""}
  </section>`;
}

function flowHtml(snap: Snapshot): string {
  const asset = snap.flow_asset ?? { asset_id: "16", name: "GNSS-1" };
  const msgs: FlowMessage[] = snap.message_flow ?? [];
  const started = snap.attack_started_at;
  const rows =
    msgs.length === 0
      ? `<li class="muted">Waiting for TAP frames from ${esc(asset.name)}.</li>`
      : msgs
          .map((m) => {
            const hot = !!(m.spoofed || (m.kind && m.kind !== "ok"));
            const tag = hot ? ` · ${esc((m.technique || m.kind || "attack").toUpperCase())}` : "";
            return `<li class="${hot ? "attack" : ""}">
              <div class="meta">${esc(fmtClock(m.t))} · ${esc(m.segment)} · SA ${esc(m.sa)} ${esc(m.name)}${tag}</div>
              <div><strong>PGN ${esc(String(m.pgn))}</strong> ${esc(m.pgn_name)}</div>
              <div>${esc(m.summary)}</div>
              <div class="hex">${esc(m.hex)}</div>
            </li>`;
          })
          .join("");
  const selected = snap.assets.find((a) => a.asset_id === state.selectedAsset) ?? null;
  return `<aside class="side">
    <section class="flow-head">
      <h2>Spoof flow</h2>
      <p class="flow-asset">${esc(asset.name)} · SA ${esc(asset.asset_id)}</p>
      <p class="attack-start ${started ? "set" : ""}">Attack started <strong>${esc(started ? fmtClock(started) : "not yet")}</strong></p>
    </section>
    <ol id="flow-log">${rows}</ol>
    ${selected ? assetCard(selected) : ""}
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
        <p class="kicker">Listen-only · NMEA 2000${snap?.tap_url ? ` · TAP ${esc(snap.tap_url)}` : ""}</p>
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
        <div class="seg page-tabs">
          <button type="button" class="btn ${state.page === "map" ? "active" : ""}" data-page="map">Map</button>
          <button type="button" class="btn ${state.page === "rules" ? "active" : ""}" data-page="rules">Rules</button>
          <button type="button" class="btn ${state.page === "models" ? "active" : ""}" data-page="models">Models</button>
          <button type="button" class="btn ${state.page === "plots" ? "active" : ""}" data-page="plots">Plots</button>
          <button type="button" class="btn ${state.page === "correlation" ? "active" : ""}" data-page="correlation">Correlation</button>
          <button type="button" class="btn ${state.page === "honeypot" ? "active" : ""}" data-page="honeypot">Honeypot</button>
          <button type="button" class="btn ${state.page === "assistant" ? "active" : ""}" data-page="assistant">Assistant</button>
        </div>
        <button type="button" class="btn primary" data-ctrl="reset">Reset</button>
      </div>
    </header>
    ${snap ? healthHtml(snap) : ""}
    ${snap?.tap_error ? `<p class="banner">Simulator TAP ${esc(snap.tap_url || "")}: ${esc(snap.tap_error)}</p>` : ""}
    ${state.error ? `<p class="banner">${esc(state.error)} — start with ot-dashboard on :8443</p>` : ""}
    <div class="main ${state.page === "rules" ? "rules-page" : ""} ${state.page === "models" || state.page === "plots" || state.page === "correlation" || state.page === "honeypot" || state.page === "assistant" ? "models-page-main" : ""}">
      ${
        state.page === "rules"
          ? snap
            ? rulesPageHtml(snap)
            : `<div class="map-col"><p class="muted">Waiting for TAP snapshot…</p></div>`
          : state.page === "models"
            ? snap
              ? modelsPageHtml(snap)
              : `<div class="map-col"><p class="muted">Waiting for TAP snapshot…</p></div>`
          : state.page === "plots"
            ? snap
              ? plotsPageHtml(snap)
              : `<div class="map-col"><p class="muted">Waiting for TAP snapshot…</p></div>`
          : state.page === "correlation"
            ? snap
              ? correlationPageHtml(snap)
              : `<div class="map-col"><p class="muted">Waiting for TAP snapshot…</p></div>`
          : state.page === "honeypot"
            ? snap
              ? honeypotPageHtml(snap)
              : `<div class="map-col"><p class="muted">Waiting for TAP snapshot…</p></div>`
          : state.page === "assistant"
            ? snap
              ? assistantPageHtml(snap)
              : `<div class="map-col"><p class="muted">Waiting for TAP snapshot…</p></div>`
          : `<div class="map-col">
        <div class="map-toolbar">
          <h2>Asset map</h2>
          <div class="seg">
            <button type="button" class="btn ${state.overlay === "comms" ? "active" : ""}" data-overlay="comms">Communications</button>
            <button type="button" class="btn ${state.overlay === "deps" ? "active" : ""}" data-overlay="deps">Dependencies</button>
          </div>
          <p class="legend"><span class="swatch fill ok"></span> benign <span class="swatch fill bad"></span> attack <span class="swatch fill idle"></span> silent <span class="swatch ok"></span> comms <span class="swatch bad"></span> violation <span class="swatch dep"></span> depends_on</p>
        </div>
        ${
          snap
            ? assetMapSvg(snap.assets, snap.comms, snap.dependencies, state.overlay, state.selectedAsset)
            : `<p class="muted">Waiting for TAP snapshot…</p>`
        }
        ${snap ? incidentsHtml(snap) : ""}
      </div>
      ${snap ? flowHtml(snap) : ""}`
      }
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

async function runControl(action: string): Promise<void> {
  try {
    if (action === "reset") {
      state.selectedAsset = null;
      state.selectedIncident = null;
      state.toastId = null;
      state.assistant = null;
      state.assistantDraft = "";
      state.assistantError = null;
    }
    state.snap = await control(action);
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
    const page = dataAttr(t.closest("[data-page]"), "page");
    if (page === "map" || page === "rules" || page === "models" || page === "plots" || page === "correlation" || page === "honeypot" || page === "assistant") {
      state.page = page as Page;
      render();
      if (page === "assistant") void loadAssistant();
      return;
    }
    const overlay = dataAttr(t.closest("[data-overlay]"), "overlay");
    if (overlay === "comms" || overlay === "deps") {
      state.overlay = overlay;
      render();
      return;
    }
    const ctrl = dataAttr(t.closest("[data-ctrl]"), "ctrl");
    if (ctrl === "reset") {
      void runControl("reset");
      return;
    }
    if (ctrl === "clear-honeypot") {
      if (!window.confirm("Delete all honeypot logs?")) return;
      void runControl("clear_honeypot");
      return;
    }
    if (ctrl === "assistant-refresh") {
      void loadAssistant(true);
      return;
    }
    if (ctrl === "export-csv") {
      if (state.snap) exportSelected(state.snap);
      return;
    }
    if (ctrl === "plots-select-all") {
      if (!state.snap) return;
      explorerRows(state.snap).forEach((m, i) => state.plots.selectedLogs.add(logId(m, i)));
      patchPlotsLive(state.snap);
      return;
    }
    if (ctrl === "plots-clear") {
      state.plots.selectedLogs.clear();
      state.plots.selectedPlots.clear();
      if (state.snap) patchPlotsLive(state.snap);
      return;
    }
    const ask = dataAttr(t.closest("[data-ask]"), "ask");
    if (ask) {
      state.assistantDraft = ask;
      void sendAssistant(ask);
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
      if (state.page === "assistant") void loadAssistant();
      return;
    }
    const toastAct = dataAttr(t.closest("[data-toast]"), "toast");
    if (toastAct === "open" && state.toastId) {
      state.selectedIncident = state.toastId;
      state.page = "correlation";
      void dismissToast();
      return;
    }
    if (toastAct === "dismiss") {
      void dismissToast();
    }
  });
  root.addEventListener("submit", (ev) => {
    if (eventEl(ev)?.closest("[data-plots-explorer]")) {
      ev.preventDefault();
      return;
    }
    if (!eventEl(ev)?.closest("[data-assistant-form]")) return;
    ev.preventDefault();
    void sendAssistant();
  });
  root.addEventListener("change", (ev) => {
    const t = eventEl(ev);
    if (t instanceof HTMLInputElement && t.hasAttribute("data-plot-key")) {
      const key = t.getAttribute("data-plot-key");
      if (!key) return;
      const keys = (state.snap?.histograms ?? []).map((h) => h.key);
      if (state.plots.selectedPlots.size === 0) {
        for (const k of keys) state.plots.selectedPlots.add(k);
      }
      if (t.checked) state.plots.selectedPlots.add(key);
      else state.plots.selectedPlots.delete(key);
      if (state.snap) patchPlotsLive(state.snap);
      return;
    }
    if (t instanceof HTMLInputElement && t.hasAttribute("data-log-id")) {
      const id = t.getAttribute("data-log-id");
      if (!id) return;
      if (t.checked) state.plots.selectedLogs.add(id);
      else state.plots.selectedLogs.delete(id);
      if (state.snap) {
        const count = document.getElementById("explorer-count");
        if (count) count.textContent = explorerCountHtml(state.snap);
      }
      return;
    }
    if (t instanceof HTMLSelectElement && t.hasAttribute("data-plots-source")) {
      const v = t.value;
      if (v === "benign" || v === "attack" || v === "both") {
        state.plots.source = v;
        if (state.snap) patchPlotsLive(state.snap);
      }
      return;
    }
    if (t instanceof HTMLInputElement && (t.hasAttribute("data-plots-from") || t.hasAttribute("data-plots-to"))) {
      if (t.hasAttribute("data-plots-from")) state.plots.from = t.value;
      if (t.hasAttribute("data-plots-to")) state.plots.to = t.value;
      if (state.snap) patchPlotsLive(state.snap);
      return;
    }
    const widget = t?.closest(".rules-widget");
    const ruleId = widget?.getAttribute("data-rule-id");
    if (!t || !widget || !ruleId) return;
    if (t instanceof HTMLInputElement && t.hasAttribute("data-rule-enabled")) {
      void saveRule(ruleId, { enabled: t.checked });
      return;
    }
    if (t instanceof HTMLSelectElement && t.hasAttribute("data-rule-severity")) {
      void saveRule(ruleId, { severity: t.value });
      return;
    }
    if (t instanceof HTMLInputElement && t.hasAttribute("data-clause")) {
      const id = t.getAttribute("data-clause");
      if (!id) return;
      const val = t.type === "checkbox" ? t.checked : Number(t.value);
      if (t.type !== "checkbox" && Number.isNaN(Number(val))) return;
      void saveRule(ruleId, { clauses: { [id]: val } });
    }
  });
  root.addEventListener("input", (ev) => {
    const t = eventEl(ev);
    if (t instanceof HTMLInputElement && (t.hasAttribute("data-plots-from") || t.hasAttribute("data-plots-to"))) {
      if (t.hasAttribute("data-plots-from")) state.plots.from = t.value;
      if (t.hasAttribute("data-plots-to")) state.plots.to = t.value;
      if (state.snap) patchPlotsLive(state.snap);
      return;
    }
    if (t instanceof HTMLTextAreaElement && t.closest("[data-assistant-form]")) {
      state.assistantDraft = t.value;
      return;
    }
    if (!(t instanceof HTMLInputElement) || t.type !== "number" || !t.hasAttribute("data-clause")) return;
    const widget = t.closest(".rules-widget");
    const ruleId = widget?.getAttribute("data-rule-id");
    const id = t.getAttribute("data-clause");
    if (!ruleId || !id) return;
    const val = Number(t.value);
    if (Number.isNaN(val)) return;
    queueClause(ruleId, id, val);
  });
}

function editingRule(): boolean {
  const el = document.activeElement;
  return el instanceof Element && !!el.closest(".rules-widget");
}

function patchRuleLive(snap: Snapshot): void {
  for (const pack of snap.rules?.packs ?? []) {
    const widget = document.querySelector(`.rules-widget[data-rule-id="${CSS.escape(pack.rule_id)}"]`);
    if (!widget) continue;
    const status = packStatus(pack);
    const statusEl = widget.querySelector(".rule-status");
    if (statusEl) {
      statusEl.className = `rule-status ${status}`;
      statusEl.textContent = status === "fired" ? "FIRED" : status;
    }
    for (const g of pack.groups) {
      for (const c of g.clauses) {
        const live = widget.querySelector(`[data-live="${CSS.escape(c.feature)}"]`);
        if (live) live.textContent = fmtLive(c.live, c.unit, c.type);
        const input = widget.querySelector(`[data-clause="${CSS.escape(c.id)}"]`);
        const row = input?.closest(".clause");
        if (row) row.classList.toggle("met", Boolean(c.met));
      }
    }
  }
}

async function saveRule(
  ruleId: string,
  partial: { enabled?: boolean; severity?: string; clauses?: Record<string, number | boolean> },
): Promise<void> {
  try {
    state.snap = await updateRule({ rule_id: ruleId, ...partial });
    state.error = null;
    if (editingRule()) patchRuleLive(state.snap);
    else render();
  } catch (e) {
    state.error = e instanceof Error ? e.message : "rules update failed";
    render();
  }
}

let ruleTimer = 0;
function queueClause(ruleId: string, id: string, value: number | boolean): void {
  window.clearTimeout(ruleTimer);
  ruleTimer = window.setTimeout(() => {
    void saveRule(ruleId, { clauses: { [id]: value } });
  }, 280);
}

function editingAssistant(): boolean {
  const el = document.activeElement;
  return el instanceof Element && !!el.closest(".assistant-page");
}

async function loadAssistant(refresh = false): Promise<void> {
  const id = state.selectedIncident ?? state.snap?.incidents[0]?.incident_id ?? null;
  if (!id) {
    state.assistant = null;
    render();
    return;
  }
  state.selectedIncident = id;
  if (!refresh && state.assistant?.incident_id === id && state.assistant.interpretation && !state.assistantBusy) {
    render();
    return;
  }
  state.assistantBusy = true;
  render();
  try {
    const sess = await fetchAssistant(id, refresh);
    if (sess.ok === false) throw new Error(sess.error || "unknown incident");
    state.assistant = sess;
    state.assistantError = null;
  } catch (e) {
    state.assistantError = e instanceof Error ? e.message : "assistant failed";
  }
  state.assistantBusy = false;
  render();
}

async function sendAssistant(preset?: string): Promise<void> {
  const id = state.selectedIncident;
  const q = (preset ?? state.assistantDraft).trim();
  if (!id || !q || state.assistantBusy) return;
  state.assistantBusy = true;
  state.assistantDraft = "";
  render();
  try {
    const sess = await askAssistant(id, q);
    if (sess.ok === false) throw new Error(sess.error || "ask failed");
    state.assistant = sess;
    state.assistantError = null;
  } catch (e) {
    state.assistantError = e instanceof Error ? e.message : "ask failed";
    state.assistantDraft = q;
  }
  state.assistantBusy = false;
  render();
}

async function pull(): Promise<void> {
  try {
    const next = await fetchSnapshot();
    state.snap = next;
    state.error = null;
    state.toastId = state.toastId ?? next.new_incident_ids[0] ?? null;
    state.selectedIncident = state.selectedIncident ?? next.incidents[0]?.incident_id ?? null;
    if (state.page === "plots" && document.querySelector(".plots-page")) {
      const health = document.querySelector(".health-row");
      if (health) health.outerHTML = healthHtml(next);
      const cap = document.querySelector(".plots-page .live-caption");
      if (cap) cap.textContent = `${next.running ? "live" : "paused"} · tick ${next.ticks}`;
      patchPlotsLive(next);
      return;
    }
    if (editingRule()) {
      patchRuleLive(next);
      return;
    }
    if (state.page === "assistant" && (editingAssistant() || state.assistantBusy)) {
      return;
    }
    const y =
      state.page === "rules"
        ? (document.querySelector(".map-col")?.scrollTop ?? 0)
        : state.page === "models" || state.page === "plots" || state.page === "correlation" || state.page === "honeypot" || state.page === "assistant"
          ? (document.querySelector(".main")?.scrollTop ?? 0)
          : 0;
    render();
    if (state.page === "rules") {
      const col = document.querySelector(".map-col");
      if (col) col.scrollTop = y;
    } else if (state.page === "models" || state.page === "plots" || state.page === "correlation" || state.page === "honeypot" || state.page === "assistant") {
      const main = document.querySelector(".main");
      if (main) main.scrollTop = y;
    }
  } catch (e) {
    state.error = e instanceof Error ? e.message : "snapshot failed";
    render();
  }
}

bind();
void pull();
setInterval(() => void pull(), 800);
