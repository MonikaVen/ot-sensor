import type { Asset, CommsEdge, DepEdge } from "./types";

const SEGMENTS = ["nav", "propulsion", "power", "aux"] as const;
const COL_W = 210;
const ROW_H = 56;
const PAD_X = 36;
const PAD_Y = 48;

type Pt = { x: number; y: number };

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] ?? c);
}

function layout(assets: Asset[]): Map<string, Pt> {
  const pos = new Map<string, Pt>();
  for (const seg of SEGMENTS) {
    const col = SEGMENTS.indexOf(seg);
    const rows = assets.filter((a) => a.segment === seg);
    rows.forEach((a, i) => {
      pos.set(a.asset_id, {
        x: PAD_X + col * COL_W + COL_W / 2,
        y: PAD_Y + i * ROW_H + 18,
      });
    });
  }
  return pos;
}

function critClass(c: number): string {
  if (c >= 5) return "crit-5";
  if (c >= 4) return "crit-4";
  if (c >= 3) return "crit-3";
  return "crit-low";
}

export function assetMapSvg(
  assets: Asset[],
  comms: CommsEdge[],
  dependencies: DepEdge[],
  overlay: "comms" | "deps",
  selectedId: string | null,
): string {
  const pos = layout(assets);
  const height = Math.max(
    280,
    PAD_Y + Math.max(...SEGMENTS.map((s) => assets.filter((a) => a.segment === s).length), 1) * ROW_H + 24,
  );
  const width = PAD_X * 2 + COL_W * 4;

  const bands = SEGMENTS.map((seg, i) => {
    const x = PAD_X + i * COL_W;
    return `<g>
      <rect x="${x + 8}" y="8" width="${COL_W - 16}" height="${height - 16}" class="seg-band" />
      <text x="${x + COL_W / 2}" y="28" text-anchor="middle" class="seg-label">${seg}</text>
      <line x1="${x + 24}" x2="${x + COL_W - 24}" y1="36" y2="36" class="bus-line" />
    </g>`;
  }).join("");

  let edges = "";
  if (overlay === "deps") {
    for (const e of dependencies) {
      const a = pos.get(e.src);
      const b = pos.get(e.dst);
      if (!a || !b) continue;
      edges += `<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" class="edge-dep" />`;
    }
  } else {
    comms.forEach((e) => {
      const a = pos.get(e.src);
      if (!a) return;
      if (!e.dst) {
        const col = SEGMENTS.indexOf(e.segment as (typeof SEGMENTS)[number]);
        const bx = PAD_X + (col >= 0 ? col : 0) * COL_W + COL_W / 2;
        const cls = e.kind === "violation" ? "edge-bad" : "edge-bus";
        edges += `<line x1="${a.x}" y1="${a.y}" x2="${bx}" y2="36" class="${cls}" />`;
        return;
      }
      const b = pos.get(e.dst);
      if (!b) return;
      const cls = e.kind === "violation" ? "edge-bad" : e.expected ? "edge-ok" : "edge-new";
      edges += `<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" class="${cls}" />`;
    });
  }

  const nodes = assets
    .map((a) => {
      const p = pos.get(a.asset_id);
      if (!p) return "";
      const hot = a.incident_ids.length > 0;
      const cls = `node ${critClass(a.criticality)} ${a.live ? "live" : "ghost"} ${selectedId === a.asset_id ? "sel" : ""} ${hot ? "hot" : ""}`;
      const meta = `SA ${esc(a.asset_id)} · C${a.criticality}${hot ? " · INC" : ""}${a.live ? "" : " · silent"}`;
      return `<g role="button" tabindex="0" data-asset="${esc(a.asset_id)}" aria-label="${esc(a.name)} SA ${esc(a.asset_id)}" class="${cls}" style="cursor:pointer">
        <rect x="${p.x - 88}" y="${p.y - 16}" width="176" height="32" rx="2" />
        <text x="${p.x - 80}" y="${p.y - 2}" class="node-name">${esc(a.name)}</text>
        <text x="${p.x - 80}" y="${p.y + 11}" class="node-meta">${meta}</text>
      </g>`;
    })
    .join("");

  return `<div class="map-wrap"><svg class="map-svg" viewBox="0 0 ${width} ${height}" role="img" aria-label="OPV asset map">${bands}${edges}${nodes}</svg></div>`;
}
