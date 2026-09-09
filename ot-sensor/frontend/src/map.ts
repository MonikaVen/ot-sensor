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

function trafficClass(a: Asset): string {
  if (a.traffic === "attack") return "traffic-attack";
  if (a.traffic === "benign") return "traffic-benign";
  return "traffic-silent";
}

function trafficLabel(a: Asset): string {
  if (a.traffic === "attack") return "attack";
  if (a.traffic === "benign") return "benign";
  return "silent";
}

export function assetMapSvg(
  assets: Asset[],
  comms: CommsEdge[],
  dependencies: DepEdge[],
  overlay: "comms" | "deps",
  selectedId: string | null,
): string {
  if (assets.length === 0) {
    return `<div class="map-wrap"><p class="muted map-empty">No talkers on the TAP yet. Start the listen-only TAP to autodetect assets from address claims and PGNs.</p></div>`;
  }
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
      const cls = `node ${trafficClass(a)} ${a.expected ? "" : "new"} ${selectedId === a.asset_id ? "sel" : ""}`;
      const meta = `SA ${esc(a.asset_id)} · ${trafficLabel(a)}${a.expected ? "" : " · new"}`;
      return `<g role="button" tabindex="0" data-asset="${esc(a.asset_id)}" aria-label="${esc(a.name)} SA ${esc(a.asset_id)} ${trafficLabel(a)}" class="${cls}" style="cursor:pointer">
        <rect x="${p.x - 88}" y="${p.y - 16}" width="176" height="32" rx="2" />
        <text x="${p.x - 80}" y="${p.y - 2}" class="node-name">${esc(a.name)}</text>
        <text x="${p.x - 80}" y="${p.y + 11}" class="node-meta">${meta}</text>
      </g>`;
    })
    .join("");

  return `<div class="map-wrap"><svg class="map-svg" viewBox="0 0 ${width} ${height}" role="img" aria-label="OPV asset map">${bands}${edges}${nodes}</svg></div>`;
}
