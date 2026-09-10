const COLORS = ["#3caf7a", "#3d8bfd", "#c9a227", "#d45b4c", "#9b7ed9", "#5ec8d8"];

export type PlotLine = {
  key: string;
  color: string;
  dash?: boolean;
  label: string;
};

export function linePlot(
  rows: Array<Record<string, number | null | undefined>>,
  lines: PlotLine[],
  opts?: { width?: number; height?: number; formatY?: (v: number) => string },
): string {
  const w = opts?.width ?? 440;
  const h = opts?.height ?? 128;
  const padL = 36;
  const padR = 10;
  const padT = 10;
  const padB = 16;
  const usable = lines.filter((ln) => rows.some((r) => Number.isFinite(Number(r[ln.key]))));
  if (rows.length < 2 || usable.length === 0) {
    return `<svg class="rt-plot" viewBox="0 0 ${w} ${h}" role="img"><text x="${w / 2}" y="${h / 2}" text-anchor="middle" fill="#8b97a8" font-size="11">waiting for samples</text></svg>`;
  }
  let ymin = Infinity;
  let ymax = -Infinity;
  for (const row of rows) {
    for (const ln of usable) {
      const v = Number(row[ln.key]);
      if (!Number.isFinite(v)) continue;
      ymin = Math.min(ymin, v);
      ymax = Math.max(ymax, v);
    }
  }
  if (!Number.isFinite(ymin)) {
    ymin = 0;
    ymax = 1;
  }
  if (ymax - ymin < 1e-6) {
    ymin -= 1;
    ymax += 1;
  }
  const span = ymax - ymin;
  ymin -= span * 0.08;
  ymax += span * 0.08;
  const innerW = w - padL - padR;
  const innerH = h - padT - padB;
  const xAt = (i: number) => padL + (i / Math.max(1, rows.length - 1)) * innerW;
  const yAt = (v: number) => padT + (1 - (v - ymin) / (ymax - ymin)) * innerH;
  const paths = usable.map((ln) => {
    let d = "";
    rows.forEach((row, i) => {
      const v = Number(row[ln.key]);
      if (!Number.isFinite(v)) return;
      d += `${d ? " L" : "M"}${xAt(i).toFixed(1)} ${yAt(v).toFixed(1)}`;
    });
    const dash = ln.dash ? ` stroke-dasharray="4 3"` : "";
    return `<path d="${d}" fill="none" stroke="${ln.color}" stroke-width="1.7"${dash} />`;
  });
  const y0 = yAt(Math.min(Math.max(0, ymin), ymax));
  const ticks = [ymin, (ymin + ymax) / 2, ymax];
  const fmt = opts?.formatY;
  const labels = ticks
    .map((v) => {
      const t = fmt ? fmt(v) : Math.abs(v) >= 10 ? v.toFixed(0) : v.toFixed(2);
      return `<text x="${padL - 4}" y="${yAt(v) + 3}" text-anchor="end" fill="#8b97a8" font-size="9">${t}</text>`;
    })
    .join("");
    const dots = rows
      .map((row, i) => {
        const v = Number(row.detect);
        if (!Number.isFinite(v)) return "";
        return `<circle cx="${xAt(i).toFixed(1)}" cy="${yAt(v).toFixed(1)}" r="3.2" fill="#d45b4c" />`;
      })
      .join("");
    return `<svg class="rt-plot" viewBox="0 0 ${w} ${h}" role="img">
    <line x1="${padL}" y1="${padT}" x2="${padL}" y2="${h - padB}" stroke="#2a3340" />
    <line x1="${padL}" y1="${h - padB}" x2="${w - padR}" y2="${h - padB}" stroke="#2a3340" />
    <line x1="${padL}" y1="${y0}" x2="${w - padR}" y2="${y0}" stroke="#2a3340" stroke-dasharray="2 4" />
    ${labels}
    ${paths.join("")}
    ${dots}
  </svg>`;
}

export function plotColors(i: number): string {
  return COLORS[i % COLORS.length];
}

export function histogramPlot(benign: number[], attack: number[], opts?: { width?: number; height?: number }): string {
  const w = opts?.width ?? 420;
  const h = opts?.height ?? 96;
  const padL = 28;
  const padR = 8;
  const padT = 8;
  const padB = 18;
  const nBins = 10;
  const vals = [...benign, ...attack];
  if (!vals.length) {
    return `<svg class="rt-plot hist-plot" viewBox="0 0 ${w} ${h}" role="img"><text x="${w / 2}" y="${h / 2}" text-anchor="middle" fill="#8b97a8" font-size="11">waiting for samples</text></svg>`;
  }
  let lo = Math.min(...vals);
  let hi = Math.max(...vals);
  if (hi - lo < 1e-9) {
    lo -= 1;
    hi += 1;
  }
  const span = hi - lo;
  const binsB = Array(nBins).fill(0);
  const binsA = Array(nBins).fill(0);
  const place = (arr: number[], bins: number[]) => {
    for (const v of arr) {
      const i = Math.min(nBins - 1, Math.floor(((v - lo) / span) * nBins));
      bins[i]++;
    }
  };
  place(benign, binsB);
  place(attack, binsA);
  const peak = Math.max(1, ...binsB, ...binsA);
  const innerW = w - padL - padR;
  const innerH = h - padT - padB;
  const slot = innerW / nBins;
  const barW = Math.max(2, (slot - 2) / 2);
  const yAt = (c: number) => padT + innerH - (c / peak) * innerH;
  const bars: string[] = [];
  for (let i = 0; i < nBins; i++) {
    const x = padL + i * slot;
    const hb = Math.max(0, innerH - (yAt(binsB[i]) - padT));
    const ha = Math.max(0, innerH - (yAt(binsA[i]) - padT));
    bars.push(`<rect x="${x.toFixed(1)}" y="${yAt(binsB[i]).toFixed(1)}" width="${barW}" height="${hb.toFixed(1)}" fill="#3caf7a"/>`);
    bars.push(`<rect x="${(x + barW + 1).toFixed(1)}" y="${yAt(binsA[i]).toFixed(1)}" width="${barW}" height="${ha.toFixed(1)}" fill="#d45b4c"/>`);
  }
  const fmt = (v: number) => (Math.abs(v) >= 10 ? v.toFixed(0) : v.toFixed(2));
  return `<svg class="rt-plot hist-plot" viewBox="0 0 ${w} ${h}" role="img">
    <line x1="${padL}" y1="${padT}" x2="${padL}" y2="${h - padB}" stroke="#2a3340" />
    <line x1="${padL}" y1="${h - padB}" x2="${w - padR}" y2="${h - padB}" stroke="#2a3340" />
    ${bars.join("")}
    <text x="${padL}" y="${h - 4}" fill="#8b97a8" font-size="9">${fmt(lo)}</text>
    <text x="${w - padR}" y="${h - 4}" text-anchor="end" fill="#8b97a8" font-size="9">${fmt(hi)}</text>
  </svg>`;
}
