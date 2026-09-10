import type { FlowMessage, HistogramRow, HistogramSample } from "./types";

export type LogSource = "benign" | "attack" | "both";

export type ExplorerFilter = {
  from: string;
  to: string;
  source: LogSource;
};

export function sampleValue(item: HistogramSample | number): number {
  return typeof item === "number" ? item : Number(item.v);
}

export function sampleTime(item: HistogramSample | number): number | null {
  if (typeof item === "number" || !item.t) return null;
  const ms = Date.parse(item.t);
  return Number.isNaN(ms) ? null : ms;
}

export function parseBound(value: string): number | null {
  const v = value.trim();
  if (!v) return null;
  const ms = Date.parse(v);
  return Number.isNaN(ms) ? null : ms;
}

export function inTimeWindow(iso: string | null | undefined, fromMs: number | null, toMs: number | null): boolean {
  if (fromMs == null && toMs == null) return true;
  if (!iso) return false;
  const ms = Date.parse(iso);
  if (Number.isNaN(ms)) return false;
  if (fromMs != null && ms < fromMs) return false;
  if (toMs != null && ms > toMs) return false;
  return true;
}

export function logSource(row: FlowMessage): "benign" | "attack" {
  if (row.source === "attack" || row.source === "benign") return row.source;
  return row.spoofed || (row.kind && row.kind !== "ok") ? "attack" : "benign";
}

export function logId(row: FlowMessage, index: number): string {
  if (row.id) return row.id;
  return `${row.t}|${row.sa}|${row.pgn}|${row.hex}|${index}`;
}

export function filterLogs(rows: FlowMessage[], filter: ExplorerFilter): FlowMessage[] {
  const fromMs = parseBound(filter.from);
  const toMs = parseBound(filter.to);
  return rows.filter((row) => {
    const src = logSource(row);
    if (filter.source !== "both" && src !== filter.source) return false;
    return inTimeWindow(row.t, fromMs, toMs);
  });
}

export function filterSeries(items: Array<HistogramSample | number> | undefined, filter: ExplorerFilter, side: "benign" | "attack"): number[] {
  if (filter.source !== "both" && filter.source !== side) return [];
  const fromMs = parseBound(filter.from);
  const toMs = parseBound(filter.to);
  const out: number[] = [];
  for (const item of items || []) {
    const t = sampleTime(item);
    if (fromMs != null || toMs != null) {
      if (t == null) continue;
      if (fromMs != null && t < fromMs) continue;
      if (toMs != null && t > toMs) continue;
    }
    const v = sampleValue(item);
    if (Number.isFinite(v)) out.push(v);
  }
  return out;
}

export function csvEscape(value: unknown): string {
  const s = value == null ? "" : String(value);
  if (/[",\n\r]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

export function toCsv(headers: string[], rows: Array<Array<unknown>>): string {
  const lines = [headers.map(csvEscape).join(",")];
  for (const row of rows) lines.push(row.map(csvEscape).join(","));
  return `${lines.join("\r\n")}\r\n`;
}

export function downloadCsv(filename: string, csv: string): void {
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function logsCsv(rows: FlowMessage[]): string {
  return toCsv(
    ["t", "source", "sa", "name", "pgn", "pgn_name", "segment", "kind", "technique", "spoofed", "summary", "hex"],
    rows.map((r) => [
      r.t,
      logSource(r),
      r.sa,
      r.name,
      r.pgn,
      r.pgn_name,
      r.segment,
      r.kind ?? "",
      r.technique ?? "",
      r.spoofed ? "true" : "false",
      r.summary,
      r.hex,
    ]),
  );
}

export function plotsCsv(rows: HistogramRow[], filter: ExplorerFilter, selected: Set<string>): string {
  const headers = ["overlay", "key", "source", "t", "value", "unit", "technique"];
  const out: Array<Array<unknown>> = [];
  const fromMs = parseBound(filter.from);
  const toMs = parseBound(filter.to);
  for (const h of rows) {
    if (selected.size && !selected.has(h.key)) continue;
    for (const side of ["benign", "attack"] as const) {
      if (filter.source !== "both" && filter.source !== side) continue;
      for (const item of h[side] || []) {
        const t = typeof item === "number" ? "" : item.t || "";
        if ((fromMs != null || toMs != null) && !inTimeWindow(t || null, fromMs, toMs)) continue;
        const v = sampleValue(item);
        if (!Number.isFinite(v)) continue;
        out.push([h.label, h.key, side, t, v, h.unit, h.technique]);
      }
    }
  }
  return toCsv(headers, out);
}

export function stampName(prefix: string): string {
  const d = new Date();
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${prefix}-${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}.csv`;
}
