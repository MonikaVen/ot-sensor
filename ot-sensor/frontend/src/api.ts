import type { Snapshot } from "./types";

export async function fetchSnapshot(): Promise<Snapshot> {
  const r = await fetch("/api/snapshot");
  if (!r.ok) throw new Error(`snapshot ${r.status}`);
  return r.json();
}

export async function control(action: string, attack_id?: string): Promise<Snapshot> {
  const r = await fetch("/api/control", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action, attack_id }),
  });
  if (!r.ok) throw new Error(`control ${r.status}`);
  const body = await r.json();
  return body.snapshot as Snapshot;
}

export async function ack(incident_ids?: string[]): Promise<void> {
  await fetch("/api/ack", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ incident_ids: incident_ids ?? null }),
  });
}
