import type { AssistantSession, Snapshot } from "./types";

export async function fetchSnapshot(): Promise<Snapshot> {
  const r = await fetch("/api/snapshot");
  if (!r.ok) throw new Error(`snapshot ${r.status}`);
  return r.json();
}

export async function control(action: string): Promise<Snapshot> {
  const r = await fetch("/api/control", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action }),
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

export async function updateRule(body: {
  rule_id: string;
  enabled?: boolean;
  severity?: string;
  clauses?: Record<string, number | boolean>;
}): Promise<Snapshot> {
  const r = await fetch("/api/rules", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`rules ${r.status}`);
  const json = await r.json();
  if (!json.ok) throw new Error(json.error || "rules update failed");
  return json.snapshot as Snapshot;
}

export async function fetchAssistant(incident_id: string, refresh = false): Promise<AssistantSession> {
  const q = new URLSearchParams({ incident_id });
  if (refresh) q.set("refresh", "true");
  const r = await fetch(`/api/assistant?${q.toString()}`);
  if (!r.ok) throw new Error(`assistant ${r.status}`);
  return r.json();
}

export async function askAssistant(incident_id: string, message: string): Promise<AssistantSession> {
  const r = await fetch("/api/assistant", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ incident_id, message }),
  });
  if (!r.ok) throw new Error(`assistant ${r.status}`);
  return r.json();
}
