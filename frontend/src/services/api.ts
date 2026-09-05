import type { AnalyzeResult, HistoryItem } from "../types/scan";

const API = import.meta.env.VITE_API_URL ?? "";

async function parseError(res: Response): Promise<string> {
  try {
    const body = await res.json();
    if (typeof body.detail === "string") return body.detail;
    if (Array.isArray(body.detail)) return body.detail.map((d: { msg?: string }) => d.msg).join("; ");
  } catch {
    /* ignore */
  }
  return `Request failed (${res.status})`;
}

export async function analyzeUrl(url: string, demo = false): Promise<AnalyzeResult> {
  const res = await fetch(`${API}/api/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, demo }),
  });
  if (!res.ok) throw new Error(await parseError(res));
  return res.json();
}

export async function analyzeStream(
  url: string,
  onStage: (name: string) => void,
  demo = false,
): Promise<AnalyzeResult> {
  const res = await fetch(`${API}/api/analyze/stream`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, demo }),
  });
  if (!res.ok) throw new Error(await parseError(res));
  const reader = res.body?.getReader();
  if (!reader) return analyzeUrl(url, demo);
  const decoder = new TextDecoder();
  let buffer = "";
  let result: AnalyzeResult | null = null;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop() ?? "";
    for (const line of lines) {
      if (!line.trim()) continue;
      const evt = JSON.parse(line) as { event: string; name?: string; data?: AnalyzeResult; detail?: string };
      if (evt.event === "stage" && evt.name) onStage(evt.name);
      if (evt.event === "error") throw new Error(evt.detail || "Analysis failed");
      if (evt.event === "result" && evt.data) result = evt.data;
    }
  }
  if (!result) throw new Error("The scanner did not return a result.");
  return result;
}

export async function fetchHistory(params: Record<string, string | number | undefined> = {}) {
  const qs = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== "") qs.set(k, String(v));
  });
  const res = await fetch(`${API}/api/history?${qs.toString()}`);
  if (!res.ok) throw new Error(await parseError(res));
  return res.json() as Promise<{ items: HistoryItem[]; total: number; page: number; page_size: number }>;
}

export async function fetchScan(id: number): Promise<AnalyzeResult> {
  const res = await fetch(`${API}/api/history/${id}`);
  if (!res.ok) throw new Error(await parseError(res));
  return res.json();
}

export async function deleteScan(id: number) {
  const res = await fetch(`${API}/api/history/${id}`, { method: "DELETE" });
  if (!res.ok) throw new Error(await parseError(res));
}

export async function fetchAnalytics() {
  const res = await fetch(`${API}/api/analytics`);
  if (!res.ok) throw new Error(await parseError(res));
  return res.json();
}

export async function fetchMetrics() {
  const res = await fetch(`${API}/api/model/metrics`);
  if (!res.ok) throw new Error(await parseError(res));
  return res.json();
}

export async function fetchFeatures() {
  const res = await fetch(`${API}/api/model/features`);
  if (!res.ok) throw new Error(await parseError(res));
  return res.json() as Promise<{ features: { feature: string; importance: number }[] }>;
}

export async function fetchHealth() {
  const res = await fetch(`${API}/api/health`);
  if (!res.ok) throw new Error(await parseError(res));
  return res.json();
}

export async function fetchConfig() {
  const res = await fetch(`${API}/api/config`);
  if (!res.ok) throw new Error(await parseError(res));
  return res.json();
}

export async function analyzeCsv(file: File) {
  const body = new FormData();
  body.append("file", file);
  const res = await fetch(`${API}/api/analyze/csv`, { method: "POST", body });
  if (!res.ok) throw new Error(await parseError(res));
  return res.json();
}

export function reportUrl(id: number) {
  return `${API}/api/report/${id}`;
}
