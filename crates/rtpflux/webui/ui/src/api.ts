// The read-only API (/api/v1). The browser sends the Basic-auth
// credentials it was given for the page with every same-origin request.

export type Row = Record<string, unknown>;

export interface Page {
  total: number;
  offset: number;
  limit: number;
  rows: Row[];
}

export interface Meta {
  version: string;
  refresh_ms: number;
  sections: Record<string, string[]>;
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export type Params = Record<string, string | number | undefined>;

export async function get<T>(path: string, params: Params = {}): Promise<T> {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== "") q.set(k, String(v));
  }
  const qs = q.toString();
  const r = await fetch(`/api/v1/${path}${qs ? `?${qs}` : ""}`, { headers: { Accept: "application/json" } });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new ApiError(r.status, (body as { error?: string }).error ?? r.statusText);
  return body as T;
}

export function isPage(v: unknown): v is Page {
  return typeof v === "object" && v !== null && Array.isArray((v as Page).rows) && typeof (v as Page).total === "number";
}
