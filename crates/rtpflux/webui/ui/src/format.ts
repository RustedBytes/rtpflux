// Display helpers.

export function duration(seconds: number | undefined | null): string {
  if (seconds === undefined || seconds === null || !Number.isFinite(seconds)) return "—";
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h ${m % 60}m`;
  return `${Math.floor(h / 24)}d ${h % 24}h`;
}

export function number(n: number | undefined | null, digits = 0): string {
  if (n === undefined || n === null || !Number.isFinite(n)) return "—";
  return n.toLocaleString(undefined, { maximumFractionDigits: digits, minimumFractionDigits: digits });
}

export function bytes(kb: number | undefined | null): string {
  if (kb === undefined || kb === null) return "—";
  if (kb < 1024) return `${kb} KB`;
  if (kb < 1024 * 1024) return `${(kb / 1024).toFixed(1)} MB`;
  return `${(kb / 1024 / 1024).toFixed(2)} GB`;
}

export function time(ms: number): string {
  return new Date(ms).toLocaleTimeString();
}

export function dateTime(unixSeconds: number | undefined | null): string {
  if (!unixSeconds) return "—";
  return new Date(unixSeconds * 1000).toLocaleString();
}

/** "user_agent" → "User agent", "call-id" → "Call ID", "ip_addr" → "IP addr". */
export function label(key: string): string {
  const words = key.replace(/[-_]+/g, " ").replace(/([a-z])([A-Z])/g, "$1 $2").trim().split(" ");
  const up = new Set(["id", "ip", "uri", "ua", "tls", "sni", "aor", "dpid", "rtp", "url", "fqdn", "spi", "q", "dns", "ws", "ims"]);
  return words
    .map((w, i) => (up.has(w.toLowerCase()) ? w.toUpperCase() : i === 0 ? w.charAt(0).toUpperCase() + w.slice(1).toLowerCase() : w.toLowerCase()))
    .join(" ");
}

/** A cell value as text (objects compact JSON). */
export function text(v: unknown): string {
  if (v === null || v === undefined || v === "") return "—";
  if (typeof v === "number") return number(v, Number.isInteger(v) ? 0 : 2);
  if (typeof v === "boolean") return v ? "yes" : "no";
  if (typeof v === "string") return v;
  return JSON.stringify(v);
}

export function rowCount(n: number): string {
  return `${n.toLocaleString()} ${n === 1 ? "row" : "rows"}`;
}
