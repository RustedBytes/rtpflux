import type { ComponentChildren } from "preact";
import { useEffect } from "preact/hooks";
import { label, text } from "../format";
import type { Row } from "../api";

const GOOD = new Set(["active", "up", "established", "confirmed", "enabled", "yes", "open", "registered", "ok", "true", "answered", "delivered", "uploaded"]);
const BAD = new Set(["inactive", "down", "disabled", "failed", "error", "blocked", "ended", "no", "false", "closed", "defunct", "rejected", "dropped", "incomplete"]);

/** A state word as a coloured badge. */
export function Badge({ value }: { value: unknown }) {
  const t = text(value);
  const k = t.toLowerCase();
  const cls = GOOD.has(k) ? "badge good" : BAD.has(k) ? "badge bad" : k === "—" ? "muted" : "badge";
  return <span class={cls}>{t}</span>;
}

export function Card({ title, actions, children }: { title?: string; actions?: ComponentChildren; children: ComponentChildren }) {
  return (
    <section class="card">
      {(title || actions) && (
        <header class="card-head">
          {title && <h2>{title}</h2>}
          {actions && <div class="card-actions">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  );
}

export function ErrorNote({ error }: { error?: string }) {
  return error ? <p class="error" role="alert">{error}</p> : null;
}

export function Empty({ children = "Nothing to show." }: { children?: ComponentChildren }) {
  return <p class="empty">{children}</p>;
}

/** Key/value pairs of an object (nested objects as compact JSON). */
export function KeyValues({ data, skip = [] }: { data: Row | undefined; skip?: string[] }) {
  if (!data) return null;
  const entries = Object.entries(data).filter(([k]) => !skip.includes(k));
  return (
    <dl class="kv">
      {entries.map(([k, v]) => (
        <div key={k}>
          <dt>{label(k)}</dt>
          <dd>{typeof v === "object" && v !== null ? <pre>{JSON.stringify(v, null, 2)}</pre> : text(v)}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Tabs({ tabs, active, onChange }: { tabs: { id: string; label: string }[]; active: string; onChange: (id: string) => void }) {
  return (
    <nav class="tabs" role="tablist">
      {tabs.map((t) => (
        <button key={t.id} role="tab" aria-selected={t.id === active} class={t.id === active ? "tab active" : "tab"} onClick={() => onChange(t.id)}>
          {t.label}
        </button>
      ))}
    </nav>
  );
}

/** A side panel with the details of one row. */
export function Drawer({ title, onClose, children }: { title: string; onClose: () => void; children: ComponentChildren }) {
  useEffect(() => {
    const on = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", on);
    return () => window.removeEventListener("keydown", on);
  }, [onClose]);
  return (
    <div class="drawer-backdrop" onClick={onClose}>
      <div class="drawer" role="dialog" aria-modal="true" aria-label={title} onClick={(e) => e.stopPropagation()}>
        <header class="drawer-head">
          <h2>{title}</h2>
          <button class="icon" aria-label="Close" onClick={onClose}>
            ✕
          </button>
        </header>
        <div class="drawer-body">{children}</div>
      </div>
    </div>
  );
}

/** A tiny line chart of the recent values. */
export function Sparkline({ values, width = 160, height = 36 }: { values: number[]; width?: number; height?: number }) {
  if (values.length < 2) return <svg class="spark" width={width} height={height} aria-hidden="true" />;
  const max = Math.max(...values, 1);
  const min = Math.min(...values, 0);
  const span = max - min || 1;
  const step = width / (values.length - 1);
  const pts = values.map((v, i) => `${(i * step).toFixed(1)},${(height - 2 - ((v - min) / span) * (height - 4)).toFixed(1)}`).join(" ");
  return (
    <svg class="spark" width={width} height={height} viewBox={`0 0 ${width} ${height}`} aria-hidden="true">
      <polyline points={pts} fill="none" stroke="currentColor" stroke-width="1.5" vector-effect="non-scaling-stroke" />
    </svg>
  );
}

export function Tile({ label: name, value, sub, history }: { label: string; value: string; sub?: string; history?: number[] }) {
  return (
    <div class="tile">
      <div class="tile-label">{name}</div>
      <div class="tile-value">{value}</div>
      {sub && <div class="tile-sub">{sub}</div>}
      {history && <Sparkline values={history} />}
    </div>
  );
}
