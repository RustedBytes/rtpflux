import { useState } from "preact/hooks";

/** Page sizes offered by every table. */
export const PAGE_SIZES = [25, 50, 100, 250];

const SIZE_KEY = "ferrosip.webui.pageSize";

/** The rows-per-page choice, remembered in this browser (if it allows). */
export function usePageSize(): [number, (n: number) => void] {
  const [size, setSize] = useState(() => {
    try {
      const n = Number(localStorage.getItem(SIZE_KEY));
      return PAGE_SIZES.includes(n) ? n : PAGE_SIZES[0];
    } catch {
      return PAGE_SIZES[0];
    }
  });
  const set = (n: number) => {
    setSize(n);
    try {
      localStorage.setItem(SIZE_KEY, String(n));
    } catch {
      // private mode / storage off: the choice lasts for this page only
    }
  };
  return [size, set];
}

/** The offset to show for `total` rows: past the end moves to the last page. */
export function clampOffset(offset: number, total: number, size: number): number {
  if (offset < total) return offset;
  return Math.max(0, Math.floor((total - 1) / size) * size);
}

/**
 * Page numbers to show: the first, the last, and two either side of the
 * current page, with gaps (`null`) between: 1 … 4 5 [6] 7 8 … 20.
 */
export function pageWindow(current: number, count: number): (number | null)[] {
  const pages = new Set<number>([0, count - 1]);
  for (let p = current - 2; p <= current + 2; p++) if (p >= 0 && p < count) pages.add(p);
  const sorted = [...pages].filter((p) => p >= 0).sort((a, b) => a - b);
  const out: (number | null)[] = [];
  for (const p of sorted) {
    const prev = out[out.length - 1];
    if (typeof prev === "number" && p - prev > 1) out.push(null);
    out.push(p);
  }
  return out;
}

/**
 * Pagination for a table of `total` rows: page numbers, first/previous/
 * next/last, and the page size. Hidden when everything fits on one page of
 * the smallest size.
 */
export function Pager({
  total,
  offset,
  size,
  onOffset,
  onSize,
}: {
  total: number;
  offset: number;
  size: number;
  onOffset: (offset: number) => void;
  onSize: (size: number) => void;
}) {
  if (total <= PAGE_SIZES[0]) return null;
  const count = Math.max(1, Math.ceil(total / size));
  const current = Math.min(Math.floor(offset / size), count - 1);
  const go = (p: number) => onOffset(Math.max(0, Math.min(count - 1, p)) * size);
  return (
    <nav class="pager" aria-label="Pages">
      <span class="muted pager-range">
        {(current * size + 1).toLocaleString()}–{Math.min((current + 1) * size, total).toLocaleString()} of {total.toLocaleString()}
      </span>
      <div class="pager-pages">
        <button aria-label="First page" disabled={current === 0} onClick={() => go(0)}>
          «
        </button>
        <button aria-label="Previous page" disabled={current === 0} onClick={() => go(current - 1)}>
          ‹
        </button>
        {pageWindow(current, count).map((p, i) =>
          p === null ? (
            <span key={`gap${i}`} class="pager-gap" aria-hidden="true">
              …
            </span>
          ) : (
            <button key={p} class={p === current ? "page active" : "page"} aria-label={`Page ${p + 1}`} aria-current={p === current ? "page" : undefined} onClick={() => go(p)}>
              {p + 1}
            </button>
          ),
        )}
        <button aria-label="Next page" disabled={current >= count - 1} onClick={() => go(current + 1)}>
          ›
        </button>
        <button aria-label="Last page" disabled={current >= count - 1} onClick={() => go(count - 1)}>
          »
        </button>
      </div>
      <label class="pager-size">
        <span class="muted">Rows</span>
        <select
          aria-label="Rows per page"
          value={size}
          onChange={(e) => {
            const s = Number((e.target as HTMLSelectElement).value);
            onSize(s);
            onOffset(Math.floor((current * size) / s) * s); // keep the first visible row in view
          }}
        >
          {PAGE_SIZES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </label>
    </nav>
  );
}
