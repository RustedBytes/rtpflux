import type { ComponentChildren } from "preact";
import { useEffect, useState } from "preact/hooks";
import type { Page, Params, Row } from "../api";
import { isPage } from "../api";
import { label, rowCount, text } from "../format";
import { usePoll } from "../hooks";
import { clampOffset, Pager, usePageSize } from "./Pager";
import { Badge, Drawer, Empty, ErrorNote, KeyValues } from "./ui";

export interface Column {
  key: string;
  label?: string;
  render?: (row: Row) => ComponentChildren;
  /** Sort on the server by this key (default: the column key). */
  sort?: string | false;
  /** Right-aligned numbers. */
  numeric?: boolean;
}

const STATE_KEYS = new Set(["state", "state_name", "status", "direction"]);

/** Identifying fields go first (the API's JSON keys arrive sorted). */
const FIRST = ["name", "id", "uri", "url", "aor", "pres_uri", "impu", "fqdn", "ip", "ip_addr", "src_ip", "addr", "peer", "prefix", "domain", "callid", "call-id", "client_id", "tree", "pipe", "state", "status"];

/** Columns from the first rows when a view doesn't list its own. */
function autoColumns(rows: Row[]): Column[] {
  const keys: string[] = [];
  for (const r of rows.slice(0, 20)) for (const k of Object.keys(r)) if (!keys.includes(k)) keys.push(k);
  const rank = (k: string) => {
    const i = FIRST.indexOf(k.toLowerCase());
    return i < 0 ? FIRST.length : i;
  };
  keys.sort((a, b) => rank(a) - rank(b));
  return keys.slice(0, 10).map((k) => ({
    key: k,
    numeric: rows.every((r) => r[k] === null || r[k] === undefined || typeof r[k] === "number"),
    render: STATE_KEYS.has(k) ? (r: Row) => <Badge value={r[k]} /> : undefined,
  }));
}

function Cell({ col, row }: { col: Column; row: Row }) {
  if (col.render) return <>{col.render(row)}</>;
  const v = row[col.key];
  const t = text(v);
  return <span title={t.length > 60 ? t : undefined}>{t.length > 120 ? `${t.slice(0, 117)}…` : t}</span>;
}

/**
 * A live table over one API path: search, sort and paging happen on the
 * server; clicking a row opens its details (or `onRow`).
 */
export function Table({
  path,
  params = {},
  columns,
  title,
  onRow,
  detail,
  emptyText,
}: {
  path: string;
  params?: Params;
  columns?: Column[];
  title?: (row: Row) => string;
  onRow?: (row: Row) => void;
  detail?: (row: Row) => ComponentChildren;
  emptyText?: string;
}) {
  const [q, setQ] = useState("");
  const [sort, setSort] = useState("");
  const [offset, setOffset] = useState(0);
  const [pageSize, setPageSize] = usePageSize();
  const [open, setOpen] = useState<Row | undefined>();
  const poll = usePoll<Page | Row>(path, { ...params, q, sort, offset, limit: pageSize });
  const page = isPage(poll.data) ? poll.data : undefined;
  const rows = page?.rows ?? [];
  const cols = columns ?? autoColumns(rows);
  // Rows went away (calls ended, a search narrowed): step back to the last page.
  useEffect(() => {
    if (page && page.total > 0 && offset >= page.total) setOffset(clampOffset(offset, page.total, pageSize));
  }, [page?.total, offset, pageSize]);

  const toggleSort = (c: Column) => {
    if (c.sort === false) return;
    const key = c.sort ?? c.key;
    setSort(sort === key ? `-${key}` : sort === `-${key}` ? "" : key);
    setOffset(0);
  };

  if (poll.data && !page) return <KeyValues data={poll.data as Row} />;
  return (
    <div class="table-wrap">
      <div class="table-tools">
        <input
          type="search"
          placeholder="Search…"
          aria-label="Search"
          value={q}
          onInput={(e) => {
            setQ((e.target as HTMLInputElement).value);
            setOffset(0);
          }}
        />
        <span class="muted">{page ? rowCount(page.total) : poll.loading ? "Loading…" : ""}</span>
      </div>
      <ErrorNote error={poll.error} />
      {page && page.total === 0 ? (
        <Empty>{q ? "No rows match." : (emptyText ?? "Nothing to show.")}</Empty>
      ) : (
        <div class="scroll-x">
          <table>
            <thead>
              <tr>
                {cols.map((c) => {
                  const key = c.sort === false ? undefined : (c.sort ?? c.key);
                  const dir = sort === key ? "ascending" : sort === `-${key}` ? "descending" : undefined;
                  return (
                    <th key={c.key} class={c.numeric ? "num" : undefined} aria-sort={dir}>
                      {key ? (
                        <button class="th-sort" onClick={() => toggleSort(c)}>
                          {c.label ?? label(c.key)}
                          <span class="sort-mark">{dir === "ascending" ? "▲" : dir === "descending" ? "▼" : ""}</span>
                        </button>
                      ) : (
                        (c.label ?? label(c.key))
                      )}
                    </th>
                  );
                })}
              </tr>
            </thead>
            <tbody>
              {rows.map((r, i) => (
                <tr key={i} class="clickable" tabIndex={0} onClick={() => (onRow ? onRow(r) : setOpen(r))} onKeyDown={(e) => e.key === "Enter" && (onRow ? onRow(r) : setOpen(r))}>
                  {cols.map((c) => (
                    <td key={c.key} class={c.numeric ? "num" : undefined}>
                      <Cell col={c} row={r} />
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {page && <Pager total={page.total} offset={offset} size={pageSize} onOffset={setOffset} onSize={setPageSize} />}
      {open && (
        <Drawer title={title ? title(open) : "Details"} onClose={() => setOpen(undefined)}>
          {detail ? detail(open) : <KeyValues data={open} />}
        </Drawer>
      )}
    </div>
  );
}
