import { useMemo, useState } from "preact/hooks";
import { clampOffset, Pager, usePageSize } from "../components/Pager";
import { Card, Empty, ErrorNote, Sparkline } from "../components/ui";
import { number } from "../format";
import { useStats } from "../stats";

export function Statistics() {
  const st = useStats();
  const [group, setGroup] = useState("");
  const [q, setQ] = useState("");
  const [offset, setOffset] = useState(0);
  const [size, setSize] = usePageSize();
  const groups = useMemo(() => [...new Set([...st.current.values()].map((r) => r.group))].sort(), [st.current]);
  const rows = [...st.current.entries()].filter(([k, r]) => (!group || r.group === group) && (!q || k.toLowerCase().includes(q.toLowerCase())));
  const start = clampOffset(offset, rows.length, size);

  return (
    <div class="page">
      <ErrorNote error={st.error} />
      <Card
        title="Statistics"
        actions={
          <>
            <select aria-label="Group" value={group} onChange={(e) => {
                setGroup((e.target as HTMLSelectElement).value);
                setOffset(0);
              }}>
              <option value="">All groups</option>
              {groups.map((g) => <option key={g} value={g}>{g}</option>)}
            </select>
            <input type="search" placeholder="Filter…" aria-label="Filter" value={q} onInput={(e) => {
                setQ((e.target as HTMLInputElement).value);
                setOffset(0);
              }} />
          </>
        }
      >
        {rows.length === 0 ? (
          <Empty />
        ) : (
          <div class="scroll-x">
            <table>
              <thead>
                <tr><th>Group</th><th>Name</th><th>Kind</th><th class="num">Value</th><th class="num">Per second</th><th>Last 5 minutes</th></tr>
              </thead>
              <tbody>
                {rows.slice(start, start + size).map(([k, r]) => (
                  <tr key={k}>
                    <td>{r.group}</td>
                    <td><code>{r.name}</code></td>
                    <td><span class="muted">{r.kind}</span></td>
                    <td class="num">{number(r.value)}</td>
                    <td class="num">{r.kind === "counter" ? number(st.rate(k), 2) : "—"}</td>
                    <td><Sparkline values={st.history(k)} width={120} height={24} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <Pager total={rows.length} offset={start} size={size} onOffset={setOffset} onSize={setSize} />
      </Card>
    </div>
  );
}
