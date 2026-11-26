import { useContext, useEffect, useRef, useState } from "preact/hooks";
import { get } from "../api";
import { Card, ErrorNote } from "../components/ui";
import { time } from "../format";
import { LiveContext, useRoute } from "../hooks";

interface Line {
  seq: number;
  ts_ms: number;
  level: string;
  text: string;
}

const LEVELS = ["TRACE", "DEBUG", "INFO", "WARN", "ERROR"];
const KEEP = 5000;

/** A live tail of the log ring: only new lines are fetched each time. */
export function Logs() {
  const { paused, intervalMs } = useContext(LiveContext);
  const [lines, setLines] = useState<Line[]>([]);
  const [error, setError] = useState<string>();
  const [minLevel, setMinLevel] = useState("TRACE");
  // `#/logs?q=…` (a call's "log lines" link) starts with that search.
  const [, params] = useRoute();
  const routed = params.get("q") ?? "";
  const [q, setQ] = useState(routed);
  useEffect(() => setQ(routed), [routed]);
  const [follow, setFollow] = useState(true);
  const after = useRef(0);
  const box = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let timer: number | undefined;
    let stopped = false;
    const tick = async () => {
      try {
        const r = await get<{ newest: number; lines: Line[] }>("logs", { after: after.current });
        if (stopped) return;
        setError(undefined);
        if (r.lines.length) {
          after.current = r.lines[r.lines.length - 1].seq;
          setLines((old) => [...old, ...r.lines].slice(-KEEP));
        }
      } catch (e) {
        if (!stopped) setError(e instanceof Error ? e.message : String(e));
      }
      if (!stopped && !paused) timer = window.setTimeout(tick, intervalMs);
    };
    tick();
    return () => {
      stopped = true;
      window.clearTimeout(timer);
    };
  }, [paused, intervalMs]);

  useEffect(() => {
    if (follow && box.current) box.current.scrollTop = box.current.scrollHeight;
  }, [lines, follow]);

  const min = LEVELS.indexOf(minLevel);
  const needle = q.toLowerCase();
  const shown = lines.filter((l) => LEVELS.indexOf(l.level) >= min && (!needle || l.text.toLowerCase().includes(needle)));

  return (
    <div class="page">
      <ErrorNote error={error} />
      <Card
        title="Log"
        actions={
          <>
            <select aria-label="Minimum level" value={minLevel} onChange={(e) => setMinLevel((e.target as HTMLSelectElement).value)}>
              {LEVELS.map((l) => <option key={l} value={l}>{l === "TRACE" ? "All levels" : `${l} and above`}</option>)}
            </select>
            <input type="search" placeholder="Filter…" aria-label="Filter" value={q} onInput={(e) => setQ((e.target as HTMLInputElement).value)} />
            <label class="check">
              <input type="checkbox" checked={follow} onChange={(e) => setFollow((e.target as HTMLInputElement).checked)} /> Follow
            </label>
          </>
        }
      >
        <div class="log" ref={box} role="log" aria-live="polite">
          {shown.length === 0 ? (
            <p class="empty">No log lines yet.</p>
          ) : (
            shown.map((l) => (
              <div key={l.seq} class={`log-line lvl-${l.level.toLowerCase()}`}>
                <span class="log-time">{time(l.ts_ms)}</span>
                <span class="log-level">{l.level}</span>
                <span class="log-text">{l.text}</span>
              </div>
            ))
          )}
        </div>
      </Card>
    </div>
  );
}
