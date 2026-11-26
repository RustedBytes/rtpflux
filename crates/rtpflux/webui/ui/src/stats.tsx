import { createContext, type ComponentChildren } from "preact";
import { useContext, useEffect, useRef, useState } from "preact/hooks";
import { usePoll } from "./hooks";

interface StatRow {
  group: string;
  name: string;
  value: number;
  kind: "counter" | "gauge";
}
interface StatsAnswer {
  ts_ms: number;
  rows: StatRow[];
}

/** Five minutes of samples at the default 2 s refresh. */
const KEEP = 150;

export interface Stats {
  /** "group:name" → current value and kind. */
  current: Map<string, StatRow>;
  value(key: string): number | undefined;
  /** Per second, from the last two samples (counters). */
  rate(key: string): number | undefined;
  /** Recent values (gauges) or per-second rates (counters). */
  history(key: string): number[];
  updated: number | undefined;
  error: string | undefined;
}

const empty: Stats = { current: new Map(), value: () => undefined, rate: () => undefined, history: () => [], updated: undefined, error: undefined };
const StatsContext = createContext<Stats>(empty);

/** Polls /api/v1/stats for the whole app, so history survives page changes. */
export function StatsProvider({ children }: { children: ComponentChildren }) {
  const poll = usePoll<StatsAnswer>("stats");
  const samples = useRef<{ t: number; v: Map<string, number> }[]>([]);
  const [stats, setStats] = useState<Stats>(empty);

  useEffect(() => {
    const d = poll.data;
    if (!d) {
      if (poll.error) setStats((s) => ({ ...s, error: poll.error }));
      return;
    }
    const current = new Map(d.rows.map((r) => [`${r.group}:${r.name}`, r]));
    const s = samples.current;
    if (!s.length || s[s.length - 1].t !== d.ts_ms) {
      s.push({ t: d.ts_ms, v: new Map([...current].map(([k, r]) => [k, r.value])) });
      if (s.length > KEEP) s.splice(0, s.length - KEEP);
    }
    const rateAt = (key: string, i: number) => {
      const a = s[i - 1];
      const b = s[i];
      const va = a.v.get(key);
      const vb = b.v.get(key);
      const dt = (b.t - a.t) / 1000;
      if (va === undefined || vb === undefined || dt <= 0) return undefined;
      return Math.max(0, (vb - va) / dt); // a reset counter doesn't go negative
    };
    setStats({
      current,
      value: (k) => current.get(k)?.value,
      rate: (k) => (s.length >= 2 ? rateAt(k, s.length - 1) : undefined),
      history: (k) => {
        const counter = current.get(k)?.kind === "counter";
        const out: number[] = [];
        for (let i = counter ? 1 : 0; i < s.length; i++) {
          const v = counter ? rateAt(k, i) : s[i].v.get(k);
          if (v !== undefined) out.push(v);
        }
        return out;
      },
      updated: poll.updated,
      error: poll.error,
    });
  }, [poll.data, poll.error]);

  return <StatsContext.Provider value={stats}>{children}</StatsContext.Provider>;
}

export const useStats = () => useContext(StatsContext);
