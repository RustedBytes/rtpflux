import { createContext } from "preact";
import { useContext, useEffect, useRef, useState } from "preact/hooks";
import { get, type Params } from "./api";

/** Live refresh settings shared by every view (the header's pause button). */
export interface Live {
  paused: boolean;
  intervalMs: number;
}
export const LiveContext = createContext<Live>({ paused: false, intervalMs: 2000 });

export interface Poll<T> {
  data: T | undefined;
  error: string | undefined;
  loading: boolean;
  updated: number | undefined;
}

/**
 * GET `path` now and then every refresh interval while the view is shown
 * and live updates aren't paused. Errors back off (up to 30 s) and keep
 * the last data on screen.
 */
export function usePoll<T>(path: string | undefined, params: Params = {}, live = true): Poll<T> {
  const { paused, intervalMs } = useContext(LiveContext);
  const [state, setState] = useState<Poll<T>>({ data: undefined, error: undefined, loading: true, updated: undefined });
  const key = path === undefined ? "" : `${path}?${JSON.stringify(params)}`;
  const keyRef = useRef(key);
  keyRef.current = key;

  useEffect(() => {
    if (path === undefined) return;
    let timer: number | undefined;
    let failures = 0;
    let stopped = false;
    setState((s) => ({ ...s, loading: true }));
    const tick = async () => {
      try {
        const data = await get<T>(path, params);
        if (stopped || keyRef.current !== key) return;
        failures = 0;
        setState({ data, error: undefined, loading: false, updated: Date.now() });
      } catch (e) {
        if (stopped) return;
        failures++;
        setState((s) => ({ ...s, error: e instanceof Error ? e.message : String(e), loading: false }));
      }
      if (!stopped && live && !paused) {
        const wait = failures ? Math.min(30000, intervalMs * 2 ** failures) : intervalMs;
        timer = window.setTimeout(tick, wait);
      }
    };
    tick();
    return () => {
      stopped = true;
      window.clearTimeout(timer);
    };
  }, [key, paused, intervalMs, live]);
  return state;
}

/** Location hash as a route: "#/calls?tab=dialogs" → ["calls", {tab: "dialogs"}]. */
export function useRoute(): [string, URLSearchParams] {
  const read = () => window.location.hash.replace(/^#\/?/, "");
  const [hash, setHash] = useState(read());
  useEffect(() => {
    const on = () => setHash(read());
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  const [page, qs] = hash.split("?", 2);
  return [page || "overview", new URLSearchParams(qs ?? "")];
}

export function navigate(page: string, params: Record<string, string> = {}) {
  const qs = new URLSearchParams(params).toString();
  window.location.hash = `#/${page}${qs ? `?${qs}` : ""}`;
}
