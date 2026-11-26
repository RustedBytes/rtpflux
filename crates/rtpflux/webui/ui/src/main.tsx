import { render } from "preact";
import { useEffect, useState } from "preact/hooks";
import "./styles.css";
import { get, type Meta } from "./api";
import { ErrorNote } from "./components/ui";
import { time } from "./format";
import { LiveContext, useRoute } from "./hooks";
import { Calls } from "./pages/Calls";
import { Logs } from "./pages/Logs";
import { Overview } from "./pages/Overview";
import { Recordings } from "./pages/Recordings";
import { Statistics } from "./pages/Statistics";
import { Xdp } from "./pages/Xdp";
import { StatsProvider, useStats } from "./stats";

/** Navigation order; a section is listed when /api/v1/meta has it. */
const NAV: { id: string; title: string }[] = [
  { id: "overview", title: "Overview" },
  { id: "calls", title: "Calls" },
  { id: "statistics", title: "Statistics" },
  { id: "recordings", title: "Recordings" },
  { id: "xdp", title: "XDP" },
  { id: "logs", title: "Logs" },
];

function Page({ id, meta }: { id: string; meta: Meta }) {
  switch (id) {
    case "calls":
      return <Calls logs={Boolean(meta.sections.logs)} />;
    case "xdp":
      return <Xdp />;
    case "statistics":
      return <Statistics />;
    case "recordings":
      return <Recordings uploads={Boolean(meta.sections.uploads)} />;
    case "logs":
      return <Logs />;
    default:
      return <Overview />;
  }
}

function Updated() {
  const st = useStats();
  return <span class="muted updated">{st.updated ? `Updated ${time(st.updated)}` : ""}</span>;
}

function App() {
  const [meta, setMeta] = useState<Meta>();
  const [error, setError] = useState<string>();
  const [paused, setPaused] = useState(false);
  const [page] = useRoute();
  const [menu, setMenu] = useState(false);

  // The burger menu (narrow screens) closes on navigation and on Escape.
  useEffect(() => setMenu(false), [page]);
  useEffect(() => {
    if (!menu) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setMenu(false);
    addEventListener("keydown", onKey);
    return () => removeEventListener("keydown", onKey);
  }, [menu]);

  useEffect(() => {
    get<Meta>("meta").then(setMeta, (e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);

  const nav = NAV.filter((n) => n.id === "overview" || meta?.sections[n.id]);
  const current = nav.find((n) => n.id === page) ?? nav[0];
  useEffect(() => {
    document.title = `${current?.title ?? "rtpflux"} · rtpflux`;
  }, [current?.id]);

  if (error) return <ErrorNote error={`Cannot reach the API: ${error}`} />;
  if (!meta) return <p class="empty">Loading…</p>;
  return (
    <LiveContext.Provider value={{ paused, intervalMs: meta.refresh_ms }}>
      <StatsProvider>
        <div class={menu ? "shell menu-open" : "shell"}>
          <aside class="sidebar" id="sidebar">
            <div class="brand">
              <img src="/favicon.svg" alt="" width="24" height="24" />
              <span>rtpflux</span>
              <span class="muted version">{meta.version}</span>
            </div>
            <nav aria-label="Sections">
              {nav.map((n) => (
                <a key={n.id} href={`#/${n.id}`} onClick={() => setMenu(false)} class={n.id === current?.id ? "nav-link active" : "nav-link"} aria-current={n.id === current?.id ? "page" : undefined}>
                  {n.title}
                </a>
              ))}
            </nav>
            <p class="readonly muted">Read-only view</p>
          </aside>
          {menu && <div class="backdrop" onClick={() => setMenu(false)} />}
          <main>
            <header class="topbar">
              <button class="burger" aria-label="Menu" aria-expanded={menu} aria-controls="sidebar" onClick={() => setMenu(!menu)}>
                <span aria-hidden="true">☰</span>
              </button>
              <h1>{current?.title}</h1>
              <div class="topbar-right">
                <Updated />
                <button class={paused ? "live paused" : "live"} onClick={() => setPaused(!paused)} aria-pressed={paused}>
                  {paused ? "▶ Resume" : "❚❚ Pause"}
                </button>
              </div>
            </header>
            {current && <Page id={current.id} meta={meta} />}
          </main>
        </div>
      </StatsProvider>
    </LiveContext.Provider>
  );
}

render(<App />, document.getElementById("app")!);
