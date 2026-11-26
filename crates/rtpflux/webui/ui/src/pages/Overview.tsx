import { useRef } from "preact/hooks";
import { Card, ErrorNote, Tile } from "../components/ui";
import { bytes, dateTime, duration, number } from "../format";
import { usePoll } from "../hooks";
import { useStats } from "../stats";

interface Info {
  version: string;
  pid: number;
  started: number;
  uptime: number;
  rss_kb?: number;
  threads?: number;
  interfaces: { name: string; address: string; advertise: string }[];
  ports: string;
  sessions_max: number;
  timeout_s: number;
  workers: number;
  state_file?: string;
  state_redis?: string;
  control: string[];
  metrics: string[];
  xdp: { devices: string[]; mode: string; af_xdp: boolean } | null;
  recording: {
    dir: string;
    format: string;
    channels: string;
    sample_rate: number;
    storage: string;
    s3: { bucket: string; prefix: string; endpoint: string; webhook: { url: string; signed: boolean } | null } | null;
  } | null;
  control_tcp: string[];
  control_http: string[];
  receive: string;
  worker_stats: { index: number; receive: string; calls: number; offloaded_calls: number; forwarded: number; kernel_packets: number; dropped: number; send_errors: number; srtp_rejected: number }[];
  timeouts: { media_s: number; silent_s: number; offer_s: number; final_s: number };
  strict_source: boolean;
  ice: { mode: string; stun_server: string | null };
  srflx: (string | null)[];
  warnings: string[];
}

type Worker = Info["worker_stats"][number];

/** Each media worker: its calls, its traffic (packets per second between
 * two polls) and how it receives; a busy or idle worker stands out. */
function WorkersCard({ workers }: { workers: Worker[] | undefined }) {
  const prev = useRef<{ at: number; forwarded: number[] } | undefined>(undefined);
  if (!workers) return null;
  const now = Date.now();
  const rates = prev.current
    ? workers.map((w, n) => {
        const dt = (now - prev.current!.at) / 1000;
        const before = prev.current!.forwarded[n];
        return dt > 0 && before !== undefined ? (w.forwarded - before) / dt : undefined;
      })
    : [];
  prev.current = { at: now, forwarded: workers.map((w) => w.forwarded) };
  return (
    <Card title="Media workers">
      <div class="scroll-x">
        <table>
          <thead>
            <tr>
              <th class="num">Worker</th><th class="num">Calls</th><th class="num">In XDP</th><th class="num">Packets / s</th>
              <th class="num">Relayed</th><th class="num">Dropped</th><th class="num">Send errors</th><th class="num">SRTP rejected</th><th>Receiving</th>
            </tr>
          </thead>
          <tbody>
            {workers.map((w, n) => (
              <tr key={w.index}>
                <td class="num">{w.index}</td>
                <td class="num">{number(w.calls)}</td>
                <td class="num">{number(w.offloaded_calls)}</td>
                <td class="num">{number(rates[n], 0)}</td>
                <td class="num">{number(w.forwarded)}</td>
                <td class="num">{number(w.dropped)}</td>
                <td class="num">{number(w.send_errors)}</td>
                <td class="num">{number(w.srtp_rejected)}</td>
                <td>{w.receive}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

/** How the workers receive: one line when they agree, else each. */
function receiveText(configured: string, workers: string[]): string {
  const kinds = [...new Set(workers)];
  if (kinds.length === 0) return configured;
  if (kinds.length === 1) return `${kinds[0]} on all ${workers.length} workers`;
  return workers.map((w, n) => `worker ${n + 1}: ${w}`).join("; ");
}

/** ng commands in the order an operator thinks of them. */

/** Element-wise sum of histories (aligned at their newest end). */
function sumHistories(hs: number[][]): number[] {
  const n = Math.max(0, ...hs.map((h) => h.length));
  const out = new Array<number>(n).fill(0);
  for (const h of hs) h.forEach((v, i) => (out[n - h.length + i] += v));
  return out;
}

export function Overview() {
  const info = usePoll<Info>("info");
  const st = useStats();
  const i = info.data;
  const ngKeys = [...st.current.keys()].filter((k) => k.startsWith("ng_requests:"));
  const ngRate = ngKeys.reduce<number | undefined>((a, k) => {
    const r = st.rate(k);
    return r === undefined ? a : (a ?? 0) + r;
  }, undefined);
  const ngTotal = ngKeys.reduce((a, k) => a + (st.value(k) ?? 0), 0);

  const tiles = [
    { label: "Packets relayed / s", key: "relay:packets_forwarded", value: number(st.rate("relay:packets_forwarded"), 0), sub: `${number(st.value("relay:packets_forwarded"))} total (userspace)` },
    { label: "Dropped / s", key: "relay:packets_dropped", value: number(st.rate("relay:packets_dropped"), 1), sub: `${number(st.value("relay:packets_dropped"))} total` },
    { label: "Sessions", key: "relay:sessions", value: number(st.value("relay:sessions")), sub: i ? `of ${number(i.sessions_max)} allowed` : undefined },
    { label: "Relay calls", key: "relay:calls", value: number(st.value("relay:calls")), sub: "media sections" },
    { label: "ng requests / s", key: "", value: number(ngRate, 1), sub: `${number(ngTotal)} total`, history: sumHistories(ngKeys.map((k) => st.history(k))) },
    { label: "SRTP rejected / s", key: "relay:srtp_rejected", value: number(st.rate("relay:srtp_rejected"), 1), sub: `${number(st.value("relay:srtp_rejected"))} total` },
    { label: "Send errors / s", key: "relay:send_errors", value: number(st.rate("relay:send_errors"), 1), sub: `${number(st.value("relay:send_errors"))} total` },
    { label: "Calls timed out", key: "relay:calls_timed_out", value: number(st.value("relay:calls_timed_out")), sub: "no media for the timeout" },
    ...(i?.xdp
      ? [
          { label: "Kernel packets / s", key: "relay:kernel_packets", value: number(st.rate("relay:kernel_packets"), 0), sub: `${number(st.value("relay:offloaded_calls"))} calls in XDP` },
        ]
      : []),
    { label: "DTLS handshakes", key: "relay:dtls_handshakes", value: number(st.value("relay:dtls_handshakes")), sub: `${number(st.value("relay:dtls_failures"))} failed` },
    {
      label: "Joins · copies · subs",
      key: "links:copies",
      value: `${number(st.value("links:connections"))} · ${number(st.value("links:copies"))} · ${number(st.value("links:subscriptions"))}`,
      sub: "transfers, monitoring, SIPREC",
    },
  ];

  return (
    <div class="page">
      <ErrorNote error={info.error ?? st.error} />
      {i && i.warnings.length > 0 && (
        <section class="card warning">
          <h2>Configuration warnings</h2>
          <ul>
            {i.warnings.map((w) => (
              <li key={w}>{w}</li>
            ))}
          </ul>
          <p class="muted">As at start-up; <code>rtpflux --check -c &lt;file&gt;</code> prints them too.</p>
        </section>
      )}
      <div class="tiles">
        {tiles.map((t) => (
          <Tile key={t.label} label={t.label} value={t.value} sub={t.sub} history={t.history ?? st.history(t.key)} />
        ))}
      </div>
      <Card title="ng requests (per second)">
        <div class="chips">
          {/* Every command the relay counts, in its order. */}
          {ngKeys.map((k) => k.slice("ng_requests:".length)).map((c) => (
            <span key={c} class="chip" title={`${number(st.value(`ng_requests:${c}`))} total`}>
              {c} <strong>{number(st.rate(`ng_requests:${c}`), 1)}</strong>
            </span>
          ))}
        </div>
        <p class="muted">
          {number(st.value("ng:errors"))} answered with an error, {number(st.value("ng:retransmissions"))} retransmissions answered from the cache.
        </p>
      </Card>
      <div class="grid2">
        <Card title="Process">
          {i && (
            <dl class="kv">
              <div><dt>Version</dt><dd>rtpflux {i.version}</dd></div>
              <div><dt>Uptime</dt><dd>{duration(i.uptime)} (since {dateTime(i.started)})</dd></div>
              <div><dt>PID</dt><dd>{i.pid}</dd></div>
              <div><dt>Memory (RSS)</dt><dd>{bytes(i.rss_kb)}</dd></div>
              <div><dt>Threads</dt><dd>{number(i.threads)}</dd></div>
              <div><dt>Media workers</dt><dd>{number(st.value("relay:workers"))}</dd></div>
              <div>
                <dt>Receiving</dt>
                <dd>
                  {receiveText(i.receive, i.worker_stats.map((w) => w.receive))}
                  {i.worker_stats.some((w) => w.receive !== i.receive) && <span class="badge bad" title={`configured: ${i.receive}`}>not as configured</span>}
                </dd>
              </div>
            </dl>
          )}
        </Card>
        <Card title="Configuration">
          {i && (
            <>
              <dl class="kv">
                <div><dt>Ports</dt><dd>{i.ports}</dd></div>
                <div><dt>Sessions</dt><dd>up to {number(i.sessions_max)}{i.strict_source ? ", strict source" : ""}</dd></div>
                <div>
                  <dt>Timeouts</dt>
                  <dd>
                    media {duration(i.timeouts.media_s)}, on hold {duration(i.timeouts.silent_s)}, unanswered {duration(i.timeouts.offer_s)}
                    {i.timeouts.final_s ? `, any call ${duration(i.timeouts.final_s)}` : ""}
                  </dd>
                </div>
                <div><dt>ng over UDP</dt><dd><code>{i.control.join(", ") || "—"}</code></dd></div>
                {i.control_tcp.length > 0 && <div><dt>ng over TCP</dt><dd><code>{i.control_tcp.join(", ")}</code></dd></div>}
                {i.control_http.length > 0 && <div><dt>ng over HTTP / WebSocket</dt><dd><code>{i.control_http.join(", ")}</code></dd></div>}
                <div><dt>ICE</dt><dd>{i.ice.mode} agent{i.ice.stun_server ? `, STUN server ${i.ice.stun_server}` : ""}</dd></div>
                <div><dt>Metrics</dt><dd><code>{i.metrics.join(", ") || "off"}</code></dd></div>
                <div><dt>State file</dt><dd><code>{i.state_file ?? "off"}</code></dd></div>
                {i.state_redis && <div><dt>State in Redis</dt><dd><code>{i.state_redis}</code></dd></div>}
                <div>
                  <dt>XDP</dt>
                  <dd>{i.xdp ? `${i.xdp.devices.join(", ")} (${i.xdp.mode})${i.xdp.af_xdp ? ", AF_XDP" : ""}` : "off"}</dd>
                </div>
                <div>
                  <dt>Recording</dt>
                  <dd>{i.recording ? `${i.recording.format}, ${i.recording.channels}, ${number(i.recording.sample_rate)} Hz, ${i.recording.storage} (${i.recording.dir})` : "off"}</dd>
                </div>
                {i.recording?.s3 && (
                  <div>
                    <dt>S3</dt>
                    <dd>
                      <code>{i.recording.s3.bucket}/{i.recording.s3.prefix}</code> at <code>{i.recording.s3.endpoint}</code>
                      {i.recording.s3.webhook ? <>; webhook <code>{i.recording.s3.webhook.url}</code>{i.recording.s3.webhook.signed ? " (signed)" : ""}</> : ""}
                    </dd>
                  </div>
                )}
              </dl>
              <h3>Interfaces</h3>
              <table>
                <thead><tr><th>Name</th><th>Address</th><th>In SDP</th>{i.ice.stun_server && <th>Server-reflexive</th>}</tr></thead>
                <tbody>
                  {i.interfaces.map((x, n) => (
                    <tr key={x.name}>
                      <td>{x.name}</td><td><code>{x.address}</code></td><td><code>{x.advertise}</code></td>
                      {i.ice.stun_server && <td><code>{i.srflx[n] ?? "not learned yet"}</code></td>}
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
        </Card>
      </div>
      <WorkersCard workers={i?.worker_stats} />
    </div>
  );
}
