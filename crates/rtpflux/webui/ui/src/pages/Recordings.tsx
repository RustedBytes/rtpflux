import { useState } from "preact/hooks";
import type { Row } from "../api";
import { Table } from "../components/Table";
import { Badge, Empty, ErrorNote, KeyValues, Tabs } from "../components/ui";
import { dateTime, duration, number, text } from "../format";
import { usePoll } from "../hooks";

interface Stream {
  src: string;
  dst: string;
  kind: string;
  ssrc: string | null;
  packets: number;
  octets: number;
  pts: { pt: number; packets: number }[];
  lost: number | null;
  duration_ms: number;
}

interface Streams {
  streams: Stream[];
  truncated: boolean;
  meta: Row | null;
}

/** File sizes in octets, as people read them. */
function size(n: unknown): string {
  if (typeof n !== "number") return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

/** A stream's length: seconds with a decimal under a minute, else as calls show it. */
const length = (ms: number) => (ms < 60_000 ? `${(ms / 1000).toFixed(1)} s` : duration(ms / 1000));

/** A protocol field (sequence number, timestamp) as it is, without digit grouping. */
const raw = (v: unknown) => (typeof v === "number" ? String(v) : "—");

/** Microseconds since the first packet, as seconds with milliseconds. */
const offset = (us: unknown) => (typeof us === "number" ? (us / 1e6).toFixed(3) : "—");

/** Which party a stream is, when the converter's JSON says which port is the caller's. */
function party(s: Stream, meta: Row | null): string {
  const left = meta?.left_port;
  if (typeof left !== "number") return "";
  const port = Number(s.dst.split(":").pop());
  return port === left || port === left + 1 ? "caller" : "callee";
}

function StreamsView({ file }: { file: string }) {
  const d = usePoll<Streams>("recordings/streams", { file });
  const s = d.data;
  return (
    <>
      <ErrorNote error={d.error} />
      {s?.truncated && <p class="error">Only the first packets of this long recording are read here; download it for all of them.</p>}
      {s && s.streams.length === 0 && <Empty>No packets recorded yet.</Empty>}
      {s && s.streams.length > 0 && (
        <div class="scroll-x">
          <table>
            <thead>
              <tr>
                <th>Party</th><th>Kind</th><th>From</th><th>To</th><th>SSRC</th><th class="num">Packets</th>
                <th class="num">Octets</th><th class="num">Lost</th><th class="num">Duration</th><th>Payload types</th>
              </tr>
            </thead>
            <tbody>
              {s.streams.map((x, i) => (
                <tr key={i}>
                  <td>{party(x, s.meta) || "—"}</td>
                  <td><span class="badge">{x.kind}</span></td>
                  <td><code>{x.src}</code></td>
                  <td><code>{x.dst}</code></td>
                  <td><code>{x.ssrc ?? "—"}</code></td>
                  <td class="num">{number(x.packets)}</td>
                  <td class="num">{number(x.octets)}</td>
                  <td class="num">{x.lost === null ? "—" : number(x.lost)}</td>
                  <td class="num">{length(x.duration_ms)}</td>
                  <td>{x.pts.map((p) => `${p.pt} (${number(p.packets)})`).join(", ") || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {s?.meta && (
        <section>
          <h3>Converted</h3>
          <KeyValues data={s.meta} skip={["opus_pts", "amr_pts", "amr_wb_pts"]} />
        </section>
      )}
    </>
  );
}

const KINDS = ["", "RTP", "RTCP", "STUN", "DTLS", "ZRTP", "other"];

function PacketsView({ file }: { file: string }) {
  const [kind, setKind] = useState("");
  return (
    <>
      <label class="muted">
        Kind{" "}
        <select value={kind} onChange={(e) => setKind((e.target as HTMLSelectElement).value)}>
          {KINDS.map((k) => (
            <option key={k} value={k}>{k || "all"}</option>
          ))}
        </select>
      </label>
      <Table
        path="recordings/packets"
        params={{ file, kind }}
        onRow={() => {}}
        columns={[
          { key: "n", label: "#", numeric: true },
          { key: "t_us", label: "Time (s)", numeric: true, render: (r) => offset(r.t_us) },
          { key: "src", label: "From", render: (r) => <code>{text(r.src)}</code> },
          { key: "dst", label: "To", render: (r) => <code>{text(r.dst)}</code> },
          { key: "kind", render: (r) => <span class="badge">{text(r.kind)}</span> },
          { key: "len", label: "Length", numeric: true },
          { key: "pt", label: "PT", numeric: true, render: (r) => (r.rtcp ? text(r.rtcp) : text(r.pt)) },
          { key: "seq", numeric: true, render: (r) => raw(r.seq) },
          { key: "ts", label: "Timestamp", numeric: true, render: (r) => raw(r.ts) },
          { key: "ssrc", label: "SSRC", render: (r) => <code>{text(r.ssrc)}</code> },
          { key: "marker", label: "M", sort: false, render: (r) => (r.marker ? "M" : "") },
        ]}
        emptyText="No packets of this kind."
      />
    </>
  );
}

/** One recording in its drawer: streams, packets, the file itself. */
function RecordingDetail({ row }: { row: Row }) {
  const file = String(row.file);
  const [tab, setTab] = useState("streams");
  return (
    <>
      <p>
        <a class="button" href={`/api/v1/recordings/download?file=${encodeURIComponent(file)}`} download={file}>
          Download the pcap
        </a>{" "}
        <span class="muted">opens in Wireshark (Telephony → RTP → RTP Streams)</span>
      </p>
      <Tabs tabs={[{ id: "streams", label: "Streams" }, { id: "packets", label: "Packets" }]} active={tab} onChange={setTab} />
      {tab === "streams" ? <StreamsView file={file} /> : <PacketsView file={file} />}
      <p class="muted">Packets are shown as recorded: after SRTP decryption, before transcoding. Their payloads are not shown.</p>
    </>
  );
}

interface S3Facts {
  bucket: string;
  region: string;
  endpoint: string;
  prefix: string;
  keep_local: boolean;
  webhook: { url: string; signed: boolean; timeout_ms: number; connect_timeout_ms: number; attempts: number; backoff_ms: number; backoff_max_ms: number; queue: number } | null;
}

interface UploadFile {
  name: string;
  key: string | null;
  size: number;
  error: string | null;
}

/** Where uploads go, and where they are notified. */
function S3Settings() {
  const d = usePoll<{ recording: { s3: S3Facts | null } | null }>("info", {}, false);
  const s3 = d.data?.recording?.s3;
  if (!s3) return <ErrorNote error={d.error} />;
  const w = s3.webhook;
  return (
    <dl class="kv">
      <div><dt>Bucket</dt><dd><code>{s3.bucket}</code> ({s3.region})</dd></div>
      <div><dt>Endpoint</dt><dd><code>{s3.endpoint}</code></dd></div>
      <div><dt>Prefix</dt><dd><code>{s3.prefix || "—"}</code>{s3.keep_local ? " (local copies kept)" : ""}</dd></div>
      <div>
        <dt>Webhook</dt>
        <dd>
          {w ? (
            <>
              <code>{w.url}</code> {w.signed ? <span class="badge good">signed</span> : <span class="badge">not signed</span>}
              <span class="muted"> {w.attempts} attempts, {w.timeout_ms} ms each, backoff {w.backoff_ms}–{w.backoff_max_ms} ms</span>
            </>
          ) : (
            "off"
          )}
        </dd>
      </div>
    </dl>
  );
}

function UploadDetail({ row }: { row: Row }) {
  const files = (row.files as UploadFile[]) ?? [];
  return (
    <>
      <KeyValues data={{ ...row, at_ms: dateTime((row.at_ms as number) / 1000) }} skip={["files"]} />
      <div class="scroll-x">
        <table class="legs">
          <thead>
            <tr><th>File</th><th>Object key</th><th class="num">Size</th><th>Result</th></tr>
          </thead>
          <tbody>
            {files.map((f) => (
              <tr key={f.name}>
                <td><code>{f.name}</code></td>
                <td>{f.key ? <code>{f.key}</code> : <span class="muted">kept locally</span>}</td>
                <td class="num">{size(f.size)}</td>
                <td>{f.key ? <span class="badge good">uploaded</span> : <span class="badge bad" title={f.error ?? ""}>{f.error ?? "failed"}</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

function Uploads() {
  return (
    <>
      <S3Settings />
      <Table
        path="uploads"
        columns={[
          { key: "at_ms", label: "When", render: (r) => <span class="nowrap">{dateTime((r.at_ms as number) / 1000)}</span> },
          { key: "call_id", label: "Call ID" },
          { key: "from_tag", label: "From tag" },
          { key: "files", sort: false, render: (r) => number((r.files as unknown[]).length) },
          { key: "complete", label: "Result", render: (r) => <Badge value={r.complete ? "uploaded" : "incomplete"} /> },
        ]}
        title={(r) => `Upload of ${text(r.call_id)}`}
        detail={(r) => <UploadDetail row={r} />}
        emptyText="No recording uploaded since the relay started (the last 200 are kept)."
      />
    </>
  );
}

function Webhooks() {
  return (
    <Table
      path="uploads/webhooks"
      columns={[
        { key: "at_ms", label: "When", render: (r) => <span class="nowrap">{dateTime((r.at_ms as number) / 1000)}</span> },
        { key: "call_id", label: "Call ID" },
        { key: "outcome", render: (r) => <Badge value={r.outcome} /> },
        { key: "status", label: "HTTP", numeric: true, render: (r) => (r.status === null ? "—" : String(r.status)) },
        { key: "attempts", numeric: true },
        { key: "error", render: (r) => (r.error ? <span class="muted">{text(r.error)}</span> : "") },
        { key: "delivery", label: "Delivery ID" },
      ]}
      title={(r) => `Notification ${text(r.delivery)}`}
      emptyText="No upload notification since the relay started (the last 200 are kept)."
    />
  );
}

/** The local pcaps; with S3 storage, also the uploads and their webhook
 * notifications (the local files are removed once uploaded). */
export function Recordings({ uploads }: { uploads: boolean }) {
  const [tab, setTab] = useState("files");
  return (
    <div class="page">
      {uploads && (
        <Tabs
          tabs={[
            { id: "files", label: "Files" },
            { id: "uploads", label: "Uploads to S3" },
            { id: "webhooks", label: "Webhook deliveries" },
          ]}
          active={tab}
          onChange={setTab}
        />
      )}
      {uploads && tab === "uploads" && <section class="card"><Uploads /></section>}
      {uploads && tab === "webhooks" && <section class="card"><Webhooks /></section>}
      {(!uploads || tab === "files") && <Files />}
    </div>
  );
}

function Files() {
  return (
    <>
      <section class="card">
        <Table
          path="recordings"
          columns={[
            { key: "modified", render: (r) => <span class="nowrap">{dateTime(r.modified as number)}</span> },
            // The file name holds the call-id, tag and section; search finds them too.
            { key: "file" },
            { key: "section", numeric: true },
            { key: "duration_ms", label: "Length", numeric: true, render: (r) => <span class="nowrap">{typeof r.duration_ms === "number" ? length(r.duration_ms) : "—"}</span> },
            { key: "size", numeric: true, render: (r) => <span class="nowrap">{size(r.size)}</span> },
            { key: "audio", render: (r) => (r.audio ? <span class="badge good">{text(r.audio)}</span> : <span class="muted">—</span>) },
          ]}
          title={(r) => `Recording ${text(r.file)}`}
          detail={(r) => <RecordingDetail row={r} />}
          emptyText="No pcap recordings in the recording directory (they are removed once converted, unless keep_pcap is set)."
        />
      </section>
    </>
  );
}
