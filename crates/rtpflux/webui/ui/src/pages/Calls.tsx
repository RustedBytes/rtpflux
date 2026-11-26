import type { Row } from "../api";
import { Table } from "../components/Table";
import { Badge, ErrorNote, KeyValues, Tile } from "../components/ui";
import { dateTime, duration, number, text } from "../format";
import { navigate, usePoll } from "../hooks";
import { useStats } from "../stats";

interface Leg {
  local_port: number;
  peer: string | null;
  packets: number;
  octets: number;
  dropped: number;
  dtmf: { event: string; duration_ms: number }[];
  rtcp_reports: number;
  rtt_ms: number | null;
  loss_percent: number | null;
  lost: number | null;
  jitter: number | null;
  settled: boolean;
  dtls: string | null;
  ice: { role: string; state: string; selected: string | null; consent_lost: boolean } | null;
}

interface Side {
  protocol: string;
  security: string;
  relay: string;
  codec: string | null;
  transcode: string | null;
  ptime_ms: number | null;
  direction: string | null;
  latching: string;
  strict_source: boolean;
  handover: boolean;
  opaque: boolean;
  dtls_role: string | null;
  ice: boolean;
  dtmf_security: boolean;
  rtp: Leg | null;
  rtcp: Leg | null;
}

interface Section {
  index: number;
  relay_call: number;
  rtcp_mux: boolean;
  a: Side;
  b: Side;
  recording: string | null;
  blocked: [number, number] | null;
  playing: [boolean, boolean] | null;
  bundle: boolean;
  mid: string | null;
  in_kernel: boolean;
  passthrough: boolean;
}

interface Timers {
  unanswered_ends_in_s: number | null;
  final_timeout_in_s: number | null;
  deleting_in_s: number | null;
}

/** What a leg's state says beyond its counters: the latch, DTLS, ICE. */
function legState(l: Leg | null): string {
  if (!l) return "";
  const parts = [l.settled ? "settled" : "learning"];
  if (l.dtls) parts.push(`DTLS ${l.dtls}`);
  if (l.ice) parts.push(`ICE ${l.ice.role}, ${l.ice.state}${l.ice.selected ? ` via ${l.ice.selected}` : ""}${l.ice.consent_lost ? ", consent lost" : ""}`);
  return parts.join("; ");
}

/** Each side's negotiation: codec, conversion, packet time, direction, how
 * it is latched, DTLS and ICE. */
function SidesTable({ m }: { m: Section }) {
  const row = (name: string, x: Side) => (
    <tr key={name}>
      <td><strong>{name}</strong></td>
      <td>{x.codec ?? "—"}</td>
      <td>{x.transcode ?? <span class="muted">—</span>}</td>
      <td class="num">{x.ptime_ms ? `${x.ptime_ms} ms` : "—"}</td>
      <td>{x.direction ? <Badge value={x.direction} /> : "—"}</td>
      <td>{x.latching}{x.strict_source ? ", strict source" : ""}{x.handover ? ", handover" : ""}</td>
      <td>{x.dtls_role ? `DTLS ${x.dtls_role}` : ""}{x.ice ? `${x.dtls_role ? ", " : ""}ICE` : ""}{!x.dtls_role && !x.ice ? "—" : ""}</td>
      <td>{[x.opaque ? "not RTP (relayed as is)" : "", x.dtmf_security ? "DTMF security" : ""].filter(Boolean).join("; ")}</td>
    </tr>
  );
  return (
    <div class="scroll-x">
      <table class="legs">
        <thead>
          <tr><th>Side</th><th>Codec it gets</th><th>Converts what it sends</th><th class="num">ptime</th><th>Direction</th><th>Latching</th><th>Transport</th><th>Notes</th></tr>
        </thead>
        <tbody>
          {row("A (caller)", m.a)}
          {row("B (callee)", m.b)}
        </tbody>
      </table>
    </div>
  );
}

/** The timers that will end a dialog, as text. */
function timersText(t: Timers | undefined): string {
  if (!t) return "";
  const parts = [];
  if (t.deleting_in_s !== null) parts.push(`deleted in ${duration(t.deleting_in_s)} (delete-delay)`);
  if (t.unanswered_ends_in_s !== null) parts.push(`ends in ${duration(t.unanswered_ends_in_s)} unless answered`);
  if (t.final_timeout_in_s !== null) parts.push(`final timeout in ${duration(t.final_timeout_in_s)}`);
  return parts.join("; ");
}

/** What links a call to more parties or to other calls. */
const LINK_TITLES: Record<string, string> = {
  "multi-party": "More than one dialog in this call (a B2BUA's legs, a three-way call, a conference)",
  joined: "A party joined with another by connect (a transfer)",
  copies: "Copies of a party's media to another (monitoring, whisper, inject, mesh)",
  subscribed: "Subscriptions to this call's media (SIPREC, monitoring)",
};

/** What is on for a dialog, as badges. */
function Flags({ row }: { row: Row }) {
  const links = (row.links as string[] | undefined) ?? [];
  return (
    <span class="chips">
      {row.recording ? <span class="badge">recording</span> : null}
      {row.blocked ? <span class="badge bad">blocked</span> : null}
      {row.playing ? <span class="badge">announcement</span> : null}
      {links.map((l) => (
        <span key={l} class="badge" title={LINK_TITLES[l] ?? l}>{l}</span>
      ))}
    </span>
  );
}

interface End {
  call_id: string;
  tag: string;
  label: string | null;
  here: boolean;
}

interface Parties {
  call_id: string;
  parties: { tag: string; label: string | null; codec: string | null; in_dialogue_with: string[]; created: number }[];
  dialogs: { key: string; a: string | null; b: string | null; state: string; age: number; sections: number; security: string }[];
  links: { kind: "joined" | "copy"; from: End; to: End; both: boolean; convert: string | null }[];
  subscriptions: { tag: string; label: string | null; sources: string[]; answered: boolean; profile: string; created: number; inactive: boolean }[];
}

/** A party as text: its label (or tag), and its call when it is another. */
function EndText({ end }: { end: End }) {
  const name = end.label ? `${end.label} (${end.tag})` : end.tag;
  return (
    <span>
      <code>{name}</code>
      {end.here ? null : <span class="muted"> in call <code>{end.call_id}</code></span>}
    </span>
  );
}

/** A call's parties, its dialogs, and what links them (joins, copies,
 * subscriptions): a conference, a transfer or monitoring at a glance. */
function PartiesPanel({ callId }: { callId: string }) {
  const p = usePoll<Parties>("calls/parties", { call_id: callId });
  const d = p.data;
  if (!d) return <ErrorNote error={p.error} />;
  const single = d.parties.length <= 2 && d.links.length === 0 && d.subscriptions.length === 0;
  if (single) return null;
  return (
    <section>
      <div class="section-head">
        <h3>Parties and links</h3>
        <span class="muted">{d.parties.length} parties, {d.dialogs.length} dialogs</span>
      </div>
      <div class="scroll-x">
        <table class="legs">
          <thead>
            <tr><th>Party</th><th>Label</th><th>Codec</th><th>In dialogs with</th><th>Since</th></tr>
          </thead>
          <tbody>
            {d.parties.map((x) => (
              <tr key={x.tag}>
                <td><code>{x.tag}</code></td>
                <td>{x.label ?? "—"}</td>
                <td>{x.codec ?? "—"}</td>
                <td>{x.in_dialogue_with.length ? x.in_dialogue_with.map((t) => <code key={t}>{t} </code>) : <span class="muted">none (created)</span>}</td>
                <td>{dateTime(x.created)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {d.links.length > 0 && (
        <div class="scroll-x">
          <table class="legs">
            <thead>
              <tr><th>Link</th><th>From</th><th></th><th>To</th><th>Codecs</th></tr>
            </thead>
            <tbody>
              {d.links.map((l, i) => (
                <tr key={i}>
                  <td>
                    <span class="badge" title={l.kind === "joined" ? "connect: they talk to each other, the parties they left are detached" : "copies: the destination also gets the source's media"}>
                      {l.kind === "joined" ? "joined" : l.both ? "copies both ways" : "copies"}
                    </span>
                  </td>
                  <td><EndText end={l.from} /></td>
                  <td>{l.both ? "⇄" : "→"}</td>
                  <td><EndText end={l.to} /></td>
                  <td>{l.convert ?? <span class="muted">as sent</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {d.subscriptions.length > 0 && (
        <div class="scroll-x">
          <table class="legs">
            <thead>
              <tr><th>Subscription</th><th>Sources</th><th>Profile</th><th>State</th><th>Since</th></tr>
            </thead>
            <tbody>
              {d.subscriptions.map((x) => (
                <tr key={x.tag}>
                  <td><code>{x.label ? `${x.label} (${x.tag})` : x.tag}</code></td>
                  <td>{x.sources.map((t) => <code key={t}>{t} </code>)}</td>
                  <td>{x.profile}</td>
                  <td>{x.inactive ? "inactive" : x.answered ? "copying" : "offered, not answered"}</td>
                  <td>{dateTime(x.created)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

const blockedText = (bits: number) => (bits === 0 ? "—" : [bits & 1 ? "media" : "", bits & 2 ? "DTMF" : ""].filter(Boolean).join(", "));

/** One side's RTP and RTCP legs as table rows. */
function SideRows({ name, side, blocked, playing }: { name: string; side: Side; blocked: number; playing: boolean }) {
  return (
    <>
      {(["rtp", "rtcp"] as const).map((kind) => {
        const l = side[kind];
        return (
          <tr key={kind}>
            <td>{kind === "rtp" ? <strong>{name}</strong> : ""}</td>
            <td>{kind.toUpperCase()}</td>
            <td><code>{l?.peer ?? "—"}</code></td>
            <td class="num">{l ? l.local_port : "—"}</td>
            <td class="num">{number(l?.packets)}</td>
            <td class="num">{number(l?.octets)}</td>
            <td class="num">{number(l?.dropped)}</td>
            <td class="num">{l?.loss_percent === null || l?.loss_percent === undefined ? "—" : `${number(l.loss_percent, 1)} %`}</td>
            <td class="num">{l?.jitter === null || l?.jitter === undefined ? "—" : number(l.jitter)}</td>
            <td class="num">{l?.rtt_ms === null || l?.rtt_ms === undefined ? "—" : `${l.rtt_ms} ms`}</td>
            <td class="dtmf">{kind === "rtp" && l?.dtmf.length ? l.dtmf.map((e) => e.event).join("") : ""}</td>
            <td>{kind === "rtp" ? [legState(l), blockedText(blocked) !== "—" ? `blocked: ${blockedText(blocked)}` : "", playing ? "announcement" : ""].filter(Boolean).join("; ") : ""}</td>
          </tr>
        );
      })}
    </>
  );
}

/** A dialog in its drawer: who, when, and each media section's legs. */
function CallDetail({ row, logs }: { row: Row; logs: boolean }) {
  // `key` names the dialog (a pair key for a dialog between two parties of
  // other dialogs); older answers had only `from_tag`.
  const d = usePoll<Row & { media: Section[]; timers?: Timers }>("calls/detail", { call_id: String(row.call_id), from_tag: String(row.key ?? row.from_tag) });
  const c = d.data;
  const timers = timersText(c?.timers);
  return (
    <>
      <ErrorNote error={d.error} />
      <KeyValues
        data={c ? { ...c, created: dateTime(c.created as number), age: duration(c.age as number) } : row}
        skip={["media", "recording", "blocked", "playing", "key", "links", "timers", "via_branch"]}
      />
      {(timers || c?.via_branch) && (
        <p class="muted">
          {timers}
          {c?.via_branch ? `${timers ? "; " : ""}fork branch ${String(c.via_branch)}` : ""}
        </p>
      )}
      {logs && (
        <p>
          <button type="button" class="button" onClick={() => navigate("logs", { q: String(row.call_id) })}>
            Log lines of this call
          </button>
        </p>
      )}
      <PartiesPanel callId={String(row.call_id)} />
      {c?.media.map((m) => (
        <section key={m.index}>
          <div class="section-head">
            <h3>Media {m.index}</h3>
            <span class="badge">{m.a.protocol} ⇄ {m.b.protocol}</span>
            <span class="badge">{m.a.security} ⇄ {m.b.security}</span>
            {m.rtcp_mux && <span class="badge">rtcp-mux</span>}
            {m.bundle && <span class="badge" title={m.mid ? `mid ${m.mid}` : ""}>BUNDLE</span>}
            {m.passthrough && <span class="badge">ICE passed through</span>}
            {m.in_kernel ? <span class="badge good" title="Relayed by the XDP program in the kernel">in kernel (XDP)</span> : null}
            {m.recording && <span class="badge" title={m.recording}>recording</span>}
            <span class="muted">relay call {m.relay_call}</span>
          </div>
          <SidesTable m={m} />
          <div class="scroll-x">
            <table class="legs">
              <thead>
                <tr>
                  <th>Side</th><th>Leg</th><th>Peer</th><th class="num">Relay port</th><th class="num">Packets</th><th class="num">Octets</th>
                  <th class="num">Dropped</th><th class="num">Loss</th><th class="num">Jitter</th><th class="num">RTT</th><th>DTMF</th><th>Notes</th>
                </tr>
              </thead>
              <tbody>
                <SideRows name="A (caller)" side={m.a} blocked={m.blocked?.[0] ?? 0} playing={m.playing?.[0] ?? false} />
                <SideRows name="B (callee)" side={m.b} blocked={m.blocked?.[1] ?? 0} playing={m.playing?.[1] ?? false} />
              </tbody>
            </table>
          </div>
        </section>
      ))}
      <p class="muted">Packets the kernel relayed (XDP) are counted once a second.</p>
    </>
  );
}

export function Calls({ logs }: { logs: boolean }) {
  const st = useStats();
  return (
    <div class="page">
      <div class="tiles">
        <Tile label="Sessions" value={number(st.value("relay:sessions"))} sub="dialogs with media" history={st.history("relay:sessions")} />
        <Tile label="Relay calls" value={number(st.value("relay:calls"))} sub="media sections" history={st.history("relay:calls")} />
        <Tile label="Calls timed out" value={number(st.value("relay:calls_timed_out"))} sub="no media for the timeout" />
      </div>
      <section class="card">
        <Table
          path="calls"
          columns={[
            { key: "state", render: (r) => <Badge value={r.state} /> },
            { key: "age", numeric: true, render: (r) => duration(r.age as number) },
            { key: "call_id", label: "Call ID" },
            { key: "from_tag", label: "From tag" },
            { key: "to_tag", label: "To tag" },
            { key: "interfaces" },
            { key: "security" },
            { key: "sections", label: "Media", numeric: true },
            { key: "flags", label: "", sort: false, render: (r) => <Flags row={r} /> },
          ]}
          title={(r) => `Call ${text(r.call_id)}`}
          detail={(r) => <CallDetail row={r} logs={logs} />}
          emptyText="No calls right now."
        />
      </section>
    </div>
  );
}
