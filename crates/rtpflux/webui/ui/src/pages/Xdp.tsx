import type { Row } from "../api";
import { Table } from "../components/Table";
import { KeyValues } from "../components/ui";
import { number, text } from "../format";
import { useStats } from "../stats";
import { Tile } from "../components/ui";

interface Dir {
  from: string;
  to: string;
  device: string;
  drops: boolean;
  events_up: boolean;
  records: boolean;
  packets: number;
  octets: number;
}

/** What the kernel does with a direction besides relaying it. */
function flags(d: Dir): string {
  return [d.drops ? "dropped (blocked)" : "", d.events_up ? "DTMF to userspace" : "", d.records ? "recorded" : ""].filter(Boolean).join(", ");
}

function FlowDetail({ row }: { row: Row }) {
  const dirs: [string, Dir][] = [
    ["From A (caller)", row.a as Dir],
    ["From B (callee)", row.b as Dir],
  ];
  return (
    <>
      <KeyValues data={row} skip={["a", "b", "key"]} />
      <div class="scroll-x">
        <table class="legs">
          <thead>
            <tr><th>Direction</th><th>From</th><th>Sent to</th><th>Device</th><th class="num">Packets</th><th class="num">Octets</th><th>In the kernel</th></tr>
          </thead>
          <tbody>
            {dirs.map(([name, d]) => (
              <tr key={name}>
                <td><strong>{name}</strong></td>
                <td><code>{d.from}</code></td>
                <td><code>{d.to}</code></td>
                <td>{d.device}</td>
                <td class="num">{number(d.packets)}</td>
                <td class="num">{number(d.octets)}</td>
                <td>{flags(d) || "relayed"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p class="muted">Counters as of the relay's last poll of the kernel (once a second).</p>
    </>
  );
}

/** The calls the XDP program relays in the kernel. */
export function Xdp() {
  const st = useStats();
  return (
    <div class="page">
      <div class="tiles">
        <Tile label="Calls in the kernel" value={number(st.value("relay:offloaded_calls"))} sub="relay calls (media sections)" history={st.history("relay:offloaded_calls")} />
        <Tile label="Kernel packets / s" value={number(st.rate("relay:kernel_packets"), 0)} sub={`${number(st.value("relay:kernel_packets"))} total`} history={st.history("relay:kernel_packets")} />
      </div>
      <section class="card">
        <Table
          path="xdp"
          columns={[
            { key: "relay_call", label: "Relay call", numeric: true },
            { key: "worker", numeric: true },
            { key: "call_id", label: "Call ID" },
            { key: "from_tag", label: "From tag" },
            { key: "section", label: "Media", numeric: true },
            { key: "packets", numeric: true, render: (r) => number(r.packets as number) },
            { key: "octets", numeric: true, render: (r) => number(r.octets as number) },
          ]}
          title={(r) => `Relay call ${text(r.relay_call)}`}
          detail={(r) => <FlowDetail row={r} />}
          emptyText="No call is relayed in the kernel right now (calls move there once both sides are settled and plain)."
        />
      </section>
    </div>
  );
}
