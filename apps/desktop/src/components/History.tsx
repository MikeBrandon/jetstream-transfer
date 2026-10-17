/**
 * Past transfers, and the ones still waiting to finish themselves.
 *
 * The interesting rows are the interrupted ones. Jetstream retries those on its
 * own when the peer reappears, so this screen's job is to say so — a user who
 * does not know that will retry by hand, or worse, assume the transfer is lost.
 */

import {
  formatBytes,
  formatDuration,
  formatRate,
  formatWhen,
  type HistoryView,
} from "../api";

interface Props {
  records: HistoryView[];
  onRetry: (record: HistoryView) => void;
  onForget: (record: HistoryView) => void;
  onClear: () => void;
  /** The modern interface groups the list by day. */
  modern?: boolean;
}

/** "Today", "Yesterday", or the date — the heading a record is filed under. */
function dayOf(unixSeconds: number): string {
  const day = new Date(unixSeconds * 1000);
  const today = new Date();
  const yesterday = new Date();
  yesterday.setDate(today.getDate() - 1);

  if (day.toDateString() === today.toDateString()) return "Today";
  if (day.toDateString() === yesterday.toDateString()) return "Yesterday";
  return day.toLocaleDateString(undefined, { weekday: "long", month: "long", day: "numeric" });
}

// Every outcome the Rust side can send must have a case. A missing one returned
// undefined, and reading `.tone` off it took the whole window down the moment a
// paused or cancelled transfer appeared in the list.
function outcomeChip(record: HistoryView): { text: string; tone: string } {
  switch (record.outcome) {
    case "completed":
      return { text: "done", tone: "" };
    case "interrupted":
      return record.willRetry
        ? { text: "will resume", tone: "cyan" }
        : { text: "stopped", tone: "amber" };
    case "paused":
      return { text: "paused", tone: "amber" };
    case "cancelled":
      return { text: "cancelled", tone: "" };
    case "declined":
      return { text: "declined", tone: "pink" };
    case "failed":
      return { text: "failed", tone: "pink" };
    default:
      return { text: String(record.outcome), tone: "" };
  }
}

function retryLabel(record: HistoryView): string {
  if (record.willRetry) return "Try now";
  if (record.outcome === "paused") return "Continue";
  return "Retry";
}

export function History({ records, onRetry, onForget, onClear, modern = false }: Props) {
  if (records.length === 0) {
    return (
      <div className="empty">
        <div className="big">No transfers yet</div>
        <p>Everything you send or receive is listed here.</p>
      </div>
    );
  }

  const pending = records.filter((r) => r.willRetry).length;

  return (
    <>
      <h3 className="section-title" style={{ display: "flex", alignItems: "center" }}>
        History
        <button className="btn ghost small" style={{ marginLeft: "auto" }} onClick={onClear}>
          Clear finished
        </button>
      </h3>

      {pending > 0 && (
        <p className="hint" style={{ marginTop: -4, marginBottom: 12 }}>
          {pending} transfer{pending === 1 ? "" : "s"} will pick up automatically when
          the other device is back — nothing already sent will be sent again.
        </p>
      )}

      {records.map((record, index) => {
        const chip = outcomeChip(record);
        const day = dayOf(record.at);
        const heading = modern && (index === 0 || dayOf(records[index - 1]!.at) !== day);

        return (
          <div key={record.id}>
          {heading && <div className="day-heading">{day}</div>}
          <div className="row">
            <span
              aria-hidden="true"
              style={{
                fontFamily: "var(--mono)",
                color: "var(--text-faint)",
                flexShrink: 0,
              }}
            >
              {record.sending ? "→" : "←"}
            </span>

            <div style={{ minWidth: 0, flex: 1 }}>
              <div style={{ fontFamily: "var(--display)", fontSize: 13 }}>
                {record.peerName}
                <span className={`chip ${chip.tone}`} style={{ marginLeft: 8 }}>
                  {chip.text}
                </span>
              </div>
              <div className="name" style={{ fontSize: 12, color: "var(--text-dim)" }}>
                {record.summary || formatBytes(record.bytes)}
                {record.outcome !== "completed" &&
                  record.transferred > 0 &&
                  record.bytes > 0 &&
                  ` · got to ${formatBytes(record.transferred)} of ${formatBytes(record.bytes)}`}
              </div>
              <div style={{ fontSize: 11, color: "var(--text-faint)" }}>
                {formatWhen(record.at)}
                {record.attempts > 0 && ` · ${record.attempts} attempt${record.attempts === 1 ? "" : "s"}`}
                {/* How long it took and how fast, so a slow transfer can be told
                    from a big one. Measured over the time data was moving. */}
                {record.seconds > 0 && ` · ${formatDuration(record.seconds)}`}
                {record.averageRate > 0 && ` · average ${formatRate(record.averageRate)}`}
              </div>
              {record.detail && (
                <div style={{ fontSize: 11.5, color: "var(--text-faint)", marginTop: 2 }}>
                  {record.detail}
                </div>
              )}
            </div>

            {record.canRetry && record.outcome !== "completed" && (
              <button className="btn small" onClick={() => onRetry(record)}>
                {retryLabel(record)}
              </button>
            )}
            <button className="btn ghost small" onClick={() => onForget(record)}>
              Remove
            </button>
          </div>
          </div>
        );
      })}
    </>
  );
}
