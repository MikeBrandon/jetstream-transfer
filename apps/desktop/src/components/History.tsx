/**
 * Past transfers, and the ones still waiting to finish themselves.
 *
 * The interesting rows are the interrupted ones. Jetstream retries those on its
 * own when the peer reappears, so this screen's job is to say so — a user who
 * does not know that will retry by hand, or worse, assume the transfer is lost.
 */

import { formatBytes, formatWhen, type HistoryView } from "../api";

interface Props {
  records: HistoryView[];
  onRetry: (record: HistoryView) => void;
  onForget: (record: HistoryView) => void;
  onClear: () => void;
}

function outcomeChip(record: HistoryView): { text: string; tone: string } {
  switch (record.outcome) {
    case "completed":
      return { text: "done", tone: "" };
    case "interrupted":
      return record.willRetry
        ? { text: "will resume", tone: "cyan" }
        : { text: "stopped", tone: "amber" };
    case "declined":
      return { text: "declined", tone: "pink" };
    case "failed":
      return { text: "failed", tone: "pink" };
  }
}

export function History({ records, onRetry, onForget, onClear }: Props) {
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

      {records.map((record) => {
        const chip = outcomeChip(record);

        return (
          <div className="row" key={record.id}>
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
              </div>
              <div style={{ fontSize: 11, color: "var(--text-faint)" }}>
                {formatWhen(record.at)}
                {record.attempts > 0 && ` · ${record.attempts} attempt${record.attempts === 1 ? "" : "s"}`}
              </div>
              {record.detail && (
                <div style={{ fontSize: 11.5, color: "var(--text-faint)", marginTop: 2 }}>
                  {record.detail}
                </div>
              )}
            </div>

            {record.canRetry && record.outcome !== "completed" && (
              <button className="btn small" onClick={() => onRetry(record)}>
                {record.willRetry ? "Try now" : "Retry"}
              </button>
            )}
            <button className="btn ghost small" onClick={() => onForget(record)}>
              Remove
            </button>
          </div>
        );
      })}
    </>
  );
}
