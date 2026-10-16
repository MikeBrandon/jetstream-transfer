/**
 * The transfer list.
 *
 * The distinction this screen has to make clearly, and that Dukto could not,
 * is between *failed* and *interrupted*. An interrupted transfer has kept
 * everything it staged and will pick up where it stopped — telling the user
 * that is the difference between "start the 40 GB copy again" and "click
 * resume".
 */

import type { KeyboardEvent } from "react";

import {
  formatBytes,
  formatEta,
  formatPercent,
  formatRate,
  isRunning,
  type TransferView,
} from "../api";

interface Props {
  transfers: TransferView[];
  onCancel: (id: number) => void;
  onPause: (id: number) => void;
  onReveal: (id: number) => void;
  onLimit: (id: number, kbps: number) => void;
  onClear: () => void;
  onResume: (transfer: TransferView) => void;
}

function stateLabel(transfer: TransferView): string {
  switch (transfer.state) {
    case "connecting":
      return "connecting…";
    case "waiting":
      return transfer.direction === "sending"
        ? "waiting for them to accept…"
        : "waiting for you to accept…";
    case "active":
      return "";
    case "done":
      return "done";
    case "interrupted":
      return "stopped — can resume";
    case "paused":
      return "paused";
    case "cancelled":
      return "cancelled";
    case "rejected":
      return "declined";
    case "failed":
      return "failed";
  }
}

/** Limits offered in the throttle menu, in KB/s. */
const LIMITS: { label: string; kbps: number }[] = [
  { label: "No limit", kbps: 0 },
  { label: "1 MB/s", kbps: 1_000 },
  { label: "5 MB/s", kbps: 5_000 },
  { label: "10 MB/s", kbps: 10_000 },
  { label: "25 MB/s", kbps: 25_000 },
  { label: "50 MB/s", kbps: 50_000 },
];

/**
 * The one place a state's colour is decided.
 *
 * `bar` and `percent` share the same modifier so they can never drift apart,
 * and the chip maps onto the existing palette classes.
 */
function tone(state: TransferView["state"]): { shade: string; chip: string } {
  switch (state) {
    case "done":
      return { shade: "done", chip: "" };
    case "interrupted":
    case "paused":
      return { shade: "stopped", chip: "amber" };
    case "failed":
    case "rejected":
    case "cancelled":
      return { shade: "failed", chip: "pink" };
    default:
      return { shade: "", chip: "cyan" };
  }
}

function Stat({
  label,
  value,
  note,
  trailing = false,
}: {
  label: string;
  value: string;
  /** Optional third line, for context the value alone does not carry. */
  note?: string;
  trailing?: boolean;
}) {
  return (
    <div className={trailing ? "stat trailing" : "stat"}>
      <span className="k">{label}</span>
      <span className="v">{value}</span>
      {note && <span className="n">{note}</span>}
    </div>
  );
}

/**
 * How the measured rate compares with what the wire can carry.
 *
 * The whole point of this line: 12 MB/s reads as broken until you know the cable
 * negotiated 100 Mbps, at which point it reads as saturated. Without the ceiling
 * a rate is a number with nothing to compare it to.
 *
 * Deliberately quiet below 60%, where the honest answer is "something else is the
 * limit" and naming a percentage would only invite the wrong conclusion.
 */
function linkNote(transfer: TransferView): string | undefined {
  const { rate, linkCeiling, linkLabel } = transfer;
  if (!linkLabel) return undefined;
  if (!linkCeiling || rate <= 0) return `${linkLabel} link`;

  const share = Math.round((rate / linkCeiling) * 100);
  if (share >= 90) return `at the ${linkLabel} limit`;
  if (share >= 60) return `${share}% of ${linkLabel}`;
  return `${linkLabel} link`;
}

export function Transfers({
  transfers,
  onCancel,
  onPause,
  onReveal,
  onLimit,
  onClear,
  onResume,
}: Props) {
  if (transfers.length === 0) {
    return (
      <div className="empty">
        <div className="big">Nothing transferring</div>
        <p>Drop files onto the window, or pick a device to send to.</p>
      </div>
    );
  }

  // Anything not running has stopped one way or another — paused and cancelled
  // included, which this used to miss, so "Clear finished" never offered to
  // clear them.
  const finished = transfers.filter((t) => !isRunning(t)).length;

  return (
    <>
      <h3 className="section-title" style={{ display: "flex", alignItems: "center" }}>
        Transfers
        {finished > 0 && (
          <button className="btn ghost small" style={{ marginLeft: "auto" }} onClick={onClear}>
            Clear finished
          </button>
        )}
      </h3>

      {transfers.map((transfer) => {
        const percent =
          transfer.bytesTotal > 0
            ? Math.min(100, (transfer.bytesDone / transfer.bytesTotal) * 100)
            : transfer.state === "done"
              ? 100
              : 0;
        const percentText =
          transfer.state === "done" ? "100%" : formatPercent(transfer.bytesDone, transfer.bytesTotal);
        // Paused and cancelled rows used to count as running, so they kept
        // offering Pause and Cancel buttons that did nothing.
        const running = isRunning(transfer);
        const sending = transfer.direction === "sending";
        const label = stateLabel(transfer);
        const { shade, chip } = tone(transfer.state);

        // No progress to show yet, so the bar sweeps instead of sitting at zero.
        // A resumed transfer already knows how far it got, so it shows that.
        const pending =
          (transfer.state === "connecting" || transfer.state === "waiting") &&
          transfer.bytesDone === 0;
        const active = transfer.state === "active";

        // A declined transfer never moved a byte, so "0%" is a number with
        // nothing behind it — the chip already says what happened. A *failed*
        // one keeps its figure, because how far it got is worth knowing.
        const showPercent = !pending && transfer.state !== "rejected";

        // A finished row opens its files. Clickable rather than a button so the
        // whole row is the target — but that means the keyboard and screen-reader
        // affordances have to be added by hand, not inherited.
        const openable = transfer.canReveal && transfer.state !== "active";
        const activate = () => {
          if (openable) onReveal(transfer.id);
        };

        return (
          <div
            className={`transfer${openable ? " openable" : ""}`}
            key={transfer.id}
            {...(openable
              ? {
                  role: "button",
                  tabIndex: 0,
                  title: "Show these files in Explorer",
                  onClick: activate,
                  onKeyDown: (event: KeyboardEvent) => {
                    if (event.key === "Enter" || event.key === " ") {
                      event.preventDefault();
                      activate();
                    }
                  },
                }
              : {})}
          >
            <div className="top">
              <span className="who">
                {transfer.direction === "sending" ? "→" : "←"} {transfer.peerName}
              </span>
              <span className="what">{transfer.summary || label}</span>

              {/* Buttons and the throttle menu live inside a clickable row, so
                  their clicks must stop here — otherwise pressing Cancel would
                  also open Explorer. */}
              <div className="right" onClick={(event) => event.stopPropagation()}>
                {/* Only the state label lives up here now. The numbers moved
                    down into their own cells, where each one is legible. */}
                {!active && label && (
                  <span className={`chip ${chip}`.trim()}>{label}</span>
                )}

                {/* Throttling only makes sense while bytes are moving, and the
                    menu doubles as the display of the current limit. */}
                {active && (
                  <select
                    className="limit"
                    value={transfer.limit ? Math.round(transfer.limit / 1000) : 0}
                    onChange={(event) => onLimit(transfer.id, Number(event.target.value))}
                    aria-label={`Speed limit for the transfer with ${transfer.peerName}`}
                    title="Slow this transfer down without stopping it"
                  >
                    {LIMITS.map((limit) => (
                      <option key={limit.kbps} value={limit.kbps}>
                        {limit.label}
                      </option>
                    ))}
                  </select>
                )}

                {/* Only the sender can pick a transfer up again, so only the
                    sender is offered a pause. A receiver can stop; what it has
                    is kept, and it carries on if the sender sends again. */}
                {running && sending && (
                  <button className="btn ghost small" onClick={() => onPause(transfer.id)}>
                    Pause
                  </button>
                )}
                {running && (
                  <button
                    className="btn ghost small"
                    onClick={() => onCancel(transfer.id)}
                    title={
                      sending
                        ? "Stop sending. What already arrived stays on the other device."
                        : "Stop receiving. What already arrived is kept."
                    }
                  >
                    {sending ? "Cancel" : "Stop"}
                  </button>
                )}
                {transfer.resumable && (
                  <button className="btn small" onClick={() => onResume(transfer)}>
                    {transfer.state === "paused" ? "Continue" : "Resume"}
                  </button>
                )}
              </div>
            </div>

            <div className="progress-row">
              <div className={`bar ${shade} ${pending ? "pending" : ""}`.trim()}>
                <span style={{ width: `${percent}%` }} />
              </div>
              {showPercent && (
                <span
                  className={`percent ${shade}`.trim()}
                  // Announced as one value rather than letting a screen reader
                  // read a bare number with no unit or context.
                  aria-label={`${percentText} complete`}
                >
                  {percentText}
                </span>
              )}
            </div>

            {active && (
              <div className="stats">
                <Stat
                  label="Speed"
                  value={transfer.rate > 0 ? formatRate(transfer.rate) : "—"}
                  // A limit the user set is more useful to see than how the rate
                  // compares with the wire, because it explains the rate.
                  note={
                    transfer.limit
                      ? `limited to ${formatRate(transfer.limit)}`
                      : linkNote(transfer)
                  }
                />
                <Stat
                  label="Time left"
                  value={transfer.eta !== null ? formatEta(transfer.eta) : "—"}
                />
                <Stat
                  label="Transferred"
                  value={`${formatBytes(transfer.bytesDone)} of ${formatBytes(transfer.bytesTotal)}`}
                />
                {transfer.filesTotal > 1 && (
                  <Stat
                    label="Files"
                    value={`${transfer.filesDone} of ${transfer.filesTotal}`}
                    trailing
                  />
                )}
              </div>
            )}

            {/* A stopped transfer still has a size worth knowing: how far it
                got is the difference between "start again" and "nearly there". */}
            {!active && transfer.state !== "done" && transfer.bytesTotal > 0 && transfer.bytesDone > 0 && (
              <div className="detail">
                {formatBytes(transfer.bytesDone)} of {formatBytes(transfer.bytesTotal)}
              </div>
            )}

            {transfer.detail && <div className="detail">{transfer.detail}</div>}

            {/* Named, not just counted. "3 items skipped" with no list is the
                kind of vagueness that makes a person doubt the whole transfer,
                and the walk already knows exactly which ones and why. */}
            {transfer.skipped.length > 0 && (
              <details className="skipped" onClick={(event) => event.stopPropagation()}>
                <summary>
                  Show what was skipped ({transfer.skipped.length})
                </summary>
                {transfer.skipped.map((item) => (
                  <div className="skipped-item" key={item.path}>
                    <span className="p">{item.path}</span>
                    <span className="r">{item.reason}</span>
                  </div>
                ))}
              </details>
            )}
          </div>
        );
      })}
    </>
  );
}
