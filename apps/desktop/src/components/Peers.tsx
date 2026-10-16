/**
 * The peer grid — Dukto's tile layout, which was the one thing it got right.
 *
 * A device is one tile whether it was found by mDNS, broadcast, or a saved
 * address. Clicking it sends; dropping files on the window arms every tile so
 * the next click is the target.
 */

import {
  initials,
  peerColor,
  trustLabel,
  type PeerView,
} from "../api";

interface Props {
  peers: PeerView[];
  armed: boolean;
  onPick: (peer: PeerView) => void;
  onAddByAddress: () => void;
  /** Choosing several devices for one send: clicks select instead of send. */
  selecting?: boolean;
  selected?: Set<string>;
}

export function Peers({
  peers,
  armed,
  onPick,
  onAddByAddress,
  selecting = false,
  selected = new Set(),
}: Props) {
  if (peers.length === 0) {
    return (
      <div className="empty">
        <div className="big">No other devices yet</div>
        <p>
          Open Jetstream on another machine on this network and it will appear
          here within a few seconds.
        </p>
        <p className="hint">
          Nothing showing up? The Network tab will tell you why. On a VPN like
          Radmin or Tailscale, devices do not appear by themselves —{" "}
          <button className="link" onClick={onAddByAddress}>
            add one by its address
          </button>
          .
        </p>
      </div>
    );
  }

  return (
    <>
      <h3 className="section-title">
        {selecting
          ? "Choose the devices to send to"
          : armed
            ? "Choose where to send"
            : `${peers.length} device${peers.length === 1 ? "" : "s"} nearby`}
      </h3>
      <div className="grid">
        {peers.map((peer) => {
          const label = trustLabel(peer.trust);
          const blocked = peer.trust === "blocked";
          const chosen = selecting && selected.has(peer.deviceId);

          return (
            <button
              key={peer.deviceId}
              className={`peer${armed && !blocked && !selecting ? " armed" : ""}${chosen ? " chosen" : ""}`}
              onClick={() => onPick(peer)}
              disabled={blocked}
              aria-pressed={selecting ? chosen : undefined}
              title={
                blocked
                  ? "This device is blocked. Unblock it in the Paired tab to send to it."
                  : `${peer.fingerprint}\nfound via ${peer.sources.join(", ")}`
              }
              style={blocked ? { opacity: 0.45, cursor: "not-allowed" } : undefined}
            >
              {selecting && !blocked && (
                <span className="check" aria-hidden="true">
                  {chosen ? "✓" : ""}
                </span>
              )}
              <div
                className="avatar"
                style={{ background: peerColor(peer.deviceId) }}
                aria-hidden="true"
              >
                {initials(peer.name)}
              </div>
              <div className="pname">{peer.name}</div>
              <div className="paddr">{peer.address ?? "no address"}</div>
              <div className="ptrust">
                <span className={`chip ${label.tone}`}>{label.text}</span>
                {peer.sources.map((source) => (
                  <span key={source} className="chip">
                    {source}
                  </span>
                ))}
              </div>
            </button>
          );
        })}
      </div>
    </>
  );
}
