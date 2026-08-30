/**
 * Paired devices, and what each is allowed to do.
 *
 * This screen exists so a trust decision made once in a dialog is not
 * permanent and invisible. Every device shows its fingerprint, so a user who
 * later becomes suspicious of an entry can verify it rather than guess.
 */

import {
  formatWhen,
  initials,
  peerColor,
  type TrustedView,
  type TrustView,
} from "../api";

interface Props {
  devices: TrustedView[];
  onSetTrust: (device: TrustedView, trust: TrustView) => void;
  onForget: (device: TrustedView) => void;
}

export function Devices({ devices, onSetTrust, onForget }: Props) {
  if (devices.length === 0) {
    return (
      <div className="empty">
        <div className="big">No paired devices</div>
        <p>
          Devices appear here once you have accepted a transfer from them, or sent
          them one.
        </p>
      </div>
    );
  }

  return (
    <>
      <h3 className="section-title">Paired devices</h3>

      {devices.map((device) => (
        <div className="row" key={device.deviceId}>
          <div
            className="avatar"
            style={{
              background: peerColor(device.deviceId),
              width: 32,
              height: 32,
              borderRadius: 8,
              display: "grid",
              placeItems: "center",
              fontFamily: "var(--display)",
              fontSize: 13,
              color: "#08161a",
              flexShrink: 0,
            }}
            aria-hidden="true"
          >
            {initials(device.name)}
          </div>

          <div style={{ minWidth: 0, flex: 1 }}>
            <div style={{ fontFamily: "var(--display)", fontSize: 13 }}>
              {device.name}
              {device.online && <span className="chip cyan" style={{ marginLeft: 8 }}>online</span>}
            </div>
            <div
              className="selectable"
              style={{
                fontSize: 11,
                color: "var(--text-faint)",
                fontFamily: "var(--mono)",
              }}
            >
              {device.fingerprint}
            </div>
            <div style={{ fontSize: 11, color: "var(--text-faint)" }}>
              paired {formatWhen(device.firstPaired)} · last seen {formatWhen(device.lastSeen)}
            </div>
          </div>

          <select
            value={device.trust}
            onChange={(event) => onSetTrust(device, event.target.value as TrustView)}
            style={{
              padding: "6px 9px",
              borderRadius: 8,
              border: "1px solid var(--line-strong)",
              background: "var(--bg-sunken)",
              color: "var(--text)",
              font: "inherit",
              fontSize: 12,
            }}
            aria-label={`Trust level for ${device.name}`}
          >
            <option value="ask">Ask every time</option>
            <option value="autoAccept">Accept automatically</option>
            <option value="blocked">Block</option>
          </select>

          <button className="btn ghost small" onClick={() => onForget(device)}>
            Forget
          </button>
        </div>
      ))}

      <p className="hint" style={{ marginTop: 14 }}>
        Forgetting a device does not block it — you will simply be asked again the
        next time it sends something.
      </p>
    </>
  );
}
