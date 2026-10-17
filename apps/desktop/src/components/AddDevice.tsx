/**
 * Add a device by its address.
 *
 * Discovery cannot cross a VPN such as Radmin or Tailscale, or reach another
 * subnet, so a device there never appears on its own. Typing its address once
 * is enough: it is checked every few seconds from then on and listed for as
 * long as it answers.
 */

import { useState } from "react";
import { api, type PeerView } from "../api";

interface Props {
  onAdded: (peer: PeerView) => void;
  onCancel: () => void;
}

export function AddDevice({ onAdded, onCancel }: Props) {
  const [address, setAddress] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const add = async () => {
    setBusy(true);
    setError(null);
    try {
      onAdded(await api.addDeviceByAddress(address));
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="row" style={{ display: "block", marginBottom: 14 }}>
      <label className="field" style={{ marginBottom: 8 }}>
        <span className="label">The other device's address</span>
        <div style={{ display: "flex", gap: 8 }}>
          <input
            autoFocus
            value={address}
            placeholder="e.g. 26.14.120.8 or 192.168.1.20"
            onChange={(event) => setAddress(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter" && address.trim()) void add();
              if (event.key === "Escape") onCancel();
            }}
          />
          <button className="btn primary" onClick={() => void add()} disabled={busy || !address.trim()}>
            {busy ? "Looking…" : "Add"}
          </button>
          <button className="btn ghost" onClick={onCancel}>
            Cancel
          </button>
        </div>
        <span className="hint">
          For a device on a VPN like Radmin or Tailscale, or on another network.
          Its address is shown in its own Network tab. It stays in the list while
          it can be reached.
        </span>
      </label>
      {error && <p style={{ color: "var(--brand-pink)", fontSize: 13, margin: 0 }}>{error}</p>}
    </div>
  );
}
