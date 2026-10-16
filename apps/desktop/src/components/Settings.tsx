/**
 * Preferences, plus this device's own identity.
 *
 * The identity block lives here rather than in a hidden "About" box because a
 * user pairing two machines needs to read their own fingerprint aloud, and
 * hunting for it is exactly the friction that makes people skip verification.
 */

import { useEffect, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { api, type SelfView, type SettingsView } from "../api";

interface Props {
  self: SelfView | null;
  /** Told the saved settings, so the window can follow an interface change. */
  onSaved: (nameChanged: boolean, saved: SettingsView) => void;
}

export function Settings({ self, onSaved }: Props) {
  const [settings, setSettings] = useState<SettingsView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [autostart, setAutostart] = useState(false);
  const [sendTo, setSendTo] = useState(false);

  useEffect(() => {
    void api.getSettings().then(setSettings);
    void api.autostartStatus().then(setAutostart);
    void api.sendToStatus().then(setSendTo);
  }, []);

  if (!settings) return <p className="hint">Loading…</p>;

  const patch = (change: Partial<SettingsView>) =>
    setSettings({ ...settings, ...change });

  const chooseFolder = async () => {
    const picked = await open({ directory: true, multiple: false });
    if (typeof picked === "string") patch({ downloadDir: picked });
  };

  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      const nameChanged = await api.saveSettings(settings);
      onSaved(nameChanged, settings);
    } catch (e) {
      setError(String(e));
    } finally {
      setSaving(false);
    }
  };

  return (
    <>
      <h3 className="section-title">This device</h3>

      {self && (
        <div className="row" style={{ display: "block" }}>
          <div className="fingerprint" style={{ marginBottom: 10 }}>
            {self.fingerprintWords.map((word, index) => (
              <span key={`${word}-${index}`}>{word}</span>
            ))}
          </div>
          <p className="hint" style={{ marginTop: 0 }}>
            Read these words aloud when pairing. If the other device shows something
            different, you are not talking to the machine you think you are.
          </p>
          <div
            className="selectable"
            style={{
              fontFamily: "var(--mono)",
              fontSize: 11,
              color: "var(--text-faint)",
              marginTop: 8,
              wordBreak: "break-all",
            }}
          >
            {self.deviceId}
          </div>
        </div>
      )}

      <h3 className="section-title" style={{ marginTop: 22 }}>
        Settings
      </h3>

      <label className="field">
        <span className="label">Device name</span>
        <input
          value={settings.deviceName}
          onChange={(event) => patch({ deviceName: event.target.value })}
          maxLength={64}
        />
        <span className="hint">How this machine appears to others.</span>
      </label>

      <label className="field">
        <span className="label">Save received files to</span>
        <div style={{ display: "flex", gap: 8 }}>
          <input value={settings.downloadDir} readOnly />
          <button className="btn" onClick={() => void chooseFolder()}>
            Browse…
          </button>
        </div>
      </label>

      <label className="field">
        <span className="label">When a file already exists</span>
        <select
          value={settings.onConflict}
          onChange={(event) =>
            patch({ onConflict: event.target.value as SettingsView["onConflict"] })
          }
        >
          <option value="rename">Keep both (add a number)</option>
          <option value="skip">Skip it — don't transfer it at all</option>
          <option value="overwrite">Replace the existing file</option>
        </select>
        <span className="hint">
          Keeping both is the default: a transfer should never destroy something you
          already had.
          {settings.onConflict === "skip" && (
            <>
              {" "}
              <strong>Skip is decided before anything is sent</strong>, so files you
              already have cost nothing. That makes it the quickest way to finish a
              part-done transfer — send the same folder again and only what is
              actually missing crosses the network.
            </>
          )}
        </span>
      </label>

      <label className="field">
        <input
          type="checkbox"
          checked={settings.folderPerDevice}
          onChange={(event) => patch({ folderPerDevice: event.target.checked })}
          style={{ width: "auto", marginRight: 8 }}
        />
        Put each device's files in a folder named after it
        <span className="hint">
          Inside the folder above. A device can also be given a folder of its own,
          anywhere, from the Paired tab.
        </span>
      </label>

      <h3 className="section-title" style={{ marginTop: 22 }}>
        Speed limits
      </h3>

      <p className="hint" style={{ marginTop: -4 }}>
        Off by default — a transfer should be as fast as your network allows. Set
        a limit when you need the rest of the connection back. Any transfer
        already running can also be slowed from its own row, without stopping it.
      </p>

      <div style={{ display: "flex", gap: 12 }}>
        {(
          [
            ["sendLimitKbps", "Sending", "When you send to another device"],
            ["receiveLimitKbps", "Receiving", "When another device sends to you"],
          ] as const
        ).map(([key, label, hint]) => (
          <label className="field" key={key} style={{ flex: 1 }}>
            <span className="label">{label}</span>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <input
                type="number"
                min={0}
                step={100}
                value={settings[key] === 0 ? "" : Math.round(settings[key] / 1000)}
                placeholder="No limit"
                onChange={(event) => {
                  // Stored in KB/s but typed in MB/s, which is the unit people
                  // think in for a LAN. Empty means no limit, not zero speed.
                  const mb = Number(event.target.value);
                  patch({ [key]: Number.isFinite(mb) && mb > 0 ? Math.round(mb * 1000) : 0 });
                }}
              />
              <span style={{ fontSize: 12, color: "var(--text-dim)" }}>MB/s</span>
            </div>
            <span className="hint">{hint}</span>
          </label>
        ))}
      </div>

      <label className="field" style={{ marginTop: 6 }}>
        <span className="label">Save bandwidth</span>
        <select
          value={settings.bandwidthSaving}
          onChange={(event) =>
            patch({ bandwidthSaving: event.target.value as SettingsView["bandwidthSaving"] })
          }
        >
          <option value="auto">Over a VPN or the internet only</option>
          <option value="always">Always</option>
          <option value="never">Never</option>
        </select>
        <span className="hint">
          Compresses what compresses well, and when a large file is sent again,
          reuses the parts the other device already has instead of sending them.
          Both cost some processing on each side, which is worth it on a slow link
          and usually not on a fast local network. Works between devices that
          both have this version.
        </span>
      </label>

      <h3 className="section-title" style={{ marginTop: 22 }}>
        Appearance
      </h3>

      <label className="field">
        <span className="label">Interface</span>
        <select
          value={settings.interface}
          onChange={(event) => patch({ interface: event.target.value as SettingsView["interface"] })}
        >
          <option value="classic">Classic</option>
          <option value="modern">Modern</option>
        </select>
        <span className="hint">
          Modern has a side bar, a speed graph on each transfer, and the transfers
          in progress on the main screen. Everything works the same in both, and
          you can switch back at any time.
        </span>
      </label>

      <h3 className="section-title" style={{ marginTop: 22 }}>
        Windows
      </h3>

      {/* Both settings below record this program's path on the computer, which
          outlives a portable copy being unplugged. Disabled rather than allowed
          to fail later on a machine the user has already walked away from. */}
      {self?.portable && (
        <p className="hint" style={{ marginTop: -4 }}>
          This is a portable copy — everything it stores lives in its own{" "}
          <code>Jetstream Data</code> folder, so the two settings below are
          unavailable. Install Jetstream on this computer to use them.
        </p>
      )}

      <label className="field">
        <input
          type="checkbox"
          checked={autostart}
          disabled={self?.portable}
          onChange={(event) => {
            void api
              .setAutostart(event.target.checked)
              .then(setAutostart)
              .catch((e) => setError(String(e)));
          }}
          style={{ width: "auto", marginRight: 8 }}
        />
        Start Jetstream when I sign in
        <span className="hint">
          Jetstream has to be running to receive anything. It starts hidden in the
          notification area.
        </span>
      </label>

      <label className="field">
        <input
          type="checkbox"
          checked={sendTo}
          disabled={self?.portable}
          onChange={(event) => {
            void api
              .setSendTo(event.target.checked)
              .then(setSendTo)
              .catch((e) => setError(String(e)));
          }}
          style={{ width: "auto", marginRight: 8 }}
        />
        Add to Explorer's "Send to" menu
        <span className="hint">
          Right-click any file, then Send to → Jetstream. No administrator rights
          needed.
        </span>
      </label>

      {error && (
        <p style={{ color: "var(--brand-pink)", fontSize: 13 }}>{error}</p>
      )}

      <div className="actions">
        <button className="btn primary" onClick={() => void save()} disabled={saving}>
          {saving ? "Saving…" : "Save"}
        </button>
      </div>
    </>
  );
}
