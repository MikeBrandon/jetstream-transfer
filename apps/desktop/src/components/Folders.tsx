/**
 * Watched folders: folders kept sent to a device as they change.
 *
 * The list says, for each one, what is happening right now — up to date,
 * changes waiting, sending, or what is in the way — because something that
 * works in the background is only trusted if it is easy to check on.
 */

import { useCallback, useEffect, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";

import {
  api,
  events,
  formatWhen,
  type PeerView,
  type TrustedView,
  type WatchedFolderView,
} from "../api";

interface Props {
  peers: PeerView[];
  trusted: TrustedView[];
  onError: (message: string) => void;
}

function status(folder: WatchedFolderView): { text: string; tone: string } {
  if (!folder.enabled) return { text: "paused", tone: "" };
  if (folder.sending) return { text: "sending", tone: "cyan" };
  if (folder.problem) return { text: "waiting", tone: "amber" };
  if (folder.waiting > 0) return { text: `${folder.waiting} to send`, tone: "cyan" };
  return { text: "up to date", tone: "" };
}

export function Folders({ peers, trusted, onError }: Props) {
  const [folders, setFolders] = useState<WatchedFolderView[]>([]);
  const [adding, setAdding] = useState<{ folder: string; deviceId: string; sendExisting: boolean } | null>(null);

  const refresh = useCallback(() => {
    void api.listWatchedFolders().then(setFolders);
  }, []);

  useEffect(() => {
    refresh();
    const subscription = events.foldersChanged(refresh);
    return () => void subscription.then((unlisten) => unlisten());
  }, [refresh]);

  // Every device that can be chosen: the ones on the network now, and paired
  // ones that are away — a folder can wait for its device to come back.
  const devices = new Map<string, string>();
  for (const peer of peers) devices.set(peer.deviceId, peer.name);
  for (const device of trusted) if (!devices.has(device.deviceId)) devices.set(device.deviceId, device.name);

  const choose = async () => {
    const picked = await open({ directory: true, multiple: false });
    if (typeof picked !== "string") return;
    setAdding({ folder: picked, deviceId: [...devices.keys()][0] ?? "", sendExisting: true });
  };

  const add = async () => {
    if (!adding?.deviceId) return;
    try {
      await api.addWatchedFolder(adding.folder, adding.deviceId, adding.sendExisting);
      setAdding(null);
      refresh();
    } catch (e) {
      onError(String(e));
    }
  };

  return (
    <>
      <h3 className="section-title" style={{ display: "flex", alignItems: "center" }}>
        Watched folders
        <span style={{ marginLeft: "auto", display: "flex", gap: 8 }}>
          {folders.length > 0 && (
            <button className="btn ghost small" onClick={() => void api.syncFolderNow()}>
              Check now
            </button>
          )}
          <button className="btn small" onClick={() => void choose()}>
            Watch a folder…
          </button>
        </span>
      </h3>

      <p className="hint" style={{ marginTop: -4 }}>
        New and changed files in a watched folder are sent to its device by
        themselves. Nothing is ever deleted on the other side, and a changed file
        arrives as that device's "When a file already exists" setting says — by
        default it keeps both copies. Set that device to accept from this one
        automatically in its Paired settings, or someone will be asked each time.
      </p>

      {adding && (
        <div className="row" style={{ display: "block" }}>
          <div className="selectable" style={{ fontFamily: "var(--mono)", fontSize: 12, marginBottom: 10 }}>
            {adding.folder}
          </div>
          <label className="field">
            <span className="label">Send to</span>
            <select
              value={adding.deviceId}
              onChange={(event) => setAdding({ ...adding, deviceId: event.target.value })}
            >
              {[...devices.entries()].map(([id, name]) => (
                <option key={id} value={id}>
                  {name}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            <input
              type="checkbox"
              checked={!adding.sendExisting}
              onChange={(event) => setAdding({ ...adding, sendExisting: !event.target.checked })}
              style={{ width: "auto", marginRight: 8 }}
            />
            The other device already has what is in this folder — only send changes from now on
          </label>
          {devices.size === 0 && (
            <p className="hint">There is no device to choose yet. Pair one by sending it something first.</p>
          )}
          <div className="actions">
            <button className="btn primary small" onClick={() => void add()} disabled={!adding.deviceId}>
              Watch this folder
            </button>
            <button className="btn ghost small" onClick={() => setAdding(null)}>
              Cancel
            </button>
          </div>
        </div>
      )}

      {folders.length === 0 && !adding && (
        <div className="empty">
          <div className="big">No watched folders</div>
          <p>Watch a folder to keep it sent to another device as it changes.</p>
        </div>
      )}

      {folders.map((folder) => {
        const chip = status(folder);
        return (
          <div className="row" key={folder.id}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontFamily: "var(--display)", fontSize: 13 }}>
                → {folder.deviceName}
                <span className={`chip ${chip.tone}`.trim()} style={{ marginLeft: 8 }}>
                  {chip.text}
                </span>
              </div>
              <div className="selectable" style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--text-dim)" }}>
                {folder.folder}
              </div>
              <div style={{ fontSize: 11, color: "var(--text-faint)" }}>
                {folder.lastSynced ? `last sent ${formatWhen(folder.lastSynced)}` : "not sent yet"}
                {` · ${folder.filesSent} file${folder.filesSent === 1 ? "" : "s"} sent so far`}
              </div>
              {folder.problem && (
                <div style={{ fontSize: 11.5, color: "var(--text-faint)", marginTop: 2 }}>{folder.problem}</div>
              )}
            </div>
            <button
              className="btn ghost small"
              onClick={() =>
                void api.setWatchedFolderEnabled(folder.id, !folder.enabled).then(refresh)
              }
            >
              {folder.enabled ? "Pause" : "Resume"}
            </button>
            <button
              className="btn ghost small"
              onClick={() => void api.removeWatchedFolder(folder.id).then(refresh)}
            >
              Stop watching
            </button>
          </div>
        );
      })}
    </>
  );
}
