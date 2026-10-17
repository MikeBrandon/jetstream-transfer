/**
 * Application shell.
 *
 * The central interaction is Dukto's, kept because it was right: a grid of
 * devices, and you drop things on it. Two ways in —
 *
 *   drop files on the window → every tile arms → click a device
 *   click a device → file picker → send
 *
 * — because dragging is natural from Explorer and impossible from the keyboard.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { getCurrentWebview } from "@tauri-apps/api/webview";

import {
  api,
  events,
  formatPercent,
  formatRate,
  isRunning,
  type Interface,
  type OfferView,
  type PeerView,
  type SelfView,
  type TransferView,
  type TrustedView,
  type TrustView,
} from "./api";
import type { FirewallView, HistoryView, NetworkProfileView, WebText } from "./api";
import { AddDevice } from "./components/AddDevice";
import { Folders } from "./components/Folders";
import { NavIcon } from "./components/NavIcon";
import { NetworkProfileCard } from "./components/NetworkProfileCard";
import { History } from "./components/History";
import { Browser } from "./components/Browser";
import { Devices } from "./components/Devices";
import { FirewallCard } from "./components/FirewallCard";
import { Network } from "./components/Network";
import { OfferDialog } from "./components/OfferDialog";
import { Peers } from "./components/Peers";
import { Settings } from "./components/Settings";
import { Transfers } from "./components/Transfers";

export type Tab =
  | "devices"
  | "transfers"
  | "history"
  | "folders"
  | "browser"
  | "trusted"
  | "network"
  | "settings";

export function App() {
  const [self, setSelf] = useState<SelfView | null>(null);
  const [peers, setPeers] = useState<PeerView[]>([]);
  const [transfers, setTransfers] = useState<TransferView[]>([]);
  const [trusted, setTrusted] = useState<TrustedView[]>([]);
  const [offers, setOffers] = useState<OfferView[]>([]);
  const [tab, setTab] = useState<Tab>("devices");
  const [toast, setToast] = useState<{ text: string; error: boolean } | null>(null);

  /** Paths waiting for a device to be chosen. */
  const [pending, setPending] = useState<string[]>([]);
  const [hovering, setHovering] = useState(false);
  const [adding, setAdding] = useState(false);
  /** Choosing several devices for one send, and which are chosen. */
  const [selecting, setSelecting] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  /** Classic or modern. Read from settings; classic until they say otherwise. */
  const [ui, setUi] = useState<Interface>("classic");
  const modern = ui === "modern";

  // Surfaced on the main screen, not buried in the Network tab. A blocked
  // firewall means the app can send but never receive, and a first-run user
  // has no reason to go looking for a diagnostics page to discover that.
  const [firewall, setFirewall] = useState<FirewallView | null>(null);
  const [profile, setProfile] = useState<NetworkProfileView | null>(null);
  const [history, setHistory] = useState<HistoryView[]>([]);
  /** Text sent from browsers this session, newest first. */
  const [texts, setTexts] = useState<(WebText & { at: number })[]>([]);

  // Held in a ref as well so the drop handler, registered once, can read the
  // current value without being torn down and re-registered on every change.
  const pendingRef = useRef<string[]>([]);
  pendingRef.current = pending;

  // One timer for the one toast. Each toast used to start its own, so an older
  // one expiring could clear a newer error after a fraction of a second.
  const toastTimer = useRef<number | undefined>(undefined);
  const say = useCallback((text: string, error = false) => {
    setToast({ text, error });
    window.clearTimeout(toastTimer.current);
    toastTimer.current = window.setTimeout(() => setToast(null), error ? 7000 : 3500);
  }, []);

  const refreshTrusted = useCallback(() => {
    void api.listTrusted().then(setTrusted);
  }, []);

  const refreshHistory = useCallback(() => {
    void api.listHistory().then(setHistory);
  }, []);

  useEffect(() => {
    void api.getSettings().then((settings) => setUi(settings.interface));
    void api.getSelf().then(setSelf);
    void api.listPeers().then(setPeers);
    void api.listTransfers().then(setTransfers);
    void api.firewallStatus().then(setFirewall);
    void api.networkProfileStatus().then(setProfile);
    refreshTrusted();
    refreshHistory();

    const subscriptions = [
      events.peers(setPeers),
      events.transfers(setTransfers),
      events.offer((offer) => setOffers((current) => [...current, offer])),
      events.offerExpired((id) =>
        setOffers((current) => current.filter((offer) => offer.id !== id)),
      ),
      // Files arriving from Explorer's "Send to", or from a second launch.
      events.externalSend((paths) => {
        if (paths.length > 0) {
          setPending(paths);
          setTab("devices");
        }
      }),
      // The tray's "Send files…" promises a dialog, so open one straight away
      // and arm the tiles with whatever was chosen — the same order as dropping
      // files on the window. Cancelling leaves nothing armed.
      events.traySend(() => {
        setTab("devices");
        void open({ multiple: true, directory: false }).then((picked) => {
          if (Array.isArray(picked) && picked.length > 0) setPending(picked);
        });
      }),
      events.hiddenToTray(() =>
        say("Jetstream is still running in the notification area, ready to receive. Quit from there when you want it to stop."),
      ),
      events.notice((text) => say(text)),
      // Keeps the History badge and list current without a visit to the tab.
      events.historyChanged(refreshHistory),
      // Used to be sent and never listened for, so text from a phone vanished.
      events.webText((text) => {
        setTexts((current) => [{ ...text, at: Date.now() }, ...current].slice(0, 20));
        say(`${text.from} sent you text — it is in the Phone tab.`);
      }),
    ];

    return () => {
      subscriptions.forEach((subscription) =>
        void subscription.then((unlisten) => unlisten()),
      );
    };
  }, [refreshTrusted, refreshHistory, say]);

  // Native drag and drop. The webview reports real filesystem paths, which is
  // what the engine needs — a browser `File` object would not do.
  useEffect(() => {
    let unlisten: (() => void) | undefined;

    void getCurrentWebview()
      .onDragDropEvent((event) => {
        if (event.payload.type === "over") {
          setHovering(true);
        } else if (event.payload.type === "drop") {
          setHovering(false);
          const paths = event.payload.paths;
          if (paths.length > 0) {
            setPending(paths);
            setTab("devices");
          }
        } else {
          setHovering(false);
        }
      })
      .then((fn) => {
        unlisten = fn;
      });

    return () => unlisten?.();
  }, []);

  const sendTo = useCallback(
    async (peer: PeerView, paths: string[]) => {
      if (paths.length === 0) return;
      try {
        await api.sendToPeer(peer.deviceId, paths);
        setPending([]);
        setTab("transfers");
      } catch (error) {
        say(String(error), true);
      }
    },
    [say],
  );

  const selectingRef = useRef(false);
  selectingRef.current = selecting;

  const pickPeer = useCallback(
    async (peer: PeerView) => {
      if (selectingRef.current) {
        setSelected((current) => {
          const next = new Set(current);
          if (!next.delete(peer.deviceId)) next.add(peer.deviceId);
          return next;
        });
        return;
      }
      if (pendingRef.current.length > 0) {
        await sendTo(peer, pendingRef.current);
        return;
      }

      const picked = await open({ multiple: true, directory: false });
      if (Array.isArray(picked) && picked.length > 0) {
        await sendTo(peer, picked);
      }
    },
    [sendTo],
  );

  // One drop, several devices: each is its own transfer, so each resumes,
  // pauses and fails on its own, exactly as if sent one at a time.
  const sendToSeveral = useCallback(async () => {
    const paths = pendingRef.current;
    const targets = peers.filter((peer) => selected.has(peer.deviceId));
    if (paths.length === 0 || targets.length === 0) return;

    const failures: string[] = [];
    for (const peer of targets) {
      try {
        await api.sendToPeer(peer.deviceId, paths);
      } catch (error) {
        failures.push(`${peer.name}: ${String(error)}`);
      }
    }

    setSelecting(false);
    setSelected(new Set());
    setPending([]);
    setTab("transfers");
    if (failures.length > 0) say(failures.join("\n"), true);
  }, [peers, selected, say]);

  const stopSelecting = useCallback(() => {
    setSelecting(false);
    setSelected(new Set());
  }, []);

  // Files and folders need separate buttons because Windows has no dialog that
  // offers both — picking a folder is a distinct mode of the native dialog, not
  // a filter within it. Both arm the tiles, the same as dropping something on
  // the window, so the order is always "choose what, then choose who".
  const chooseAndArm = useCallback(async (directory: boolean) => {
    const picked = await open({ multiple: !directory, directory });
    const paths = Array.isArray(picked) ? picked : picked ? [picked] : [];
    if (paths.length > 0) setPending(paths);
  }, []);

  const respond = useCallback(
    async (offer: OfferView, accept: boolean, remember: TrustView | null) => {
      setOffers((current) => current.filter((o) => o.id !== offer.id));
      await api.respondToOffer(offer.id, accept, remember);
      if (remember) refreshTrusted();
      setTab("transfers");
    },
    [refreshTrusted],
  );

  const active = transfers.filter(isRunning).length;

  const tabs: [Tab, string, number][] = [
    ["devices", "Devices", peers.length],
    ["transfers", "Transfers", active],
    ["history", "History", history.filter((r) => r.willRetry).length],
    ["folders", "Folders", 0],
    ["browser", "Phone", texts.length],
    ["trusted", "Paired", 0],
    ["network", "Network", 0],
    ["settings", "Settings", 0],
  ];

  const openTab = (key: Tab) => {
    setTab(key);
    if (key === "trusted") refreshTrusted();
    if (key === "history") refreshHistory();
    // Cheap, and it clears the banner without a restart if the
    // user allowed us through the firewall by other means.
    if (key === "devices") void api.firewallStatus().then(setFirewall);
    if (key === "folders") refreshTrusted();
  };

  const tabButtons = tabs.map(([key, label, count]) => (
    <button
      key={key}
      role="tab"
      className="tab"
      aria-selected={tab === key}
      onClick={() => openTab(key)}
    >
      {modern && <NavIcon tab={key} />}
      <span className="label">{label}</span>
      {count > 0 && <span className="count">{count}</span>}
    </button>
  ));

  // What to send and to whom. The same choices in both interfaces; the modern
  // one gives them a larger target to drop on.
  const sendBar =
    pending.length > 0 ? (
      <div className={modern ? "hero ready" : "row"} style={modern ? undefined : { marginBottom: 14 }}>
        <div style={{ flex: 1 }}>
          <div className={modern ? "hero-title" : undefined}>
            <strong>
              {pending.length} item{pending.length === 1 ? "" : "s"} ready to send
            </strong>
          </div>
          <div className={modern ? "hero-sub" : undefined} style={modern ? undefined : { fontSize: 12, color: "var(--text-dim)" }}>
            {selecting ? "Pick the devices, then send to all of them." : "Choose a device below."}
          </div>
        </div>
        {selecting ? (
          <>
            <button
              className="btn primary small"
              disabled={selected.size === 0}
              onClick={() => void sendToSeveral()}
            >
              Send to {selected.size} device{selected.size === 1 ? "" : "s"}
            </button>
            <button className="btn ghost small" onClick={stopSelecting}>
              Back
            </button>
          </>
        ) : (
          <>
            {peers.length > 1 && (
              <button className="btn small" onClick={() => setSelecting(true)}>
                Send to several…
              </button>
            )}
            <button className="btn ghost small" onClick={() => setPending([])}>
              Cancel
            </button>
          </>
        )}
      </div>
    ) : (
      <div className={modern ? "hero" : "row"} style={modern ? undefined : { marginBottom: 14 }}>
        <div style={{ flex: 1 }} className={modern ? undefined : "drop-hint"}>
          {modern ? (
            <>
              <div className="hero-title">Drop files or folders anywhere</div>
              <div className="hero-sub">or choose them, then pick a device below</div>
            </>
          ) : (
            <span style={{ fontSize: 12, color: "var(--text-dim)" }}>
              Drop anything on this window, or pick it here.
            </span>
          )}
        </div>
        <button className="btn small" onClick={() => void chooseAndArm(false)}>
          Choose files…
        </button>
        <button className="btn small" onClick={() => void chooseAndArm(true)}>
          Choose folder…
        </button>
        <button
          className="btn ghost small"
          onClick={() => setAdding(true)}
          title="For a device on a VPN or another network, which will not appear by itself"
        >
          Add by address…
        </button>
      </div>
    );

  // The modern interface keeps what is moving in view on the main screen.
  const running = transfers.filter(isRunning);
  const inProgress = modern && running.length > 0 && (
    <button className="in-progress" onClick={() => openTab("transfers")}>
      <span className="in-progress-title">In progress</span>
      {running.slice(0, 3).map((transfer) => {
        const percent =
          transfer.bytesTotal > 0 ? Math.min(100, (transfer.bytesDone / transfer.bytesTotal) * 100) : 0;
        return (
          <span className="mini" key={transfer.id}>
            <span className="mini-who">
              {transfer.direction === "sending" ? "→" : "←"} {transfer.peerName}
            </span>
            <span className="mini-bar">
              <span style={{ width: `${percent}%` }} />
            </span>
            <span className="mini-num">
              {formatPercent(transfer.bytesDone, transfer.bytesTotal)}
              {transfer.rate > 0 && ` · ${formatRate(transfer.rate)}`}
            </span>
          </span>
        );
      })}
      {running.length > 3 && <span className="mini-more">and {running.length - 3} more</span>}
    </button>
  );

  return (
    <div className={`app${modern ? " modern" : ""}`}>
      {modern ? (
        <aside className="sidebar">
          <div className="wordmark">
            <img className="mark" src="./mark.png" alt="" aria-hidden="true" />
            JETSTREAM
          </div>
          <nav className="tabs" role="tablist" aria-orientation="vertical">
            {tabButtons}
          </nav>
          {self && (
            <div className="identity">
              <div className="name">{self.name}</div>
              <div className="fp">{self.fingerprint}</div>
            </div>
          )}
        </aside>
      ) : (
        <header className="header">
          <div className="wordmark">
            <img className="mark" src="./mark.png" alt="" aria-hidden="true" />
            JETSTREAM
          </div>

          <nav className="tabs" role="tablist">
            {tabButtons}
          </nav>

          {self && (
            <div className="identity">
              <div className="name">{self.name}</div>
              <div className="fp">{self.fingerprint}</div>
            </div>
          )}
        </header>
      )}

      <main className="body">
        {tab === "devices" && (
          <>
            {firewall && !firewall.allowed && (
              <div style={{ marginBottom: 16 }}>
                <FirewallCard firewall={firewall} onChanged={setFirewall} />
              </div>
            )}

            {/* After the firewall card: being unreachable is the blocking
                problem, an awkward network category is only an annoyance. */}
            {profile?.needsFixing && (
              <div style={{ marginBottom: 16 }}>
                <NetworkProfileCard profile={profile} onChanged={setProfile} />
              </div>
            )}

            {sendBar}
            {inProgress}
            {adding && (
              <AddDevice
                onCancel={() => setAdding(false)}
                onAdded={(peer) => {
                  setAdding(false);
                  setPeers((current) => [
                    ...current.filter((p) => p.deviceId !== peer.deviceId),
                    peer,
                  ]);
                  say(`Found ${peer.name}. It will stay in the list while it can be reached.`);
                }}
              />
            )}
            <Peers
              peers={peers}
              armed={pending.length > 0}
              onPick={(peer) => void pickPeer(peer)}
              onAddByAddress={() => setAdding(true)}
              selecting={selecting}
              selected={selected}
            />
          </>
        )}

        {tab === "transfers" && (
          <Transfers
            transfers={transfers}
            modern={modern}
            onCancel={(id) => void api.cancelTransfer(id)}
            onPause={(id) => void api.pauseTransfer(id)}
            onReveal={(id) => {
              void api.revealTransfer(id).catch((e) => say(String(e), true));
            }}
            onLimit={(id, kbps) => void api.setTransferLimit(id, kbps)}
            onClear={() => {
              void api.clearFinished().then(() => api.listTransfers().then(setTransfers));
            }}
            // Continues this transfer under its own id. It used to open a file
            // picker and start a brand-new transfer, which is exactly the
            // "it started again from scratch" it was meant to avoid.
            onResume={(transfer) => {
              void api
                .retryTransfer(transfer.id)
                .then(refreshHistory)
                .catch((e) => say(String(e), true));
            }}
          />
        )}

        {tab === "trusted" && (
          <Devices
            devices={trusted}
            onSetTrust={(device, trust) => {
              void api.setTrust(device.deviceId, device.name, trust).then(refreshTrusted);
            }}
            onForget={(device) => {
              void api.forgetDevice(device.deviceId).then(() => {
                refreshTrusted();
                say(`Forgot ${device.name}. It will ask again next time.`);
              });
            }}
            onSetFolder={(device, folder) => {
              void api
                .setDeviceFolder(device.deviceId, folder)
                .then(refreshTrusted)
                .catch((e) => say(String(e), true));
            }}
            onWake={(device) => {
              void api
                .wakeDevice(device.deviceId)
                .then(() =>
                  say(`Sent ${device.name} a wake-up signal. It can take a minute to appear.`),
                )
                .catch((e) => say(String(e), true));
            }}
          />
        )}

        {tab === "history" && (
          <History
            records={history}
            modern={modern}
            onRetry={(record) => {
              void api
                .retryTransfer(record.id)
                .then(() => {
                  setTab("transfers");
                  refreshHistory();
                })
                .catch((e) => say(String(e), true));
            }}
            onForget={(record) => {
              void api.forgetHistory(record.id).then(refreshHistory);
            }}
            onClear={() => {
              void api.clearHistory().then(refreshHistory);
            }}
          />
        )}

        {tab === "folders" && (
          <Folders peers={peers} trusted={trusted} onError={(message) => say(message, true)} />
        )}

        {tab === "browser" && (
          <Browser
            texts={texts}
            onClearTexts={() => setTexts([])}
            onCopied={() => say("Copied.")}
          />
        )}

        {tab === "network" && <Network self={self} />}

        {tab === "settings" && (
          <Settings
            self={self}
            onSaved={(nameChanged, saved) => {
              void api.getSelf().then(setSelf);
              setUi(saved.interface);
              say(
                nameChanged
                  ? "Saved. Other devices will see the new name within a few seconds."
                  : "Saved.",
              );
            }}
          />
        )}
      </main>

      {hovering && (
        <div className="dropzone">
          <div className="inner">
            <div className="headline">Drop to send</div>
            <div className="sub">You will choose which device next.</div>
          </div>
        </div>
      )}

      {offers[0] && (
        <OfferDialog
          offer={offers[0]}
          onRespond={(accept, remember) => void respond(offers[0]!, accept, remember)}
        />
      )}

      {toast && <div className={`toast${toast.error ? " error" : ""}`}>{toast.text}</div>}
    </div>
  );
}
