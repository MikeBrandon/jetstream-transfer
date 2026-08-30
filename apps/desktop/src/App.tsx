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
  type OfferView,
  type PeerView,
  type SelfView,
  type TransferView,
  type TrustedView,
  type TrustView,
} from "./api";
import type { FirewallView, HistoryView, NetworkProfileView } from "./api";
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

type Tab = "devices" | "transfers" | "history" | "browser" | "trusted" | "network" | "settings";

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

  // Surfaced on the main screen, not buried in the Network tab. A blocked
  // firewall means the app can send but never receive, and a first-run user
  // has no reason to go looking for a diagnostics page to discover that.
  const [firewall, setFirewall] = useState<FirewallView | null>(null);
  const [profile, setProfile] = useState<NetworkProfileView | null>(null);
  const [history, setHistory] = useState<HistoryView[]>([]);

  // Held in a ref as well so the drop handler, registered once, can read the
  // current value without being torn down and re-registered on every change.
  const pendingRef = useRef<string[]>([]);
  pendingRef.current = pending;

  const say = useCallback((text: string, error = false) => {
    setToast({ text, error });
    window.setTimeout(() => setToast(null), error ? 7000 : 3500);
  }, []);

  const refreshTrusted = useCallback(() => {
    void api.listTrusted().then(setTrusted);
  }, []);

  const refreshHistory = useCallback(() => {
    void api.listHistory().then(setHistory);
  }, []);

  useEffect(() => {
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

  const pickPeer = useCallback(
    async (peer: PeerView) => {
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

  const active = transfers.filter(
    (transfer) => !["done", "failed", "rejected", "interrupted"].includes(transfer.state),
  ).length;

  const tabs: [Tab, string, number][] = [
    ["devices", "Devices", peers.length],
    ["transfers", "Transfers", active],
    ["history", "History", history.filter((r) => r.willRetry).length],
    ["browser", "Phone", 0],
    ["trusted", "Paired", 0],
    ["network", "Network", 0],
    ["settings", "Settings", 0],
  ];

  return (
    <div className="app">
      <header className="header">
        <div className="wordmark">
          <img className="mark" src="./mark.png" alt="" aria-hidden="true" />
          JETSTREAM
        </div>

        <nav className="tabs" role="tablist">
          {tabs.map(([key, label, count]) => (
            <button
              key={key}
              role="tab"
              className="tab"
              aria-selected={tab === key}
              onClick={() => {
                setTab(key);
                if (key === "trusted") refreshTrusted();
                if (key === "history") refreshHistory();
                // Cheap, and it clears the banner without a restart if the
                // user allowed us through the firewall by other means.
                if (key === "devices") void api.firewallStatus().then(setFirewall);
              }}
            >
              {label}
              {count > 0 && <span className="count">{count}</span>}
            </button>
          ))}
        </nav>

        {self && (
          <div className="identity">
            <div className="name">{self.name}</div>
            <div className="fp">{self.fingerprint}</div>
          </div>
        )}
      </header>

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

            {pending.length > 0 ? (
              <div className="row" style={{ marginBottom: 14 }}>
                <div style={{ flex: 1 }}>
                  <strong>
                    {pending.length} item{pending.length === 1 ? "" : "s"} ready to send
                  </strong>
                  <div style={{ fontSize: 12, color: "var(--text-dim)" }}>
                    Choose a device below.
                  </div>
                </div>
                <button className="btn ghost small" onClick={() => setPending([])}>
                  Cancel
                </button>
              </div>
            ) : (
              <div className="row" style={{ marginBottom: 14 }}>
                <div style={{ flex: 1, fontSize: 12, color: "var(--text-dim)" }}>
                  Drop anything on this window, or pick it here.
                </div>
                <button className="btn small" onClick={() => void chooseAndArm(false)}>
                  Choose files…
                </button>
                <button className="btn small" onClick={() => void chooseAndArm(true)}>
                  Choose folder…
                </button>
              </div>
            )}
            <Peers peers={peers} armed={pending.length > 0} onPick={(peer) => void pickPeer(peer)} />
          </>
        )}

        {tab === "transfers" && (
          <Transfers
            transfers={transfers}
            onCancel={(id) => void api.cancelTransfer(id)}
            onPause={(id) => void api.pauseTransfer(id)}
            onReveal={(id) => {
              void api.revealTransfer(id).catch((e) => say(String(e), true));
            }}
            onLimit={(id, kbps) => void api.setTransferLimit(id, kbps)}
            onClear={() => {
              void api.clearFinished().then(() => api.listTransfers().then(setTransfers));
            }}
            onResume={(transfer) => {
              const peer = peers.find((p) => p.deviceId === transfer.peerDeviceId);
              if (peer) {
                void pickPeer(peer);
              } else {
                say(`${transfer.peerName} is not on the network right now.`, true);
              }
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
          />
        )}

        {tab === "history" && (
          <History
            records={history}
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

        {tab === "browser" && <Browser />}

        {tab === "network" && <Network self={self} />}

        {tab === "settings" && (
          <Settings
            self={self}
            onSaved={(nameChanged) => {
              void api.getSelf().then(setSelf);
              say(
                nameChanged
                  ? "Saved. The new name will be visible to other devices after a restart."
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
