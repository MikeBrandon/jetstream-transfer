/**
 * Typed bridge to the Rust side.
 *
 * These types mirror `src-tauri/src/views.rs` by hand. There is no codegen, so
 * the discipline is: change a view struct, change it here in the same commit.
 * Keeping the surface small is what makes that maintainable.
 */

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export type TrustView = "unknown" | "ask" | "autoAccept" | "blocked";
export type Direction = "sending" | "receiving";
export type TransferState =
  | "connecting"
  | "waiting"
  | "active"
  | "done"
  | "interrupted"
  | "paused"
  | "failed"
  | "rejected"
  | "cancelled";

export interface SelfView {
  name: string;
  deviceId: string;
  fingerprint: string;
  fingerprintWords: string[];
  port: number;
  downloadDir: string;
  /** Running from a `Jetstream Data` folder beside the executable. */
  portable: boolean;
}

export interface PeerView {
  deviceId: string;
  name: string;
  fingerprint: string;
  address: string | null;
  sources: string[];
  trust: TrustView;
}

export interface TrustedView {
  deviceId: string;
  name: string;
  fingerprint: string;
  trust: TrustView;
  firstPaired: number;
  lastSeen: number;
  online: boolean;
}

export interface TransferView {
  id: number;
  direction: Direction;
  peerName: string;
  peerDeviceId: string;
  state: TransferState;
  bytesDone: number;
  bytesTotal: number;
  filesDone: number;
  filesTotal: number;
  rate: number;
  /** Current rate limit in bytes/sec, or null when unlimited. */
  limit: number | null;
  /** Items the walk left out, with a reason each. Truncated for huge trees. */
  skipped: { path: string; reason: string }[];
  /** Whether this row can open its files in Explorer. */
  canReveal: boolean;
  /** Bytes/sec this wire can carry at most, or null if unknown. */
  linkCeiling: number | null;
  /** The same figure as hardware speaks of it, e.g. "1 Gbps". */
  linkLabel: string | null;
  eta: number | null;
  summary: string;
  detail: string | null;
  startedAt: number;
  resumable: boolean;
}

export interface OfferView {
  id: number;
  peerName: string;
  peerDeviceId: string;
  fingerprint: string;
  fingerprintWords: string[];
  firstContact: boolean;
  summary: string;
  fileCount: number;
  totalBytes: number;
  topLevel: string[];
  moreTopLevel: boolean;
}

export interface FindingView {
  severity: "ok" | "note" | "problem";
  summary: string;
  remedy: string;
}

export interface FirewallView {
  state: "present" | "disabled" | "absent" | "moved" | "unknown" | "unsupported";
  allowed: boolean;
  canFix: boolean;
  summary: string;
  remedy: string;
}

export interface DiagnosticsView {
  findings: FindingView[];
  hasProblems: boolean;
  firewall: FirewallView;
}

export interface NetworkProfileView {
  needsFixing: boolean;
  fixable: string[];
  /** Public networks left alone on purpose, because they reach the internet. */
  publicWithInternet: string[];
  summary: string;
  remedy: string;
}

export interface WebStatusView {
  running: boolean;
  /** Empty unless a code was just minted — pairing codes are single-use. */
  url: string;
  qrSvg: string;
  expiresIn: number;
  guests: number;
  address: string;
}

export interface HistoryView {
  id: number;
  peerName: string;
  peerDeviceId: string;
  sending: boolean;
  summary: string;
  bytes: number;
  outcome: "completed" | "interrupted" | "declined" | "failed";
  at: number;
  /** True when the app will retry by itself once the peer reappears. */
  willRetry: boolean;
  attempts: number;
  detail: string | null;
  canRetry: boolean;
}

export interface SettingsView {
  deviceName: string;
  downloadDir: string;
  onConflict: "rename" | "overwrite" | "skip";
  /** Kilobytes per second; 0 means no limit. */
  sendLimitKbps: number;
  receiveLimitKbps: number;
}

export const api = {
  getSelf: () => invoke<SelfView>("get_self"),
  listPeers: () => invoke<PeerView[]>("list_peers"),
  listTrusted: () => invoke<TrustedView[]>("list_trusted"),
  listTransfers: () => invoke<TransferView[]>("list_transfers"),

  setTrust: (deviceId: string, name: string, trust: TrustView) =>
    invoke<void>("set_trust", { deviceId, name, trust }),
  forgetDevice: (deviceId: string) =>
    invoke<boolean>("forget_device", { deviceId }),

  sendToPeer: (deviceId: string, paths: string[]) =>
    invoke<number>("send_to_peer", { deviceId, paths }),
  cancelTransfer: (id: number) => invoke<void>("cancel_transfer", { id }),
  pauseTransfer: (id: number) => invoke<void>("pause_transfer", { id }),
  revealTransfer: (id: number) => invoke<void>("reveal_transfer", { id }),
  setTransferLimit: (id: number, kbps: number) =>
    invoke<void>("set_transfer_limit", { id, kbps }),
  clearFinished: () => invoke<void>("clear_finished"),

  respondToOffer: (id: number, accept: boolean, remember: TrustView | null) =>
    invoke<boolean>("respond_to_offer", { id, accept, remember }),

  getSettings: () => invoke<SettingsView>("get_settings"),
  saveSettings: (settings: SettingsView) =>
    invoke<boolean>("save_settings", { settings }),
  runDiagnostics: () => invoke<DiagnosticsView>("run_diagnostics"),
  firewallStatus: () => invoke<FirewallView>("firewall_status"),
  allowThroughFirewall: () => invoke<FirewallView>("allow_through_firewall"),
  networkProfileStatus: () => invoke<NetworkProfileView>("network_profile_status"),
  makeNetworkPrivate: () => invoke<NetworkProfileView>("make_network_private"),

  startWeb: () => invoke<WebStatusView>("start_web"),
  stopWeb: () => invoke<WebStatusView>("stop_web"),
  webStatus: () => invoke<WebStatusView>("web_status"),
  setWebShared: (paths: string[], text: string | null) =>
    invoke<void>("set_web_shared", { paths, text }),

  listHistory: () => invoke<HistoryView[]>("list_history"),
  forgetHistory: (id: number) => invoke<void>("forget_history", { id }),
  clearHistory: () => invoke<void>("clear_history"),
  retryTransfer: (id: number) => invoke<number>("retry_transfer", { id }),

  sendToStatus: () => invoke<boolean>("send_to_status"),
  setSendTo: (enabled: boolean) => invoke<boolean>("set_send_to", { enabled }),
  autostartStatus: () => invoke<boolean>("autostart_status"),
  setAutostart: (enabled: boolean) => invoke<boolean>("set_autostart", { enabled }),
};

export const events = {
  peers: (fn: (peers: PeerView[]) => void): Promise<UnlistenFn> =>
    listen<PeerView[]>("peers", (e) => fn(e.payload)),
  transfers: (fn: (transfers: TransferView[]) => void): Promise<UnlistenFn> =>
    listen<TransferView[]>("transfers", (e) => fn(e.payload)),
  offer: (fn: (offer: OfferView) => void): Promise<UnlistenFn> =>
    listen<OfferView>("offer", (e) => fn(e.payload)),
  offerExpired: (fn: (id: number) => void): Promise<UnlistenFn> =>
    listen<number>("offer-expired", (e) => fn(e.payload)),

  /** Files arriving from Explorer's "Send to", or a second launch. */
  externalSend: (fn: (paths: string[]) => void): Promise<UnlistenFn> =>
    listen<string[]>("external-send", (e) => fn(e.payload)),
  /** The tray asked for a file picker. */
  traySend: (fn: () => void): Promise<UnlistenFn> =>
    listen("tray-send", () => fn()),
  /** The window was hidden rather than closed, for the first time. */
  hiddenToTray: (fn: () => void): Promise<UnlistenFn> =>
    listen("hidden-to-tray", () => fn()),
};

/* --------------------------------------------------------------- helpers -- */

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value.toFixed(1)} ${units[unit]}`;
}

export function formatRate(bytesPerSecond: number): string {
  return bytesPerSecond > 0 ? `${formatBytes(bytesPerSecond)}/s` : "";
}

export function formatEta(seconds: number | null): string {
  if (seconds === null) return "";
  if (seconds < 60) return `${Math.max(1, Math.round(seconds))}s left`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m left`;
  return `${(seconds / 3600).toFixed(1)}h left`;
}

export function formatWhen(unixSeconds: number): string {
  if (!unixSeconds) return "never";
  const ago = Date.now() / 1000 - unixSeconds;

  if (ago < 60) return "just now";
  if (ago < 3600) return `${Math.round(ago / 60)} min ago`;
  if (ago < 86400) return `${Math.round(ago / 3600)} hr ago`;
  if (ago < 2592000) return `${Math.round(ago / 86400)} days ago`;
  return new Date(unixSeconds * 1000).toLocaleDateString();
}

/**
 * Two initials for a device tile.
 *
 * Uses `Intl.Segmenter` so a name starting with an emoji or a non-Latin script
 * yields one whole character rather than half a surrogate pair.
 */
export function initials(name: string): string {
  const words = name.trim().split(/[\s_-]+/).filter(Boolean);
  const segment = (text: string) => {
    const segmenter = new Intl.Segmenter(undefined, { granularity: "grapheme" });
    return [...segmenter.segment(text)][0]?.segment ?? "";
  };

  if (words.length === 0) return "?";
  if (words.length === 1) return segment(words[0]!).toUpperCase();
  return (segment(words[0]!) + segment(words[1]!)).toUpperCase();
}

/**
 * A stable colour per device, derived from its id.
 *
 * The same device is the same colour on every machine, which makes the peer
 * grid scannable without reading names.
 */
export function peerColor(deviceId: string): string {
  let hash = 0;
  for (const char of deviceId.slice(0, 16)) {
    hash = (hash * 31 + char.charCodeAt(0)) >>> 0;
  }
  return `hsl(${hash % 360} 55% 62%)`;
}

export function trustLabel(trust: TrustView): {
  text: string;
  tone: "cyan" | "pink" | "amber" | "";
} {
  switch (trust) {
    case "autoAccept":
      return { text: "auto-accept", tone: "cyan" };
    case "blocked":
      return { text: "blocked", tone: "pink" };
    case "ask":
      return { text: "paired", tone: "" };
    default:
      return { text: "new", tone: "amber" };
  }
}
