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
  /** This machine's IPv4 addresses, for "Add by address" elsewhere. */
  addresses: string[];
}

export interface PeerView {
  deviceId: string;
  name: string;
  fingerprint: string;
  address: string | null;
  sources: string[];
  trust: TrustView;
}

/** A device added by address, for networks discovery cannot see across. */
export interface ManualDevice {
  deviceId: string;
  name: string;
  address: string;
}

export interface TrustedView {
  deviceId: string;
  name: string;
  fingerprint: string;
  trust: TrustView;
  firstPaired: number;
  lastSeen: number;
  online: boolean;
  /** This device's own download folder, if one was chosen. */
  downloadDir: string | null;
  /** Whether it can be woken with Wake-on-LAN. */
  canWake: boolean;
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
  /** Speed over the last minute, one reading a second, oldest first. */
  rateHistory: number[];
  /** Bytes copied from an older copy at the destination instead of sent. */
  reused: number;
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
  /** From a browser, not a Jetstream device: no key, so no fingerprint. */
  browser: boolean;
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
  /** The phone-sharing rule, which is separate: the web server is TCP. */
  browserState: FirewallView["state"];
  browserAllowed: boolean;
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
  /** The address the current code points at. */
  address: string;
  /** Every network this machine can be reached on from a browser. */
  addresses: { ip: string; interface: string }[];
}

export interface HistoryView {
  id: number;
  peerName: string;
  peerDeviceId: string;
  sending: boolean;
  summary: string;
  bytes: number;
  outcome: "completed" | "interrupted" | "paused" | "cancelled" | "declined" | "failed";
  at: number;
  /** True when the app will retry by itself once the peer reappears. */
  willRetry: boolean;
  attempts: number;
  detail: string | null;
  /** How much had arrived when it last stopped. */
  transferred: number;
  /** Seconds the last attempt spent moving data. */
  seconds: number;
  /** Average speed over those seconds, bytes per second. */
  averageRate: number;
  canRetry: boolean;
}

/** A folder kept sent to a device as it changes. */
export interface WatchedFolderView {
  id: number;
  folder: string;
  deviceId: string;
  deviceName: string;
  enabled: boolean;
  lastSynced: number;
  problem: string | null;
  sending: boolean;
  waiting: number;
  filesSent: number;
}

export type Interface = "classic" | "modern";

/** Text pasted on a phone or other browser and sent to this machine. */
export interface WebText {
  from: string;
  text: string;
}

export interface SettingsView {
  deviceName: string;
  downloadDir: string;
  onConflict: "rename" | "overwrite" | "skip";
  /** Kilobytes per second; 0 means no limit. */
  sendLimitKbps: number;
  receiveLimitKbps: number;
  /** When to compress and reuse older copies. `auto`: VPN and internet only. */
  bandwidthSaving: "auto" | "always" | "never";
  /** Put each device's files in a folder named after it. */
  folderPerDevice: boolean;
  /** Which interface to show. Classic stays the default. */
  interface: Interface;
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
  addDeviceByAddress: (address: string) =>
    invoke<PeerView>("add_device_by_address", { address }),
  listManualDevices: () => invoke<ManualDevice[]>("list_manual_devices"),
  setDeviceFolder: (deviceId: string, folder: string | null) =>
    invoke<void>("set_device_folder", { deviceId, folder }),
  wakeDevice: (deviceId: string) => invoke<void>("wake_device", { deviceId }),

  listWatchedFolders: () => invoke<WatchedFolderView[]>("list_watched_folders"),
  addWatchedFolder: (folder: string, deviceId: string, sendExisting: boolean) =>
    invoke<void>("add_watched_folder", { folder, deviceId, sendExisting }),
  removeWatchedFolder: (id: number) => invoke<void>("remove_watched_folder", { id }),
  setWatchedFolderEnabled: (id: number, enabled: boolean) =>
    invoke<void>("set_watched_folder_enabled", { id, enabled }),
  syncFolderNow: () => invoke<void>("sync_folder_now"),
  forgetManualDevice: (deviceId: string) =>
    invoke<void>("forget_manual_device", { deviceId }),
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

  /** Start sharing if needed, and mint a code — for `address`, if given. */
  startWeb: (address?: string) => invoke<WebStatusView>("start_web", { address: address ?? null }),
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
  /** Something worth a toast that no button caused, e.g. a resume starting. */
  notice: (fn: (text: string) => void): Promise<UnlistenFn> =>
    listen<string>("notice", (e) => fn(e.payload)),
  /** A transfer finished, so the history list is out of date. */
  historyChanged: (fn: () => void): Promise<UnlistenFn> =>
    listen("history-changed", () => fn()),
  /** Text sent from a browser. */
  webText: (fn: (text: WebText) => void): Promise<UnlistenFn> =>
    listen<WebText>("web-text", (e) => fn(e.payload)),
  /** A watched folder was looked at, or finished sending. */
  foldersChanged: (fn: () => void): Promise<UnlistenFn> =>
    listen("folders-changed", () => fn()),
};

/** States in which a transfer is still going. Everything else has stopped. */
export const RUNNING_STATES: TransferState[] = ["connecting", "waiting", "active"];

export function isRunning(transfer: TransferView): boolean {
  return RUNNING_STATES.includes(transfer.state);
}

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

/**
 * A percentage that never claims more than is true.
 *
 * Rounded down, so a transfer never reads 100% while it is still going. On a
 * large transfer one decimal place is shown: at 100 GB a whole percent is a
 * gigabyte, and a figure that does not move for a minute looks stuck.
 */
export function formatPercent(done: number, total: number): string {
  if (total <= 0) return "0%";
  const percent = Math.min(100, (done / total) * 100);
  if (done >= total) return "100%";
  if (total >= 1024 ** 3) return `${(Math.floor(percent * 10) / 10).toFixed(1)}%`;
  return `${Math.floor(percent)}%`;
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

/** A length of time as a person says it: "45s", "3m 20s", "1h 12m". */
export function formatDuration(seconds: number): string {
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}

export function formatWhen(unixSeconds: number): string {
  if (!unixSeconds) return "never";
  const ago = Date.now() / 1000 - unixSeconds;

  if (ago < 60) return "just now";
  if (ago < 3600) return `${Math.round(ago / 60)} min ago`;
  if (ago < 86400) return `${Math.round(ago / 3600)} hr ago`;
  if (ago < 2592000) {
    const days = Math.round(ago / 86400);
    return days === 1 ? "yesterday" : `${days} days ago`;
  }
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
