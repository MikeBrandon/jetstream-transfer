/**
 * The browser-receiver panel: a QR code a phone can scan.
 *
 * This is how devices without Jetstream take part, so the screen has one job —
 * get a code in front of a camera in as few steps as possible, pointing
 * somewhere the phone can actually reach.
 *
 * It is also the one place in the app that exposes an unencrypted server, so it
 * states that plainly rather than burying it. Off until switched on, and it
 * stops when switched off; nothing here runs in the background.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { api, type FirewallView, type WebStatusView, type WebText } from "../api";

interface Props {
  /** Text sent from browsers this session, newest first. */
  texts: (WebText & { at: number })[];
  onClearTexts: () => void;
  onCopied: () => void;
}

function formatCountdown(seconds: number): string {
  const minutes = Math.floor(seconds / 60);
  return `${minutes}:${String(seconds % 60).padStart(2, "0")}`;
}

export function Browser({ texts, onClearTexts, onCopied }: Props) {
  const [status, setStatus] = useState<WebStatusView | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [shared, setShared] = useState<{ path: string; name: string }[]>([]);
  const [text, setText] = useState("");
  const [firewall, setFirewall] = useState<FirewallView | null>(null);
  const [fixing, setFixing] = useState(false);

  /** The network the code points at, once the user has picked one. */
  const [chosen, setChosen] = useState<string | undefined>(undefined);
  /** When the code on screen stops working, in ms since the epoch. */
  const [expiresAt, setExpiresAt] = useState<number | null>(null);
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    void api.webStatus().then(setStatus);
    void api.firewallStatus().then(setFirewall);
  }, []);

  const running = status?.running ?? false;

  const mint = useCallback(async (address?: string) => {
    setBusy(true);
    setError(null);
    try {
      const next = await api.startWeb(address);
      setStatus(next);
      setExpiresAt(next.qrSvg ? Date.now() + next.expiresIn * 1000 : null);
    } catch (e) {
      setError(String(e));
      // Stop the countdown, or running out would retry a failing call forever.
      setExpiresAt(null);
    } finally {
      setBusy(false);
    }
  }, []);

  // While running, poll for connected guests so the panel shows when a phone has
  // actually arrived — otherwise the user cannot tell whether the code worked.
  const guests = useRef(0);
  useEffect(() => {
    if (!running) return;

    const timer = window.setInterval(() => {
      void api.webStatus().then((next) => {
        // A new guest means the code on screen was just spent. Put up a fresh
        // one, so the next device can scan without anyone pressing anything.
        const arrived = next.guests > guests.current;
        guests.current = next.guests;

        setStatus((current) =>
          // Keep the QR already on screen: the status poll does not carry one.
          current ? { ...next, url: current.url, qrSvg: current.qrSvg, address: current.address } : next,
        );
        if (arrived) void mint(chosen);
      });
    }, 2000);

    return () => window.clearInterval(timer);
  }, [running, chosen, mint]);

  // The countdown, and a fresh code when it runs out. A code left on screen used
  // to expire silently, so a phone scanning it later got "link expired" with
  // nothing on the computer to say why.
  useEffect(() => {
    if (expiresAt === null) return;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [expiresAt]);

  const secondsLeft = expiresAt === null ? null : Math.max(0, Math.ceil((expiresAt - now) / 1000));
  useEffect(() => {
    if (secondsLeft === 0 && !busy) void mint(chosen);
  }, [secondsLeft, busy, chosen, mint]);

  const stop = useCallback(async () => {
    setBusy(true);
    try {
      setStatus(await api.stopWeb());
      setShared([]);
      setText("");
      setExpiresAt(null);
      guests.current = 0;
    } finally {
      setBusy(false);
    }
  }, []);

  const allowPhones = useCallback(async () => {
    setFixing(true);
    try {
      setFirewall(await api.allowThroughFirewall());
    } catch (e) {
      setError(String(e));
    } finally {
      setFixing(false);
    }
  }, []);

  const chooseShared = useCallback(async () => {
    const picked = await open({ multiple: true, directory: false });
    if (!Array.isArray(picked)) return;

    const files = picked.map((path) => ({
      path,
      name: path.split(/[\\/]/).pop() ?? path,
    }));
    setShared(files);
    await api.setWebShared(files.map((f) => f.path), text || null);
  }, [text]);

  const publish = useCallback(
    async (paths: string[], value: string | null) => {
      await api.setWebShared(paths, value);
    },
    [],
  );

  const copy = useCallback(
    (value: string) => {
      void navigator.clipboard.writeText(value).then(onCopied);
    },
    [onCopied],
  );

  if (!status) return <p className="hint">Loading…</p>;

  // Windows drops a phone's connection silently without this rule, so the page
  // never loads and scanning appears to do nothing. Said up front, with the fix.
  const phonesBlocked =
    firewall !== null && ["absent", "moved", "disabled"].includes(firewall.browserState);
  const firewallCard = phonesBlocked && (
    <div className="finding problem" style={{ marginBottom: 16 }}>
      <div>Windows Firewall will stop phones from opening the page.</div>
      <div className="remedy">
        {firewall?.browserState === "disabled"
          ? "Jetstream's phone sharing rule has been switched off. Re-enable \"Jetstream (phone sharing)\" in Windows Security > Firewall & network protection > Allow an app through firewall."
          : "Phone sharing is a small web server, which needs its own permission. Jetstream can add it — Windows will ask, because firewall changes always need an administrator. It only admits devices on your local network."}
      </div>
      {firewall?.browserState !== "disabled" && (
        <div className="actions" style={{ marginTop: 10 }}>
          <button className="btn primary small" onClick={() => void allowPhones()} disabled={fixing}>
            {fixing ? "Waiting for Windows…" : "Allow phones through"}
          </button>
        </div>
      )}
    </div>
  );

  const receivedTexts = texts.length > 0 && (
    <>
      <h3 className="section-title" style={{ marginTop: 26, display: "flex", alignItems: "center" }}>
        Received text
        <button className="btn ghost small" style={{ marginLeft: "auto" }} onClick={onClearTexts}>
          Clear
        </button>
      </h3>
      {texts.map((item) => (
        <div className="row" key={item.at} style={{ alignItems: "flex-start" }}>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: 12, color: "var(--text-dim)", marginBottom: 4 }}>
              from {item.from}
            </div>
            <div className="selectable" style={{ whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
              {item.text}
            </div>
          </div>
          <button className="btn small" onClick={() => copy(item.text)}>
            Copy
          </button>
        </div>
      ))}
    </>
  );

  if (!running) {
    return (
      <>
        <h3 className="section-title">Send from a phone or another computer</h3>
        {firewallCard}
        <div className="row" style={{ display: "block" }}>
          <p style={{ marginTop: 0 }}>
            Devices without Jetstream installed — a phone, a Mac, a work laptop —
            can send and receive through their browser. No app, no account.
          </p>
          <p className="hint">
            This starts a small web server on your local network. It is not
            encrypted, it only runs while you leave it switched on, and each code
            works once.
          </p>
          <div className="actions">
            <button className="btn primary" onClick={() => void mint(chosen)} disabled={busy}>
              {busy ? "Starting…" : "Start browser sharing"}
            </button>
          </div>
          {error && (
            <p style={{ color: "var(--brand-pink)", fontSize: 13 }}>{error}</p>
          )}
        </div>
        {receivedTexts}
      </>
    );
  }

  return (
    <>
      <h3 className="section-title">Scan to connect</h3>
      {firewallCard}

      <div className="qr-row">
        {status.qrSvg ? (
          <div
            className="qr"
            /* Generated by our own Rust side from a URL we built, never from
               user input, so inserting it as markup is safe here. */
            dangerouslySetInnerHTML={{ __html: status.qrSvg }}
          />
        ) : (
          <div className="qr placeholder">
            <button className="btn small" onClick={() => void mint(chosen)}>
              Show a code
            </button>
          </div>
        )}

        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontFamily: "var(--display)", fontSize: 14, letterSpacing: "0.02em" }}>
            Point the other device's camera at this
          </div>
          <p className="hint" style={{ marginTop: 6 }}>
            Anything that can open a web page will work, as long as it is on the
            same network as this computer. Each code works once; a new one appears
            by itself after a device connects or the code runs out.
          </p>

          {status.url && <div className="qr-url selectable">{status.url}</div>}

          {/* The phone has to be on the network the code points at. On a
              machine with Ethernet, Wi-Fi and a VPN, the default guess is
              sometimes the wrong one — this is how to pick another. */}
          {status.addresses.length > 1 && (
            <label className="field" style={{ marginTop: 10, marginBottom: 0 }}>
              <span className="label">Network the phone is on</span>
              <select
                value={chosen ?? status.address.split(":")[0]}
                onChange={(event) => {
                  setChosen(event.target.value);
                  void mint(event.target.value);
                }}
              >
                {status.addresses.map((address) => (
                  <option key={address.ip} value={address.ip}>
                    {address.interface ? `${address.interface} — ${address.ip}` : address.ip}
                  </option>
                ))}
              </select>
            </label>
          )}

          <div style={{ marginTop: 12, fontSize: 13, color: "var(--text-dim)" }}>
            {status.guests > 0
              ? `${status.guests} device${status.guests === 1 ? "" : "s"} connected`
              : "Waiting for a device to scan…"}
            {status.qrSvg && secondsLeft !== null && secondsLeft > 0 && (
              <span style={{ color: "var(--text-faint)" }}>
                {" "}· code expires in {formatCountdown(secondsLeft)}
              </span>
            )}
          </div>

          <div className="actions" style={{ marginTop: 14 }}>
            <button className="btn small" onClick={() => void mint(chosen)} disabled={busy}>
              New code
            </button>
            <button className="btn ghost small" onClick={() => void stop()} disabled={busy}>
              Stop sharing
            </button>
          </div>
          {error && (
            <p style={{ color: "var(--brand-pink)", fontSize: 13 }}>{error}</p>
          )}
        </div>
      </div>

      {receivedTexts}

      <h3 className="section-title" style={{ marginTop: 26 }}>
        Offer files for them to download
      </h3>
      <div className="row" style={{ display: "block" }}>
        {shared.length === 0 ? (
          <p className="hint" style={{ marginTop: 0 }}>
            Nothing offered yet. Anything added here appears on the other device,
            ready to save. Individual files only — a browser downloads one file
            per link, so offer a zip if you want to hand over a whole folder.
          </p>
        ) : (
          <div style={{ marginBottom: 12 }}>
            {shared.map((file) => (
              <div key={file.path} style={{ fontSize: 13, padding: "3px 0" }}>
                {file.name}
              </div>
            ))}
          </div>
        )}
        <div className="actions">
          <button className="btn small" onClick={() => void chooseShared()}>
            Choose files…
          </button>
          {shared.length > 0 && (
            <button
              className="btn ghost small"
              onClick={() => {
                setShared([]);
                void publish([], text || null);
              }}
            >
              Clear
            </button>
          )}
        </div>
      </div>

      <h3 className="section-title" style={{ marginTop: 26 }}>
        Share text
      </h3>
      <div className="row" style={{ display: "block" }}>
        <textarea
          value={text}
          onChange={(event) => setText(event.target.value)}
          placeholder="Anything typed here appears on the other device."
          style={{
            width: "100%",
            minHeight: 84,
            font: "inherit",
            padding: 11,
            background: "var(--bg-sunken)",
            color: "var(--text)",
            border: "1px solid var(--line-strong)",
            borderRadius: 8,
            resize: "vertical",
            userSelect: "text",
          }}
        />
        <div className="actions">
          <button
            className="btn small"
            onClick={() => void publish(shared.map((f) => f.path), text || null)}
          >
            Share text
          </button>
        </div>
      </div>
    </>
  );
}
