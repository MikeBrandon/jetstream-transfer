/**
 * The one-click firewall fix.
 *
 * This card is the difference between "it doesn't work" and a working app for
 * anyone who would not otherwise go looking through Windows Security settings.
 *
 * Two rules govern the wording:
 *
 * 1. **Say what will happen before it happens.** The button triggers a UAC
 *    prompt, and a user who is not expecting one is right to be suspicious of
 *    it. So the card says a permission prompt is coming, and why.
 * 2. **Never claim success we have not observed.** After the prompt, the Rust
 *    side re-reads the actual firewall rule rather than trusting an exit code.
 *    If the user clicked No, this says so plainly.
 */

import { useState } from "react";
import { api, type FirewallView } from "../api";

interface Props {
  firewall: FirewallView;
  onChanged: (next: FirewallView) => void;
}

export function FirewallCard({ firewall, onChanged }: Props) {
  const [working, setWorking] = useState(false);
  const [declined, setDeclined] = useState(false);

  const allow = async () => {
    setWorking(true);
    setDeclined(false);
    try {
      const next = await api.allowThroughFirewall();
      onChanged(next);
      // The command reports the *observed* state, so a still-blocked result
      // here means the prompt was declined or the change did not take.
      if (!next.allowed) setDeclined(true);
    } catch {
      setDeclined(true);
    } finally {
      setWorking(false);
    }
  };

  if (firewall.allowed) {
    return (
      <div className="finding ok">
        <div>{firewall.summary}</div>
      </div>
    );
  }

  return (
    <div className="firewall-card">
      <div className="firewall-head">
        <span className="firewall-badge" aria-hidden="true" />
        <div>
          <div className="firewall-title">{firewall.summary}</div>
          <div className="firewall-body">
            {firewall.remedy}
            {firewall.canFix && (
              <>
                {" "}
                Jetstream will ask Windows to allow it to receive on UDP only —
                the narrowest permission that lets transfers arrive.
              </>
            )}
          </div>
          {firewall.state === "moved" && (
            <div className="firewall-body" style={{ marginTop: 6 }}>
              This is normal after updating or moving a portable copy, and it is
              not something you did wrong.
            </div>
          )}
        </div>
      </div>

      {firewall.canFix && (
        <div className="actions" style={{ marginTop: 14 }}>
          <button className="btn primary" onClick={() => void allow()} disabled={working}>
            {working ? "Waiting for Windows…" : "Allow through firewall"}
          </button>
          {declined && (
            <span
              style={{
                alignSelf: "center",
                fontSize: 12.5,
                color: "var(--brand-amber)",
              }}
            >
              Still blocked — the permission prompt was not accepted.
            </span>
          )}
        </div>
      )}
    </div>
  );
}
