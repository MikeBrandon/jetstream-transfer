/**
 * The one-click fix for a network Windows refuses to let you categorise.
 *
 * Connect two computers with a single cable and there is no router in between
 * for Windows to identify, so the link becomes an "Unidentified network" and is
 * filed as Public — and for that kind of network the Settings UI usually offers
 * no way to change it at all. The user is left staring at a warning with no
 * button.
 *
 * Two things this card must get right, because it changes a security setting:
 *
 * 1. **Be specific about scope.** It names the network it will change and states
 *    outright that networks reaching the internet are never touched. "Make my
 *    network private" is not a thing to do vaguely.
 * 2. **Do not overstate the problem.** Jetstream's firewall rule covers every
 *    profile, so transfers are not blocked by Public. This is a real annoyance
 *    worth fixing, not the reason nothing works — and the copy says so.
 */

import { useState } from "react";
import { api, type NetworkProfileView } from "../api";

interface Props {
  profile: NetworkProfileView;
  onChanged: (next: NetworkProfileView) => void;
}

export function NetworkProfileCard({ profile, onChanged }: Props) {
  const [working, setWorking] = useState(false);
  const [declined, setDeclined] = useState(false);

  const fix = async () => {
    setWorking(true);
    setDeclined(false);
    try {
      const next = await api.makeNetworkPrivate();
      onChanged(next);
      // The command reports what it observed afterwards, so still-needing-a-fix
      // means the prompt was declined or the change did not take.
      if (next.needsFixing) setDeclined(true);
    } catch {
      setDeclined(true);
    } finally {
      setWorking(false);
    }
  };

  if (!profile.needsFixing) return null;

  return (
    <div className="firewall-card">
      <div className="firewall-head">
        <span className="firewall-badge" aria-hidden="true" />
        <div>
          <div className="firewall-title">{profile.summary}</div>
          <div className="firewall-body">{profile.remedy}</div>
        </div>
      </div>

      <div className="actions" style={{ marginTop: 14 }}>
        <button className="btn primary" onClick={() => void fix()} disabled={working}>
          {working ? "Waiting for Windows…" : "Set to Private"}
        </button>
        {declined && (
          <span
            style={{ alignSelf: "center", fontSize: 12.5, color: "var(--on-amber)" }}
          >
            Unchanged — the permission prompt was not accepted.
          </span>
        )}
      </div>

      {profile.publicWithInternet.length > 0 && (
        <p className="hint" style={{ marginBottom: 0 }}>
          Leaving {profile.publicWithInternet.join(", ")} as Public — it reaches
          the internet, so Public is the right setting for it.
        </p>
      )}
    </div>
  );
}
