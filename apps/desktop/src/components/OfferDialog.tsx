/**
 * The accept prompt — the security decision point of the whole application.
 *
 * Design rules this follows, in priority order:
 *
 * 1. **Nothing is accepted by default.** There is no timer that accepts, and
 *    Escape declines. Dukto's silent auto-accept is the behaviour this replaces.
 * 2. **The fingerprint is the most prominent thing on screen** for a device
 *    never seen before, because comparing it against the sender's screen is the
 *    only thing standing between the user and an impersonator.
 * 3. **What is arriving is stated before the buttons**, in counts and names, so
 *    "accept" is an informed answer rather than a reflex.
 * 4. **Remembering is opt-in and separate from accepting.** Accepting once and
 *    trusting forever are different decisions and get different controls.
 */

import { useEffect, useState } from "react";
import { formatBytes, type OfferView, type TrustView } from "../api";

interface Props {
  offer: OfferView;
  onRespond: (accept: boolean, remember: TrustView | null) => void;
}

export function OfferDialog({ offer, onRespond }: Props) {
  const [remember, setRemember] = useState(false);

  // Escape declines. A dialog you cannot dismiss without answering encourages
  // clicking the affirmative button to make it go away.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onRespond(false, null);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onRespond]);

  return (
    <div className="scrim" role="dialog" aria-modal="true" aria-labelledby="offer-title">
      <div className="dialog">
        <h2 id="offer-title">
          {offer.peerName} wants to send you {offer.fileCount === 1 ? "a file" : "files"}
        </h2>
        {/* `summary` already carries the size, so do not repeat it here. */}
        <p className="lede">{offer.summary}</p>

        <div className="fingerprint" aria-label="Sender fingerprint">
          {offer.fingerprintWords.map((word, index) => (
            <span key={`${word}-${index}`}>{word}</span>
          ))}
        </div>

        {offer.firstContact ? (
          <div className="first-contact">
            You have not received from this device before. Check that these six words
            match what it is showing. If they do not, something else is answering in
            its place — decline.
          </div>
        ) : (
          <p className="hint">
            You have received from this device before, and its identity still matches.
          </p>
        )}

        <div className="manifest">
          <strong>
            {offer.fileCount} {offer.fileCount === 1 ? "file" : "files"}
          </strong>
          , {formatBytes(offer.totalBytes)}
          {offer.topLevel.length > 0 && (
            <ul>
              {offer.topLevel.map((name) => (
                <li key={name}>{name}</li>
              ))}
              {offer.moreTopLevel && <li>…and more</li>}
            </ul>
          )}
        </div>

        <label className="field" style={{ marginTop: 16, marginBottom: 0 }}>
          <input
            type="checkbox"
            checked={remember}
            onChange={(event) => setRemember(event.target.checked)}
            style={{ width: "auto", marginRight: 8 }}
          />
          Always accept from {offer.peerName} without asking
        </label>

        <div className="actions">
          <button
            className="btn danger"
            onClick={() => onRespond(false, remember ? "blocked" : null)}
          >
            {remember ? "Decline and block" : "Decline"}
          </button>
          <div className="spacer" />
          <button
            className="btn primary"
            autoFocus
            onClick={() => onRespond(true, remember ? "autoAccept" : "ask")}
          >
            Accept
          </button>
        </div>
      </div>
    </div>
  );
}
