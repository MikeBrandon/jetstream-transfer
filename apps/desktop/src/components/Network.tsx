/**
 * The diagnostics panel.
 *
 * Dukto's answer to "why can't I see the other machine" is a blank window. This
 * screen exists to replace that with a named cause and a next step. It is a
 * differentiator, so it is worth the space it takes.
 */

import { useEffect, useState } from "react";
import { api, type DiagnosticsView, type SelfView } from "../api";
import { FirewallCard } from "./FirewallCard";

interface Props {
  self: SelfView | null;
}

export function Network({ self }: Props) {
  const [report, setReport] = useState<DiagnosticsView | null>(null);
  const [running, setRunning] = useState(false);

  const run = async () => {
    setRunning(true);
    try {
      setReport(await api.runDiagnostics());
    } catch (error) {
      setReport({
        hasProblems: true,
        findings: [
          {
            severity: "problem",
            summary: "The check could not be run.",
            remedy: String(error),
          },
        ],
        firewall: {
          state: "unknown",
          allowed: false,
          canFix: false,
          summary: "Firewall state unknown.",
          remedy: String(error),
        },
      });
    } finally {
      setRunning(false);
    }
  };

  // Run once on open: a user who came here has a problem and should not have to
  // press a button first.
  useEffect(() => {
    void run();
  }, []);

  return (
    <>
      <h3 className="section-title" style={{ display: "flex", alignItems: "center" }}>
        Network
        <button
          className="btn ghost small"
          style={{ marginLeft: "auto" }}
          onClick={() => void run()}
          disabled={running}
        >
          {running ? "Checking…" : "Check again"}
        </button>
      </h3>

      {/* First and largest, because it is the one problem here with a fix
          attached — and the most common reason nothing works on Windows. */}
      {report && (
        <FirewallCard
          firewall={report.firewall}
          onChanged={(firewall) => {
            setReport({ ...report, firewall });
            // A change to reachability invalidates every other finding.
            void run();
          }}
        />
      )}

      {self && (
        <div className="row" style={{ display: "block" }}>
          <div style={{ fontSize: 12, color: "var(--text-dim)" }}>This device</div>
          <div className="selectable" style={{ fontFamily: "var(--mono)", fontSize: 12 }}>
            listening on port {self.port} · saving to {self.downloadDir}
          </div>
        </div>
      )}

      {running && !report && <p className="hint">Testing the network…</p>}

      {/* The firewall finding is skipped here: the card above already says it,
          with a button. Repeating it reads as two separate problems. */}
      {report?.findings
        .filter((finding) => finding.summary !== report.firewall.summary)
        .map((finding, index) => (
          <div className={`finding ${finding.severity}`} key={index}>
            <div>{finding.summary}</div>
            {finding.remedy && <div className="remedy">{finding.remedy}</div>}
          </div>
        ))}

      {report && !report.hasProblems && (
        <p className="hint" style={{ marginTop: 12 }}>
          Nothing here looks wrong. If a device is still missing, check that Jetstream
          is actually running on it.
        </p>
      )}
    </>
  );
}
