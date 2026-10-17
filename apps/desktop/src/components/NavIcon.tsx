/**
 * Line icons for the modern interface's side bar.
 *
 * Drawn inline rather than pulled from an icon set: eight simple shapes are
 * smaller than any dependency, and they follow the text colour, so the
 * selected, hover and theme states need nothing extra.
 */

import type { Tab } from "../App";

const PATHS: Record<Tab, string> = {
  // Four tiles.
  devices: "M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z",
  // Two opposed arrows.
  transfers: "M5 8h13m-4-4 4 4-4 4M19 16H6m4 4-4-4 4-4",
  // A clock.
  history: "M12 4a8 8 0 1 0 0 16 8 8 0 0 0 0-16zm0 4v4l3 2",
  // A folder.
  folders: "M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z",
  // A phone.
  browser: "M8 3h8a1 1 0 0 1 1 1v16a1 1 0 0 1-1 1H8a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1zm3 15h2",
  // Two linked rings.
  trusted: "M10 14a4 4 0 0 0 5.66 0l3-3a4 4 0 0 0-5.66-5.66l-1 1M14 10a4 4 0 0 0-5.66 0l-3 3a4 4 0 0 0 5.66 5.66l1-1",
  // Signal arcs.
  network: "M2 9a15 15 0 0 1 20 0M5 12.5a10 10 0 0 1 14 0M8.5 16a5 5 0 0 1 7 0M12 19.5h.01",
  // A gear, simplified.
  settings:
    "M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6zm8 3-2-.6-.6-1.5 1-1.8-1.5-1.5-1.8 1-1.5-.6L13 4h-2l-.6 2-1.5.6-1.8-1-1.5 1.5 1 1.8-.6 1.5L4 11v2l2 .6.6 1.5-1 1.8 1.5 1.5 1.8-1 1.5.6.6 2h2l.6-2 1.5-.6 1.8 1 1.5-1.5-1-1.8.6-1.5L20 13z",
};

export function NavIcon({ tab }: { tab: Tab }) {
  return (
    <svg
      className="nav-icon"
      viewBox="0 0 24 24"
      width="16"
      height="16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d={PATHS[tab]} />
    </svg>
  );
}
