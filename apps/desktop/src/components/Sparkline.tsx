/**
 * The speed of one transfer over the last minute.
 *
 * One series, so no legend: the "Speed" caption beside it names it. A 2px line
 * with a faint area under it, scaled from zero so a dip reads as a dip rather
 * than a cliff. Hovering shows the reading under the pointer.
 */

import { useState, type MouseEvent } from "react";
import { formatRate } from "../api";

interface Props {
  /** Bytes per second, one reading a second, oldest first. */
  values: number[];
}

const WIDTH = 120;
const HEIGHT = 36;

export function Sparkline({ values }: Props) {
  const [hover, setHover] = useState<number | null>(null);

  if (values.length < 2) return <div className="sparkline empty" aria-hidden="true" />;

  const peak = Math.max(...values, 1);
  const step = WIDTH / (values.length - 1);
  const y = (value: number) => HEIGHT - 2 - (value / peak) * (HEIGHT - 6);
  const points = values.map((value, index) => `${(index * step).toFixed(2)},${y(value).toFixed(2)}`);
  const line = `M${points.join(" L")}`;
  const area = `${line} L${WIDTH},${HEIGHT} L0,${HEIGHT} Z`;

  const onMove = (event: MouseEvent<HTMLDivElement>) => {
    const box = event.currentTarget.getBoundingClientRect();
    const fraction = (event.clientX - box.left) / box.width;
    setHover(Math.max(0, Math.min(values.length - 1, Math.round(fraction * (values.length - 1)))));
  };

  const shown = hover ?? values.length - 1;
  const secondsAgo = values.length - 1 - shown;

  return (
    <div
      className="sparkline"
      onMouseMove={onMove}
      onMouseLeave={() => setHover(null)}
      role="img"
      aria-label={`Speed over the last ${values.length} seconds, peaking at ${formatRate(peak)}`}
    >
      <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} preserveAspectRatio="none" aria-hidden="true">
        <line className="base" x1="0" y1={HEIGHT - 0.5} x2={WIDTH} y2={HEIGHT - 0.5} />
        <path className="area" d={area} />
        <path className="line" d={line} />
        {hover !== null && (
          <line className="cross" x1={hover * step} y1="0" x2={hover * step} y2={HEIGHT} />
        )}
      </svg>
      {hover !== null && (
        <div
          className="sparkline-tip"
          style={{ left: `${(hover / (values.length - 1)) * 100}%` }}
        >
          {formatRate(values[shown] ?? 0) || "0 B/s"}
          <span>{secondsAgo === 0 ? "now" : `${secondsAgo}s ago`}</span>
        </div>
      )}
    </div>
  );
}
