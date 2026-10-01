// Shared pieces the pages are built from.
//
// Deliberately small and unstyled-by-props: the look lives in theme.css, so
// changing it is one file rather than a search through components.

import { useCallback, useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";

/** formatBytes renders a byte count the way an operator reads one. */
export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined) return "—";
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  let value = Math.abs(bytes);
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  const sign = bytes < 0 ? "-" : "";
  const decimals = value < 10 && unit > 0 ? 2 : value < 100 && unit > 0 ? 1 : 0;
  return `${sign}${value.toFixed(decimals)} ${units[unit]}`;
}

/** formatDate renders a timestamp in the viewer's own time zone. */
export function formatDate(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/** formatRelative says how long ago something was, which is what a node list wants. */
export function formatRelative(value: string | null | undefined): string {
  if (!value) return "never";
  const then = new Date(value).getTime();
  if (Number.isNaN(then)) return "never";
  const seconds = Math.round((Date.now() - then) / 1000);
  if (seconds < 0) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return "—";
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

/** Spinner is the one loading indicator. */
export function Spinner(): ReactNode {
  return <span className="spinner" aria-label="Loading" />;
}

export function Card({
  title,
  actions,
  children,
  className,
}: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}): ReactNode {
  return (
    <section className={className ? `card ${className}` : "card"}>
      {(title || actions) && (
        <div className="card-head">
          {title && <h2>{title}</h2>}
          {actions && <div className="actions">{actions}</div>}
        </div>
      )}
      {children}
    </section>
  );
}

export function Stat({
  label,
  value,
  hint,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
}): ReactNode {
  return (
    <div className="card stat">
      <div className="label">{label}</div>
      <div className="value">{value}</div>
      {hint && <div className="hint">{hint}</div>}
    </div>
  );
}

export function Pill({
  kind,
  children,
  dot,
}: {
  kind?: "ok" | "warn" | "bad" | "accent";
  children: ReactNode;
  dot?: boolean;
}): ReactNode {
  return (
    <span className={kind ? `pill ${kind}` : "pill"}>
      {dot && <span className="dot" />}
      {children}
    </span>
  );
}

export function Field({
  label,
  help,
  error,
  children,
}: {
  label?: ReactNode;
  help?: ReactNode;
  error?: ReactNode;
  children: ReactNode;
}): ReactNode {
  return (
    <div className="field">
      {label && <label>{label}</label>}
      {children}
      {help && <div className="help">{help}</div>}
      {error && <div className="error">{error}</div>}
    </div>
  );
}

export function Banner({
  kind,
  children,
}: {
  kind?: "error" | "warn" | "ok";
  children: ReactNode;
}): ReactNode {
  return <div className={kind ? `banner ${kind}` : "banner"}>{children}</div>;
}

export function Modal({
  title,
  onClose,
  footer,
  children,
  wide,
}: {
  title: ReactNode;
  onClose: () => void;
  footer?: ReactNode;
  children: ReactNode;
  wide?: boolean;
}): ReactNode {
  // Escape closes, because a dialog that traps you is worse than one that
  // closes by accident.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div
      className="modal-scrim"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div className={wide ? "modal wide" : "modal"} role="dialog" aria-modal="true">
        <header>
          <h2>{title}</h2>
          <button className="ghost" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </header>
        <div className="body">{children}</div>
        {footer && <footer>{footer}</footer>}
      </div>
    </div>
  );
}

/** CopyLine shows a value with a button that copies it. */
export function CopyLine({ value, label }: { value: string; label?: string }): ReactNode {
  const [copied, setCopied] = useState(false);

  const copy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(value);
    } catch {
      // Clipboard access needs a secure context, which a panel on plain http
      // is not. Selecting the text is the fallback that always works.
      const node = document.createElement("textarea");
      node.value = value;
      document.body.appendChild(node);
      node.select();
      try {
        document.execCommand("copy");
      } catch {
        // Nothing left to try; the value is on screen to select by hand.
      }
      node.remove();
    }
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1400);
  }, [value]);

  return (
    <div className="copyline">
      <div className="value mono">{value}</div>
      <button onClick={copy} className="small">
        {copied ? "Copied" : (label ?? "Copy")}
      </button>
    </div>
  );
}

/** Confirm asks before something irreversible. */
export function Confirm({
  title,
  message,
  confirmLabel,
  onConfirm,
  onCancel,
  danger,
}: {
  title: string;
  message: ReactNode;
  confirmLabel?: string;
  onConfirm: () => void;
  onCancel: () => void;
  danger?: boolean;
}): ReactNode {
  return (
    <Modal
      title={title}
      onClose={onCancel}
      footer={
        <>
          <button onClick={onCancel}>Cancel</button>
          <button className={danger ? "danger" : "primary"} onClick={onConfirm}>
            {confirmLabel ?? "Confirm"}
          </button>
        </>
      }
    >
      <div>{message}</div>
    </Modal>
  );
}

/**
 * LineChart draws one series.
 *
 * Written rather than imported: the panel needs four small charts and a chart
 * library would be the largest thing in the bundle. Gaps in the data are left
 * as gaps, because a node that stopped reporting did not report zero.
 */
export function LineChart({
  points,
  height = 160,
  format = (value: number) => String(Math.round(value)),
  max,
}: {
  points: { at: string; value: number | null }[];
  height?: number;
  format?: (value: number) => string;
  max?: number;
}): ReactNode {
  const width = 600;
  const padLeft = 44;
  const padRight = 8;
  const padTop = 10;
  const padBottom = 20;

  const values = points.map((point) => point.value).filter((value): value is number => value !== null);
  if (values.length === 0) {
    return <div className="empty">No data for this window yet.</div>;
  }

  const highest = max ?? Math.max(...values, 0);
  const ceiling = highest <= 0 ? 1 : highest * 1.1;
  const plotWidth = width - padLeft - padRight;
  const plotHeight = height - padTop - padBottom;

  const x = (index: number) =>
    padLeft + (points.length === 1 ? plotWidth / 2 : (index / (points.length - 1)) * plotWidth);
  const y = (value: number) => padTop + plotHeight - (value / ceiling) * plotHeight;

  // Each run of consecutive readings is its own path, so a gap stays a gap.
  const segments: string[] = [];
  let current: string[] = [];
  points.forEach((point, index) => {
    if (point.value === null) {
      if (current.length > 1) segments.push(current.join(" "));
      current = [];
      return;
    }
    current.push(`${current.length === 0 ? "M" : "L"}${x(index).toFixed(1)},${y(point.value).toFixed(1)}`);
  });
  if (current.length > 1) segments.push(current.join(" "));

  const ticks = [0, ceiling / 2, ceiling];
  const firstLabel = points[0]?.at;
  const lastLabel = points[points.length - 1]?.at;

  return (
    <svg className="chart" viewBox={`0 0 ${width} ${height}`} style={{ height }} role="img">
      {ticks.map((tick) => (
        <g key={tick}>
          <line className="grid-line" x1={padLeft} x2={width - padRight} y1={y(tick)} y2={y(tick)} />
          <text className="axis-label" x={0} y={y(tick) + 3}>
            {format(tick)}
          </text>
        </g>
      ))}
      {segments.map((segment, index) => (
        <path key={index} className="series" d={segment} />
      ))}
      {firstLabel && (
        <text className="axis-label" x={padLeft} y={height - 4}>
          {new Date(firstLabel).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })}
        </text>
      )}
      {lastLabel && (
        <text className="axis-label" x={width - padRight} y={height - 4} textAnchor="end">
          {new Date(lastLabel).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })}
        </text>
      )}
    </svg>
  );
}

/** BarChart draws daily totals, which is what traffic history is. */
export function BarChart({
  points,
  height = 160,
}: {
  points: { label: string; value: number }[];
  height?: number;
}): ReactNode {
  const width = 600;
  const padLeft = 52;
  const padRight = 8;
  const padTop = 10;
  const padBottom = 20;

  if (points.length === 0) {
    return <div className="empty">No traffic recorded yet.</div>;
  }
  const highest = Math.max(...points.map((point) => point.value), 0);
  const ceiling = highest <= 0 ? 1 : highest * 1.1;
  const plotWidth = width - padLeft - padRight;
  const plotHeight = height - padTop - padBottom;
  const slot = plotWidth / points.length;
  const barWidth = Math.max(1, slot * 0.62);

  return (
    <svg className="chart" viewBox={`0 0 ${width} ${height}`} style={{ height }} role="img">
      {[0, ceiling / 2, ceiling].map((tick) => {
        const ty = padTop + plotHeight - (tick / ceiling) * plotHeight;
        return (
          <g key={tick}>
            <line className="grid-line" x1={padLeft} x2={width - padRight} y1={ty} y2={ty} />
            <text className="axis-label" x={0} y={ty + 3}>
              {formatBytes(tick)}
            </text>
          </g>
        );
      })}
      {points.map((point, index) => {
        const barHeight = (point.value / ceiling) * plotHeight;
        return (
          <rect
            key={point.label}
            className="area"
            x={padLeft + index * slot + (slot - barWidth) / 2}
            y={padTop + plotHeight - barHeight}
            width={barWidth}
            height={Math.max(barHeight, point.value > 0 ? 1 : 0)}
            rx={2}
          >
            <title>
              {point.label}: {formatBytes(point.value)}
            </title>
          </rect>
        );
      })}
      <text className="axis-label" x={padLeft} y={height - 4}>
        {points[0]?.label}
      </text>
      <text className="axis-label" x={width - padRight} y={height - 4} textAnchor="end">
        {points[points.length - 1]?.label}
      </text>
    </svg>
  );
}

/**
 * useAsync runs a request and tracks its state.
 *
 * It also drops the result of a request that was superseded, which is what
 * stops a slow page from overwriting a fast one when someone clicks twice.
 */
export function useAsync<T>(
  loader: () => Promise<T>,
  deps: unknown[],
): { data: T | null; error: string | null; loading: boolean; reload: () => void } {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [nonce, setNonce] = useState(0);
  const latest = useRef(0);

  useEffect(() => {
    const generation = ++latest.current;
    setLoading(true);
    loader()
      .then((result) => {
        if (generation !== latest.current) return;
        setData(result);
        setError(null);
      })
      .catch((caught: unknown) => {
        if (generation !== latest.current) return;
        setError(caught instanceof Error ? caught.message : String(caught));
      })
      .finally(() => {
        if (generation === latest.current) setLoading(false);
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce]);

  return { data, error, loading, reload: () => setNonce((value) => value + 1) };
}

/** usePoll re-runs a loader on an interval, for the pages that watch a fleet. */
export function usePoll<T>(
  loader: () => Promise<T>,
  intervalMs: number,
  deps: unknown[] = [],
): { data: T | null; error: string | null; loading: boolean; reload: () => void } {
  const state = useAsync(loader, deps);
  const reload = state.reload;

  useEffect(() => {
    // Polling stops while the tab is hidden: a panel left open in a
    // background tab should not keep a database busy.
    const tick = () => {
      if (document.visibilityState === "visible") reload();
    };
    const timer = window.setInterval(tick, intervalMs);
    return () => window.clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [intervalMs, ...deps]);

  return state;
}
