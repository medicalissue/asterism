import {useCallback, useEffect, useRef} from 'react';

/**
 * The shell every dialog in this window sits in: a scrim, a focus trap, an
 * Escape that backs out, and the focus put back where it came from.
 *
 * Written here rather than taken from a component library because the two
 * system dialog mechanisms this app can reach are both unusable — see
 * `src/applescript.rs` — and because the rules below are the ones the
 * destructive actions need, stated once. `ConfirmDialog` and `FormDialog`
 * are what a caller uses; neither restates any of this.
 */
export function Modal({
  className,
  labelledBy,
  describedBy,
  /** The present-tense verb while work is running, or ''. */
  pending = '',
  onCancel,
  children,
  /** What to focus when the dialog appears. */
  initialFocus,
}: {
  className: string;
  labelledBy: string;
  describedBy?: string;
  pending?: string;
  onCancel: () => void;
  children: React.ReactNode;
  initialFocus: React.RefObject<HTMLElement | null>;
}) {
  const dialog = useRef<HTMLDivElement>(null);
  const busy = pending !== '';

  // The trigger gets the focus back when this closes, wherever it was. Kept
  // in a ref rather than looked up on unmount, by which time the button may
  // have been removed along with the row it belonged to.
  const opener = useRef<HTMLElement | null>(
    typeof document === 'undefined' ? null : (document.activeElement as HTMLElement | null),
  );

  useEffect(() => {
    initialFocus.current?.focus();
    return () => opener.current?.focus?.();
  }, [initialFocus]);

  const onKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLDivElement>) => {
      // Escape backs out — but not out from under work that is already
      // running, which would leave the user with no report of it.
      if (event.key === 'Escape' && !busy) {
        event.stopPropagation();
        onCancel();
        return;
      }
      if (event.key !== 'Tab') return;
      const stops = focusable(dialog.current);
      if (stops.length === 0) return;
      const first = stops[0];
      const last = stops[stops.length - 1];
      const here = document.activeElement;
      // Wrap by hand: a modal the keyboard can walk out of is a modal in
      // appearance only.
      if (event.shiftKey && (here === first || here === dialog.current)) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && here === last) {
        event.preventDefault();
        first.focus();
      }
    },
    [busy, onCancel],
  );

  return (
    <div
      className="dialog-scrim"
      role="presentation"
      // Clicking away is a cancel, and only while nothing is running.
      onMouseDown={event => {
        if (event.currentTarget === event.target && !busy) onCancel();
      }}
    >
      <div
        className={className}
        role="dialog"
        aria-modal="true"
        aria-labelledby={labelledBy}
        aria-describedby={describedBy}
        aria-busy={busy || undefined}
        ref={dialog}
        tabIndex={-1}
        onKeyDown={onKeyDown}
      >
        {children}
      </div>
    </div>
  );
}

/** Everything inside the dialog the keyboard may land on, in tab order. */
function focusable(root: HTMLElement | null): HTMLElement[] {
  if (root === null) return [];
  const stops = root.querySelectorAll<HTMLElement>(
    'a[href], button, input, select, textarea, [tabindex]:not([tabindex="-1"])',
  );
  return Array.from(stops).filter(stop => !stop.hasAttribute('disabled') && stop.tabIndex !== -1);
}
