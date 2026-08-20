// The controls both windows are built out of.
//
// They were written for the New Instance dialog and moved here when the
// main window needed the same select, the same checkbox and the same
// popover. Nothing in this file decides anything: no daemon call, no
// validation, no copy. It is the skin in controls.css given behaviour.
//
// The platform's own popup menu and checkbox would arrive with the
// platform's own proportions and shading, which is the one thing these
// windows are not.

import {useEffect, useId, useRef, useState} from 'react';
import type {ReactNode} from 'react';

export interface Option {
  value: string;
  /** What the row says, when that is not the value itself. */
  label?: string;
  /** A word to the right of the row, in the quiet colour. */
  aside?: string;
}

/** A dropdown and its menu, both drawn here. */
export function Select({
  label,
  value,
  onChange,
  options,
  disabled,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: Option[];
  disabled: boolean;
}) {
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  const id = useId();
  useDismiss(open, box, () => setOpen(false));

  const current = options.find(o => o.value === value);

  return (
    <div className="select" ref={box}>
      <button
        className="field"
        disabled={disabled}
        aria-label={label}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={id}
        onClick={() => setOpen(!open)}
      >
        <span className="value">{current?.label ?? value}</span>
        <Chevron />
      </button>
      {open ? (
        <div className="popover" id={id} role="listbox" aria-label={label}>
          {options.map(o => (
            <button
              key={o.value}
              className="option"
              role="option"
              aria-selected={o.value === value}
              onClick={() => {
                onChange(o.value);
                setOpen(false);
              }}
            >
              <span className="value">{o.label ?? o.value}</span>
              {o.aside ? <span className="aside">{o.aside}</span> : null}
            </button>
          ))}
        </div>
      ) : null}
    </div>
  );
}

/**
 * A button and the flat panel it opens, for the cases a listbox is the
 * wrong shape: a menu of verbs, a list that has to say why it is empty.
 * `right` hangs the panel off the right edge, which is where a row's own
 * menu has to open from.
 */
export function Menu({
  trigger,
  label,
  right,
  children,
}: {
  trigger: (props: {onClick: () => void; 'aria-expanded': boolean}) => ReactNode;
  label: string;
  right?: boolean;
  children: (close: () => void) => ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  useDismiss(open, box, () => setOpen(false));

  return (
    <div className="select" ref={box}>
      {trigger({onClick: () => setOpen(!open), 'aria-expanded': open})}
      {open ? (
        <div className={right ? 'popover right' : 'popover'} role="menu" aria-label={label}>
          {children(() => setOpen(false))}
        </div>
      ) : null}
    </div>
  );
}

/**
 * Click anywhere else, or press Escape, and the panel goes away.
 *
 * Escape is caught in the capture phase so that it closes the panel without
 * also reaching the window behind it, which would close the dialog the user
 * was only trying to back out of a menu in.
 */
function useDismiss(open: boolean, box: React.RefObject<HTMLElement | null>, close: () => void) {
  useEffect(() => {
    if (!open) return;
    const away = (e: MouseEvent) => {
      if (!box.current?.contains(e.target as Node)) close();
    };
    const key = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        close();
      }
    };
    document.addEventListener('mousedown', away);
    document.addEventListener('keydown', key, true);
    return () => {
      document.removeEventListener('mousedown', away);
      document.removeEventListener('keydown', key, true);
    };
  }, [open, box, close]);
}

/** A number field with its unit, and no stepper. */
export function NumberField({
  label,
  value,
  set,
  min,
  max,
  unit,
  busy,
}: {
  label: string;
  value: number;
  set: (n: number) => void;
  min: number;
  max: number;
  unit?: string;
  busy: boolean;
}) {
  return (
    <div className="stack">
      <span className="caption">{label}</span>
      <div className="field number">
        <input
          type="number"
          value={value}
          min={min}
          max={max}
          disabled={busy}
          aria-label={unit ? `${label} in ${unit}` : label}
          onChange={e => {
            const n = Number(e.target.value);
            set(Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : min);
          }}
        />
        {unit ? <span className="unit">{unit}</span> : null}
      </div>
    </div>
  );
}

/** A checkbox whose label is part of the target. */
export function Check({
  checked,
  onChange,
  disabled,
  children,
}: {
  checked: boolean;
  onChange: (on: boolean) => void;
  disabled?: boolean;
  children: ReactNode;
}) {
  return (
    <button
      className="check"
      role="checkbox"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => onChange(!checked)}
    >
      <span className="box" aria-hidden="true">
        {checked ? <Tick /> : null}
      </span>
      {children}
    </button>
  );
}

/** Running, stopped, online, offline: a shape rather than a colour. */
export function Dot({state}: {state: string}) {
  return <span className="dot" data-state={state} role="img" aria-label={state} title={state} />;
}

/** 9px chevron, drawn rather than fetched. */
export function Chevron() {
  return (
    <svg className="chevron" width="9" height="9" viewBox="0 0 9 9" aria-hidden="true">
      <path
        d="M2 3.6 4.5 6 7 3.6"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

/** The mark inside a checked box. */
export function Tick() {
  return (
    <svg width="9" height="9" viewBox="0 0 9 9">
      <path
        d="M1.6 4.6 3.5 6.5 7.4 2.6"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

/** A shell prompt: what Open Terminal gets you. */
export function Prompt() {
  return (
    <svg width="13" height="13" viewBox="0 0 13 13" aria-hidden="true">
      <path
        d="M2.5 3.5 5.5 6.5 2.5 9.5M7 9.5h3.5"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.3"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

/** Two sheets, one behind the other: a disk with copies of itself. */
export function Layers() {
  return (
    <svg width="13" height="13" viewBox="0 0 13 13" aria-hidden="true">
      <path
        d="M4.5 2.5h6v6M2.5 4.5h6v6h-6z"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
