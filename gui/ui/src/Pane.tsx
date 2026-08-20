// The frame a section sits in.
//
// A header carrying the section's name and its one or two primary verbs, a
// body that scrolls, and a footer that says what just happened. Each
// section draws its own, because the verbs in the header belong to the
// section and not to the window.

import type {ReactNode} from 'react';

export function Pane({
  title,
  actions,
  status,
  children,
}: {
  title: string;
  actions?: ReactNode;
  status: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="pane">
      {/* The window has no title bar, so this is what you drag it by. */}
      <header className="pane-head" data-tauri-drag-region>
        <h1 className="pane-title">{title}</h1>
        {actions ? <div className="pane-actions">{actions}</div> : null}
      </header>
      <div className="pane-body">{children}</div>
      <footer className="pane-foot">{status}</footer>
    </div>
  );
}
