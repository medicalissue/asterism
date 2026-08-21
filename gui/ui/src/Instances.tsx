import {useCallback, useEffect, useRef, useState} from 'react';
import {Button} from '@astryxdesign/core/Button';
import {DropdownMenu} from '@astryxdesign/core/DropdownMenu';

import type {InstanceRow, Instances as Model, SnapshotRow} from './bridge';
import {copy, defaultSnapshotTag, loadConsoleTail, loadSnapshots, nameError, snapshotTagError} from './bridge';
import {ConfirmDialog} from './ConfirmDialog';
import {FormDialog} from './FormDialog';
import {CloseIcon, CopyIcon, LinkIcon, PlayIcon, RefreshIcon, StopIcon, TerminalIcon} from './Icons';

/** Do this action, with the word a destructive dialog collected. */
export type Act = (id: string, confirmation?: string) => Promise<void>;

/**
 * What the tray asked the window to open, once it is here: `restore:<tag>`,
 * `snapshot-delete:<tag>` or `remove`. A menu click carries no typed word,
 * so those items route here instead of doing the work.
 */
export type Intent = string | null;

export function Instances({
  model,
  onAct,
  pending,
  intent,
  onIntentDone,
  selected: selectedName,
  onSelect,
}: {
  model: Model | null;
  onAct: Act;
  /** Instance name → the present-tense verb Rust gave the action. */
  pending: Record<string, string>;
  intent: Intent;
  onIntentDone: () => void;
  selected: string | null;
  onSelect: (name: string | null) => void;
}) {
  const rows = model?.fleet.kind === 'rows' ? model.fleet.rows : [];
  const [connecting, setConnecting] = useState(false);
  const names = rows.map(row => row.name).join('\0');
  // Where the selection was standing, so that a row disappearing under it
  // lands somewhere sensible rather than at the top of the list.
  const wasAt = useRef(0);

  useEffect(() => {
    const here = rows.findIndex(row => row.name === selectedName);
    if (here >= 0) {
      wasAt.current = here;
      return;
    }
    if (rows.length === 0) {
      onSelect(null);
      return;
    }
    // A removal takes the next row, or the previous one when the row that
    // went was the last.
    onSelect(rows[Math.min(wasAt.current, rows.length - 1)].name);
    // `names` is the dependency that matters: re-running on every poll would
    // fight the user's own selection.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [names]);

  const selected = rows.find(row => row.name === selectedName) ?? null;

  if (model === null) return <Loading label="Assembling the orbit registry…" />;
  if (model.fleet.kind === 'unreachable') {
    return <Failure title="The local daemon is not answering" detail={model.fleet.reason} />;
  }
  if (rows.length === 0) {
    return (
      <div className="zero-state">
        <span className="zero-glyph">✦</span>
        <strong>No instances in this orbit</strong>
        <p>Create a cloud VM or boot an OCI image on hardware you already own.</p>
      </div>
    );
  }

  return (
    <div className="split-view instances-view">
      <section className="collection-pane" aria-label="Orbit-wide instances">
        <div className="collection-head">
          <span>{rows.length} {rows.length === 1 ? 'instance' : 'instances'}</span>
          <span>CPU source</span>
        </div>
        <div className="instance-list">
          {rows.map(row => (
            <button
              key={row.name}
              className="instance-row"
              aria-current={row.name === selectedName ? 'true' : undefined}
              onClick={() => onSelect(row.name)}
            >
              <span className={`status-dot ${statusClass(row.status)}`} />
              <span className="row-main">
                <strong>{row.name}</strong>
                <small>{pending[row.name] ? `${pending[row.name]}…` : statusText(row)}</small>
              </span>
              <span className="row-source">{row.cpu_device}</span>
            </button>
          ))}
        </div>
      </section>

      <section className="detail-pane">
        {selected ? (
          <InstanceDetail
            // Remounting on a change of instance is deliberate: the snapshot
            // listing, the dialogs and their in-flight state all belong to
            // one row and none of them should survive a move to another.
            key={selected.name}
            row={selected}
            onAct={onAct}
            pending={pending[selected.name] ?? ''}
            intent={intent}
            onIntentDone={onIntentDone}
            onRenamed={onSelect}
            onConnect={() => setConnecting(true)}
          />
        ) : null}
      </section>

      {selected && connecting ? (
        <ConnectionSheet row={selected} onAct={onAct} onClose={() => setConnecting(false)} />
      ) : null}
    </div>
  );
}

/** Where the keyboard should be put once a snapshot change lands. */
type Landing = {kind: 'row'; tag: string} | {kind: 'heading'} | null;

/** Which dialog is open, and what it is about. */
type Dialog =
  | {kind: 'rename'}
  | {kind: 'take'}
  | {kind: 'restore'; snapshot: SnapshotRow}
  | {kind: 'snapshot-delete'; snapshot: SnapshotRow}
  | {kind: 'remove'}
  | null;

function InstanceDetail({
  row,
  onAct,
  pending,
  intent,
  onIntentDone,
  onRenamed,
  onConnect,
}: {
  row: InstanceRow;
  onAct: Act;
  pending: string;
  intent: Intent;
  onIntentDone: () => void;
  onRenamed: (name: string) => void;
  onConnect: () => void;
}) {
  const [snapshots, setSnapshots] = useState<SnapshotRow[] | null>(null);
  const [snapshotError, setSnapshotError] = useState('');
  const [dialog, setDialog] = useState<Dialog>(null);
  const [dialogError, setDialogError] = useState('');
  const [tagSeed, setTagSeed] = useState('');
  // Where the keyboard should land once the listing comes back: on the row
  // just taken, on whatever took a deleted row's place, or — when the last
  // snapshot went — on the section's own heading, because there is no table
  // left to stand in.
  const [land, setLand] = useState<Landing>(null);
  const table = useRef<HTMLDivElement>(null);
  const snapshotSection = useRef<HTMLDivElement>(null);
  const snapshotHeading = useRef<HTMLSpanElement>(null);

  const readSnapshots = useCallback(() => {
    // Conflicted, moving and unreachable rows are not asked. The daemon
    // refuses `SnapshotList` on the first two, and the third has nobody to
    // ask; the gate reason is shown instead of a listing that would fail.
    if (!row.can_read_snapshots) {
      setSnapshots([]);
      setSnapshotError('');
      return;
    }
    setSnapshots(null);
    setSnapshotError('');
    loadSnapshots(row.name).then(
      rows => {
        setSnapshots(rows);
        setSnapshotError('');
      },
      // An error is not an empty list. One says the disk has no
      // checkpoints, the other says we could not look.
      error => {
        setSnapshots(null);
        setSnapshotError(String(error));
      },
    );
  }, [row.name, row.can_read_snapshots]);

  useEffect(readSnapshots, [readSnapshots]);

  // A route from the tray: select the snapshot it named, or open the
  // removal dialog. Restores and deletes wait for the listing, because
  // their wording quotes the snapshot's own size and date.
  useEffect(() => {
    if (intent === null) return;
    if (intent === 'remove') {
      setDialog({kind: 'remove'});
      onIntentDone();
      return;
    }
    if (intent === 'snapshots') {
      // A deep link to the table rather than to a dialog. The pane scrolls,
      // so "show me this instance's snapshots" has to say where to look.
      snapshotSection.current?.scrollIntoView({block: 'start', behavior: 'auto'});
      onIntentDone();
      return;
    }
    const [verb, tag] = split2(intent);
    if (verb !== 'restore' && verb !== 'snapshot-delete') {
      onIntentDone();
      return;
    }
    if (snapshots === null) {
      if (snapshotError === '') return;
      onIntentDone();
      return;
    }
    const snapshot = snapshots.find(candidate => candidate.tag === tag);
    if (snapshot) setDialog(verb === 'restore' ? {kind: 'restore', snapshot} : {kind: 'snapshot-delete', snapshot});
    onIntentDone();
  }, [intent, snapshots, snapshotError, onIntentDone]);

  const close = () => {
    setDialog(null);
    setDialogError('');
  };

  // Every dialog does the same thing with its answer: run the action, and
  // on a refusal stay open with the daemon's own sentence.
  const run = (id: string, confirmation?: string) => {
    setDialogError('');
    onAct(id, confirmation).then(close, error => setDialogError(String(error)));
  };

  useEffect(() => {
    if (land === null || snapshots === null) return;
    const target =
      land.kind === 'heading'
        ? snapshotHeading.current
        : table.current?.querySelector<HTMLElement>(
            `[data-snapshot="${cssEscape(land.tag)}"] button`,
          );
    target?.focus();
    setLand(null);
  }, [land, snapshots]);

  const openTake = () => {
    setDialogError('');
    setTagSeed('');
    setDialog({kind: 'take'});
    defaultSnapshotTag().then(setTagSeed, () => setTagSeed(''));
  };

  const busy = pending !== '';
  const reason = gateReason(row);

  return (
    <div className="instance-detail">
      <div className="detail-title-row">
        <div>
          <h1>{row.name}</h1>
          <div className="state-line">
            <span className={`status-dot ${statusClass(row.status)}`} />
            <span>{busy ? `${pending}…` : statusText(row)}</span>
            <span className="separator-dot">·</span>
            <span>CPU/RAM from {row.cpu_device}</span>
          </div>
        </div>
        <Button
          label="Connect"
          size="md"
          variant="secondary"
          icon={<LinkIcon />}
          isDisabled={!row.can_read_logs}
          onClick={onConnect}
        />
      </div>

      <AlertBand row={row} onRename={() => setDialog({kind: 'rename'})} busy={busy} />

      <div className="action-strip">
        {row.can_stop ? (
          <Button
            label="Stop"
            size="md"
            variant="secondary"
            icon={<StopIcon />}
            isDisabled={busy}
            onClick={() => run(`down:${row.name}`)}
          />
        ) : (
          // One lifecycle slot, never both buttons at once. The split half
          // is the policy: plain Start keeps whatever the instance was
          // recorded with, and the menu records a new one — which is the
          // only way the current wire has of changing it.
          <span className="split-control">
            <Button
              label="Start"
              size="md"
              variant="primary"
              icon={<PlayIcon />}
              isDisabled={!row.can_start || busy}
              onClick={() => run(`up:${row.name}`)}
            />
            <DropdownMenu
              button={{
                label: 'Start options',
                size: 'md',
                variant: 'primary',
                isDisabled: !row.can_start || busy,
              }}
              hasChevron
              items={[
                {
                  label: 'Start and keep running',
                  description: 'astd brings it back after an unexpected stop or a reboot.',
                  onClick: () => run(`up:${row.name}:always`),
                },
                {
                  label: 'Start once',
                  description: 'It stays down until you start it again.',
                  onClick: () => run(`up:${row.name}:never`),
                },
              ]}
            />
          </span>
        )}

        <Button
          label="Take snapshot…"
          size="md"
          variant="secondary"
          isDisabled={!row.can_snapshot || busy}
          onClick={openTake}
        />
        {/* Beside the control rather than a tooltip on it: a disabled
            element gets no hover and no focus, so a tooltip there is a
            reason nobody can read. */}
        {!row.can_snapshot && reason ? <span className="gate-reason">{reason}</span> : null}

        <span className="strip-spacer" />

        <DropdownMenu
          button={{label: 'More actions', size: 'md', variant: 'ghost', icon: <span aria-hidden="true">···</span>, isIconOnly: true}}
          alignment="end"
          items={[
            {
              label: 'Rename…',
              isDisabled: !row.can_rename || busy,
              onClick: () => setDialog({kind: 'rename'}),
            },
            {type: 'divider'},
            {
              label: 'Remove…',
              variant: 'destructive',
              isDisabled: !row.can_remove || busy,
              onClick: () => setDialog({kind: 'remove'}),
            },
          ]}
        />
      </div>

      <div className="policy-row">
        <span className="policy-label">Restart policy</span>
        <strong>{row.policy_restart}</strong>
        <p>{row.policy_sentence}</p>
      </div>

      <DetailSection title="Parts" aside={`${row.parts.length} sourced`}>
        <div className="parts-table" role="table" aria-label={`Parts of ${row.name}`}>
          <div className="parts-head" role="row">
            <span role="columnheader">Part</span>
            <span role="columnheader">Source device</span>
            <span role="columnheader">Detail</span>
            <span role="columnheader">Note</span>
          </div>
          {row.parts.map((part, index) => (
            <div className="parts-row" role="row" key={`${part.kind}-${index}`}>
              <span role="cell" className="part-kind">{part.kind}</span>
              <span role="cell">{part.source}</span>
              <span role="cell">{part.detail}</span>
              <span role="cell" className="part-note">{part.note ?? ''}</span>
            </div>
          ))}
        </div>
      </DetailSection>

      <div ref={snapshotSection}>
        <Snapshots
        row={row}
        snapshots={snapshots}
        error={snapshotError}
        reason={reason}
        busy={busy}
        tableRef={table}
        headingRef={snapshotHeading}
        onRefresh={readSnapshots}
        onTake={openTake}
        onRestore={snapshot => setDialog({kind: 'restore', snapshot})}
        onDelete={snapshot => setDialog({kind: 'snapshot-delete', snapshot})}
        />
      </div>

      <details className="detail-disclosure">
        <summary>Definition</summary>
        <dl>
          <div><dt>Backend</dt><dd className="mono">{row.backend || 'not recorded'}</dd></div>
          <div><dt>Image</dt><dd className="mono">{row.image}</dd></div>
          <div><dt>Created</dt><dd>{stamp(row.created_at)}</dd></div>
          <div><dt>Instance ID</dt><dd className="mono">{row.id}</dd></div>
        </dl>
      </details>

      {dialog?.kind === 'rename' ? (
        <FormDialog
          title={`Rename ${row.name}`}
          fieldLabel="New name"
          helper="Letters, digits and dashes."
          submitLabel="Rename"
          initialValue={row.name}
          unchangedValue={row.name}
          validate={nameError}
          pending={pending}
          error={dialogError}
          onSubmit={next => {
            setDialogError('');
            onAct(`rename:${row.name}:${next}`).then(
              () => {
                // The renamed row is the same instance, so the selection
                // follows the name rather than being dropped.
                onRenamed(next);
                close();
              },
              error => setDialogError(String(error)),
            );
          }}
          onCancel={close}
        />
      ) : null}

      {dialog?.kind === 'take' ? (
        <FormDialog
          title={`Snapshot ${row.name}`}
          body="A checkpoint of the current root disk. The instance is unchanged."
          fieldLabel="Snapshot name"
          helper="Use letters, digits, hyphens, underscores, and periods. The first character must be a letter or digit."
          submitLabel="Take snapshot"
          initialValue={tagSeed}
          validate={snapshotTagError}
          pending={pending}
          error={dialogError}
          onSubmit={tag => {
            setLand({kind: 'row', tag});
            run(`snap:${row.name}:${tag}`);
          }}
          onCancel={close}
        />
      ) : null}

      {dialog?.kind === 'restore' ? (
        <ConfirmDialog
          title={`Restore ${dialog.snapshot.tag}?`}
          body={`The current root disk will be replaced by this snapshot. Writes made after ${dialog.snapshot.date} will be discarded. The snapshot is kept.`}
          prompt={`Type ${dialog.snapshot.tag} to restore it.`}
          confirmLabel="Restore snapshot"
          expectedToken={dialog.snapshot.tag}
          typed
          pending={pending}
          error={dialogError}
          onConfirm={token => run(`restore:${row.name}:${dialog.snapshot.tag}`, token)}
          onCancel={close}
        />
      ) : null}

      {dialog?.kind === 'snapshot-delete' ? (
        <ConfirmDialog
          title={`Delete ${dialog.snapshot.tag}?`}
          body={`This deletes the ${dialog.snapshot.size} snapshot from ${dialog.snapshot.date}. The current disk is unchanged. This cannot be undone.`}
          prompt={`Type ${dialog.snapshot.tag} to delete it.`}
          confirmLabel="Delete snapshot"
          expectedToken={dialog.snapshot.tag}
          typed
          pending={pending}
          error={dialogError}
          onConfirm={token => {
            // Whatever comes to stand where this row did, so the next
            // delete is one keystroke away rather than a fresh hunt — and
            // the heading when this was the last row.
            const next = after(snapshots, dialog.snapshot.tag);
            setLand(next === '' ? {kind: 'heading'} : {kind: 'row', tag: next});
            run(`snaprm:${row.name}:${dialog.snapshot.tag}`, token);
          }}
          onCancel={close}
        />
      ) : null}

      {dialog?.kind === 'remove' ? (
        <ConfirmDialog
          title={`Remove ${row.name}?`}
          body={`This deletes the instance record, root disk, snapshots, and local instance files from ${row.cpu_device}. Asterism will try to release attached block-volume leases, but an offline provider can retain a stale lease. Attached block-volume data, shared directories, and orbit secret values are not deleted.`}
          prompt={`Type ${row.name} to remove it.`}
          confirmLabel="Remove instance"
          expectedToken={row.name}
          typed
          pending={pending}
          error={dialogError}
          onConfirm={token => run(`rm:${row.name}`, token)}
          onCancel={close}
        />
      ) : null}
    </div>
  );
}

/**
 * One band, or none.
 *
 * Three things can be true of a row and only the most specific is worth the
 * space: bytes in flight, then a name that is not unique, then a device that
 * did not answer. Stranded volume paths deliberately get no band — the parts
 * table already carries the accurate note on the row it happened to.
 */
function AlertBand({row, onRename, busy}: {row: InstanceRow; onRename: () => void; busy: boolean}) {
  if (row.moving) {
    return (
      <div className="alert-band" role="status">
        <strong>Moving CPU/RAM to {row.moving.to_device}. Read-only until the move finishes.</strong>
        {/* The epoch is a fence number, not a percentage. It is said as one. */}
        <span>Fence epoch {row.moving.epoch}, since {stamp(row.moving.started_at)}.</span>
      </div>
    );
  }
  if (row.conflict) {
    return (
      <div className="alert-band conflict" role="status">
        <strong>Another instance named {row.name} is on {row.conflict.other_cpu_device}.</strong>
        <span>
          {row.can_rename
            ? 'Renaming this one ends the conflict.'
            : 'Stop this instance, then rename it.'}
        </span>
        {row.can_rename ? (
          <Button label="Rename…" size="sm" variant="secondary" isDisabled={busy} onClick={onRename} />
        ) : null}
      </div>
    );
  }
  if (!row.live) {
    return (
      <div className="alert-band" role="status">
        <strong>This device is not answering.</strong>
        <span>Values below are last known.</span>
      </div>
    );
  }
  return null;
}

function Snapshots({
  row,
  snapshots,
  error,
  reason,
  busy,
  tableRef,
  headingRef,
  onRefresh,
  onTake,
  onRestore,
  onDelete,
}: {
  row: InstanceRow;
  snapshots: SnapshotRow[] | null;
  error: string;
  reason: string;
  busy: boolean;
  tableRef: React.RefObject<HTMLDivElement | null>;
  headingRef: React.RefObject<HTMLSpanElement | null>;
  onRefresh: () => void;
  onTake: () => void;
  onRestore: (snapshot: SnapshotRow) => void;
  onDelete: (snapshot: SnapshotRow) => void;
}) {
  const aside = row.can_read_snapshots ? (
    <button className="text-action" onClick={onRefresh}>Refresh</button>
  ) : null;

  return (
    <DetailSection title="Snapshots" aside={aside} titleRef={headingRef}>
      {!row.can_read_snapshots ? (
        <p className="quiet-copy">{reason || 'Snapshots cannot be read right now.'}</p>
      ) : error ? (
        <div className="listing-error">
          <p className="inline-error" role="alert">{error}</p>
          <Button label="Retry" size="sm" variant="secondary" onClick={onRefresh} />
        </div>
      ) : snapshots === null ? (
        <div className="parts-table" aria-busy="true" aria-label="Reading snapshots">
          <div className="snapshot-row skeleton"><span /><span /><span /></div>
          <div className="snapshot-row skeleton"><span /><span /><span /></div>
        </div>
      ) : snapshots.length === 0 ? (
        <p className="quiet-copy">
          No snapshots yet.{' '}
          {row.can_snapshot ? (
            <button className="text-action inline" onClick={onTake}>Take snapshot…</button>
          ) : (
            (reason || 'Stop the instance to take one.')
          )}
        </p>
      ) : (
        <div className="parts-table" role="table" aria-label={`Snapshots of ${row.name}`} ref={tableRef}>
          <div className="snapshot-head" role="row">
            <span role="columnheader">Tag</span>
            <span role="columnheader">Date</span>
            <span role="columnheader">Size</span>
            <span role="columnheader" className="visually-hidden">Actions</span>
          </div>
          {snapshots.map(snapshot => (
            <div className="snapshot-row" role="row" key={snapshot.id + snapshot.tag} data-snapshot={snapshot.tag}>
              <span role="cell"><strong>{snapshot.tag}</strong></span>
              <span role="cell">{snapshot.date}</span>
              <span role="cell">{snapshot.size}</span>
              <span role="cell" className="snapshot-actions">
                <Button
                  label={`Restore ${snapshot.tag}`}
                  size="md"
                  variant="secondary"
                  isDisabled={!row.can_snapshot || busy}
                  onClick={() => onRestore(snapshot)}
                >
                  Restore
                </Button>
                <DropdownMenu
                  button={{
                    label: `More actions for ${snapshot.tag}`,
                    size: 'md',
                    variant: 'ghost',
                    icon: <span aria-hidden="true">···</span>,
                    isIconOnly: true,
                  }}
                  alignment="end"
                  items={[
                    {
                      label: 'Delete snapshot…',
                      variant: 'destructive',
                      isDisabled: !row.can_snapshot || busy,
                      onClick: () => onDelete(snapshot),
                    },
                  ]}
                />
              </span>
            </div>
          ))}
          {!row.can_snapshot && reason ? <p className="gate-reason row-note">{reason}</p> : null}
        </div>
      )}
    </DetailSection>
  );
}

function ConnectionSheet({
  row,
  onAct,
  onClose,
}: {
  row: InstanceRow;
  onAct: Act;
  onClose: () => void;
}) {
  const [tail, setTail] = useState<{text: string; truncated: boolean} | null>(null);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);
  const command = `ast ssh ${row.name}`;

  const read = useCallback(() => {
    setTail(null);
    setError('');
    loadConsoleTail(row.name).then(setTail, reason => setError(String(reason)));
  }, [row.name]);

  useEffect(read, [read]);
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  return (
    <div className="sheet-scrim" role="presentation" onMouseDown={event => {
      if (event.currentTarget === event.target) onClose();
    }}>
      <section className="connection-sheet" role="dialog" aria-modal="true" aria-label={`Connect to ${row.name}`}>
        <header className="sheet-head">
          <div><div className="eyebrow">CONNECTION</div><h2>{row.name}</h2></div>
          <Button label="Close" isIconOnly size="sm" variant="ghost" icon={<CloseIcon />} onClick={onClose} />
        </header>

        <div className="connection-summary">
          <span className={`status-dot ${statusClass(row.status)}`} />
          <strong>{statusText(row)}</strong>
          <span>{row.live ? `local daemon → ${row.cpu_device} → guest` : `last known on ${row.cpu_device}`}</span>
        </div>

        <section className="sheet-section">
          <div className="section-heading"><span>Secure shell</span><small>routed by astd</small></div>
          <div className="command-row">
            <code>{command}</code>
            <Button
              label={copied ? 'Copied' : 'Copy'}
              size="sm"
              variant="ghost"
              icon={<CopyIcon />}
              onClick={() => {
                copy(command).then(() => {
                  setCopied(true);
                  window.setTimeout(() => setCopied(false), 1400);
                });
              }}
            />
          </div>
          {/* The terminal is gated on its own, not on the sheet: reading a
              console is worth doing on an instance nothing can shell into. */}
          <Button
            label="Open Terminal"
            size="md"
            variant="primary"
            icon={<TerminalIcon />}
            isDisabled={!row.can_shell}
            onClick={() => onAct(`term:${row.name}`)}
          />
          {!row.can_shell ? (
            <p className="gate-reason">{gateReason(row) || 'Start the instance to open a terminal.'}</p>
          ) : null}
        </section>

        <section className="sheet-section console-section">
          <div className="section-heading">
            <span>Guest console</span>
            <button className="icon-text-action" onClick={read}><RefreshIcon />Refresh</button>
          </div>
          <pre className="console-tail">
            {error || (tail === null ? 'Reading the last console lines…' : tail.text || 'The console has not written anything yet.')}
          </pre>
          {tail?.truncated ? <small className="console-note">Showing the last 120 lines. Use `ast logs {row.name} -n 0` for all available output.</small> : null}
        </section>
      </section>
    </div>
  );
}

function DetailSection({
  title,
  aside,
  children,
  // Focusable only when somebody has a reason to land on it — a deletion
  // that took the last row away, and nothing else.
  titleRef,
}: {
  title: string;
  aside?: React.ReactNode;
  children: React.ReactNode;
  titleRef?: React.RefObject<HTMLSpanElement | null>;
}) {
  return (
    <section className="detail-section">
      <div className="section-heading">
        <span ref={titleRef} tabIndex={titleRef ? -1 : undefined}>{title}</span>
        <span>{aside}</span>
      </div>
      {children}
    </section>
  );
}

/**
 * Why a mutating control is off, in the words the alert band already used.
 *
 * It explains a gate; it does not decide one. Every branch reads a fact Rust
 * put on the row, in the same priority the band uses, and an empty string
 * means the row is not held back by anything.
 */
function gateReason(row: InstanceRow): string {
  if (!row.live) return 'This device is not answering.';
  if (row.moving) return `Read-only until the move to ${row.moving.to_device} finishes.`;
  if (row.conflict) return `Rename this instance to end the conflict with ${row.conflict.other_cpu_device}.`;
  if (row.status === 'running') return 'Stop the instance to change snapshots.';
  return '';
}

/**
 * What a row says it is doing. An unreachable row says what it last was and
 * says that it is a memory: "running" about a machine nobody can reach is
 * the one thing a fleet view must not claim.
 */
function statusText(row: InstanceRow): string {
  if (row.live) return row.status;
  return row.last_status ? `Last known: ${row.last_status}` : 'Unknown';
}

function statusClass(status: string) {
  if (status === 'running') return 'running';
  if (status === 'unknown') return 'unknown';
  return 'stopped';
}

/** `2026-08-22 09:14` UTC, from unix seconds. */
function stamp(unixSeconds: number): string {
  if (!unixSeconds) return 'not recorded';
  return new Date(unixSeconds * 1000).toISOString().replace('T', ' ').slice(0, 16) + 'Z';
}

/** The tag that will stand where `tag` does once it is gone, or ''. */
function after(snapshots: SnapshotRow[] | null, tag: string): string {
  if (snapshots === null) return '';
  const at = snapshots.findIndex(snapshot => snapshot.tag === tag);
  if (at === -1) return '';
  const next = snapshots[at + 1] ?? snapshots[at - 1];
  return next?.tag ?? '';
}

/** One attribute-selector value. Tags are `[A-Za-z0-9._-]`, but the
    selector is built from data either way, so it is escaped. */
function cssEscape(value: string): string {
  return value.replace(/["\\]/g, '\\$&');
}

/** `restore:nightly` → `['restore', 'nightly']`. Tags cannot contain `:`. */
function split2(intent: string): [string, string] {
  const at = intent.indexOf(':');
  return at === -1 ? [intent, ''] : [intent.slice(0, at), intent.slice(at + 1)];
}

function Loading({label}: {label: string}) {
  return <div className="loading-state"><span className="spinner" />{label}</div>;
}

function Failure({title, detail}: {title: string; detail: string}) {
  return <div className="failure-state"><strong>{title}</strong><code>{detail}</code></div>;
}
