import {useEffect, useState} from 'react';
import {Button} from '@astryxdesign/core/Button';

import type {InstanceRow, Instances as Model} from './bridge';
import {backupInstance, copy, loadConsoleTail, loadSnapshots, restoreInstance} from './bridge';
import {
  CloseIcon,
  BackupIcon,
  CopyIcon,
  LayersIcon,
  LinkIcon,
  PlayIcon,
  RefreshIcon,
  StopIcon,
  TerminalIcon,
} from './Icons';

export function Instances({
  model,
  onAct,
  busy,
}: {
  model: Model | null;
  onAct: (id: string, description: string) => void;
  busy: boolean;
}) {
  const rows = model?.fleet.kind === 'rows' ? model.fleet.rows : [];
  const [selectedName, setSelectedName] = useState<string | null>(null);
  const [connecting, setConnecting] = useState(false);
  const [restoring, setRestoring] = useState(false);

  useEffect(() => {
    setSelectedName(previous => {
      if (previous && rows.some(row => row.name === previous)) return previous;
      return rows[0]?.name ?? null;
    });
  }, [rows.map(row => row.name).join('\0')]);

  const selected = rows.find(row => row.name === selectedName) ?? null;

  if (model === null) return <Loading label="Assembling the orbit registry…" />;
  if (model.fleet.kind === 'unreachable') {
    return <Failure title="The local daemon is not answering" detail={model.fleet.reason} />;
  }
  if (rows.length === 0) {
    return (
      <>
        <div className="zero-state">
          <span className="zero-glyph">✦</span>
          <strong>No instances in this orbit</strong>
          <p>Create a new instance, or restore a portable backup from another device.</p>
          <Button label="Restore backup" size="sm" variant="secondary" icon={<BackupIcon />} onClick={() => setRestoring(true)} />
        </div>
        {restoring ? <RestoreSheet onClose={() => setRestoring(false)} /> : null}
      </>
    );
  }

  return (
    <div className="split-view instances-view">
      <section className="collection-pane" aria-label="Orbit-wide instances">
        <div className="collection-head">
          <span>{rows.length} {rows.length === 1 ? 'instance' : 'instances'}</span>
          <button className="text-action" onClick={() => setRestoring(true)}>Restore backup</button>
        </div>
        <div className="instance-list">
          {rows.map(row => (
            <button
              key={row.name}
              className="instance-row"
              aria-current={row.name === selectedName ? 'true' : undefined}
              onClick={() => setSelectedName(row.name)}
            >
              <span className={`status-dot ${statusClass(row.status)}`} />
              <span className="row-main">
                <strong>{row.name}</strong>
                <small>{row.status}</small>
              </span>
              <span className="row-source">{row.compute_device}</span>
            </button>
          ))}
        </div>
      </section>

      <section className="detail-pane">
        {selected ? (
          <InstanceDetail
            row={selected}
            busy={busy}
            onAct={onAct}
            onConnect={() => setConnecting(true)}
          />
        ) : null}
      </section>

      {selected && connecting ? (
        <ConnectionSheet row={selected} onAct={onAct} onClose={() => setConnecting(false)} />
      ) : null}
      {restoring ? <RestoreSheet onClose={() => setRestoring(false)} /> : null}
    </div>
  );
}

function InstanceDetail({
  row,
  busy,
  onAct,
  onConnect,
}: {
  row: InstanceRow;
  busy: boolean;
  onAct: (id: string, description: string) => void;
  onConnect: () => void;
}) {
  const [snapshots, setSnapshots] = useState<string[] | null>(null);
  const [snapshotError, setSnapshotError] = useState('');
  const [backupStatus, setBackupStatus] = useState('');
  const [backupBusy, setBackupBusy] = useState(false);

  const readSnapshots = () => {
    setSnapshots(null);
    setSnapshotError('');
    loadSnapshots(row.name).then(setSnapshots, error => setSnapshotError(String(error)));
  };

  useEffect(readSnapshots, [row.name]);

  return (
    <div className="instance-detail">
      <div className="detail-title-row">
        <div>
          <div className="eyebrow">INSTANCE</div>
          <h1>{row.name}</h1>
          <div className="state-line">
            <span className={`status-dot ${statusClass(row.status)}`} />
            <span>{row.live ? row.status : 'last known state'}</span>
            <span className="separator-dot">·</span>
            <span>{row.compute_device}</span>
          </div>
        </div>
        <Button label="Connect" size="sm" variant="secondary" icon={<LinkIcon />} onClick={onConnect} />
      </div>

      <div className="action-strip">
        <Button
          label="Start"
          size="sm"
          variant="primary"
          icon={<PlayIcon />}
          isDisabled={!row.can_start || busy}
          onClick={() => onAct(`up:${row.name}`, `Starting ${row.name}`)}
        />
        <Button
          label="Stop"
          size="sm"
          variant="secondary"
          icon={<StopIcon />}
          isDisabled={!row.can_stop || busy}
          onClick={() => onAct(`down:${row.name}`, `Stopping ${row.name}`)}
        />
        <Button
          label="Terminal"
          size="sm"
          variant="secondary"
          icon={<TerminalIcon />}
          isDisabled={!row.can_shell || busy}
          tooltip={!row.can_shell ? 'The instance must be running before a terminal can open.' : undefined}
          onClick={() => onAct(`term:${row.name}`, `Opening a terminal on ${row.name}`)}
        />
        <span className="action-divider" />
        <Button
          label="Snapshot"
          size="sm"
          variant="ghost"
          icon={<LayersIcon />}
          isDisabled={!row.can_snapshot || busy}
          tooltip={!row.can_snapshot ? 'Stop the instance before changing its disk snapshots.' : undefined}
          onClick={() => onAct(`snap:${row.name}`, `Taking a snapshot of ${row.name}`)}
        />
        <Button
          label="Backup"
          size="sm"
          variant="ghost"
          icon={<BackupIcon />}
          isDisabled={!row.can_snapshot || busy || backupBusy}
          tooltip={!row.can_snapshot ? 'Stop the instance before exporting a consistent backup.' : undefined}
          onClick={() => {
            setBackupBusy(true);
            setBackupStatus('Exporting and verifying chunks…');
            backupInstance(row.name).then(
              report => setBackupStatus(`Saved to ${report.destination}`),
              error => setBackupStatus(String(error)),
            ).finally(() => setBackupBusy(false));
          }}
        />
      </div>
      {backupStatus ? <p className="operation-note">{backupStatus}</p> : null}

      <div className="facts-grid">
        <Fact label="Compute" value={row.compute_device} />
        <Fact label="Backend" value={row.backend || 'not recorded'} mono />
        <Fact label="Resources" value={row.shape} />
        <Fact label="Image" value={row.image} mono />
      </div>

      <DetailSection title="Storage parts" aside={`${row.volumes.length} attached`}>
        {row.volumes.length === 0 ? (
          <p className="quiet-copy">No additional volumes are attached. The instance still has its root disk.</p>
        ) : (
          <div className="data-list">
            {row.volumes.map(volume => (
              <div className="data-row" key={`${volume.source_device}:${volume.name}`}>
                <span className="volume-symbol">{volume.kind === 'block' ? '◫' : '⌑'}</span>
                <span className="data-primary"><strong>{volume.name}</strong><small>{volume.guest_path}</small></span>
                <span className="data-meta">{volume.source_device}{volume.size ? ` · ${volume.size}` : ''}</span>
              </div>
            ))}
          </div>
        )}
      </DetailSection>

      <DetailSection
        title="Disk snapshots"
        aside={<button className="text-action" onClick={readSnapshots}>Refresh</button>}
      >
        {snapshotError ? <p className="inline-error">{snapshotError}</p> : snapshots === null ? (
          <p className="quiet-copy">Reading snapshots…</p>
        ) : snapshots.length === 0 ? (
          <p className="quiet-copy">No snapshots yet. Stop the instance to take the first one.</p>
        ) : (
          <div className="data-list">
            {snapshots.map(tag => (
              <div className="data-row" key={tag}>
                <LayersIcon />
                <span className="data-primary"><strong>{tag}</strong><small>Disk checkpoint</small></span>
                <Button
                  label="Restore"
                  size="sm"
                  variant="ghost"
                  isDisabled={!row.can_snapshot || busy}
                  onClick={() => onAct(`restore:${row.name}:${tag}`, `Restoring ${row.name} to ${tag}`)}
                />
              </div>
            ))}
          </div>
        )}
      </DetailSection>
    </div>
  );
}

function RestoreSheet({onClose}: {onClose: () => void}) {
  const [source, setSource] = useState('');
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState('');
  const [bad, setBad] = useState(false);

  return (
    <div className="sheet-scrim" role="presentation" onMouseDown={event => {
      if (event.currentTarget === event.target && !busy) onClose();
    }}>
      <section className="connection-sheet" role="dialog" aria-modal="true" aria-label="Restore portable backup">
        <header className="sheet-head">
          <div><div className="eyebrow">PORTABLE BACKUP</div><h2>Restore an instance</h2></div>
          <Button label="Close" isIconOnly size="sm" variant="ghost" icon={<CloseIcon />} isDisabled={busy} onClick={onClose} />
        </header>
        <section className="sheet-section backup-form">
          <p className="quiet-copy">The manifest and every content-addressed chunk are verified before the instance becomes visible.</p>
          <label><span>Backup directory</span><input value={source} onChange={event => setSource(event.target.value)} placeholder="/Volumes/Backup/dev" autoFocus /></label>
          <label><span>Instance name <small>optional</small></span><input value={name} onChange={event => setName(event.target.value)} placeholder="Keep the exported name" /></label>
          <Button
            label={busy ? 'Restoring…' : 'Verify and restore'}
            size="sm"
            variant="primary"
            icon={<BackupIcon />}
            isDisabled={!source.trim() || busy}
            onClick={() => {
              setBusy(true);
              setBad(false);
              setResult('Verifying manifest and chunks…');
              restoreInstance(source.trim(), name.trim() || undefined).then(
                report => {
                  const rebinds = report.rebind.volumes.length + report.rebind.secrets.length;
                  setResult(`${report.instance} restored. ${rebinds ? `${rebinds} external part(s) need rebinding.` : 'No external parts need rebinding.'}`);
                },
                error => {
                  setBad(true);
                  setResult(String(error));
                },
              ).finally(() => setBusy(false));
            }}
          />
          {result ? <p className={bad ? 'inline-error' : 'operation-note'}>{result}</p> : null}
        </section>
      </section>
    </div>
  );
}

function ConnectionSheet({
  row,
  onAct,
  onClose,
}: {
  row: InstanceRow;
  onAct: (id: string, description: string) => void;
  onClose: () => void;
}) {
  const [tail, setTail] = useState<{text: string; truncated: boolean} | null>(null);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);
  const command = `ast ssh ${row.name}`;

  const read = () => {
    setTail(null);
    setError('');
    loadConsoleTail(row.name).then(setTail, reason => setError(String(reason)));
  };

  useEffect(read, [row.name]);
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
          <strong>{row.live ? row.status : 'unreachable'}</strong>
          <span>{row.live ? `local daemon → ${row.compute_device} → guest` : `last known compute on ${row.compute_device}`}</span>
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
          <Button
            label="Open Terminal"
            size="sm"
            variant="primary"
            icon={<TerminalIcon />}
            isDisabled={!row.can_shell}
            onClick={() => onAct(`term:${row.name}`, `Opening a terminal on ${row.name}`)}
          />
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

        <section className="sheet-section future-slot">
          <div className="section-heading"><span>Port connections</span><small>not exposed yet</small></div>
          <p>Asterism does not currently expose port-connection controls to this app. This area will hold real forwarded services when the daemon protocol supports them.</p>
        </section>
      </section>
    </div>
  );
}

function DetailSection({title, aside, children}: {title: string; aside?: React.ReactNode; children: React.ReactNode}) {
  return <section className="detail-section"><div className="section-heading"><span>{title}</span><span>{aside}</span></div>{children}</section>;
}

function Fact({label, value, mono = false}: {label: string; value: string; mono?: boolean}) {
  return <div className="fact"><span>{label}</span><strong className={mono ? 'mono' : undefined}>{value}</strong></div>;
}

function statusClass(status: string) {
  if (status === 'running') return 'running';
  if (status === 'unknown') return 'unknown';
  return 'stopped';
}

function Loading({label}: {label: string}) {
  return <div className="loading-state"><span className="spinner" />{label}</div>;
}

function Failure({title, detail}: {title: string; detail: string}) {
  return <div className="failure-state"><strong>{title}</strong><code>{detail}</code></div>;
}
