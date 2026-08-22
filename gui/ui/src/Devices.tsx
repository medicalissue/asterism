import {useEffect, useState} from 'react';
import {Button} from '@astryxdesign/core/Button';

import type {DeviceRow, DeviceShell, Devices as Model, Pairing} from './bridge';
import {copy, onPairing, onWake, pairCancel, pairConfirm, pairStart, setDeviceShell, wake} from './bridge';
import {canSetDeviceShell, changedAtIso, shellStateLabel} from './deviceShellView';
import {CloseIcon, CopyIcon, DevicesIcon, PlusIcon} from './Icons';

export function Devices({
  model,
  onSay,
  refresh,
}: {
  model: Model | null;
  onSay: (line: string, bad?: boolean) => void;
  refresh: () => void;
}) {
  const rows = model?.fleet.kind === 'rows' ? model.fleet.rows : [];
  const [selectedName, setSelectedName] = useState<string | null>(null);
  const [pairMode, setPairMode] = useState<'invite' | 'add' | null>(null);
  const [pairing, setPairing] = useState<Pairing | null>(null);
  const [ticket, setTicket] = useState('');
  const [waking, setWaking] = useState('');

  useEffect(() => {
    setSelectedName(previous => {
      if (previous && rows.some(row => row.name === previous)) return previous;
      return rows.find(row => row.is_self)?.name ?? rows[0]?.name ?? null;
    });
  }, [rows.map(row => row.name).join('\0')]);

  useEffect(() => {
    const stop = onPairing(state => {
      setPairing(state);
      if (state.state === 'paired') {
        onSay(`${state.name} joined this orbit.`);
        refresh();
      }
      if (state.state === 'failed') onSay(state.reason, true);
    });
    return () => { stop.then(off => off()); };
  }, [onSay, refresh]);

  useEffect(() => {
    const stop = onWake(line => onSay(line));
    return () => { stop.then(off => off()); };
  }, [onSay]);

  if (model === null) return <div className="loading-state"><span className="spinner" />Probing trusted devices…</div>;
  if (model.fleet.kind === 'unreachable') {
    return <div className="failure-state"><strong>The orbit cannot be read</strong><code>{model.fleet.reason}</code></div>;
  }

  const selected = rows.find(row => row.name === selectedName) ?? null;
  const begin = (mode: 'invite' | 'add') => {
    setPairMode(mode);
    setPairing(mode === 'invite' ? {state: 'waiting'} : null);
    setTicket('');
    if (mode === 'invite') pairStart('invite').catch(error => onSay(String(error), true));
  };
  const cancel = () => {
    setPairMode(null);
    setPairing(null);
    setTicket('');
    void pairCancel();
  };

  return (
    <div className="split-view devices-view">
      <section className="collection-pane">
        <div className="collection-tools">
          <Button label="Invite" size="sm" variant="primary" icon={<PlusIcon />} onClick={() => begin('invite')} />
          <Button label="Add with ticket" size="sm" variant="secondary" onClick={() => begin('add')} />
        </div>
        <div className="collection-head"><span>Trusted device</span><span>Path</span></div>
        <div className="device-list">
          {rows.map(row => (
            <button
              key={row.short_id}
              className="device-row"
              aria-current={row.name === selectedName ? 'true' : undefined}
              onClick={() => setSelectedName(row.name)}
            >
              <span className={`status-dot ${row.online ? 'running' : 'stopped'}`} />
              <span className="row-main"><strong>{row.name}</strong><small>{row.is_self ? 'this device' : row.short_id} · {shellStateLabel(row.shell.status)}</small></span>
              <span className="row-source">{row.path || '—'}</span>
            </button>
          ))}
        </div>
      </section>

      <section className="detail-pane">
        {selected ? (
          <DeviceDetail
            row={selected}
            waking={waking === selected.name}
            onSay={onSay}
            refresh={refresh}
            onWake={() => {
              setWaking(selected.name);
              onSay(`Waking ${selected.name}…`);
              wake(selected.name).then(refresh, error => onSay(String(error), true)).finally(() => setWaking(''));
            }}
          />
        ) : (
          <div className="zero-state"><DevicesIcon /><strong>No trusted devices</strong><p>Invite another device to begin an orbit.</p></div>
        )}
      </section>

      {pairMode ? (
        <PairSheet
          mode={pairMode}
          pairing={pairing}
          ticket={ticket}
          setTicket={setTicket}
          onRedeem={() => {
            if (!ticket.trim()) return;
            setPairing({state: 'waiting'});
            pairStart(`add:${ticket.trim()}`).catch(error => onSay(String(error), true));
          }}
          onClose={cancel}
          onSay={onSay}
        />
      ) : null}
    </div>
  );
}

function DeviceDetail({
  row,
  waking,
  onWake,
  onSay,
  refresh,
}: {
  row: DeviceRow;
  waking: boolean;
  onWake: () => void;
  onSay: (line: string, bad?: boolean) => void;
  refresh: () => void;
}) {
  const canWake = row.wakeable && !row.online && !row.is_self;
  const [shell, setShell] = useState<DeviceShell>(row.shell);
  const [shellBusy, setShellBusy] = useState(false);

  useEffect(() => setShell(row.shell), [row.short_id, row.shell]);

  const changeShell = (enabled: boolean) => {
    if (!canSetDeviceShell({...row, shell})) return;
    setShellBusy(true);
    onSay(`${enabled ? 'Enabling' : 'Disabling'} device shell on this device…`);
    setDeviceShell(enabled).then(
      authoritative => {
        // Render only the daemon's reply; never optimistically invent policy.
        setShell(authoritative);
        onSay(`Device shell ${enabled ? 'enabled' : 'disabled'} on this device.`);
        refresh();
      },
      error => onSay(String(error), true),
    ).finally(() => setShellBusy(false));
  };

  return (
    <div className="device-detail">
      <div className="detail-title-row">
        <div><div className="eyebrow">TRUSTED DEVICE</div><h1>{row.name}</h1><div className="state-line"><span className={`status-dot ${row.online ? 'running' : 'stopped'}`} />{row.online ? 'online' : 'offline'}{row.is_self ? ' · this device' : ''}</div></div>
        {canWake ? <Button label="Wake" size="sm" variant="primary" isLoading={waking} onClick={onWake} /> : null}
      </div>
      <div className="facts-grid device-facts">
        <Fact label="Device ID" value={row.short_id} mono />
        <Fact label="Current path" value={row.path || 'not connected'} />
        <Fact label="Wake on LAN" value={row.wakeable ? 'available' : 'not configured'} />
        <Fact label="Trust" value="verified orbit peer" />
      </div>
      <section className="detail-section">
        <div className="section-heading"><span>Presence</span><small>live daemon probe</small></div>
        <p className="quiet-copy">{row.online ? `${row.name} answered through ${row.path || 'the current mesh path'}.` : `${row.name} did not answer this probe. Its trusted identity remains in the orbit.`}</p>
      </section>
      <DeviceShellSection row={{...row, shell}} busy={shellBusy} onChange={changeShell} />
    </div>
  );
}

function DeviceShellSection({row, busy, onChange}: {row: DeviceRow; busy: boolean; onChange: (enabled: boolean) => void}) {
  const status = row.shell.status;
  const changedIso = changedAtIso(status.changed_at);
  const mutable = canSetDeviceShell(row);
  const enabled = status.state === 'enabled_orbit' || status.state === 'active';

  return (
    <section className="detail-section device-shell-section" aria-label="Device shell policy">
      <div className="section-heading">
        <span>Device shell</span>
        <small>{row.shell.access === 'local_only' ? 'local control' : 'read-only'}</small>
      </div>
      <div className="shell-policy-row">
        <div className="data-primary">
          <strong>{shellStateLabel(status)}</strong>
          <small>
            {changedIso && status.changed_at !== undefined ? (
              <>Changed <time dateTime={changedIso}>{formatTime(status.changed_at)}</time></>
            ) : 'Change time unavailable'}
          </small>
        </div>
        {mutable ? (
          <Button
            label={enabled ? 'Disable' : 'Enable'}
            size="sm"
            variant={enabled ? 'secondary' : 'primary'}
            isLoading={busy}
            onClick={() => onChange(!enabled)}
          />
        ) : <span className="read-only-label">Read-only</span>}
      </div>
      {status.unavailable_reason ? <p className="inline-error">{status.unavailable_reason}</p> : null}
      {status.active.length > 0 ? (
        <div className="shell-session-list" aria-label="Active device shell sessions">
          {status.active.map(session => (
            <div className="data-row" key={session.session_id}>
              <div className="data-primary">
                <strong>{session.peer_name}</strong>
                <small>{session.peer_device_id} · {session.pty ? 'PTY' : 'command'}</small>
              </div>
              <time className="data-meta" dateTime={changedAtIso(session.started_at) ?? undefined}>
                Since {formatTime(session.started_at)}
              </time>
            </div>
          ))}
        </div>
      ) : null}
    </section>
  );
}

function formatTime(unixSeconds: number): string {
  const iso = changedAtIso(unixSeconds);
  if (iso === null) return 'time unavailable';
  return new Intl.DateTimeFormat(undefined, {dateStyle: 'medium', timeStyle: 'short'})
    .format(new Date(iso));
}

function PairSheet({
  mode,
  pairing,
  ticket,
  setTicket,
  onRedeem,
  onClose,
  onSay,
}: {
  mode: 'invite' | 'add';
  pairing: Pairing | null;
  ticket: string;
  setTicket: (value: string) => void;
  onRedeem: () => void;
  onClose: () => void;
  onSay: (line: string, bad?: boolean) => void;
}) {
  return (
    <div className="sheet-scrim" role="presentation">
      <section className="pair-sheet" role="dialog" aria-modal="true" aria-label={mode === 'invite' ? 'Invite a device' : 'Add a device'}>
        <header className="sheet-head">
          <div><div className="eyebrow">ORBIT TRUST</div><h2>{mode === 'invite' ? 'Invite a device' : 'Add with a ticket'}</h2></div>
          <Button label="Close" isIconOnly size="sm" variant="ghost" icon={<CloseIcon />} onClick={onClose} />
        </header>
        {mode === 'add' && pairing === null ? (
          <div className="pair-body">
            <p>Paste the one-time ticket shown on the device you want to trust.</p>
            <textarea className="ticket-input mono" value={ticket} autoFocus onChange={event => setTicket(event.target.value)} placeholder="Paste pairing ticket" />
            <Button label="Continue" variant="primary" isDisabled={!ticket.trim()} onClick={onRedeem} />
          </div>
        ) : <PairingState state={pairing} onClose={onClose} onSay={onSay} />}
      </section>
    </div>
  );
}

function PairingState({state, onClose, onSay}: {state: Pairing | null; onClose: () => void; onSay: (line: string, bad?: boolean) => void}) {
  if (!state || state.state === 'waiting') return <div className="pair-body centered"><span className="spinner large" /><strong>Waiting for the other device</strong><p>The invitation stays private until both screens confirm the same six digits.</p></div>;
  if (state.state === 'ticket') return (
    <div className="pair-body">
      <p>Run Asterism on the other device and add it with this one-time ticket.</p>
      <div className="ticket-block"><code>{state.ticket}</code><Button label="Copy ticket" size="sm" variant="secondary" icon={<CopyIcon />} onClick={() => copy(state.ticket).then(() => onSay('Ticket copied.'))} /></div>
      <small>Expires in {Math.max(1, Math.round(state.expires_in_secs / 60))} minutes.</small>
    </div>
  );
  if (state.state === 'sas') return (
    <div className="pair-body centered"><div className="sas-code">{state.code}</div><strong>Do both screens show this code?</strong><p>Confirm only if the code on {state.peer} matches exactly.</p><div className="pair-actions"><Button label="Reject" variant="secondary" onClick={() => void pairConfirm(false)} /><Button label="Codes match" variant="primary" onClick={() => void pairConfirm(true)} /></div></div>
  );
  if (state.state === 'paired') return <div className="pair-body centered"><span className="success-mark">✓</span><strong>{state.name} is trusted</strong><p>Device ID {state.short_id}</p><Button label="Done" variant="primary" onClick={onClose} /></div>;
  return <div className="pair-body centered"><strong>Pairing failed</strong><p className="inline-error">{state.reason}</p><Button label="Close" onClick={onClose} /></div>;
}

function Fact({label, value, mono = false}: {label: string; value: string; mono?: boolean}) {
  return <div className="fact"><span>{label}</span><strong className={mono ? 'mono' : undefined}>{value}</strong></div>;
}
