// The Devices section: this orbit, and the two ways to grow it.
//
// A pairing is a conversation rather than a request, so this panel is
// driven by events: Rust holds a connection open, sends what the daemon
// says as it arrives, and waits for Confirm or Reject before anything is
// written down. Nothing here trusts a key — the six digits are compared by
// a person, at two screens, which is the whole security property.

import {useEffect, useState} from 'react';
import type {ReactNode} from 'react';

import type {DeviceRow, Devices as Model, Pairing} from './bridge';
import {copy, onPairing, onWake, pairCancel, pairConfirm, pairStart, wake} from './bridge';
import {Dot} from './controls';
import {Pane} from './Pane';

export function Devices({
  model,
  status,
  onSay,
  refresh,
}: {
  model: Model | null;
  status: ReactNode;
  onSay: (line: string, bad: boolean) => void;
  refresh: () => void;
}) {
  const [pairing, setPairing] = useState<Pairing | null>(null);
  const [half, setHalf] = useState<'invite' | 'add'>('invite');
  const [ticket, setTicket] = useState('');
  const [waking, setWaking] = useState<string | null>(null);

  useEffect(() => {
    const stop = onPairing(state => {
      setPairing(state);
      if (state.state === 'paired') {
        onSay(`${state.name} joined this orbit.`, false);
        refresh();
      }
      if (state.state === 'failed') onSay(state.reason, true);
    });
    return () => {
      stop.then(off => off());
    };
  }, [onSay, refresh]);

  // The daemon narrates a wake as it happens: who is sending the packet,
  // that it went, and a minute later whether the machine turned up.
  useEffect(() => {
    const stop = onWake(line => onSay(line, false));
    return () => {
      stop.then(off => off());
    };
  }, [onSay]);

  const begin = (which: 'invite' | 'add') => {
    setHalf(which);
    setTicket('');
    setPairing(which === 'invite' ? {state: 'waiting'} : null);
    if (which === 'invite') {
      pairStart('invite').catch((e: unknown) => onSay(String(e), true));
    }
  };

  const redeem = () => {
    if (ticket.trim() === '') return;
    setPairing({state: 'waiting'});
    pairStart(`add:${ticket.trim()}`).catch((e: unknown) => onSay(String(e), true));
  };

  const stop = () => {
    setPairing(null);
    setTicket('');
    void pairCancel();
  };

  const rouse = (name: string) => {
    setWaking(name);
    onSay(`Waking ${name}.`, false);
    wake(name)
      .catch((e: unknown) => onSay(String(e), true))
      .finally(() => {
        setWaking(null);
        refresh();
      });
  };

  const head = (
    <>
      <button className="button" onClick={() => begin('add')}>
        Add device…
      </button>
      <button className="button primary" onClick={() => begin('invite')}>
        Invite device…
      </button>
    </>
  );

  return (
    <Pane title="Devices" actions={head} status={status}>
      {body()}
    </Pane>
  );

  function body() {
    if (model === null) {
      return (
        <div className="empty">
          <span>Reading the orbit…</span>
        </div>
      );
    }

    if (model.fleet.kind === 'unreachable') {
      return (
        <div className="empty">
          <span>astd is not answering, so this orbit cannot be read.</span>
          <span className="mono">{model.fleet.reason}</span>
        </div>
      );
    }

    const rows = model.fleet.rows;
    const panel = pairing !== null || half === 'add';

    return (
      <>
        <div className="table devices">
          <div className="head">
            <span className="cell">Name</span>
            <span className="cell">Device ID</span>
            <span className="cell">Status</span>
            <span className="cell">Path</span>
            <span className="cell" />
          </div>
          {rows.map(row => (
            <Row key={row.short_id} row={row} waking={waking === row.name} onWake={rouse} />
          ))}
        </div>

        {rows.length === 1 ? (
          <div className="empty">
            <span>One device. Invite another and they become one pool of parts.</span>
          </div>
        ) : null}

        {panel ? (
          <Panel
            half={half}
            pairing={pairing}
            ticket={ticket}
            setTicket={setTicket}
            onRedeem={redeem}
            onStop={stop}
            onSay={onSay}
          />
        ) : null}
      </>
    );
  }
}

function Row({
  row,
  waking,
  onWake,
}: {
  row: DeviceRow;
  waking: boolean;
  onWake: (name: string) => void;
}) {
  const state = row.online ? 'online' : 'offline';
  // A device that is asleep and that this orbit knows a MAC and a network
  // for. Rust decides both halves; this only draws the button.
  const canWake = row.wakeable && !row.online && !row.is_self;
  return (
    <div className="row" data-active={false}>
      <span className="cell first">
        <Dot state={state} />
        <span className="cell">{row.name}</span>
        {row.is_self ? <span className="tag">this device</span> : null}
      </span>
      <span className="cell mono quiet">{row.short_id}</span>
      <span className="cell quiet">{state}</span>
      <span className="cell quiet">{row.path || '—'}</span>
      <span className="cell verbs">
        {canWake ? (
          <button className="button small" disabled={waking} onClick={() => onWake(row.name)}>
            {waking ? 'Waking…' : 'Wake'}
          </button>
        ) : null}
      </span>
    </div>
  );
}

/**
 * The pairing panel, inline under the rows it is adding to.
 *
 * Both halves land in the same place: an invite prints a ticket and waits, an
 * add takes one and redeems it, and from the six digits onwards they are the
 * same screen.
 */
function Panel({
  half,
  pairing,
  ticket,
  setTicket,
  onRedeem,
  onStop,
  onSay,
}: {
  half: 'invite' | 'add';
  pairing: Pairing | null;
  ticket: string;
  setTicket: (t: string) => void;
  onRedeem: () => void;
  onStop: () => void;
  onSay: (line: string, bad: boolean) => void;
}) {
  const title = half === 'invite' ? 'Invite a device' : 'Add a device';

  return (
    <div className="panel">
      <div className="panel-head">
        <span className="what">{title}</span>
        <span>{caption(half, pairing)}</span>
      </div>

      {half === 'add' && pairing === null ? (
        <div className="panel-row">
          <input
            className="field mono"
            value={ticket}
            placeholder="Paste the ticket the other device printed"
            autoFocus
            spellCheck={false}
            autoComplete="off"
            aria-label="Ticket"
            onChange={e => setTicket(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter') onRedeem();
            }}
          />
          <button className="button primary" disabled={ticket.trim() === ''} onClick={onRedeem}>
            Add
          </button>
          <button className="button" onClick={onStop}>
            Cancel
          </button>
        </div>
      ) : null}

      {pairing?.state === 'ticket' ? (
        <>
          <div className="panel-row">
            <code className="ticket mono">{pairing.ticket}</code>
            <button
              className="button"
              onClick={() =>
                copy(pairing.ticket).then(
                  () => onSay('Ticket copied.', false),
                  (e: unknown) => onSay(String(e), true),
                )
              }
            >
              Copy
            </button>
          </div>
          <div className="panel-row">
            <span className="status">
              Paste this into the other machine's Add device field, or run{' '}
              <code className="mono">ast device add</code> with it there. Good for{' '}
              {pairing.expires_in_secs}s.
            </span>
            <button className="button" onClick={onStop}>
              Cancel
            </button>
          </div>
        </>
      ) : null}

      {pairing?.state === 'sas' ? (
        <>
          <div className="panel-row">
            <span className="sas">{pairing.code}</span>
          </div>
          <div className="panel-row">
            <span className="status">
              {pairing.peer} wants to join. Both screens must show these digits.
            </span>
            <button className="button" onClick={() => void pairConfirm(false).finally(onStop)}>
              Reject
            </button>
            <button className="button primary" onClick={() => void pairConfirm(true)}>
              Confirm
            </button>
          </div>
        </>
      ) : null}

      {pairing?.state === 'paired' ? (
        <div className="panel-row">
          <span className="status">
            {pairing.name} ({pairing.short_id}) is in this orbit.
          </span>
          <button className="button" onClick={onStop}>
            Done
          </button>
        </div>
      ) : null}

      {pairing?.state === 'failed' ? (
        <div className="panel-row">
          <span className="status" data-bad="true">
            {pairing.reason}
          </span>
          <button className="button" onClick={onStop}>
            Close
          </button>
        </div>
      ) : null}
    </div>
  );
}

function caption(half: 'invite' | 'add', pairing: Pairing | null): string {
  switch (pairing?.state) {
    case 'waiting':
      return half === 'invite' ? 'Minting a ticket…' : 'Redeeming…';
    case 'ticket':
      return 'Waiting for a device to redeem it';
    case 'sas':
      return 'Compare the codes';
    case 'paired':
      return 'Paired';
    case 'failed':
      return 'Stopped';
    default:
      return 'Paste a ticket from the other machine';
  }
}

export function deviceCount(model: Model | null): number | null {
  return model?.fleet.kind === 'rows' ? model.fleet.rows.length : null;
}
