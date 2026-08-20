// The Settings section: two things you can change about this device, and
// two you can only read.
//
// The backend row is drawn only when this device has more than one to
// offer, because a control with one option is clutter pretending to be a
// choice — the same rule the New Instance dialog follows, decided in the
// same place in Rust.

import type {ReactNode} from 'react';

import type {Settings as Model} from './bridge';
import {setDefaultBackend} from './bridge';
import {Check, Select} from './controls';
import {Pane} from './Pane';

export function Settings({
  model,
  status,
  onAct,
  refresh,
  onSay,
}: {
  model: Model | null;
  status: ReactNode;
  onAct: (id: string, what: string) => void;
  refresh: () => void;
  onSay: (line: string, bad: boolean) => void;
}) {
  return (
    <Pane title="Settings" status={status}>
      {model === null ? (
        <div className="empty">
          <span>Reading this device…</span>
        </div>
      ) : (
        <div className="settings">
          <Row label="Start at Login" hint="Asterism comes back when you log in.">
            <Check
              checked={model.autostart}
              onChange={() => onAct('autostart', 'changing start at login')}
            >
              {model.autostart ? 'On' : 'Off'}
            </Check>
          </Row>

          {model.backends.length > 1 ? (
            <Row label="Default backend" hint="What New Instance opens on.">
              <Select
                label="Default backend"
                value={model.default_backend}
                disabled={false}
                options={model.backends.map(b => ({value: b.id, label: b.label}))}
                onChange={id =>
                  setDefaultBackend(id).then(refresh, (e: unknown) => onSay(String(e), true))
                }
              />
            </Row>
          ) : null}

          <Row label="Daemon">
            <span className="readout" title={model.daemon_error ?? undefined}>
              {model.daemon ?? `unavailable — ${model.daemon_error ?? 'no reason given'}`}
            </span>
          </Row>

          <Row label="Home" hint="Where astd keeps this device's state.">
            <span className="readout mono" title={model.home}>
              {model.home}
            </span>
          </Row>

          <Row
            label="Service"
            hint={`Have ${model.service.mechanism} keep astd running.`}
          >
            <span className="readout" title={model.service.unit || undefined}>
              {model.service.summary}
            </span>
            {model.service.installed ? (
              <button
                className="button"
                onClick={() => onAct('service:uninstall', 'removing the astd service')}
              >
                Uninstall
              </button>
            ) : (
              <button
                className="button"
                onClick={() => onAct('service:install', 'installing the astd service')}
              >
                Install
              </button>
            )}
          </Row>
        </div>
      )}
    </Pane>
  );
}

function Row({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <div className="setting">
      <span className="label">
        {label}
        {hint ? <span className="hint">{hint}</span> : null}
      </span>
      <span className="control">{children}</span>
    </div>
  );
}
