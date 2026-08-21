import {Button} from '@astryxdesign/core/Button';
import {CheckboxInput} from '@astryxdesign/core/CheckboxInput';
import {Selector} from '@astryxdesign/core/Selector';

import type {Act} from './Instances';
import type {Settings as Model} from './bridge';
import {setDefaultBackend} from './bridge';

export function Settings({
  model,
  onAct,
  refresh,
  onSay,
}: {
  model: Model | null;
  onAct: Act;
  refresh: () => void;
  onSay: (line: string, bad?: boolean) => void;
}) {
  if (model === null) return <div className="loading-state"><span className="spinner" />Reading this device…</div>;
  return (
    <div className="single-pane settings-pane">
      <section className="settings-group">
        <div className="settings-heading"><h2>Application</h2><p>How the menu-bar app behaves on this Mac.</p></div>
        <div className="setting-row">
          <div><strong>Start at login</strong><p>Keep Asterism available in the menu bar after you sign in.</p></div>
          <CheckboxInput label="Start Asterism at login" isLabelHidden size="sm" value={model.autostart} onChange={() => { void onAct('autostart').catch(() => {}); }} />
        </div>
        {model.backends.length > 1 ? (
          <div className="setting-row">
            <div><strong>Default backend</strong><p>Preselected when you create an instance on this device.</p></div>
            <Selector
              label="Default backend"
              isLabelHidden
              size="sm"
              width={180}
              value={model.default_backend}
              options={model.backends.map(backend => ({value: backend.id, label: backend.label}))}
              onChange={value => setDefaultBackend(value).then(refresh, error => onSay(String(error), true))}
            />
          </div>
        ) : null}
      </section>

      <section className="settings-group">
        <div className="settings-heading"><h2>Daemon service</h2><p>The background process that owns this device's parts.</p></div>
        <div className="setting-row">
          <div><strong>{model.service.mechanism}</strong><p title={model.service.unit}>{model.service.summary}</p></div>
          <Button
            label={model.service.installed ? 'Uninstall service' : 'Install service'}
            size="sm"
            variant="secondary"
            onClick={() => { void onAct(model.service.installed ? 'service:uninstall' : 'service:install').catch(() => {}); }}
          />
        </div>
        <div className="setting-row read-only"><div><strong>Daemon version</strong><p>{model.daemon ?? `Unavailable — ${model.daemon_error ?? 'no response'}`}</p></div><span className={`status-dot ${model.daemon ? 'running' : 'unknown'}`} /></div>
        <div className="setting-row read-only"><div><strong>Asterism home</strong><p className="mono" title={model.home}>{model.home}</p></div></div>
      </section>
    </div>
  );
}
