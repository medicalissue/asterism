import {Button} from '@astryxdesign/core/Button';
import {CheckboxInput} from '@astryxdesign/core/CheckboxInput';
import {Selector} from '@astryxdesign/core/Selector';

import type {Settings as Model} from './bridge';
import {setDefaultBackend} from './bridge';

export function Settings({
  model,
  onAct,
  refresh,
  onSay,
}: {
  model: Model | null;
  onAct: (id: string, description: string) => void;
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
          <CheckboxInput label="Start Asterism at login" isLabelHidden size="sm" value={model.autostart} onChange={() => onAct('autostart', 'Changing start at login')} />
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
        <div className="settings-heading"><h2>Updates</h2><p>One signed channel for the app, CLI, daemon and VZ helper.</p></div>
        <div className="setting-row">
          <div><strong>{model.update_channel} channel</strong><p>{model.update_error ?? `${model.update_version} · ${model.update_build} · ${model.update_manager}`}</p></div>
          <div className="button-row">
            <Button label="Check" size="sm" variant="secondary" onClick={() => onAct('update:check', 'Checking the signed update channel')} />
            <Button label="Install" size="sm" variant="primary" onClick={() => onAct('update:apply', 'Installing the signed update')} />
          </div>
        </div>
      </section>

      <section className="settings-group">
        <div className="settings-heading"><h2>Daemon service</h2><p>The background process that owns this device's parts.</p></div>
        <div className="setting-row">
          <div><strong>{model.service.mechanism}</strong><p title={model.service.unit}>{model.service.summary}</p></div>
          <Button
            label={model.service.installed ? 'Uninstall service' : 'Install service'}
            size="sm"
            variant="secondary"
            onClick={() => onAct(model.service.installed ? 'service:uninstall' : 'service:install', model.service.installed ? 'Removing the daemon service' : 'Installing the daemon service')}
          />
        </div>
        <div className="setting-row read-only"><div><strong>Daemon version</strong><p>{model.daemon ?? `Unavailable — ${model.daemon_error ?? 'no response'}`}</p></div><span className={`status-dot ${model.daemon ? 'running' : 'unknown'}`} /></div>
        {/* Which builds these two actually are. The app and the daemon ship
            separately, so a version they agree on is not proof they are the
            same build — and when they are not, this row is the only place
            that says so. */}
        <div className="setting-row read-only"><div><strong>Build</strong><p>app {model.app_build}{model.daemon ? ` · daemon ${model.daemon_build ?? 'unknown'}` : ''}</p></div></div>
        <div className="setting-row read-only"><div><strong>Asterism home</strong><p className="mono" title={model.home}>{model.home}</p></div></div>
      </section>
    </div>
  );
}
