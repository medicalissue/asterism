import {useCallback, useEffect, useRef, useState} from 'react';
import {Button} from '@astryxdesign/core/Button';

import type {
  Devices as DeviceModel,
  Instances as InstanceModel,
  Settings as SettingsModel,
  Volumes as VolumeModel,
} from './bridge';
import {act, loadDevices, loadInstances, loadSettings, loadVolumes} from './bridge';
import {Devices} from './Devices';
import {Instances} from './Instances';
import {Settings} from './Settings';
import {Volumes} from './Volumes';
import {DevicesIcon, InstancesIcon, PlusIcon, SettingsIcon, VolumesIcon} from './Icons';

const SECTIONS = ['instances', 'devices', 'volumes', 'settings'] as const;
type Section = (typeof SECTIONS)[number];
const POLL_MS = 3000;

const NAV = {
  instances: {label: 'Instances', icon: InstancesIcon},
  devices: {label: 'Devices', icon: DevicesIcon},
  volumes: {label: 'Volumes', icon: VolumesIcon},
  settings: {label: 'Settings', icon: SettingsIcon},
} satisfies Record<Section, {label: string; icon: typeof InstancesIcon}>;

function opening(): Section {
  const asked = new URLSearchParams(location.search).get('section');
  return SECTIONS.find(section => section === asked) ?? 'instances';
}

export function Shell() {
  const [section, setSection] = useState<Section>(opening);
  const [instances, setInstances] = useState<InstanceModel | null>(null);
  const [devices, setDevices] = useState<DeviceModel | null>(null);
  const [volumes, setVolumes] = useState<VolumeModel | null>(null);
  const [settings, setSettings] = useState<SettingsModel | null>(null);
  const [notice, setNotice] = useState<{text: string; bad: boolean}>({text: '', bad: false});
  const [busy, setBusy] = useState(false);
  const reading = useRef(false);

  const say = useCallback((text: string, bad = false) => setNotice({text, bad}), []);

  const refresh = useCallback(() => {
    if (reading.current) return;
    reading.current = true;
    const finish = <T,>(setter: (value: T) => void) => (value: T) => {
      reading.current = false;
      setter(value);
    };
    const fail = (error: unknown) => {
      reading.current = false;
      say(String(error), true);
    };
    if (section === 'instances') loadInstances().then(finish(setInstances), fail);
    if (section === 'devices') loadDevices().then(finish(setDevices), fail);
    if (section === 'volumes') loadVolumes().then(finish(setVolumes), fail);
    if (section === 'settings') loadSettings().then(finish(setSettings), fail);
  }, [section, say]);

  useEffect(() => {
    refresh();
    const timer = setInterval(() => {
      if (!busy) refresh();
    }, POLL_MS);
    return () => clearInterval(timer);
  }, [busy, refresh]);

  const run = useCallback((id: string, description: string) => {
    setBusy(true);
    say(`${description}…`);
    act(id).then(
      () => {
        setBusy(false);
        say(`${description} complete.`);
        refresh();
      },
      (error: unknown) => {
        setBusy(false);
        say(String(error), true);
        refresh();
      },
    );
  }, [refresh, say]);

  const counts: Partial<Record<Section, number>> = {};
  if (instances?.fleet.kind === 'rows') counts.instances = instances.fleet.rows.length;
  if (devices?.fleet.kind === 'rows') counts.devices = devices.fleet.rows.length;
  if (volumes?.inventory.kind === 'rows') counts.volumes = volumes.inventory.rows.length;

  return (
    <div className="control-center">
      <aside className="rail" data-tauri-drag-region>
        <div className="brand" data-tauri-drag-region>
          <span className="brand-mark" aria-hidden="true">✦</span>
          <span>Asterism</span>
        </div>
        <div className="orbit-label">CONTROL CENTER</div>
        <nav className="nav" aria-label="Control Center sections">
          {SECTIONS.map(id => {
            const item = NAV[id];
            const NavIcon = item.icon;
            return (
              <button
                key={id}
                className="nav-item"
                aria-current={section === id ? 'page' : undefined}
                onClick={() => {
                  setSection(id);
                  say('');
                }}
              >
                <NavIcon />
                <span>{item.label}</span>
                {counts[id] !== undefined ? <span className="nav-count">{counts[id]}</span> : null}
              </button>
            );
          })}
        </nav>
        <div className="rail-bottom">
          <div className="local-health"><span className="status-dot running" />Local daemon</div>
          <span className="version">Asterism {__VERSION__}</span>
        </div>
      </aside>

      <main className="workspace">
        <header className="workspace-bar" data-tauri-drag-region>
          <div className="workspace-title" data-tauri-drag-region>
            <span>{NAV[section].label}</span>
            {section === 'volumes' ? <small>on this device</small> : <small>orbit view</small>}
          </div>
          {section === 'instances' ? (
            <Button
              label="New instance"
              size="sm"
              variant="primary"
              icon={<PlusIcon />}
              onClick={() => run('new', 'Opening New Instance')}
            />
          ) : null}
        </header>

        <div className="workspace-body">
          {section === 'instances' ? <Instances model={instances} onAct={run} busy={busy} /> : null}
          {section === 'devices' ? <Devices model={devices} onSay={say} refresh={refresh} /> : null}
          {section === 'volumes' ? <Volumes model={volumes} /> : null}
          {section === 'settings' ? (
            <Settings model={settings} onAct={run} refresh={refresh} onSay={say} />
          ) : null}
        </div>

        <footer className="status-bar" data-bad={notice.bad}>
          <span className="status-dot" data-state={notice.bad ? 'error' : busy ? 'busy' : 'idle'} />
          <span>{notice.text || (busy ? 'Working…' : 'Up to date')}</span>
          <span className="status-spacer" />
          <button className="text-action" onClick={refresh}>Refresh</button>
        </footer>
      </main>
    </div>
  );
}
