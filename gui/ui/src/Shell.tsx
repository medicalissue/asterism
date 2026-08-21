import {useCallback, useEffect, useRef, useState} from 'react';
import {Button} from '@astryxdesign/core/Button';

import type {
  Devices as DeviceModel,
  Instances as InstanceModel,
  Route,
  Settings as SettingsModel,
  Volumes as VolumeModel,
} from './bridge';
import {act, actionLabel, loadDevices, loadInstances, loadSettings, loadVolumes, onRoute, takeRoute} from './bridge';
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
  // Which instances this window has an action in flight on, and what Rust
  // calls each one. Local state, cleared on the response; the daemon's
  // answer and the next poll are the truth.
  const [pending, setPending] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [intent, setIntent] = useState<string | null>(null);
  const reading = useRef(false);

  const say = useCallback((text: string, bad = false) => setNotice({text, bad}), []);
  // Stable, so the pane's route effect does not re-run on every poll tick.
  const intentDone = useCallback(() => setIntent(null), []);

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

  // Where the tray asked this window to go. Two ways in, because a route can
  // be decided before there is a window to tell: a window that is starting
  // takes the queued one here, and one that was already up is sent an event.
  useEffect(() => {
    const go = (route: Route) => {
      const asked = SECTIONS.find(candidate => candidate === route.section);
      if (asked) setSection(asked);
      if (route.instance) setSelected(route.instance);
      setIntent(route.intent);
    };
    takeRoute().then(route => route && go(route), () => {});
    const listening = onRoute(go);
    return () => {
      listening.then(stop => stop(), () => {});
    };
  }, []);

  /**
   * Do one action and say how it went.
   *
   * Rejects with the daemon's own sentence, because the dialogs need it:
   * a refusal keeps the dialog open with the reason under the field rather
   * than closing on a change that did not happen.
   */
  const run = useCallback(
    async (id: string, confirmation?: string) => {
      // What to call it, from Rust. In process and off the socket, so the
      // window is not keeping a second list of verbs beside `Action`'s.
      const label = await actionLabel(id);
      const subject = label.subject;
      if (subject && label.verb) setPending(was => ({...was, [subject]: label.verb as string}));
      setBusy(true);
      say(`${label.what}…`);
      try {
        await act(id, confirmation);
        say(`${label.what} — done.`);
      } catch (error) {
        say(String(error), true);
        throw error;
      } finally {
        if (subject) {
          setPending(was => {
            const {[subject]: _gone, ...rest} = was;
            return rest;
          });
        }
        setBusy(false);
        refresh();
      }
    },
    [refresh, say],
  );

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
              size="md"
              variant="primary"
              icon={<PlusIcon />}
              onClick={() => { void run('new').catch(() => {}); }}
            />
          ) : null}
        </header>

        <div className="workspace-body">
          {section === 'instances' ? (
            <Instances
              model={instances}
              onAct={run}
              pending={pending}
              intent={intent}
              onIntentDone={intentDone}
              selected={selected}
              onSelect={setSelected}
            />
          ) : null}
          {section === 'devices' ? <Devices model={devices} onSay={say} refresh={refresh} /> : null}
          {section === 'volumes' ? <Volumes model={volumes} /> : null}
          {section === 'settings' ? (
            <Settings model={settings} onAct={run} refresh={refresh} onSay={say} />
          ) : null}
        </div>

        <footer className="status-bar" data-bad={notice.bad}>
          <span className="status-dot" data-state={notice.bad ? 'error' : busy ? 'busy' : 'idle'} />
          {/* Two live regions, both always in the tree. A failure is an
              alert and gets read at once; progress and success are a status
              and wait their turn. Swapping the role on one node would leave
              a screen reader announcing whichever it saw first. */}
          <span role="status">{notice.bad ? '' : notice.text || (busy ? 'Working…' : 'Up to date')}</span>
          <span role="alert">{notice.bad ? notice.text : ''}</span>
          <span className="status-spacer" />
          <button className="text-action" onClick={refresh}>Refresh</button>
        </footer>
      </main>
    </div>
  );
}
