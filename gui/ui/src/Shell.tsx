// The main window: a sidebar, whichever section it names, and a status
// line.
//
// It holds three things and no more: which section is showing, the model of
// that section, and the last line worth saying. Everything else belongs to a
// section or to Rust.
//
// Polling is the tray's rhythm, three seconds, and only for the section on
// screen: Devices probes every peer on the mesh as it is served, and a pane
// nobody is looking at should not be paying for that. A poll that arrives
// while an action is running is dropped, because a table that reshuffled
// under a menu you had open would be worse than a table three seconds late.

import {useCallback, useEffect, useRef, useState} from 'react';

import type {Devices as DeviceModel, Instances as InstanceModel, Settings as SettingsModel} from './bridge';
import {act, loadDevices, loadInstances, loadSettings} from './bridge';
import {Devices} from './Devices';
import {Instances} from './Instances';
import {Settings} from './Settings';

/** The sidebar, in the order Rust's `Section::ALL` lists it. */
const SECTIONS = ['instances', 'devices', 'settings'] as const;
type Section = (typeof SECTIONS)[number];

const TITLES: Record<Section, string> = {
  instances: 'Instances',
  devices: 'Devices',
  settings: 'Settings',
};

/** Cheap enough to be live, slow enough to be free — the tray's interval. */
const POLL_MS = 3000;

/**
 * Which section to open on. Rust puts it in the query when something asked
 * for one; anything else opens on the fleet, which is what somebody opening
 * this window came for.
 */
function opening(): Section {
  const asked = new URLSearchParams(location.search).get('section');
  return SECTIONS.find(s => s === asked) ?? 'instances';
}

export function Shell() {
  const [section, setSection] = useState<Section>(opening);
  const [instances, setInstances] = useState<InstanceModel | null>(null);
  const [devices, setDevices] = useState<DeviceModel | null>(null);
  const [settings, setSettings] = useState<SettingsModel | null>(null);
  const [said, setSaid] = useState<{line: string; bad: boolean}>({line: '', bad: false});

  // While an action is in flight the pane is left alone: the daemon is
  // mid-change and a poll would draw a half-finished fleet.
  const busy = useRef(false);
  // And while a read is in flight, another is not started. An orbit view is
  // assembled from every device that answers, so on a fleet with a sleeping
  // machine in it one read can outlast several ticks of this clock.
  const reading = useRef(false);

  const say = useCallback((line: string, bad: boolean) => setSaid({line, bad}), []);

  const refresh = useCallback(() => {
    if (reading.current) return;
    reading.current = true;
    const done = <T,>(set: (v: T) => void) => (v: T) => {
      reading.current = false;
      set(v);
    };
    const fail = (e: unknown) => {
      reading.current = false;
      say(String(e), true);
    };
    if (section === 'instances') loadInstances().then(done(setInstances), fail);
    if (section === 'devices') loadDevices().then(done(setDevices), fail);
    if (section === 'settings') loadSettings().then(done(setSettings), fail);
  }, [section, say]);

  useEffect(() => {
    refresh();
    const tick = setInterval(() => {
      if (!busy.current) refresh();
    }, POLL_MS);
    return () => clearInterval(tick);
  }, [refresh]);

  /**
   * Run one action by the id the tray uses for the same verb, and say how
   * it went. Rust has already put a failure in Notification Center and in
   * the log; the status line is the part you can read without leaving the
   * window.
   */
  const run = useCallback(
    (id: string, what: string) => {
      busy.current = true;
      say(`${what[0].toUpperCase()}${what.slice(1)}…`, false);
      act(id).then(
        () => {
          busy.current = false;
          say(`Done ${what}.`, false);
          refresh();
        },
        (e: unknown) => {
          busy.current = false;
          say(String(e), true);
          refresh();
        },
      );
    },
    [refresh, say],
  );

  const counts: Record<Section, number | null> = {
    instances: instances?.fleet.kind === 'rows' ? instances.fleet.rows.length : null,
    devices: devices?.fleet.kind === 'rows' ? devices.fleet.rows.length : null,
    settings: null,
  };

  const status = (
    <span className="status" data-bad={said.bad} title={said.line}>
      {said.line}
    </span>
  );

  return (
    <div className="shell">
      <nav className="sidebar" aria-label="Sections" data-tauri-drag-region>
        {SECTIONS.map(id => (
          <button
            key={id}
            className="tab"
            aria-current={id === section}
            onClick={() => {
              setSection(id);
              say('', false);
            }}
          >
            {TITLES[id]}
            {counts[id] !== null ? <span className="count">{counts[id]}</span> : null}
          </button>
        ))}
        <span className="build">Asterism {__VERSION__}</span>
      </nav>

      {section === 'instances' ? (
        <Instances
          model={instances}
          status={status}
          onAct={run}
          onNew={() => run('new', 'opening the New Instance window')}
        />
      ) : null}
      {section === 'devices' ? (
        <Devices model={devices} status={status} onSay={say} refresh={refresh} />
      ) : null}
      {section === 'settings' ? (
        <Settings model={settings} status={status} onAct={run} refresh={refresh} onSay={say} />
      ) : null}
    </div>
  );
}
