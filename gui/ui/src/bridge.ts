// The Rust side, as seen from the webview.
//
// Fourteen commands and three events, which is the whole surface. The types
// here mirror `src/newinstance.rs`, `src/instances.rs`, `src/devices.rs` and
// `src/settings.rs`; the field names are snake_case because the shapes
// crossing this boundary are the daemon's own structs, and renaming them on
// the way through would be one more thing to keep in step.
//
// Nothing here decides anything. Which buttons a row offers, whether a
// backend may be chosen, why a name will not do: all of it is decided in
// Rust, against the daemon's own rules, and arrives as data.

import {invoke} from '@tauri-apps/api/core';
import {listen} from '@tauri-apps/api/event';
import {getCurrentWindow} from '@tauri-apps/api/window';

// Vite can render the two windows in an ordinary browser for visual QA.
// The packaged app always has Tauri internals, so none of these preview
// fixtures can leak into real daemon reads or actions.
const browserPreview = typeof window !== 'undefined' && !('__TAURI_INTERNALS__' in window);

// ---- the New Instance dialog ----------------------------------------------

export interface Image {
  name: string;
  /** The bytes are on this device already. */
  pulled: boolean;
}

export interface Backend {
  id: string;
  /** What the control says. One word. */
  label: string;
}

export interface Shape {
  cpus: number;
  mem_mib: number;
  disk_gib: number;
}

export interface Form {
  images: Image[];
  backends: Backend[];
  default_image: string;
  default_backend: string;
  shape: Shape;
  /** Names the daemon already has. */
  taken: string[];
  /** Why `taken` is empty, when it is empty because nobody answered. */
  taken_error: string | null;
}

export interface Wanted {
  name: string;
  image: string;
  cpus: number;
  mem_gib: number;
  disk_gib: number;
  backend: string;
  start: boolean;
}

/** The event `create` emits as it goes. */
export const PROGRESS = 'new-instance://progress';

export function loadForm(): Promise<Form> {
  if (browserPreview) return Promise.resolve(PREVIEW_FORM);
  return invoke<Form>('form');
}

/** Why this name will not do, or null. The daemon's rule, run in process. */
export function nameError(name: string): Promise<string | null> {
  if (browserPreview) return Promise.resolve(PREVIEW_FORM.taken.includes(name) ? 'name is already in use' : null);
  return invoke<string | null>('name_error', {name});
}

/**
 * Define the instance, and boot it if that was asked for. Rejects with the
 * daemon's own words; Rust closes the window itself when it works.
 */
export function create(wanted: Wanted): Promise<void> {
  if (browserPreview) return Promise.resolve();
  return invoke<void>('create', {wanted});
}

export function onProgress(handler: (step: string) => void) {
  return listen<string>(PROGRESS, event => handler(event.payload));
}

export function closeWindow(): Promise<void> {
  return getCurrentWindow().close();
}

/** Which of the two windows in this bundle this page is. */
export function windowLabel(): string {
  if (browserPreview) return new URLSearchParams(location.search).get('window') === 'new' ? 'new' : 'main';
  return getCurrentWindow().label;
}

// ---- the main window: Instances --------------------------------------------

export interface InstanceRow {
  name: string;
  /** `running`, `stopped`, `defined`, or `unknown` when its device is out
      of touch. */
  status: string;
  live: boolean;
  cpu_device: string;
  backend: string;
  shape: string;
  image: string;
  volumes: AttachedVolume[];
  can_start: boolean;
  can_stop: boolean;
  can_shell: boolean;
  can_snapshot: boolean;
}

export interface AttachedVolume {
  kind: string;
  name: string;
  source_device: string;
  guest_path: string;
  size: string;
}

/** A section that either has rows or has a reason it has none. */
export type Fleet<T> = {kind: 'unreachable'; reason: string} | {kind: 'rows'; rows: T[]};

export interface Instances {
  fleet: Fleet<InstanceRow>;
}

export function loadInstances(): Promise<Instances> {
  if (browserPreview) return Promise.resolve(PREVIEW_INSTANCES);
  return invoke<Instances>('instances');
}

/** The tags on one instance's disk, read when the popover opens. */
export function loadSnapshots(name: string): Promise<string[]> {
  if (browserPreview) return Promise.resolve(name === 'night-shift' ? ['clean-install', 'tools-ready'] : []);
  return invoke<string[]>('snapshots', {name});
}

export interface ConsoleTail {
  text: string;
  truncated: boolean;
}

export function loadConsoleTail(name: string, lines = 120): Promise<ConsoleTail> {
  if (browserPreview) return Promise.resolve({text: `[    0.000000] Booting Asterism guest\n[    1.482913] ${name} ready on orbit\n$`, truncated: false});
  return invoke<ConsoleTail>('console_tail', {name, lines});
}

export interface BackupReport {
  destination: string;
  files: number;
  logical_bytes: number;
  data_chunks: number;
  reused_chunks: number;
}

export interface RestoreReport {
  instance: string;
  id: string;
  files: number;
  logical_bytes: number;
  rebind: {
    volumes: Array<{kind: string; path: string; source_device: string}>;
    secrets: Array<{secret: string; authority: string; source_device: string}>;
  };
}

export function backupInstance(name: string): Promise<BackupReport> {
  if (browserPreview) return Promise.resolve({destination: `~/.asterism/backups/${name}`, files: 2, logical_bytes: 1024, data_chunks: 1, reused_chunks: 0});
  return invoke<BackupReport>('backup_instance', {name});
}

export function restoreInstance(source: string, name?: string): Promise<RestoreReport> {
  if (browserPreview) return Promise.resolve({instance: name || 'restored', id: 'preview-id', files: 2, logical_bytes: 1024, rebind: {volumes: [], secrets: []}});
  return invoke<RestoreReport>('restore_instance', {source, name: name || null});
}

// ---- the main window: Devices ----------------------------------------------

export interface DeviceRow {
  name: string;
  short_id: string;
  online: boolean;
  path: string;
  is_self: boolean;
  wakeable: boolean;
}

export interface Devices {
  fleet: Fleet<DeviceRow>;
}

export function loadDevices(): Promise<Devices> {
  if (browserPreview) return Promise.resolve(PREVIEW_DEVICES);
  return invoke<Devices>('device_rows');
}

// ---- the main window: Volumes ----------------------------------------------

export interface VolumeRow {
  name: string;
  size: string;
  state: string;
  holder: string;
  holder_device: string;
  epoch: number;
}

export interface Volumes {
  inventory:
    | {kind: 'unreachable'; reason: string}
    | {kind: 'rows'; rows: VolumeRow[]};
}

export function loadVolumes(): Promise<Volumes> {
  if (browserPreview) return Promise.resolve(PREVIEW_VOLUMES);
  return invoke<Volumes>('volume_rows');
}

/** Where a pairing has got to. Tagged, so one field says which it is. */
export type Pairing =
  | {state: 'waiting'}
  | {state: 'ticket'; ticket: string; expires_in_secs: number}
  | {state: 'sas'; code: string; peer: string}
  | {state: 'paired'; name: string; short_id: string}
  | {state: 'failed'; reason: string};

export const PAIRING = 'main://pairing';
export const WAKE = 'main://wake';

/** `invite`, or `add:<ticket>`. */
export function pairStart(spec: string): Promise<void> {
  return invoke<void>('pair_start', {spec});
}

/** The human's verdict on the six digits. */
export function pairConfirm(accept: boolean): Promise<void> {
  return invoke<void>('pair_confirm', {accept});
}

export function pairCancel(): Promise<void> {
  return invoke<void>('pair_cancel');
}

export function onPairing(handler: (state: Pairing) => void) {
  return listen<Pairing>(PAIRING, event => handler(event.payload));
}

/** Wake a sleeping device. Resolves when the daemon has stopped talking. */
export function wake(name: string): Promise<void> {
  return invoke<void>('wake', {name});
}

export function onWake(handler: (line: string) => void) {
  return listen<string>(WAKE, event => handler(event.payload));
}

// ---- the main window: Settings ---------------------------------------------

export interface Service {
  mechanism: string;
  summary: string;
  installed: boolean;
  unit: string;
}

export interface Settings {
  autostart: boolean;
  backends: Backend[];
  default_backend: string;
  daemon: string | null;
  daemon_error: string | null;
  daemon_build: string | null;
  app_build: string;
  update_channel: string;
  update_version: string;
  update_build: string;
  update_manager: string;
  update_error: string | null;
  home: string;
  service: Service;
}

export function loadSettings(): Promise<Settings> {
  if (browserPreview) return Promise.resolve(PREVIEW_SETTINGS);
  return invoke<Settings>('settings_rows');
}

export function setDefaultBackend(id: string): Promise<void> {
  if (browserPreview) return Promise.resolve();
  return invoke<void>('set_default_backend', {id});
}

// ---- doing things ----------------------------------------------------------

/**
 * Perform one action, by the id the tray uses for the same verb.
 *
 * `up:<name>`, `down:<name>`, `term:<name>`, `snap:<name>`,
 * `restore:<name>:<tag>`, `autostart`, `service:install`,
 * `service:uninstall`, `new`. Rust parses these; the strings are built here
 * only because an id is how the boundary is crossed.
 */
export function act(id: string): Promise<void> {
  if (browserPreview) return Promise.resolve();
  return invoke<void>('act', {id});
}

/** Put text on the pasteboard. */
export function copy(text: string): Promise<void> {
  if (browserPreview) return navigator.clipboard.writeText(text);
  return invoke<void>('copy', {text});
}

const PREVIEW_FORM: Form = {
  images: [
    {name: 'ubuntu-24.04', pulled: true},
    {name: 'debian-13', pulled: true},
    {name: 'alpine-3.22', pulled: false},
  ],
  backends: [{id: 'vz', label: 'Apple Virtualization'}, {id: 'qemu', label: 'QEMU'}],
  default_image: 'ubuntu-24.04',
  default_backend: 'vz',
  shape: {cpus: 4, mem_mib: 8192, disk_gib: 40},
  taken: ['night-shift', 'build-cache'],
  taken_error: null,
};

const PREVIEW_INSTANCES: Instances = {fleet: {kind: 'rows', rows: [
  {
    name: 'night-shift', status: 'running', live: true, cpu_device: 'desk-mini',
    backend: 'vz', shape: '4 CPU · 8 GB', image: 'ubuntu-24.04',
    volumes: [{kind: 'block', name: 'agent-work', source_device: 'nas', guest_path: '/dev/vdb', size: '100 GB'}],
    can_start: false, can_stop: true, can_shell: true, can_snapshot: false,
  },
  {
    name: 'build-cache', status: 'stopped', live: true, cpu_device: 'studio',
    backend: 'qemu', shape: '2 CPU · 4 GB', image: 'debian-13', volumes: [],
    can_start: true, can_stop: false, can_shell: false, can_snapshot: true,
  },
]}};

const PREVIEW_DEVICES: Devices = {fleet: {kind: 'rows', rows: [
  {name: 'desk-mini', short_id: '7A2F19C4', online: true, path: 'Direct · 1.2 ms', is_self: true, wakeable: false},
  {name: 'studio', short_id: 'C14B902E', online: true, path: 'Relay · Seoul', is_self: false, wakeable: false},
  {name: 'nas', short_id: '982DE614', online: false, path: 'Last seen 18m ago', is_self: false, wakeable: true},
]}};

const PREVIEW_VOLUMES: Volumes = {inventory: {kind: 'rows', rows: [
  {name: 'agent-work', size: '100 GB', state: 'attached', holder: 'night-shift', holder_device: 'desk-mini', epoch: 12},
  {name: 'artifacts', size: '250 GB', state: 'available', holder: '—', holder_device: '—', epoch: 4},
]}};

const PREVIEW_SETTINGS: Settings = {
  autostart: true,
  backends: PREVIEW_FORM.backends,
  default_backend: 'vz',
  daemon: '0.0.2',
  daemon_error: null,
  daemon_build: '0.0.2+0123456789ab',
  app_build: '0.0.2+0123456789ab',
  update_channel: 'stable',
  update_version: '0.0.2',
  update_build: '0.0.2+0123456789ab',
  update_manager: 'asterism',
  update_error: null,
  home: '~/.asterism',
  service: {mechanism: 'LaunchAgent', summary: 'Running for this user', installed: true, unit: 'run.asterism.astd'},
};
