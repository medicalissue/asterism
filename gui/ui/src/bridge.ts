// The Rust side, as seen from the webview.
//
// Twenty commands and four events, which is the whole surface. The types
// here mirror `src/newinstance.rs`, `src/instances.rs`, `src/devices.rs` and
// `src/settings.rs`; the field names are snake_case because the shapes
// crossing this boundary are the daemon's own structs, and renaming them on
// the way through would be one more thing to keep in step.
//
// Nothing here decides anything. Which buttons a row offers, whether a
// backend may be chosen, why a name or a snapshot tag will not do, what an
// action in flight is called, whether a typed word is the right one: all of
// it is decided in Rust, against the daemon's own rules, and arrives as data.

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
  id: string;
  name: string;
  /** `running`, `stopped`, `defined`, or `unknown` when its device is out
      of touch. */
  status: string;
  /** What the registry last recorded, when `status` is `unknown`. */
  last_status: string | null;
  live: boolean;
  cpu_device: string;
  backend: string;
  shape: string;
  image: string;
  created_at: number;
  /** `always` or `never`. */
  policy_restart: string;
  policy_max_attempts: number;
  /** What that policy actually promises. Written in Rust; see
      `instances::policy_sentence` for why it is not written here. */
  policy_sentence: string;
  /** Everything the instance is assembled from, in the daemon's own order
      and wording. This is the parts table. */
  parts: PartRow[];
  conflict: {other_cpu_device: string; found_at: number} | null;
  moving: {to_device: string; epoch: number; started_at: number} | null;
  move_epoch: number;
  // The gates. Eight booleans, all decided in `src/instances.rs`; no
  // component below may recompute one from `status` or `live`.
  can_start: boolean;
  can_stop: boolean;
  can_shell: boolean;
  can_read_logs: boolean;
  can_read_snapshots: boolean;
  can_snapshot: boolean;
  can_rename: boolean;
  can_remove: boolean;
}

export interface PartRow {
  /** `cpu/ram`, `disk`, `volume`, `secret`, `network`, `gpu`. */
  kind: string;
  /** The device supplying it, or `-` when nothing does. */
  source: string;
  detail: string;
  note: string | null;
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

export interface SnapshotRow {
  id: string;
  tag: string;
  size: string;
  /** `YYYY-MM-DD HH:MM:SS`, as the daemon formats it. */
  date: string;
}

/**
 * The snapshots on one instance's disk, read when the detail pane asks
 * rather than on every poll. Rejects with the daemon's own words; an empty
 * list means the disk has none, and the two must not look alike.
 */
export function loadSnapshots(name: string): Promise<SnapshotRow[]> {
  if (browserPreview) return Promise.resolve(name === 'night-shift' ? PREVIEW_SNAPSHOTS : []);
  return invoke<SnapshotRow[]>('snapshots', {name});
}

/** Why this snapshot name will not do, or null. `asterism-core`'s rule. */
export function snapshotTagError(tag: string): Promise<string | null> {
  if (browserPreview) return Promise.resolve(/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/.test(tag) ? null : 'Use letters, digits, hyphens, underscores, and periods. The first character must be a letter or digit.');
  return invoke<string | null>('snapshot_tag_error', {tag});
}

/** The name a Take snapshot dialog opens on: the tray's and the CLI's. */
export function defaultSnapshotTag(): Promise<string> {
  if (browserPreview) return Promise.resolve('snap-20260822T090000Z');
  return invoke<string>('default_snapshot_tag');
}

export interface ConsoleTail {
  text: string;
  truncated: boolean;
}

export function loadConsoleTail(name: string, lines = 120): Promise<ConsoleTail> {
  if (browserPreview) return Promise.resolve({text: `[    0.000000] Booting Asterism guest\n[    1.482913] ${name} ready on orbit\n$`, truncated: false});
  return invoke<ConsoleTail>('console_tail', {name, lines});
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
export const ROUTE = 'main://route';

/**
 * Where something outside the window asked it to go: the tray's Restore and
 * Remove items, which never mutate from a menu click.
 *
 * Two ways in, because a route can be decided before there is a window to
 * tell. A window that is starting takes the queued one on mount
 * ({@link takeRoute}); one that was already up is told ({@link onRoute}).
 */
export interface Route {
  section: string;
  instance: string | null;
  /** `restore:<tag>`, `snapshot-delete:<tag>`, or `remove`. */
  intent: string | null;
}

export function takeRoute(): Promise<Route | null> {
  if (browserPreview) return Promise.resolve(null);
  return invoke<Route | null>('take_route');
}

export function onRoute(handler: (route: Route) => void) {
  return listen<Route>(ROUTE, event => handler(event.payload));
}

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
 * `up:<name>`, `up:<name>:always`, `up:<name>:never`, `down:<name>`,
 * `term:<name>`, `rename:<name>:<new>`, `rm:<name>`, `snap:<name>`,
 * `snap:<name>:<tag>`, `restore:<name>:<tag>`, `snaprm:<name>:<tag>`,
 * `autostart`, `service:install`, `service:uninstall`, `new`. Rust parses
 * these; the strings are built here only because an id is how the boundary
 * is crossed.
 *
 * `confirmation` is the word typed into a destructive dialog. Rust checks
 * it — a restore, a snapshot delete or a removal without the exact tag or
 * name sends no frame. Rejects with the daemon's own sentence.
 */
export function act(id: string, confirmation?: string): Promise<void> {
  if (browserPreview) return Promise.resolve();
  return invoke<void>('act', {id, confirmation: confirmation ?? null});
}

/** What one action is called, and what it is about. Rust's vocabulary. */
export interface ActionLabel {
  /** `Starting`, `Removing`… null when it is over before a frame is drawn. */
  verb: string | null;
  subject: string | null;
  /** The long form, as the log and the status row say it. */
  what: string;
  /** The exact word a confirmation dialog has to collect, or null. */
  confirmation: string | null;
}

export function actionLabel(id: string): Promise<ActionLabel> {
  if (browserPreview) return Promise.resolve({verb: 'Working', subject: null, what: id, confirmation: null});
  return invoke<ActionLabel>('action_label', {id});
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

const PREVIEW_SNAPSHOTS: SnapshotRow[] = [
  {id: '1', tag: 'clean-install', size: '412 MiB', date: '2026-08-14 11:02:31Z'},
  {id: '2', tag: 'tools-ready', size: '1.1 GiB', date: '2026-08-19 08:40:07Z'},
];

const PREVIEW_INSTANCES: Instances = {fleet: {kind: 'rows', rows: [
  {
    id: 'c0ffee', name: 'night-shift', status: 'running', last_status: null, live: true,
    cpu_device: 'desk-mini', backend: 'vz', shape: '4 CPU · 8 GB · 60 GB',
    image: 'ubuntu-24.04', created_at: 1_755_000_000,
    policy_restart: 'always', policy_max_attempts: 3,
    policy_sentence: 'If it was running, astd restarts it after an unexpected stop or device reboot, up to 3 attempts. Stop remains stopped.',
    parts: [
      {kind: 'cpu/ram', source: 'desk-mini', detail: '4 cores · 8192 MiB', note: null},
      {kind: 'disk', source: 'desk-mini', detail: '60 GiB · ubuntu-24.04', note: 'follows cpu'},
      {kind: 'volume', source: 'nas', detail: 'agent-work (100 GB) -> a disk in the guest', note: 'nbd over the mesh · lease epoch 12'},
      {kind: 'network', source: 'desk-mini', detail: 'user-mode NAT · 127.0.0.1:8080 -> :80', note: 'exit default: same as cpu'},
      {kind: 'gpu', source: '-', detail: 'none', note: null},
    ],
    conflict: null, moving: null, move_epoch: 0,
    can_start: false, can_stop: true, can_shell: true, can_read_logs: true,
    can_read_snapshots: true, can_snapshot: false, can_rename: false, can_remove: false,
  },
  {
    id: 'decaf', name: 'build-cache', status: 'stopped', last_status: null, live: true,
    cpu_device: 'studio', backend: 'qemu', shape: '2 CPU · 4 GB · 20 GB',
    image: 'debian-13', created_at: 1_754_000_000,
    policy_restart: 'never', policy_max_attempts: 3,
    policy_sentence: 'Asterism starts it only when you ask.',
    parts: [
      {kind: 'cpu/ram', source: 'studio', detail: '2 cores · 4096 MiB', note: null},
      {kind: 'disk', source: 'studio', detail: '20 GiB · debian-13', note: 'follows cpu'},
      {kind: 'network', source: 'studio', detail: 'user-mode NAT', note: 'exit default: same as cpu'},
      {kind: 'gpu', source: '-', detail: 'none', note: null},
    ],
    conflict: null, moving: null, move_epoch: 0,
    can_start: true, can_stop: false, can_shell: false, can_read_logs: true,
    can_read_snapshots: true, can_snapshot: true, can_rename: true, can_remove: true,
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
  home: '~/.asterism',
  service: {mechanism: 'LaunchAgent', summary: 'Running for this user', installed: true, unit: 'run.asterism.astd'},
};
