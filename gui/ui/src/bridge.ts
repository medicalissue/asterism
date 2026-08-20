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
  return invoke<Form>('form');
}

/** Why this name will not do, or null. The daemon's rule, run in process. */
export function nameError(name: string): Promise<string | null> {
  return invoke<string | null>('name_error', {name});
}

/**
 * Define the instance, and boot it if that was asked for. Rejects with the
 * daemon's own words; Rust closes the window itself when it works.
 */
export function create(wanted: Wanted): Promise<void> {
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
  can_start: boolean;
  can_stop: boolean;
  can_shell: boolean;
  can_snapshot: boolean;
}

/** A section that either has rows or has a reason it has none. */
export type Fleet<T> = {kind: 'unreachable'; reason: string} | {kind: 'rows'; rows: T[]};

export interface Instances {
  fleet: Fleet<InstanceRow>;
}

export function loadInstances(): Promise<Instances> {
  return invoke<Instances>('instances');
}

/** The tags on one instance's disk, read when the popover opens. */
export function loadSnapshots(name: string): Promise<string[]> {
  return invoke<string[]>('snapshots', {name});
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
  return invoke<Devices>('device_rows');
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
  home: string;
  service: Service;
}

export function loadSettings(): Promise<Settings> {
  return invoke<Settings>('settings_rows');
}

export function setDefaultBackend(id: string): Promise<void> {
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
  return invoke<void>('act', {id});
}

/** Put text on the pasteboard. */
export function copy(text: string): Promise<void> {
  return invoke<void>('copy', {text});
}
