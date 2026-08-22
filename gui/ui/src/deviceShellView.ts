import type {DeviceRow, ShellPolicyStatus} from './bridge';

/** The four product labels shared by the row and detail views. */
export function shellStateLabel(status: ShellPolicyStatus): string {
  if (status.state === 'disabled') return 'Disabled';
  if (status.state === 'enabled_orbit') return 'Enabled orbit members';
  if (status.state === 'active') return `Active ${status.active.length} sessions`;
  return 'Unavailable';
}

/** Stable machine-readable time for `<time dateTime>`, or no claimed time. */
export function changedAtIso(changedAt?: number): string | null {
  if (changedAt === undefined || !Number.isFinite(changedAt) || changedAt < 0) return null;
  const changed = new Date(changedAt * 1000);
  return Number.isFinite(changed.getTime()) ? changed.toISOString() : null;
}

/** Only this packaged app's local-device row may show a policy control. */
export function canSetDeviceShell(row: DeviceRow): boolean {
  return row.is_self && row.shell.access === 'local_only' && row.shell.status.state !== 'unavailable';
}
