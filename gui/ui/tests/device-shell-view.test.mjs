import assert from 'node:assert/strict';
import test from 'node:test';

import {canSetDeviceShell, changedAtIso, shellStateLabel} from '../src/deviceShellView.ts';

const status = (state, sessions = 0) => ({
  state,
  epoch: 2,
  changed_at: 1_777_777_777,
  active: Array.from({length: sessions}, (_, index) => ({
    session_id: `session-${index}`,
    peer_device_id: `peer-${index}`,
    peer_name: `Peer ${index}`,
    started_at: 1_777_777_700 + index,
    pty: true,
  })),
});

test('all daemon states have the required product label', () => {
  assert.equal(shellStateLabel(status('disabled')), 'Disabled');
  assert.equal(shellStateLabel(status('enabled_orbit')), 'Enabled orbit members');
  assert.equal(shellStateLabel(status('active', 3)), 'Active 3 sessions');
  assert.equal(shellStateLabel(status('unavailable')), 'Unavailable');
});

test('changed_at becomes a stable timestamp and absence stays absent', () => {
  assert.equal(changedAtIso(0), '1970-01-01T00:00:00.000Z');
  assert.equal(changedAtIso(), null);
  assert.equal(changedAtIso(Number.NaN), null);
  assert.equal(changedAtIso(Number.MAX_VALUE), null);
});

test('mutation requires both local identity and local-only authority', () => {
  const row = {
    name: 'laptop', short_id: 'abc', online: true, path: 'direct', wakeable: false,
    is_self: true, shell: {access: 'local_only', status: status('disabled')},
  };
  assert.equal(canSetDeviceShell(row), true);
  assert.equal(canSetDeviceShell({...row, is_self: false}), false);
  assert.equal(canSetDeviceShell({...row, shell: {...row.shell, access: 'read_only'}}), false);
  assert.equal(canSetDeviceShell({...row, shell: {...row.shell, status: status('unavailable')}}), false);
});
