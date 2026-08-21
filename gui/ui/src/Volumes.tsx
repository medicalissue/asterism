import type {Volumes as Model} from './bridge';
import {VolumesIcon} from './Icons';

export function Volumes({model}: {model: Model | null}) {
  if (model === null) return <div className="loading-state"><span className="spinner" />Reading local block volumes…</div>;
  if (model.inventory.kind === 'unreachable') {
    return <div className="failure-state"><strong>Volumes cannot be read</strong><code>{model.inventory.reason}</code></div>;
  }
  const rows = model.inventory.rows;
  if (rows.length === 0) {
    return (
      <div className="zero-state">
        <VolumesIcon />
        <strong>No block volumes on this device</strong>
        <p>Create and attach volumes with the CLI. The Control Center only shows capabilities the daemon exposes safely here.</p>
        <code>ast volume create data --size 20G</code>
      </div>
    );
  }
  return (
    <div className="single-pane volume-pane">
      <div className="scope-note"><strong>Local inventory</strong><span>Volumes belong to the device holding their bytes. This list is intentionally not presented as orbit-wide.</span></div>
      <div className="volume-table" role="table" aria-label="Local block volumes">
        <div className="table-head" role="row"><span>Name</span><span>Size</span><span>State</span><span>Holder</span><span>Fence</span></div>
        {rows.map(row => (
          <div className="table-row" role="row" key={row.name}>
            <span className="table-name"><VolumesIcon /><strong>{row.name}</strong></span>
            <span>{row.size}</span>
            <span><span className={`status-dot ${row.state === 'attached' ? 'busy' : 'running'}`} />{row.state}</span>
            <span>{row.holder ? `${row.holder} on ${row.holder_device}` : '—'}</span>
            <span className="mono">epoch {row.epoch}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
