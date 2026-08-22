import type {Volumes as Model} from './bridge';
import {VolumesIcon} from './Icons';

export function Volumes({model}: {model: Model | null}) {
  if (model === null) return <div className="loading-state"><span className="spinner" />Reading orbit storage…</div>;
  if (model.inventory.kind === 'unreachable') {
    return <div className="failure-state"><strong>Volumes cannot be read</strong><code>{model.inventory.reason}</code></div>;
  }
  const rows = model.inventory.rows;
  if (rows.length === 0) {
    return (
      <div className="zero-state">
        <VolumesIcon />
        <strong>No block volumes in the reachable orbit</strong>
        <p>Create a volume on any device, then attach it by name as one of the instance’s parts.</p>
        <code>ast volume create data --size 20G</code>
      </div>
    );
  }
  return (
    <div className="single-pane volume-pane">
      <div className="scope-note"><strong>Orbit storage</strong><span>One catalog; each row states who owns the bytes and how this device reaches them.</span></div>
      {model.unreachable.map(provider => <div className="failure-state" key={provider.device}><strong>{provider.device} storage is unreachable</strong><code>{provider.reason}</code></div>)}
      <div className="volume-table" role="table" aria-label="Orbit block volumes">
        <div className="table-head" role="row"><span>Name</span><span>Owner · access</span><span>Size</span><span>State</span><span>Policy · fence</span></div>
        {rows.map(row => (
          <div className="table-row" role="row" key={`${row.owner}:${row.name}`}>
            <span className="table-name"><VolumesIcon /><strong>{row.name}</strong></span>
            <span>{row.owner} · {row.access}</span>
            <span>{row.size}</span>
            <span><span className={`status-dot ${row.state === 'attached' ? 'busy' : 'running'}`} />{row.holder ? `${row.holder} on ${row.holder_device}` : row.state}</span>
            <span className="mono">{row.durability} · {row.sharing} · epoch {row.epoch}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
