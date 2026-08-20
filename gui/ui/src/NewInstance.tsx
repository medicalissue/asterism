// The New Instance dialog.
//
// Six controls, one line of status, two buttons. Nothing in here decides
// anything: the name rule, the image list, the shape defaults and which
// backends exist all come from Rust, which gets them from the same places
// `ast` does.
//
// The controls come out of controls.tsx, which the main window draws from
// too; see the note at the top of controls.css for why they are written here
// rather than taken from Astryx or from the platform.

import {useCallback, useEffect, useRef, useState} from 'react';

import type {Form} from './bridge';
import {closeWindow, create, loadForm, nameError, onProgress} from './bridge';
import {Check, NumberField, Select} from './controls';

export function NewInstance() {
  const [form, setForm] = useState<Form | null>(null);
  const [name, setName] = useState('');
  const [image, setImage] = useState('');
  const [cpus, setCpus] = useState(2);
  const [memGib, setMemGib] = useState(2);
  const [diskGib, setDiskGib] = useState(20);
  const [backend, setBackend] = useState('');
  const [start, setStart] = useState(false);

  const [spelling, setSpelling] = useState<string | null>(null);
  const [step, setStep] = useState<string | null>(null);
  const [failure, setFailure] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    loadForm().then(
      loaded => {
        setForm(loaded);
        setImage(loaded.default_image);
        setBackend(loaded.default_backend);
        setCpus(loaded.shape.cpus);
        setMemGib(Math.max(1, Math.round(loaded.shape.mem_mib / 1024)));
        setDiskGib(loaded.shape.disk_gib);
      },
      (e: unknown) => setFailure(String(e)),
    );
  }, []);

  // Progress arrives as events rather than as a return value, because a
  // pull is minutes long and a return value shows up once, at the end.
  useEffect(() => {
    const stop = onProgress(setStep);
    return () => {
      stop.then(off => off());
    };
  }, []);

  // The spelling rule lives in Rust. Asking per keystroke costs a function
  // call, and a stale answer is dropped when a later keystroke overtakes it.
  const asked = useRef(0);
  useEffect(() => {
    const mine = ++asked.current;
    if (name === '') {
      setSpelling(null);
      return;
    }
    nameError(name).then(why => {
      if (asked.current === mine) setSpelling(why);
    });
  }, [name]);

  const taken = form?.taken.includes(name) ?? false;
  const nameProblem = spelling ?? (taken ? 'Name taken.' : null);
  const ready = form !== null && name !== '' && nameProblem === null && !busy;

  const submit = useCallback(() => {
    if (!ready) return;
    setBusy(true);
    setFailure(null);
    setStep('Checking.');
    create({name, image, cpus, mem_gib: memGib, disk_gib: diskGib, backend, start}).catch(
      (why: unknown) => {
        setBusy(false);
        setStep(null);
        setFailure(String(why));
      },
    );
  }, [ready, name, image, cpus, memGib, diskGib, backend, start]);

  // Escape closes and Return creates, from anywhere in the dialog.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (busy) return;
      if (e.key === 'Escape') void closeWindow();
      if (e.key === 'Enter') submit();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [busy, submit]);

  const images = form?.images ?? [];
  const backends = form?.backends ?? [];
  const status = failure ?? nameProblem ?? step ?? form?.taken_error ?? '';
  const bad = failure !== null || nameProblem !== null || form?.taken_error != null;

  return (
    <div className="dialog">
      <div className="form">
        <span className="label">Name</span>
        <input
          className="field"
          value={name}
          placeholder="dev"
          autoFocus
          spellCheck={false}
          autoComplete="off"
          disabled={busy}
          aria-label="Name"
          aria-invalid={nameProblem !== null}
          onChange={e => setName(e.target.value)}
        />

        <span className="label">Image</span>
        <Select
          label="Image"
          value={image}
          onChange={setImage}
          disabled={busy}
          options={images.map(i => ({
            value: i.name,
            aside: i.pulled ? undefined : 'downloads',
          }))}
        />

        <span />
        <div className="trio">
          <NumberField label="CPU" value={cpus} set={setCpus} min={1} max={64} busy={busy} />
          <NumberField
            label="Memory"
            value={memGib}
            set={setMemGib}
            min={1}
            max={512}
            unit="GB"
            busy={busy}
          />
          <NumberField
            label="Disk"
            value={diskGib}
            set={setDiskGib}
            min={5}
            max={2000}
            unit="GB"
            busy={busy}
          />
        </div>

        {/* One backend is not a choice, so Rust sends one entry and this row
            never appears. */}
        {backends.length > 1 ? (
          <>
            <span className="label">Backend</span>
            <Select
              label="Backend"
              value={backend}
              onChange={setBackend}
              disabled={busy}
              options={backends.map(b => ({value: b.id, label: b.label}))}
            />
          </>
        ) : null}

        <span />
        <Check checked={start} onChange={setStart} disabled={busy}>
          Start after create
        </Check>
      </div>

      <div className="footer">
        <span className="status" data-bad={bad} title={status}>
          {status}
        </span>
        <div className="buttons">
          <button className="button" disabled={busy} onClick={() => void closeWindow()}>
            Cancel
          </button>
          <button className="button primary" disabled={!ready} onClick={submit}>
            Create
          </button>
        </div>
      </div>
    </div>
  );
}
