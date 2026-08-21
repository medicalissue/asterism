import {useCallback, useEffect, useRef, useState} from 'react';
import {Button} from '@astryxdesign/core/Button';
import {CheckboxInput} from '@astryxdesign/core/CheckboxInput';

import type {Form} from './bridge';
import {closeWindow, create, loadForm, nameError, onProgress} from './bridge';
import {BoxIcon, ChevronIcon, CloudIcon} from './Icons';

type Source = 'cloud' | 'oci';
const STEPS = ['Source', 'Image', 'Resources', 'Review'] as const;

export function NewInstance() {
  const [form, setForm] = useState<Form | null>(null);
  const [step, setStep] = useState(0);
  const [source, setSource] = useState<Source | null>(null);
  const [name, setName] = useState('');
  const [image, setImage] = useState('');
  const [ociImage, setOciImage] = useState('');
  const [backend, setBackend] = useState('');
  const [cpus, setCpus] = useState(2);
  const [memGib, setMemGib] = useState(2);
  const [diskGib, setDiskGib] = useState(20);
  const [start, setStart] = useState(true);
  const [spelling, setSpelling] = useState<string | null>(null);
  const [progress, setProgress] = useState('');
  const [failure, setFailure] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    loadForm().then(loaded => {
      setForm(loaded);
      setImage(loaded.default_image);
      setBackend(loaded.default_backend);
      setCpus(loaded.shape.cpus);
      setMemGib(Math.max(1, Math.round(loaded.shape.mem_mib / 1024)));
      setDiskGib(loaded.shape.disk_gib);
    }, error => setFailure(String(error)));
  }, []);

  useEffect(() => {
    const stop = onProgress(setProgress);
    return () => { stop.then(off => off()); };
  }, []);

  const asked = useRef(0);
  useEffect(() => {
    const mine = ++asked.current;
    if (!name) {
      setSpelling(null);
      return;
    }
    nameError(name).then(error => {
      if (mine === asked.current) setSpelling(error);
    });
  }, [name]);

  const chosenImage = source === 'oci' ? ociImage.trim() : image;
  const nameProblem = spelling ?? (form?.taken.includes(name) ? 'That name already exists in this orbit.' : null);
  const canContinue = step === 0 ? source !== null : step === 1 ? Boolean(name && !nameProblem && chosenImage) : true;

  const submit = useCallback(() => {
    if (!form || !source || !name || nameProblem || !chosenImage || busy) return;
    setBusy(true);
    setFailure('');
    setProgress('Checking the request…');
    create({name, image: chosenImage, cpus, mem_gib: memGib, disk_gib: diskGib, backend, start}).catch(error => {
      setBusy(false);
      setFailure(String(error));
      setProgress('');
    });
  }, [form, source, name, nameProblem, chosenImage, busy, cpus, memGib, diskGib, backend, start]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !busy) void closeWindow();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [busy]);

  return (
    <div className="create-window">
      <header className="create-head" data-tauri-drag-region>
        <div data-tauri-drag-region><span className="eyebrow">NEW INSTANCE</span><h1>Assemble a computer</h1></div>
        <div className="stepper" aria-label="Creation progress">
          {STEPS.map((label, index) => <span key={label} data-state={index === step ? 'current' : index < step ? 'done' : 'ahead'}><i>{index < step ? '✓' : index + 1}</i>{label}</span>)}
        </div>
      </header>

      <main className="create-body">
        {form === null && !failure ? <div className="loading-state"><span className="spinner large" />Reading images and backends…</div> : null}
        {form && step === 0 ? <SourceStep source={source} setSource={setSource} /> : null}
        {form && step === 1 && source ? (
          <ImageStep
            form={form}
            source={source}
            name={name}
            setName={setName}
            nameProblem={nameProblem}
            image={image}
            setImage={setImage}
            ociImage={ociImage}
            setOciImage={setOciImage}
            backend={backend}
            setBackend={setBackend}
          />
        ) : null}
        {form && step === 2 ? <ResourcesStep cpus={cpus} setCpus={setCpus} mem={memGib} setMem={setMemGib} disk={diskGib} setDisk={setDiskGib} /> : null}
        {form && step === 3 && source ? (
          <ReviewStep name={name} source={source} image={chosenImage} backend={backend} backendLabel={form.backends.find(item => item.id === backend)?.label ?? backend} cpus={cpus} mem={memGib} disk={diskGib} start={start} setStart={setStart} />
        ) : null}
      </main>

      <footer className="create-foot">
        <div className="create-status" data-bad={Boolean(failure || nameProblem)}>{failure || progress || (step === 1 ? nameProblem : '') || form?.taken_error || ''}</div>
        <div className="create-actions">
          <Button label="Cancel" size="sm" variant="ghost" isDisabled={busy} onClick={() => void closeWindow()} />
          {step > 0 ? <Button label="Back" size="sm" variant="secondary" isDisabled={busy} onClick={() => setStep(value => value - 1)} /> : null}
          {step < STEPS.length - 1 ? (
            <Button label="Continue" size="sm" variant="primary" endContent={<ChevronIcon />} isDisabled={!canContinue || form === null} onClick={() => setStep(value => value + 1)} />
          ) : (
            <Button label="Create instance" size="sm" variant="primary" isLoading={busy} isDisabled={!canContinue} onClick={submit} />
          )}
        </div>
      </footer>
    </div>
  );
}

function SourceStep({source, setSource}: {source: Source | null; setSource: (source: Source) => void}) {
  return (
    <section className="create-stage source-stage">
      <div className="stage-copy"><h2>What should this instance boot from?</h2><p>Both become real virtual machines. The difference is where their root filesystem comes from.</p></div>
      <div className="source-options">
        <Choice selected={source === 'cloud'} onClick={() => setSource('cloud')} icon={<CloudIcon />} title="Cloud VM" description="Boot a maintained Ubuntu, Debian, Fedora, or Alpine cloud disk." detail="cloud-init · persistent disk" />
        <Choice selected={source === 'oci'} onClick={() => setSource('oci')} icon={<BoxIcon />} title="OCI image" description="Turn a container image into a microVM with its own kernel and isolation." detail="Docker Hub or registry reference" />
      </div>
    </section>
  );
}

function ImageStep({form, source, name, setName, nameProblem, image, setImage, ociImage, setOciImage, backend, setBackend}: {
  form: Form; source: Source; name: string; setName: (value: string) => void; nameProblem: string | null;
  image: string; setImage: (value: string) => void; ociImage: string; setOciImage: (value: string) => void;
  backend: string; setBackend: (value: string) => void;
}) {
  return (
    <section className="create-stage image-stage">
      <div className="stage-copy compact"><h2>Choose the machine</h2><p>Name it across the orbit, then choose only capabilities this device can actually provide.</p></div>
      <label className="create-field"><span>Name</span><input autoFocus value={name} onChange={event => setName(event.target.value)} placeholder="dev" spellCheck={false} aria-invalid={Boolean(nameProblem)} /><small>Unique across the entire orbit</small></label>
      <div className="choice-section">
        <div className="choice-label">{source === 'cloud' ? 'Cloud image' : 'OCI reference'}</div>
        {source === 'cloud' ? (
          <div className="image-options">
            {form.images.map(item => (
              <button key={item.name} className="image-option" aria-pressed={image === item.name} onClick={() => setImage(item.name)}>
                <span className="distro-mark">{item.name.slice(0, 1).toUpperCase()}</span>
                <span><strong>{prettyImage(item.name)}</strong><small>{item.name}</small></span>
                <span className="download-state">{item.pulled ? 'On disk' : 'Downloads'}</span>
              </button>
            ))}
          </div>
        ) : (
          <label className="create-field oci-field"><input value={ociImage} onChange={event => setOciImage(event.target.value)} placeholder="docker.io/library/nginx:latest" spellCheck={false} /><small>A registry reference supported by `ast create`; it will be pulled when needed.</small></label>
        )}
      </div>
      <div className="choice-section">
        <div className="choice-label">Hypervisor backend</div>
        <div className="backend-options">
          {form.backends.map(item => (
            <button key={item.id} className="backend-option" aria-pressed={backend === item.id} onClick={() => setBackend(item.id)}>
              <span className="backend-icon">{item.id === 'vz' ? '⌘' : 'Q'}</span>
              <span><strong>{item.label}</strong><small>{item.id === 'vz' ? 'Apple Virtualization.framework' : 'Portable native virtualization'}</small></span>
            </button>
          ))}
        </div>
      </div>
    </section>
  );
}

function ResourcesStep({cpus, setCpus, mem, setMem, disk, setDisk}: {cpus: number; setCpus: (value: number) => void; mem: number; setMem: (value: number) => void; disk: number; setDisk: (value: number) => void}) {
  return (
    <section className="create-stage resources-stage">
      <div className="stage-copy"><h2>Size the instance</h2><p>These resources come from the device supplying CPU and RAM. You can inspect that source from Control Center.</p></div>
      <div className="resource-options">
        <Resource label="CPU" description="Virtual processor cores" value={cpus} min={1} max={64} setValue={setCpus} />
        <Resource label="Memory" description="Guest working memory" value={mem} unit="GB" min={1} max={512} setValue={setMem} />
        <Resource label="Root disk" description="Persistent boot storage" value={disk} unit="GB" min={5} max={2000} step={5} setValue={setDisk} />
      </div>
    </section>
  );
}

function ReviewStep({name, source, image, backend, backendLabel, cpus, mem, disk, start, setStart}: {name: string; source: Source; image: string; backend: string; backendLabel: string; cpus: number; mem: number; disk: number; start: boolean; setStart: (value: boolean) => void}) {
  return (
    <section className="create-stage review-stage">
      <div className="stage-copy"><h2>Review {name}</h2><p>Asterism will define this instance on the local device and add it to the orbit-wide namespace.</p></div>
      <div className="review-machine">
        <div className="review-glyph">{source === 'cloud' ? <CloudIcon /> : <BoxIcon />}</div>
        <div className="review-title"><strong>{name}</strong><span>{image}</span></div>
        <div className="review-facts"><span><small>SOURCE</small>{source === 'cloud' ? 'Cloud VM' : 'OCI image'}</span><span><small>BACKEND</small>{backendLabel || backend}</span><span><small>RESOURCES</small>{cpus} CPU · {mem} GB · {disk} GB</span></div>
      </div>
      <div className="start-choice"><CheckboxInput label="Start after creation" description="Boot immediately after the image and root disk are ready." value={start} onChange={setStart} /></div>
    </section>
  );
}

function Choice({selected, onClick, icon, title, description, detail}: {selected: boolean; onClick: () => void; icon: React.ReactNode; title: string; description: string; detail: string}) {
  return <button className="source-option" aria-pressed={selected} onClick={onClick}><span className="source-icon">{icon}</span><strong>{title}</strong><p>{description}</p><small>{detail}</small><span className="choice-check">{selected ? '✓' : ''}</span></button>;
}

function Resource({label, description, value, unit, min, max, step = 1, setValue}: {label: string; description: string; value: number; unit?: string; min: number; max: number; step?: number; setValue: (value: number) => void}) {
  return (
    <div className="resource-option"><div><strong>{label}</strong><span>{description}</span></div><div className="number-control"><button aria-label={`Decrease ${label}`} onClick={() => setValue(Math.max(min, value - step))}>−</button><label><input type="number" value={value} min={min} max={max} step={step} onChange={event => setValue(Math.max(min, Math.min(max, Number(event.target.value))))} /><span>{unit}</span></label><button aria-label={`Increase ${label}`} onClick={() => setValue(Math.min(max, value + step))}>+</button></div></div>
  );
}

function prettyImage(value: string) {
  const [name, version] = value.split(':');
  return `${name[0]?.toUpperCase() ?? ''}${name.slice(1)} ${version ?? ''}`.trim();
}
