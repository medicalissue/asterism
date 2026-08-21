import {useEffect, useId, useRef, useState} from 'react';
import {Button} from '@astryxdesign/core/Button';

import {Modal} from './Modal';

/**
 * A dialog that asks for one name: a rename, and a snapshot's tag.
 *
 * Neither of these is destructive, so neither asks for a typed
 * confirmation — a rename is reversible by renaming back, and taking a
 * snapshot only adds one. What they need instead is validation, and the rule
 * is `asterism-core`'s: `validate` is a call into Rust, once per keystroke,
 * rather than a second regular expression living here.
 *
 * The daemon still has the last word. A name free everywhere this device can
 * see may be taken on a device it cannot, so a refusal keeps the dialog open
 * with the daemon's own sentence under the field rather than closing on a
 * change that did not happen.
 */
export function FormDialog({
  title,
  body,
  fieldLabel,
  helper,
  submitLabel,
  initialValue,
  /** A value that would be a no-op, refused without asking the daemon. */
  unchangedValue,
  validate,
  pending = '',
  error = '',
  onSubmit,
  onCancel,
}: {
  title: string;
  body?: string;
  fieldLabel: string;
  helper?: string;
  submitLabel: string;
  initialValue: string;
  unchangedValue?: string;
  validate: (value: string) => Promise<string | null>;
  pending?: string;
  error?: string;
  onSubmit: (value: string) => void;
  onCancel: () => void;
}) {
  const [value, setValue] = useState(initialValue);
  const [why, setWhy] = useState<string | null>(null);
  const titleId = useId();
  const bodyId = useId();
  const helperId = useId();
  const field = useRef<HTMLInputElement>(null);
  const busy = pending !== '';

  // The prefilled value arrives from Rust a tick after the dialog opens
  // (a timestamped tag is generated there, not here), so it is applied
  // rather than only used as an initial state.
  useEffect(() => {
    setValue(initialValue);
    // Selected, not just present: the common case is replacing it.
    field.current?.select();
  }, [initialValue]);

  useEffect(() => {
    let current = true;
    validate(value).then(
      reason => current && setWhy(reason),
      reason => current && setWhy(String(reason)),
    );
    return () => {
      current = false;
    };
  }, [validate, value]);

  const unchanged = unchangedValue !== undefined && value === unchangedValue;
  const ready = why === null && value !== '' && !unchanged && !busy;

  const submit = () => {
    if (ready) onSubmit(value);
  };

  return (
    <Modal
      className="form-dialog"
      labelledBy={titleId}
      describedBy={body ? bodyId : undefined}
      pending={pending}
      onCancel={onCancel}
      initialFocus={field}
    >
      <h2 id={titleId}>{title}</h2>
      {body ? <p id={bodyId} className="dialog-body">{body}</p> : null}

      <label className="dialog-field">
        <span>{fieldLabel}</span>
        <input
          ref={field}
          value={value}
          spellCheck={false}
          autoCapitalize="off"
          autoCorrect="off"
          disabled={busy}
          aria-invalid={why !== null ? 'true' : undefined}
          aria-describedby={helperId}
          onChange={event => setValue(event.target.value)}
          onKeyDown={event => {
            if (event.key === 'Enter') {
              event.preventDefault();
              submit();
            }
          }}
        />
      </label>

      {/* One line under the field, and it is the most specific thing there
          is to say: the daemon's refusal, then the syntax rule, then the
          helper. Never colour alone — each of these is a sentence. */}
      <p className="dialog-helper" id={helperId} role={error || why ? 'alert' : undefined}>
        {error || why || (unchanged ? 'This is already its name.' : helper)}
      </p>

      <div className="dialog-actions">
        <Button label="Cancel" size="md" variant="secondary" isDisabled={busy} onClick={onCancel} />
        <Button
          label={busy ? `${pending}…` : submitLabel}
          size="md"
          variant="primary"
          isDisabled={!ready}
          onClick={submit}
        />
      </div>
    </Modal>
  );
}
