import {useId, useRef, useState} from 'react';
import {Button} from '@astryxdesign/core/Button';

import {Modal} from './Modal';

/**
 * The question asked before something that cannot be undone.
 *
 * One component for all three — restore a snapshot, delete a snapshot,
 * remove an instance — because they differ only in their words and in what
 * has to be typed. A second dialog would be a second set of these rules.
 *
 * The typed word is a courtesy, not the safety property. Rust checks it
 * again in `perform` and sends no frame without it, which is what makes
 * `--click rm:dev` harmless and `--click rm:dev --confirm dev` a removal.
 * Paste is deliberately not blocked: exact matching is the property, and
 * making somebody type it out by hand is theatre rather than safety.
 */
export function ConfirmDialog({
  title,
  body,
  prompt,
  confirmLabel,
  expectedToken,
  typed = false,
  pending = '',
  error = '',
  onConfirm,
  onCancel,
}: {
  title: string;
  body: string;
  /** What to type, and what typing it does. */
  prompt: string;
  confirmLabel: string;
  /** The exact word that has to be typed, when `typed`. */
  expectedToken: string;
  /** Whether this one asks for the word or only for a press. */
  typed?: boolean;
  /** The present-tense verb while the daemon is working, or ''. */
  pending?: string;
  /** The daemon's own refusal, kept on screen until the next attempt. */
  error?: string;
  onConfirm: (token: string) => void;
  onCancel: () => void;
}) {
  const [token, setToken] = useState('');
  const titleId = useId();
  const bodyId = useId();
  const cancel = useRef<HTMLButtonElement>(null);
  const field = useRef<HTMLInputElement>(null);
  const busy = pending !== '';
  // Exact and case-sensitive. Matching is the safety property; a trimmed or
  // lowercased match is a different, weaker one.
  const matches = !typed || token === expectedToken;

  const submit = () => {
    if (!matches || busy) return;
    onConfirm(typed ? token : expectedToken);
  };

  return (
    <Modal
      className="confirm-dialog"
      labelledBy={titleId}
      describedBy={bodyId}
      pending={pending}
      onCancel={onCancel}
      // A typed dialog puts the caret where the work is. An acknowledge one
      // focuses Cancel, so a stray Return does nothing.
      initialFocus={typed ? field : cancel}
    >
      <h2 id={titleId}>{title}</h2>
      <p id={bodyId} className="dialog-body">{body}</p>

      {typed ? (
        <label className="dialog-field">
          <span>{prompt}</span>
          {/* Return in this field does nothing. Typing a name and pressing
              Return is muscle memory, and the whole point of the field is
              to interrupt that: the destructive button has to be reached
              and pressed on purpose. */}
          <input
            ref={field}
            value={token}
            spellCheck={false}
            autoCapitalize="off"
            autoCorrect="off"
            disabled={busy}
            aria-invalid={token !== '' && !matches ? 'true' : undefined}
            onChange={event => setToken(event.target.value)}
            onKeyDown={event => {
              if (event.key === 'Enter') event.preventDefault();
            }}
          />
        </label>
      ) : null}

      {error ? <p className="dialog-error" role="alert">{error}</p> : null}

      <div className="dialog-actions">
        {/* Cancel first in the DOM and first to the left: the way out of a
            destructive question should be what the hand and the tab key
            reach first. Enter does nothing here unless the destructive
            button itself is focused, which is why nothing is a submit. */}
        <Button
          ref={cancel}
          label="Cancel"
          size="md"
          variant="secondary"
          isDisabled={busy}
          onClick={onCancel}
        />
        <Button
          label={busy ? `${pending}…` : confirmLabel}
          size="md"
          variant="destructive"
          isDisabled={!matches || busy}
          onClick={submit}
        />
      </div>
    </Modal>
  );
}
