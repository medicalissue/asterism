# Device shell

Device shell is an opt-in way to use one paired device's own user account over
the existing encrypted Asterism mesh. It is separate from `ast ssh <instance>`:
it does not contact a guest, start `sshd`, or open a TCP listener.

It is disabled by default. On the device whose account will be exposed, run:

```console
$ ast device shell status
$ ast device shell enable
$ ast device shell disable
```

Policy commands are local-only. Enabling snapshots the full public keys of the
devices currently in the orbit; a device paired later is refused until the
target user enables again. The policy survives an `astd` restart. Disabling
first blocks new opens, then terminates every active session Asterism tracks.
Removing a peer from the orbit terminates that peer's tracked sessions too.

From an approved peer:

```console
$ ast ssh --host desktop
$ ast ssh --host desktop -- uname -a
$ ast ssh --host desktop -t -- 'stty size'
```

An interactive terminal gets a PTY automatically. Commands do not get one
unless `-t` is present. Command stdout and stderr remain separate, terminal
resize is forwarded, and the target command's exit status becomes `ast`'s exit
status. The initial directory is the target account's canonical home. Only
bounded `TERM`, `COLORTERM`, `LANG`, and `LC_*` values cross the mesh; account,
path, loader, agent-socket, and Asterism variables are rebuilt or omitted.

## Authority and revocation limits

Enabling grants every approved peer the full authority of the user running
`astd`. This is not a sandboxed command runner. An approved peer can read or
change anything that account can, including Asterism's same-UID Unix socket and
0600 state, install persistence, copy credentials, and use the network. Device
shell refuses to run from a root daemon or when the daemon's real and effective
UID differ, but that does not isolate a shell from its ordinary user account.

Disable, peer removal, disconnect, and daemon shutdown signal the tracked
process group and reap its leader. They cannot undo commands already run,
delete copied data, revoke credentials learned by the peer, or reliably remove
a process that deliberately escaped into a different session or persistence
mechanism. After compromise, remove the peer and rotate the target device
identity and any exposed user credentials. Strong isolation requires a
separate sandboxed execution design, not device shell.

The target writes 0600 structured JSONL audit records to
`$ASTERISM_HOME/shell-audit.jsonl`. Records contain lifecycle events, a random
session ID, the full authenticated peer key, display name, policy epoch, mode,
and result. Commands, environment values, input, output, and terminal
transcripts are not logged. Because the shell has the same UID, this file is an
operational trail rather than tamper-proof evidence; immutable audit needs a
separate remote sink.

## Management read model

The daemon exposes device-shell status as a read-only, authenticated mesh
capability for a future hosted management consumer. It
returns the same `ShellPolicyStatus` JSON model everywhere: `disabled`, `enabled_orbit`,
`active` (with the active session rows), or `unavailable`, plus `changed_at`
as Unix seconds when the visible state last changed. A missing `changed_at`
means an older daemon or a target whose status could not be read.

Policy mutation is a different request and remains local-control-socket only.
The local mutation command deliberately accepts only `enabled: boolean`
and no device target; remote device rows are read-only by construction. A
hosted management panel is outside this implementation and can consume the
same read model without gaining a mutation path.
