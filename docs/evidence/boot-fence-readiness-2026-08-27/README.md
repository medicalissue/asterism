# A failed boot, and what "ready" means — AST-161 and AST-162, 2026-08-27

Both defects were found by hand during the AST-148 MAGIC-MOMENTS capture, on
VZ. Both are reproduced here on real hardware against `origin/main`, and then
against this branch.

**Host.** MacBook Pro, macOS 26.5.2 (25F84), arm64. Backend `vz`
(Virtualization.framework 26.5.2) through the ad-hoc-signed `astd-vz` helper
built from this tree. Scratch `ASTERISM_HOME` under `/private/tmp`,
`ASTERISM_MESH=local`. The "before" column is `origin/main` at `9df8be05`
(protocol 17), built from a clean export of that tree; the helper binary is the
same one in both columns, because this branch does not change it.

| file | what it is |
|---|---|
| `ast-161-before.txt` | `origin/main`: a failed boot, and the three commands that refuse |
| `ast-161-after.txt` | this branch: the same failure, resolved and readable |
| `ast-161-fenced-row.txt` | a fence as a daemon killed mid-boot leaves it, and the way out |
| `ast-162-readiness.txt` | one live Ubuntu guest, old `ast status` and new, side by side |
| `astd-ast-161.log`, `astd-ast-162.log` | the daemon's own log for those runs |

## AST-161 — a failed boot left an instance nothing could touch

The failure is the capture's own: an OCI instance whose boot needs the
packaged Linux guest-control agent, on a device that does not have one. It is
raised inside `Hypervisor::boot`, after the durable launch fence is committed
and before any handle exists — precisely the window the fence covers.

**Before** (`ast-161-before.txt`):

```text
$ ast up bot
error: backend launch outcome is ambiguous; durable boot intent
0b53ab58-5ffb-4a3e-89bc-ee76ad8edb94 remains fenced: finding the packaged
Linux OCI guest-control agent: No such file or directory (os error 2)

$ ast status bot          → status:  running
$ ast down bot            → error: instance "bot" is not running
$ ast rm bot              → error: instance "bot" is running — `ast down bot` first
$ ast up bot              → error: instance "bot" has unresolved boot intent
                                   0b53ab58-…; refusing a second guest
```

Three commands, three refusals, no way out — the dead end reported in the
capture, reproduced verbatim.

**After** (`ast-161-after.txt`):

```text
$ ast up bot
error: no VMM for "bot" was left running, so it is recorded stopped
(boot failed): finding the packaged Linux OCI guest-control agent:
No such file or directory (os error 2)

$ ast status bot
status:  stopped (boot failed: finding the packaged Linux OCI guest-control
         agent: No such file or directory (os error 2))

$ ast rm bot
bot  removed
```

The fence is not cleared on a guess. `up` asks the backend whether a VMM it
may have created is still there, and the vz backend answers from the one thing
only a live helper can be holding: this instance's own control socket. Nothing
is bound to it, so the launch is resolved — leases compensated, fence
released — and the outcome is *recorded*, which is what lets `ast status` still
say why an instance nobody asked to stop is stopped.

### The fence a crash leaves, and the two ways out

`ast-161-fenced-row.txt` starts from a row shaped exactly as a daemon killed
inside its boot window leaves one: recorded running, an unresolved
`boot_intent_id`, no handle. All three commands now say one sentence:

```text
$ ast rm bot
error: instance "bot" is holding a boot fence: its last launch left no handle
and the backend cannot prove whether a VMM for it is still running, so
releasing it here could put a second guest on one disk. `ast down bot` lowers
the fence the moment the backend can prove there is nothing left; while it
cannot, check yourself that no VMM for "bot" is running
  fix: ast down --force bot

$ ast up bot     → the same sentence, and the same fix line
$ ast down bot   → bot  stopped
$ ast status bot → status:  stopped (boot failed: the launch left no VMM running)
$ ast rm bot     → bot  removed
```

`ast down` is the ordinary way out, because it asks the backend again — a
fence can outlive the daemon that raised it, and nothing used to go back and
look. `--force` buys exactly one thing: releasing a fence whose outcome
*cannot* be proven. It buys nothing against a VMM that is demonstrably there;
that one is running rather than stuck, and no flag turns a process this daemon
holds no handle for into one it may retire.

On VZ the unprovable answer never came up on this host: the control socket is
instance-bound and always tells. `Unknown` is the default for any backend that
keeps no such record, and is covered by
`instance::tests::a_lost_launch_nobody_can_prove_keeps_its_fence_and_says_how_to_end_it`.

## AST-162 — two readiness probes, and the reassuring one won

One live Ubuntu 24.04 guest on VZ, reachable, `ast ssh` working. Then, from
inside it, sshd is stopped and something else is left holding port 22:

```text
$ ast ssh dev -- sudo sh -c "systemctl stop ssh.socket ssh.service;
    setsid python3 -m http.server 22 --bind 0.0.0.0 & ss -ltnp"
LISTEN 0 5   0.0.0.0:22  users:(("python3",pid=1279,fd=3))
```

The guest's agent reads its own `/proc` and sees a listener on 22, which is
true. Nothing out here can ssh to it, which is also true. Both `ast` binaries
then ask the *same daemon* about the *same guest*:

```text
--- origin/main
guest:   192.168.64.44, fd1a:…:fffc · up 11s · ssh listening · cloud-init done
health:  load 0.23 · memory 1626 MiB available

--- this branch
ready:   no — 192.168.64.44:22 accepts connections but sent no ssh banner
         within 600ms (last reachable 5s ago)
guest:   192.168.64.44, fd1a:…:fffc · up 11s · guest says sshd listening ·
         cloud-init done
health:  load 0.23 · memory 1626 MiB available
```

Readiness is now measured the way `ast ssh` and `ast exec` measure it: sshd's
own banner for a cloud image, an authenticated agent session for an OCI guest,
the control socket for a container. A port that accepts and says nothing is
what a liveness check calls healthy, and it is exactly the case in front of
us. What the guest says about itself is still on the page — it is worth
reading — and now says whose opinion it is.

The healthy line, from the same run before the injection:

```text
ready:   yes (ssh banner from 192.168.64.42:22)
guest:   192.168.64.42, fe80::…:fffc · up 8s · guest says sshd listening ·
         cloud-init running
```

Note the two disagreeing honestly a second time: cloud-init is still running
and the guest is already reachable.

## What was not reproduced

The capture's original AST-162 sighting was a *bridge* failure — three guests
on one VZ bridge after a deliberate `kill -9` of `astd` and `astd-vz`, none of
them reachable afterwards. That half is a separate defect about the bridge, and
this branch does not claim to fix it. What it fixes is the screen: a guest
nobody can reach can no longer read as ready.
