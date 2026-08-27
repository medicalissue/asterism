# The orbit, and the one namespace inside it

An **orbit** is your set of trusted devices — Tailscale calls the same idea a
tailnet. Membership is a set of Ed25519 public keys, one per device,
established by pairing rather than by a server, and it survives every service
being down: an orbit on a LAN with no coordinator, no relay and no internet is
a fully working orbit.

Two kinds of thing inside it have names you type: **devices**, the machines
that supply compute, and **instances**, the guests that run on them.

## One namespace

Device names and Instance names share a single namespace. A name means exactly
one thing anywhere in the orbit, so one bare name is the address for either
kind of thing:

```console
$ ast ls
NAME   STATUS   IMAGE          SHAPE       DEVICE   AGE  TODAY  ACCESS
bot    running  ubuntu:24.04   2c/2048M/20G studio  4h   $4.12  127.0.0.1:2201
web    running  nginx:alpine   2c/1024M/10G dev5    2h   -      -

$ ast ssh bot           # bot's shell, wherever bot runs
$ ast ssh studio        # the host shell on the device called studio
$ ast logs web -f       # routed to dev5, which is where web is
$ ast move bot studio   # bot's compute, to the device called studio
```

Nothing here names a device *and* an instance, because nothing has to. The
daemon in front of you resolves the name against the whole orbit and forwards
the request to whichever device holds it. `ast` itself holds no device key and
opens no mesh connection.

There is no `--device` flag. Instances are reached by name from any device;
the few commands that really are about one machine's own disk take `--on`:

```console
$ ast images --on studio
$ ast pull nginx:alpine --on studio
$ ast volume create data --size 100G --on storage
$ ast volume ls --on storage
$ ast device check --on studio
```

## Collisions are refused before anything is written

Because a name means one thing, both directions of a clash are refused at the
moment the second thing would be created:

```console
$ ast create studio --image nginx:alpine
error: "studio" is already a device in this orbit — Instance and device names share one namespace
  fix: ast create studio-bot --image …

$ ast device add <ticket> --name bot
error: "bot" is already an instance in this orbit (compute on studio) — Instance and
device names share one namespace: pair with `ast device add <ticket> --name bot-host`,
or rename the instance first with `ast rename bot <new-name>`
```

The pairing refusal happens *before* the peer is written to the orbit store: a
device that is a member is already trusted, so a name clash has to end the
pairing rather than be repaired afterwards.

A name that is neither is refused with both halves of the namespace listed,
because the next thing you want is the list:

```console
$ ast ssh nope
error: unknown name "nope" (orbit has devices: macbook, studio, dev5; instances: bot, web)
```

## When a device is asleep

An instance whose device is not answering is unreachable, which is a different
sentence from "no such instance" — and the difference matters, because one of
them means wake the machine and the other means you typed it wrong:

```console
$ ast ssh web
error: dev5 is offline (last seen 4 min ago) — web is unreachable
```

The row is still in `ast ls`, with its status shown as `unknown`: the instance
is real, only its state is stale. `ast device wake dev5` is the next command.

## `ast ssh <device>` — the host shell

`ast ssh <instance>` splices you into the guest's own ssh server.
`ast ssh <device>` is a different thing: it runs the login shell of the target
device's user account, over the authenticated mesh, with that user's full
authority.

It is **off by default** and is enabled only on the machine that would be
offering it:

```console
studio$ ast device shell enable
laptop$ ast ssh studio
laptop$ ast ssh studio -- uname -a
studio$ ast device shell disable
```

Enabling snapshots the public keys of the devices currently in the orbit; a
device paired later is refused until `enable` is run again locally. A peer
cannot enable it remotely, and the refusal on a device that has not enabled it
says so with the command to run. Read
[docs/device-shell.md](device-shell.md) before turning it on.

## Related

* [Compute is the device an instance runs on](compute-device.md) — what a
  device supplies, and how `ast move` transfers it.
* [Device shell](device-shell.md) — the policy, the session lifecycle and what
  the authority actually is.
* [Orbit storage](orbit-storage.md) — volumes, which are per device rather
  than orbit-global, and why.
