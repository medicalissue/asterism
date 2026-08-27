# Linux runtime components

Linux uses Cloud Hypervisor over KVM as the product backend. QEMU is an
explicit compatibility/development backend; it is not in Linux's default
selection order ahead of Cloud Hypervisor.

Binary releases contain `ast`, `astd`, the exact `cloud-hypervisor` v53.0
static binary published upstream, and `virtiofsd` v1.14.0 built from its
tagged source. The immutable URLs, input digests and licenses are recorded in
`packaging/linux-components.env`. The release archive is checksummed as one
unit, so installation requires neither a Rust toolchain nor a separately
installed VMM. The installer grants the bundled VMM only `CAP_NET_ADMIN`,
which it needs to create per-instance TAP devices; KVM access remains governed
by `/dev/kvm` ownership. Its executable payload is flat (the layout consumed
by `packaging/install.sh`) and carries the Asterism `LICENSE-*` and `NOTICE`
files alongside the component notices.

Catalog cloud images are retained as publisher-verified qcow2 until a native
backend first uses them. Asterism's read-only Rust qcow2 v2/v3 materializer
preflights the active mapping and refcounts, writes sparse raw under a staging
name, and durably adopts it before Cloud Hypervisor sees it. That raw base can
then be cloned and grown to `disk_gib`. No QEMU binary or runtime converter is
installed on the Linux product path; QEMU is a separately installed explicit
compatibility backend.

Remote volumes are served by a native NBD exporter inside `astd` itself, over
a per-epoch Unix socket; no `qemu-storage-daemon` is installed or spawned on
the provider side. See [orbit-storage.md](orbit-storage.md) for what that
exporter negotiates and how it keeps volumes sparse.

The consumer side uses the kernel NBD client below the backend seam. On a clean
host the installer adds `nbd-client` plus `kmod` (`nbd` plus `kmod` on
Fedora-family systems), loads `nbd` with 64 devices, and records the same
setting under `modules-load.d` and `modprobe.d` for reboot. The daemon has no
general root or `nbd-client` permission: sudoers allows the installing account
to run `/usr/local/libexec/asterism/asterism-nbd` and the exact
`setcap cap_net_admin+ep <installed-cloud-hypervisor>` updater command without
a prompt. The latter restores the one capability lost when a verified update
replaces the VMM inode; rollback restores the old capable inode and explicitly
reapplies the same capability. The root-owned NBD wrapper accepts only
attach/detach and diagnostic probe forms used by Asterism and only
for `/dev/nbd0` through `/dev/nbd63`; after attach it grants the invoking
unprivileged account access to that selected device only, then restores root
ownership on detach. The wrapper owns a `flock` on
`/run/lock/asterism-nbd.lock` and an atomic root-owned claim under
`/run/asterism-nbd`; selection, claim, attach, owner capture, and detach are
one system-wide critical section. Detach checks the invoking uid/gid against
the claim, so a racing or cross-owner caller cannot disconnect the winner's
device. Uninstall removes that state and the account's sudoers rule. If detach
fails, the instance keeps its device-and-kernel-pid ownership record so later
stop or state reconciliation can retry safely.

Component updates are deliberate release changes, never a moving download:
update the lock file, run the common backend suite on Ubuntu and Fedora, boot
the pinned cloud and OCI lanes on KVM, and publish a new Asterism tag. Existing
guests keep the VMM process that started them. A daemon upgrade may adopt that
process by its executable plus instance-owned API/pid paths, and no installer
rewrites a running executable in place.

Cloud Hypervisor is Apache-2.0 and BSD-3-Clause; virtiofsd is Apache-2.0 and
BSD-3-Clause. Their license texts are included by the Linux release packaging
under `share/asterism/licenses/`.

## Installed shapes

Linux has two installed shapes, and the daemon finds its own components in
both without an environment override:

| | `ast`/`astd` | pinned helpers | guest payloads | component lock and licenses |
|---|---|---|---|---|
| flat prefix (`packaging/install.sh`) | `<prefix>/bin` | beside `astd` | beside `astd` | `<prefix>/share/asterism` |
| native package (`.deb`, `.rpm`) | `/usr/bin` | `/usr/libexec/asterism` | `/usr/lib/asterism` | `/usr/share/asterism` |

The shapes differ because a distribution package may not write into
`/usr/local`, and because `/usr/bin/cloud-hypervisor` would be Asterism
claiming a distribution-wide name for a version-pinned private copy.
`asterism_core::layout` owns the difference: every lookup searches the shape
the running executable was installed as first, then the absolute system
shapes. The NBD wrapper is resolved the same way, because its path is the
subject of the sudoers rule and the daemon has to name the one the
installation authorised.

The package installs `/usr/lib/systemd/user/astd.service`,
`/usr/lib/modules-load.d/asterism-nbd.conf`,
`/usr/lib/modprobe.d/asterism-nbd.conf` and
`/usr/lib/tmpfiles.d/asterism-nbd.conf` — the vendor directories, not `/etc`,
because those files are the package's and not the administrator's. Its
post-install grants the bundled VMM `cap_net_admin+ep`, materialises the
root-owned NBD lock and claim directory, and loads `nbd` with 64 devices.
None of those may fail the installation: a container without
module-loading rights makes one feature unavailable, and `ast doctor` says
which.

What the package deliberately does **not** do is write the sudoers rule. That
rule names one account and one uid; at package-install time the only account
present is root, and root is not who runs the daemon. So the package ships
`/usr/libexec/asterism/asterism-nbd-policy`, and `ast service install` — run
by the account that will own the instances — invokes it through `sudo`. It
writes the same `/etc/sudoers.d/asterism-nbd-<uid>` with the same two lines
and the same `visudo -cf` validation `install.sh` uses, so the two shapes
cannot leave two conflicting rules for one account. `ast service uninstall`
withdraws it, and asks for a password to do so: the rule authorises the NBD
wrapper and the updater's capability restore, not the helper that writes the
rule, so an account cannot silently re-grant itself. Removing the package
removes every rule the helper wrote, whether or not the account got that far.

Package removal refuses while an NBD device is still attached, for the same
reason `install.sh --uninstall` does: the wrapper and its sudoers rule are
the only way left to detach it. Removal leaves `~/.asterism` alone, does not
unload the running `nbd` module (it is the kernel's, not Asterism's, and
other software may hold it), and cannot disable another account's systemd
user unit — `ast service uninstall` is that command, per account by
construction.

In-app updates over a packaged install are refused the way Homebrew is:
`ast update status` reports `manager dpkg` or `manager rpm`, `check` still
verifies the signed manifest and reports what is available, and `apply`
refuses with `apt-get install --only-upgrade asterism` or
`dnf upgrade asterism`. Files under `/usr` belong to the package database,
and rewriting them from underneath it would leave that database describing
bytes that are no longer on disk.

## Host integration

`astd` is a systemd `--user` unit (`~/.config/systemd/user/astd.service`)
with `Restart=always` and `WantedBy=default.target`. A user unit dies at
logout unless lingering is on:

```console
$ ast service install
$ loginctl enable-linger "$USER"
$ ast doctor
```

While at least one instance is running, the daemon holds
`systemd-inhibit --what=sleep:idle --mode=block`. The lock is a child of
`astd`, so a dead daemon cannot keep the machine awake.

Secret material lives in FreeDesktop Secret Service
(`org.freedesktop.secrets`) under `dev.asterism.secret`. There is no
plaintext file fallback. A headless host needs a session bus and a Secret
Service provider (gnome-keyring, KWallet, or KeePassXC). `ast doctor`
probes the bus name rather than checking that an environment variable is set.
