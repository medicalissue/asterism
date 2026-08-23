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

Catalog cloud images remain in their publisher-verified qcow2 form on disk and
Cloud Hypervisor consumes them directly. The backend validates the qcow2
virtual size without rewriting its metadata: an image whose size does not
exactly match `disk_gib` is refused, rather than silently grown or shrunk. The
Linux installer never adds a runtime converter to make an unsafe format
transition appear to work; choose QEMU when a conversion is required.

Remote volumes use the kernel NBD client below the backend seam. On a clean
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
