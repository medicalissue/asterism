# Cloud Hypervisor OCI parts, with a real Secret Service — dev5, 2026-08-27

This is bounded real-host evidence for AST-115: the guest-only secret-egress
door on Cloud Hypervisor, exercised together with the other parts an OCI
instance carries, on real KVM, with no QEMU in the userspace under test and
with a real FreeDesktop Secret Service holding the value.

Before this change `chv` declared `guest_egress: None`, so `ast attach
--secret` refused before registry mutation on the backend `ast` picks by
default on a Linux/KVM host. What is proved below is that the refusal is gone
because a door exists, not because the check was relaxed.

## Artifact and host

- source: the gate ran from `claude/ast-115-chv-oci-parts` at `57b5907d`,
  before the branch was rebased onto `eb320a08`. It is preserved here as
  `64446003` — the same tree, replayed onto a `main` that had since taken
  AST-114's VZ door (#23), the native NBD sparse/discard work (#30) and the
  CI hotfix (#27). The rebase resolved five conflicts, all of them a backend
  stating its own answer where the two branches had each written "the other
  one has no door"; none of them touched the CHV door's own code path.
- the binaries were packaged from `539f2f18` (pre-rebase), which differs from
  `57b5907d` only in `scripts/e2e-chv-oci-parts.sh` (`git diff 539f2f18
  57b5907d -- crates/ packaging/` is empty), so the archive is the code that
  ran. **The rebase is not re-covered by this record**: `main` moved under
  this branch after the gate, and nothing here was re-run against the merged
  result. What guards that is CI plus the executable tests, not this file.
- build id: `0.0.2+ast115`
- archive: `asterism-0.0.2+ast115-linux-x86_64.tar.gz`
- archive SHA-256:
  `48eaeae9180330cb40ce028e58d58f6033ae6711ad4f78f52ae4acad2c288683`
- built on dev5 with `scripts/package-linux.sh`, the same script `packaging/`
  uses; `cloud-hypervisor v53.0` and `virtiofsd v1.14.0` came from their
  pinned URLs and were digest-verified by that script
- host kernel: Linux `6.6.87.2-microsoft-standard-WSL2`, x86_64
- userspace under test: Ubuntu 26.04 container from
  `ubuntu@sha256:2260313b31c8c011cd2eebe728008efac1b3982be73eb71348ea2648d2c0e09b`,
  plus the scaffolding packages listed below
- storage: an ext4 loop filesystem on a dedicated disposable image on dev5's
  D drive, mounted at `/work`, so disk images were written to Linux ext4
  rather than WSL DrvFS
- image: `docker.io/library/nginx:alpine`

**No QEMU.** `scripts/e2e-chv-oci-parts.sh` refuses to start, and refuses to
report green, unless `qemu-img`, `qemu-system-x86_64`, `qemu-system-aarch64`,
`qemu-storage-daemon` and `qemu-nbd` are all absent from `PATH` and from
`/usr/local/bin`, `/usr/bin` and `/usr/sbin`, and unless `dpkg-query` records
no installed `qemu*` package. Both checks ran and passed, at the start and at
the end of the lane. The dev5 *host* outside the container does have QEMU
installed; the container did not share its filesystem.

**Container privileges — weaker than the AST-108 lane, deliberately.** This
container was `--privileged`, with `/dev/kvm` and `/dev/net/tun`. That is
required by `virtiofsd`, which enters a `pivot_root` sandbox and re-applies a
capability set that an unprivileged container cannot satisfy; without a
directory part the lane runs unprivileged, and with one it does not. The
`docs/evidence/native-no-qemu-dev5-2026-08-27` result — that the lifecycle
needs only `/dev/kvm`, `/dev/net/tun`, `NET_ADMIN` and `NET_RAW` — is
therefore **not** re-proved here and must not be read into this one.

## Test scaffolding, and what is product

None of the following is Asterism install. It is host environment that a
headless WSL container does not have and that the gate needs before it can
start. It is listed so a reader can tell it apart from the product.

Installed in the container with `apt-get`:

```text
ca-certificates curl python3 iproute2 openssh-client
dbus-x11 gnome-keyring libsecret-tools
iptables nftables dnsmasq
```

Started before the gate (`scripts/e2e-chv-oci-parts.sh` itself starts none of
it):

```sh
# 1. A session bus and a Secret Service provider. `ast secret create` refuses
#    rather than writing a plaintext fallback, and a bare container image has
#    no provider, so without this there is nothing to gate.
rm -rf /root/.local/share/keyrings /root/.cache/keyring-*
dbus-run-session -- sh -c '
  printf %s asterism-gate-test |
    gnome-keyring-daemon --unlock --components=secrets --daemonize > /tmp/gk.env
  export $(tr "\n" " " < /tmp/gk.env)
  ... run the gate ...
'

# 2. Egress for the guest. Cloud Hypervisor has no user-mode NAT: Asterism
#    gives each instance a TAP with a host address and sets the guest's
#    kernel cmdline to `asterism.dns=<that address>`, so a guest that has to
#    reach a package mirror needs masquerading and a resolver from the host.
iptables -t nat -A POSTROUTING -s 10.64.0.0/10 -j MASQUERADE
dnsmasq --server=8.8.8.8 --server=1.1.1.1 --no-resolv --no-hosts
```

`asterism-gate-test` is the keyring's own unlock password, and it is not the
secret under test. The value the lane stores in Secret Service is a random
per-run sentinel (`raw-chv-oci-sentinel-$$-$RANDOM-$RANDOM`); no real
credential was used anywhere in this record.

`dnsmasq` is deliberately left on the wildcard address rather than given
`--bind-dynamic` or `--listen-address`. The TAP is created and destroyed with
every instance, and a resolver bound to that one address does not come back
when the interface does — a first attempt with `--bind-dynamic` produced a
guest with no resolver and a `base` profile that never applied. That failure
was scaffolding, not product, and is recorded here because the symptom looked
exactly like a product failure.

## Command under test

```sh
AST_BIN=/release/ast \
ASTD_BIN=/release/astd \
ASTERISM_GUEST_AGENT_ARTIFACT=/release/guest/bin/asterism-guest \
E2E_HOME=/work/home-1 \
ASTERISM_TEST_ARTIFACTS=/work/artifacts-1 \
E2E_PROFILE_TIMEOUT=600 \
bash /src/scripts/e2e-chv-oci-parts.sh
```

Its successful terminal record was:

```text
ok: doctor probes org.freedesktop.secrets and names it as the only store
ok: create an OCI VM on the native Cloud Hypervisor backend
ok: the instance records chv and not a compatibility fallback
ok: attach a writable directory part
ok: the raw sentinel entered Secret Service through stdin
ok: bind only an opaque guest handle
ok: boot the bound OCI VM with persistent restart policy
ok: base@2 verifies over authenticated OCI guest control
ok: the writable directory part is writable from the guest
ok: the directory part is shared, not copied
ok: the OCI guest sees an opaque handle, not the Secret Service value
ok: no TCP listener for the door exists on this device
ok: the guest is pointed at its own loopback, not at a shared address
ok: the OCI egress proxy substitutes the Secret Service value in flight
ok: the raw sentinel is absent from the live OCI root disk
ok: the live OCI root disk contains the handle but not the Secret Service value
ok: the raw sentinel is absent from registry, metadata and logs
ok: a restarted daemon adopted Cloud Hypervisor pid 4256 in place
ok: the adopted OCI profile still verifies
ok: the opaque handle survives daemon adoption
ok: write the snapshot control marker
ok: stop for a consistent snapshot
ok: stopping the guest takes its egress door down with it
ok: snapshot the bound OCI root
ok: inspect the OCI snapshot
ok: the raw sentinel is absent from the OCI snapshot
ok: the OCI snapshot contains the handle but not the Secret Service value
ok: export the stopped bound OCI instance
ok: the raw sentinel is absent from the portable OCI backup chunks
ok: the portable backup manifest exports neither value nor handle
ok: boot after the snapshot
ok: change the live OCI disk
ok: stop before restore
ok: restore the OCI snapshot
ok: boot the restored OCI VM
ok: restore returned the OCI disk marker
ok: the restored OCI profile still verifies
ok: the restored OCI handle still resolves through the door
ok: detach the secret part
ok: the detached handle stops resolving, with the guest never rebooted
ok: the raw sentinel is absent from registry, metadata and logs
ok: bugreport contains neither value nor handle; persisted metadata contains no Secret Service value
ok: stop the completed OCI lane
ok: remove the completed OCI lane
CHV OCI PARTS GREEN (docker.io/library/nginx:alpine, chv; door 127.0.0.1:1021 over vsock 1021)
```

The lane then completed `down` and `rm`; no instance row remained.

## Proves

1. **Cloud Hypervisor's secret-egress door works on real KVM.** A guest
   holding only an opaque `ast-…` handle made a real HTTPS request to
   `httpbin.org/bearer`, and the token that arrived upstream hashed to the
   value held in Secret Service. The guest's `HTTPS_PROXY` was
   `http://127.0.0.1:1021` — its own loopback, inside its own network
   namespace.
2. **The door is a path, not a port.** The lane asserted that
   `instances/<name>/chv-vsock.sock_1021` exists as a socket and that nothing
   on this device published TCP port 1021 (`ss -Hltn`). Nothing bound a host
   interface at any point on the path.
3. **The value never reached the guest, its disk, a snapshot, a backup, the
   registry, the logs or `ast bugreport`.** The root disk and the snapshot
   were swept sparsely for the sentinel and for the handle: the handle is
   present (so the sweep can find what is there), the value is not. Every
   non-image file under `$ASTERISM_HOME` was swept for the sentinel twice.
   The portable backup's content-addressed chunks and its manifest carried
   neither the value nor the host-bound handle.
4. **Attach is policy-first.** `ast attach --secret` was accepted on `chv`
   only because the backend declares a door; the same check still refuses on
   a backend that does not, and on a CHV instance created from a cloud image
   whose agent does not carry one. Both refusals are executable tests.
5. **Detach revokes before it refreshes.** After `ast detach --secret`, the
   handle the guest was still holding stopped resolving, with the guest never
   rebooted and its door still bound.
6. **Adoption re-binds the door.** The daemon was killed and restarted under
   a live guest. It adopted Cloud Hypervisor pid 4256 in place — the same pid,
   not a recreated VM — the door came back on the path the VMM already held,
   and the guest's next bound request was served.
7. **Stopping the guest takes the door down with it.** The socket was gone
   after `ast down`.
8. **The parts compose.** A writable directory part over virtiofs, a `base@2`
   profile verified over authenticated OCI guest control, and a
   Secret-Service-backed secret were all attached to the same instance, and
   all three survived snapshot, restore and daemon adoption.
9. **Secret Service is the only store on Linux, and `ast doctor` probes it by
   bus name.** The lane refused to proceed unless `doctor` named the
   FreeDesktop Secret Service and reported the `org.freedesktop.secrets`
   probe.
10. **The vsock transport is loaded only where it is needed.** The guest
    console shows `NET: Registered PF_VSOCK protocol family` on this bound
    guest; the module chain is injected by `InstanceParts::needs_vsock`,
    which is false for an unbound guest and for every QEMU guest.

## Does not prove

- the reboot-equivalent. `wsl.exe --terminate` and restart-policy recovery
  across a distro restart were **not** run: dev5 is shared with other agents'
  in-flight work, and terminating the distro would have destroyed it. This
  lane proves daemon adoption under a live VMM, which is a weaker statement.
  The restart policy was recorded (`ast up --restart always`) but its recovery
  path was not exercised;
- two-device volume fencing over native NBD, and any remote volume part. The
  remote volume *provider* still materialises through `qemu-storage-daemon`
  until AST-109 lands, so this lane attaches a **local directory part only**.
  A related consumer-side defect is known and deferred: after a provider
  daemon restarts under a live guest, the kernel `nbd-client` that CHV
  consumes holds one connection for the device's lifetime and never
  reconnects, so `/dev/nbdN` stalls. The fix belongs in `backend/chv.rs` and
  is not in this change;
- an unprivileged container. See the privileges note above;
- a clean physical Linux installation, or the public installer transaction;
- macOS VZ. Its door is AST-114's and has its own evidence;
- native Hyper-V, which still declares no door and still refuses;
- the cloud-image (non-OCI) CHV lane, which is refused by name;
- CHV remote GPU projection, live migration, or mesh;
- another CPU architecture, Linux kernel, or filesystem;
- guest DNS or outbound NAT as a *product* capability. Asterism sets
  `asterism.dns=<TAP host address>` on the guest cmdline and does not put a
  resolver there; this lane supplied one as scaffolding. That gap is real and
  is not addressed by this change.

Those remain independent gates; this result must not be promoted into them.
