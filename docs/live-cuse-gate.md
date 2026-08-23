# Linux live CUSE lifecycle gate

This one-off gate validates production CUSE source from exact candidate
`747a6b9d4c2a300244f28be438f136af1fe15545` (tree
`21f91cb23eafab1240181f977cd1d8e7078f9e47`) on the repository's
GitHub-hosted Ubuntu runner. The observer commit may add this harness and its
workflow, but the gate refuses to run if the candidate's CUSE source,
workspace manifest, crate manifest, or lockfile changed.

The process that opens `/dev/cuse` is `asterism-gpu-guest` inside the attached
Linux guest, not host `astd`. The host installer therefore ships the guest ELF
unit beside `astd` but does not grant the host account CUSE access. Cloud-init
creates the guest-only `asterism-gpu` system identity and installs the shipped
udev rule as `root:root` mode 0644; that rule keeps `/dev/cuse` root-owned and
grants mode 0660 only to the service group. Direct-kernel OCI guests apply the
same UID/GID boundary on each boot because they deliberately have no udev.

The hosted preflight reproduces that guest service boundary on a real Ubuntu
kernel from the exact checked-in rule. It starts a fresh service identity (no
interactive re-login or inherited supplementary groups), requires that identity
to open the real character device, and requires the ordinary runner account to
be refused. A missing module, node, group transition, or permission is a failed
gate with uploaded diagnostics. It is never a skip or portable-fixture pass.

After preflight, the gate proves one-read kernel record framing and
malformed/oversized fail-closed parsing, then exercises mount, character-node
publication, open, write, poll, read, signal cancellation/FUSE interrupt, and
bounded teardown through the live kernel CUSE path. Its data-channel socket is
asserted to be `AF_UNIX`; there is no TCP, QEMU, or portable socket-fixture
fallback.

The gate also uses the shipped source installer and requires the packaged guest
service and `libcuda` unit to appear beside `astd`. Product uninstall must remove
that unit exactly. Finally it removes the guest rule/account, reloads CUSE, and
proves the ordinary account is refused again, mirroring guest teardown without
granting host `astd` any device authority.

Every run uploads `summary.txt`, phase logs, and `SHA256SUMS` even when the
host blocks the gate. The workflow summary records the GitHub artifact ID,
URL, and digest. This gate makes no NVIDIA hardware-execution claim and does
not provision any host or GPU.
