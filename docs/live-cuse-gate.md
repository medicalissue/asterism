# Linux live CUSE lifecycle gate

This one-off gate validates production CUSE source from exact candidate
`747a6b9d4c2a300244f28be438f136af1fe15545` (tree
`21f91cb23eafab1240181f977cd1d8e7078f9e47`) on the repository's
GitHub-hosted Ubuntu runner. The observer commit may add this harness and its
workflow, but the gate refuses to run if the candidate's CUSE source,
workspace manifest, crate manifest, or lockfile changed.

The preflight runs `sudo -n modprobe cuse` and then requires `/dev/cuse` to be
a character device readable and writable by the runner user. A missing module,
node, or permission is a failed gate with uploaded diagnostics. It is never a
skip or portable-fixture pass.

After preflight, the gate proves one-read kernel record framing and
malformed/oversized fail-closed parsing, then exercises mount, character-node
publication, open, write, poll, read, signal cancellation/FUSE interrupt, and
bounded teardown through the live kernel CUSE path. Its data-channel socket is
asserted to be `AF_UNIX`; there is no TCP, QEMU, or portable socket-fixture
fallback.

Every run uploads `summary.txt`, phase logs, and `SHA256SUMS` even when the
host blocks the gate. The workflow summary records the GitHub artifact ID,
URL, and digest. This gate makes no NVIDIA hardware-execution claim and does
not provision any host or GPU.
