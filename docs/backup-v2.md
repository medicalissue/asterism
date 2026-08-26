# Target-aware backups

`ast backup export` writes format 2 bundles. The manifest records the source
guest platform, the exact `Instance.machine`, every root/snapshot disk format,
and—when the source is OCI—the selected manifest, config, layers, and platform.
The chunk store remains content-addressed and resumable.

An ordinary import is byte-exact and keeps the recorded backend:

```console
ast backup import ~/Backups/agent
```

It may register the stopped Instance before that backend is installed on the
device; the backend is checked when the Instance is started. This does not
convert its disks or change its recorded machine.

To move a compatible disk to another backend on the same architecture, name
the backend explicitly:

```console
ast backup import ~/Backups/agent --backend vz
```

The importer probes that backend and checks its instance-local disk formats
before creating a staging directory or registry row. Raw and already-supported
formats are retained. A standalone qcow2 disk can be materialized as sparse
raw for a raw-only backend. VHDX, ASIF, an unsupported qcow2 feature, duplicate
snapshot formats, and every conversion Asterism cannot perform are refused;
bytes are never relabelled.

## Another CPU architecture

A mutable root disk is architecture-specific. Direct restore from `arm64` to
`amd64`, or the reverse, is refused. An OCI-sourced Instance may instead ask
for a rebuild:

```console
ast backup import ~/Backups/agent --backend hyperv --re-materialize
```

Cross-architecture rebuilding requires an immutable OCI index reference such
as `registry.example/app@sha256:...`. Asterism resolves that index for the
destination architecture, verifies the selected config and manifest, creates
a fresh rootfs, retains Instance identity/configuration, and returns external
volume, secret, and GPU rebind requirements. It does **not** translate packages
or binaries installed into the old root, and it does not import the old root
or its snapshots. Application data that must travel belongs in an attached
portable volume or another explicit data export.

Secrets and host-bound handles are never bundle payloads. Their redacted
rebind requirements survive, so the destination can reconnect them through
its own platform store.

Format 1 bundles remain inspectable and byte-exact restorable to their recorded
machine. They do not contain architecture/materialization metadata, so they
cannot select another backend or request OCI rebuilding.
