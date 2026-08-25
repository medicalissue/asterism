# Platform seams

Asterism's product control plane is the same on every supported host. The
operating-system differences live behind a handful of modules that are
allowed to carry `#[cfg(target_os)]`. This file is the decided row for each
of those seams.

| Seam | macOS | Linux | Windows |
|---|---|---|---|
| Persistence | launchd user agent `~/Library/LaunchAgents/com.asterism.astd.plist` | systemd user unit `~/.config/systemd/user/astd.service` | Windows Service `com.asterism.astd` (SCM / `sc.exe create`, `start=auto`, `obj=LocalSystem`, ImagePath `astd.exe --service`) **only** when the ImagePath is under a protected prefix (`Program Files`, `Program Files (x86)`, `Windows`, `ProgramData\Asterism`). A user-writable prefix (`%LOCALAPPDATA%`) is refused: LocalSystem executing a replaceable binary is a privilege-escalation path. |
| Sleep | IOKit `PreventUserIdleSystemSleep` | `systemd-inhibit --what=sleep:idle --mode=block` | `SetThreadExecutionState(ES_CONTINUOUS \| ES_SYSTEM_REQUIRED)` acquired and released on one dedicated thread (`asterism-power`). The API is thread-affine; Drop from a tokio worker is not a release. |
| Secrets | login Keychain `dev.asterism.secret` | Secret Service (when available); otherwise refused, no plaintext fallback | Credential Manager generic credential `dev.asterism.secret/<device>/<name>` |
| Native helper | `astd-vz` next to `astd`, code-signed with `com.apple.security.virtualization` | Cloud Hypervisor / Firecracker as decided by the Linux backend | `astd-hyperv.exe` next to `astd.exe` (`ASTERISM_HYPERV_HELPER` override). `ast doctor` **Probes** the helper over the 510d330 protocol; a file on disk is not readiness. |
| Install / update / uninstall | `install.sh`, signed `RELEASE.json`, Homebrew | `install.sh` source path until a native package lands | `install.ps1` (native) and `install.sh` (Git Bash); SHA-256; optional Authenticode thumbprint; receipt uninstall. The updater (`asterism-update.ps1`) is claimed, backed up, and rolled back on failure. |
| Capability doctor | `ast doctor` / `ast bugreport` | `ast doctor` / `ast bugreport` | `ast doctor`: Windows build 22000+, elevated token, `vmcompute`/`hns`/`vmms`, exact inbound firewall rule `Asterism device daemon` matching `astd.exe` (a Hyper-V group substring is not a pass), helper Probe, SCM, Credential Manager, sleep assertion. Home is reported as experimental and passes only on real HCS/HCN capability, never on SKU alone. |

Windows product virtualization is native Hyper-V behind the helper protocol
preserved from `510d3304e648ae884b125a2eb4dc8d4b92f7475d`. HCS/HCN/VirtDisk
and `AF_HYPERV` stay in the helper. WHPX/QEMU is not a product fallback.
The helper implementation files themselves (`crates/asterism-daemon/src/backend/hyperv.rs`,
`crates/asterism-hyperv/src/windows.rs`) are owned by the backend bead
(`as-lvf.8` / candidate `6b0669f`), not by host integration, and are **not**
merged here.

Host-integration modules `crates/asterism-core/src/windows_host.rs` and
`crates/asterism-core/src/hyperv.rs` are portable: they are compiled on every
target. `cfg(windows)` blocks inside them are skipped on Unix and still live
in rustc dep-info because they are the same files. The unix daemon door
(`AF_UNIX`, `OpenOptionsExt`) is **not** a proven Windows compile; GitHub
`windows-host` is source-and-script only and does not invoke Cargo.

Guest lifecycle (create / boot / snapshot / restart / adoption / stop) on a
real Windows host is **unverified** until the real-host harness records it. Do not
read the decided rows above as a proof that a clean machine already ran
guests. What host integration claims, with executable fixtures:

1. install from a checksummed tarball (`install.ps1` or `install.sh`)
2. `ast doctor` Probes the helper and matches the firewall rule the installer creates
3. `ast service install` refuses LocalSystem + a user-writable prefix
4. SCM STOP sets a latch the daemon accept loop waits on
5. `asterism-update.ps1 apply` is claimed and rolls back on failure
6. `ast bugreport` prints the doctor
