# Platform seams

Asterism's product control plane is the same on every supported host. The
operating-system differences live behind a handful of modules that are
allowed to carry `#[cfg(target_os)]`. This file is the decided row for each
of those seams.

| Seam | macOS | Linux | Windows |
|---|---|---|---|
| Persistence | launchd user agent `~/Library/LaunchAgents/com.asterism.astd.plist` | systemd user unit `~/.config/systemd/user/astd.service` | Windows Service `com.asterism.astd` (SCM / `sc.exe create`, `start=auto`, ImagePath `astd.exe --service`) |
| Sleep | IOKit `PreventUserIdleSystemSleep` | `systemd-inhibit --what=sleep:idle --mode=block` | `SetThreadExecutionState(ES_CONTINUOUS \| ES_SYSTEM_REQUIRED)` |
| Secrets | login Keychain `dev.asterism.secret` | Secret Service (when available); otherwise refused, no plaintext fallback | Credential Manager generic credential `dev.asterism.secret/<device>/<name>` |
| Native helper | `astd-vz` next to `astd`, code-signed with `com.apple.security.virtualization` | Cloud Hypervisor / Firecracker as decided by the Linux backend | `astd-hyperv.exe` next to `astd.exe` (`ASTERISM_HYPERV_HELPER` override) |
| Install / update / uninstall | `install.sh`, signed `RELEASE.json`, Homebrew | `install.sh` source path until a native package lands | `install.ps1` (native) and `install.sh` (Git Bash); SHA-256; optional Authenticode thumbprint; receipt uninstall |
| Capability doctor | `ast doctor` / `ast bugreport` | `ast doctor` / `ast bugreport` | `ast doctor`: Windows 11 Pro/Enterprise build 22000+, elevated token, `vmcompute`/`hns`/`vmms`, Hyper-V firewall group, helper, SCM, Credential Manager, sleep assertion |

Windows product virtualization is native Hyper-V behind the helper protocol
preserved from `510d3304e648ae884b125a2eb4dc8d4b92f7475d`. HCS/HCN/VirtDisk
and `AF_HYPERV` stay in the helper. WHPX/QEMU is not a product fallback.
The helper implementation files themselves (`crates/asterism-daemon/src/backend/hyperv.rs`,
`crates/asterism-hyperv/src/windows.rs`) are owned by the backend bead, not
by host integration.

A clean Windows machine, with no development tools, is expected to:

1. install from a signed tarball (`install.ps1` or `install.sh`)
2. pass `ast doctor`
3. persist via `ast service install`
4. create, reboot (service comes back), update, uninstall
5. export `ast bugreport`
