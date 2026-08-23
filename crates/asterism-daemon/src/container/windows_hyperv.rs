//! Windows container adapter backed by a managed Linux Hyper-V utility VM.
//!
//! The daemon owns the HCS compute system and talks to a small agent in the
//! utility image over AF_HYPERV. The OCI filesystem is a per-instance VHDX;
//! the utility image is immutable and digest-pinned. Hyper-V, VirtDisk and
//! WinSock details stop in this module.
//!
//! The installed artifact is `runtime/windows-container-utility.vhdx` below
//! `ASTERISM_HOME` (or `ASTERISM_CONTAINER_UTILITY_VM`) plus a sibling
//! `.blake3` pin. Its init must bind [`SERVICE_ID`], identify the HCS VM and
//! image digest in `hello`, mount SCSI disk 1 as the container filesystem, and
//! implement the bounded newline-JSON [`ControlRequest`] lifecycle. A missing
//! artifact, mismatched digest, unsupported Windows edition, unelevated token,
//! stopped vmcompute service, or unavailable HCS API is a create-time refusal.

#[cfg(target_os = "windows")]
use std::fs;
#[cfg(target_os = "windows")]
use std::path::Path;
#[cfg(any(target_os = "windows", test))]
use std::path::PathBuf;
use std::time::Duration;

#[cfg(any(target_os = "windows", test))]
use anyhow::Context;
use anyhow::{bail, Result};
#[cfg(any(target_os = "windows", test))]
use serde::{Deserialize, Serialize};

#[cfg(target_os = "windows")]
use asterism_core::hv::ControlChannel;
#[cfg(any(target_os = "windows", test))]
use asterism_core::hv::{ContainerControlEndpoint, ContainerControlTransport, ContainerIsolation};
use asterism_core::hv::{Handle, Machine, RunState};
use asterism_core::instance::Instance;
#[cfg(target_os = "windows")]
use asterism_core::paths;

use super::{Prepared, WINDOWS_ID};

#[cfg(any(target_os = "windows", test))]
const PROTOCOL_VERSION: u32 = 1;
#[cfg(any(target_os = "windows", test))]
const OWNER: &str = "asterism-container";
#[cfg(any(target_os = "windows", test))]
pub(crate) const SERVICE_ID: &str = "9d8f5f8e-31cb-4a39-ae74-6b4d68f50f6d";
#[cfg(target_os = "windows")]
const MAX_FRAME_BYTES: usize = 1024 * 1024;

#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UtilityVmConfig {
    protocol: u32,
    owner: String,
    vm_id: String,
    instance: String,
    utility_vhdx: PathBuf,
    utility_digest: String,
    rootfs_vhdx: PathBuf,
    cpus: u32,
    mem_mib: u64,
    argv: Vec<String>,
    env: Vec<String>,
    workdir: Option<String>,
}

#[cfg(any(target_os = "windows", test))]
impl UtilityVmConfig {
    fn validate(&self) -> Result<()> {
        if self.protocol != PROTOCOL_VERSION || self.owner != OWNER {
            bail!("unsupported Hyper-V container utility-VM protocol or owner");
        }
        uuid::Uuid::parse_str(&self.vm_id).context("container instance id is not a GUID")?;
        uuid::Uuid::parse_str(SERVICE_ID).expect("the fixed service id is a GUID");
        if self.instance.trim().is_empty() || self.argv.is_empty() {
            bail!("the container utility VM needs an instance name and command");
        }
        if self.cpus == 0 || self.mem_mib < 256 {
            bail!("the container utility VM needs at least one CPU and 256 MiB");
        }
        if self.utility_digest.len() != 64
            || !self
                .utility_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            bail!("the container utility image digest is not a BLAKE3 hash");
        }
        Ok(())
    }

    /// HCS schema 2.1 Generation-2 VM with exactly two disks: the immutable
    /// utility OS and this instance's OCI filesystem. The only host control
    /// transport is the private Hyper-V socket service.
    fn hcs_document(&self) -> Result<String> {
        self.validate()?;
        Ok(serde_json::to_string(&serde_json::json!({
            "SchemaVersion": { "Major": 2, "Minor": 1 },
            "Owner": self.owner,
            "ShouldTerminateOnLastHandleClosed": false,
            "VirtualMachine": {
                "StopOnReset": true,
                "Chipset": {
                    "Uefi": {
                        "BootThis": {
                            "DeviceType": "ScsiDrive",
                            "DevicePath": "root",
                            "DiskNumber": 0
                        }
                    }
                },
                "ComputeTopology": {
                    "Memory": {
                        "Backing": "Virtual",
                        "SizeInMB": self.mem_mib,
                        "AllowOvercommit": true
                    },
                    "Processor": { "Count": self.cpus }
                },
                "Devices": {
                    "Scsi": {
                        "root": {
                            "Attachments": {
                                "0": {
                                    "Type": "VirtualDisk",
                                    "Path": self.utility_vhdx,
                                    "ReadOnly": true
                                },
                                "1": {
                                    "Type": "VirtualDisk",
                                    "Path": self.rootfs_vhdx,
                                    "ReadOnly": false
                                }
                            }
                        }
                    },
                    "HvSocket": {
                        "HvSocketConfig": {
                            "ServiceTable": {
                                SERVICE_ID: {
                                    "AllowWildcardBinds": false,
                                    "BindSecurityDescriptor": "D:P(A;;FA;;;SY)(A;;FA;;;BA)",
                                    "ConnectSecurityDescriptor": "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
                                }
                            }
                        }
                    }
                }
            }
        }))?)
    }

    #[cfg(target_os = "windows")]
    fn read(path: &Path) -> Result<Self> {
        let value: Self = serde_json::from_slice(
            &fs::read(path).with_context(|| format!("reading {}", path.display()))?,
        )?;
        value.validate()?;
        Ok(value)
    }

    #[cfg(target_os = "windows")]
    fn write(&self, path: &Path) -> Result<()> {
        self.validate()?;
        fs::write(path, serde_json::to_vec_pretty(self)?)
            .with_context(|| format!("writing {}", path.display()))
    }
}

#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum ControlRequest {
    Hello,
    Start {
        argv: Vec<String>,
        env: Vec<String>,
        workdir: Option<String>,
    },
    Exec {
        argv: Vec<String>,
    },
    Logs {
        lines: u32,
        max_bytes: usize,
    },
    Stop,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
enum ControlResponse {
    Ready {
        vm_id: String,
        utility_digest: String,
    },
    Started,
    Exec {
        status: i32,
        stdout: String,
        stderr: String,
    },
    Logs {
        text: String,
        truncated: bool,
    },
    Stopping,
    Error {
        message: String,
    },
}

#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Clone)]
struct HostReady {
    windows_build: u32,
    edition: String,
    elevated: bool,
    vmcompute_running: bool,
    hcs_api_ready: bool,
}

#[cfg(any(target_os = "windows", test))]
impl HostReady {
    fn require_supported(&self) -> Result<()> {
        if self.windows_build < 22_000 {
            bail!(
                "the Hyper-V container adapter needs Windows 11 build 22000 or newer; this is build {}",
                self.windows_build
            );
        }
        if self.edition != "Pro" && self.edition != "Enterprise" {
            bail!(
                "the Hyper-V container adapter needs Windows 11 Pro or Enterprise; this is {}",
                self.edition
            );
        }
        if !self.elevated {
            bail!("the Hyper-V container adapter needs an elevated administrator token");
        }
        if !self.vmcompute_running || !self.hcs_api_ready {
            bail!(
                "Hyper-V is disabled or awaiting a reboot (vmcompute running: {}, HCS API ready: {})",
                self.vmcompute_running,
                self.hcs_api_ready
            );
        }
        Ok(())
    }
}

pub(super) fn probe() -> Result<Machine> {
    #[cfg(target_os = "windows")]
    {
        let host = platform::probe()?;
        host.require_supported()?;
        let utility = utility_image_path();
        verify_utility_image(&utility)?;
        return Ok(Machine {
            backend: WINDOWS_ID.into(),
            machine_type: "hcs-v2.1-linux-utility-vm".into(),
            cpu: std::env::consts::ARCH.into(),
            hv_version: format!("Windows build {}", host.windows_build),
        });
    }
    #[cfg(not(target_os = "windows"))]
    bail!("the {WINDOWS_ID} adapter is available only on Windows")
}

pub(super) fn prepare(inst: &Instance) -> Result<Prepared> {
    #[cfg(target_os = "windows")]
    {
        probe()?;
        if !inst.publish.is_empty() {
            bail!("Hyper-V utility-VM port publishing is not implemented; no port was reserved");
        }
        if !inst.volumes.is_empty() {
            bail!("Hyper-V utility-VM directory and block attachments are not implemented; no placeholder disk was attached");
        }
        if !inst.profiles.is_empty() || !inst.secrets.is_empty() {
            bail!("Hyper-V utility-VM bootstrap and secret projection are unavailable; refusing a partially configured container");
        }

        let req = crate::backend::disk_req(inst)?;
        let dir = paths::instance_dir(&inst.name);
        fs::create_dir_all(&dir)?;
        let utility_vhdx = utility_image_path();
        let utility_digest = verify_utility_image(&utility_vhdx)?;
        let rootfs_vhdx = dir.join("container-rootfs.vhdx");
        let source_size = fs::metadata(&req.base.path)?.len();
        let requested_size = u64::from(inst.shape.disk_gib) * (1 << 30);
        platform::materialize_vhdx(
            &req.base.path,
            &rootfs_vhdx,
            source_size.max(requested_size),
        )?;

        let image: serde_json::Value = serde_json::from_slice(
            &fs::read(req.base.path.with_extension("json"))
                .context("reading the OCI config sidecar")?,
        )?;
        let image = &image["config"];
        let strings = |key: &str| -> Vec<String> {
            image[key]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|value| value.as_str().map(str::to_owned))
                .collect()
        };
        let mut argv = strings("Entrypoint");
        argv.extend(strings("Cmd"));
        if argv.is_empty() {
            bail!("the OCI image declares neither Entrypoint nor Cmd");
        }
        if image["User"]
            .as_str()
            .is_some_and(|user| !user.is_empty() && user != "0" && user != "root")
        {
            bail!("the Hyper-V utility agent does not yet map the OCI image's non-root User; refusing to run it as another identity");
        }
        let config = UtilityVmConfig {
            protocol: PROTOCOL_VERSION,
            owner: OWNER.into(),
            vm_id: inst.id.clone(),
            instance: inst.name.clone(),
            utility_vhdx,
            utility_digest,
            rootfs_vhdx,
            cpus: inst.shape.cpus,
            mem_mib: u64::from(inst.shape.mem_mib),
            argv,
            env: strings("Env"),
            workdir: image["WorkingDir"].as_str().map(str::to_owned),
        };
        let spec = dir.join("container-hyperv.json");
        config.write(&spec)?;
        return Ok(Prepared {
            adapter: WINDOWS_ID,
            spec,
        });
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = inst;
        bail!("the {WINDOWS_ID} adapter is available only on Windows")
    }
}

pub(super) fn start(prepared: &Prepared) -> Result<Handle> {
    #[cfg(target_os = "windows")]
    {
        let config = UtilityVmConfig::read(&prepared.spec)?;
        platform::boot(&config)?;
        wait_ready(&config)?;
        expect(
            platform::call(
                &config,
                &ControlRequest::Start {
                    argv: config.argv.clone(),
                    env: config.env.clone(),
                    workdir: config.workdir.clone(),
                },
                Duration::from_secs(30),
            )?,
            |reply| matches!(reply, ControlResponse::Started),
            "start",
        )?;
        return Ok(Handle {
            backend: WINDOWS_ID.into(),
            pid: None,
            proc: None,
            ctl: ControlChannel::Rpc {
                path: prepared.spec.clone(),
            },
            endpoint: None,
            container_control: Some(ContainerControlEndpoint {
                transport: ContainerControlTransport::HyperVSocket {
                    vm_id: config.vm_id.clone(),
                    service_id: SERVICE_ID.into(),
                },
                isolation: ContainerIsolation::UtilityVm {
                    vm_id: config.vm_id,
                    config: prepared.spec.clone(),
                    rootfs: config.rootfs_vhdx,
                },
            }),
            started_at: asterism_core::instance::now_unix(),
        });
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = prepared;
        bail!("the {WINDOWS_ID} adapter is available only on Windows")
    }
}

pub(super) fn state(handle: &Handle) -> Result<RunState> {
    #[cfg(target_os = "windows")]
    {
        let config = handle_config(handle)?;
        match platform::state(&config.vm_id)? {
            platform::VmState::Missing | platform::VmState::Stopped => Ok(RunState::Stopped),
            platform::VmState::Running => {
                validate_ready(
                    &config,
                    platform::call(&config, &ControlRequest::Hello, Duration::from_secs(2))?,
                )?;
                Ok(RunState::Running)
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = handle;
        bail!("the {WINDOWS_ID} adapter is available only on Windows")
    }
}

pub(super) fn stop(handle: &Handle, deadline: Duration) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        let config = handle_config(handle)?;
        if platform::state(&config.vm_id)? != platform::VmState::Running {
            return Ok(());
        }
        let _ = cache_logs(&config);
        let control = platform::call(&config, &ControlRequest::Stop, Duration::from_secs(5));
        let shutdown = platform::shutdown(&config.vm_id, deadline);
        match shutdown {
            Ok(()) => Ok(()),
            Err(shutdown) => match control {
                Ok(ControlResponse::Error { message }) => {
                    Err(shutdown).context(format!("utility agent also refused stop: {message}"))
                }
                Ok(other) if !matches!(other, ControlResponse::Stopping) => {
                    Err(shutdown).context(format!("utility VM returned {other:?} to stop"))
                }
                Err(control) => {
                    Err(shutdown).context(format!("utility agent stop also failed: {control:#}"))
                }
                _ => Err(shutdown),
            },
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (handle, deadline);
        bail!("the {WINDOWS_ID} adapter is available only on Windows")
    }
}

pub(super) fn exec(handle: &Handle, argv: Vec<String>) -> Result<(i32, String, String)> {
    if argv.is_empty() {
        bail!("container exec needs a command");
    }
    #[cfg(target_os = "windows")]
    {
        let config = handle_config(handle)?;
        match platform::call(
            &config,
            &ControlRequest::Exec { argv },
            Duration::from_secs(120),
        )? {
            ControlResponse::Exec {
                status,
                stdout,
                stderr,
            } => Ok((status, stdout, stderr)),
            ControlResponse::Error { message } => bail!(message),
            other => bail!("utility VM returned {other:?} to exec"),
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (handle, argv);
        bail!("the {WINDOWS_ID} adapter is available only on Windows")
    }
}

pub(super) fn logs(handle: &Handle, name: &str, lines: u32) -> Result<(String, bool)> {
    #[cfg(target_os = "windows")]
    {
        let config = handle_config(handle)?;
        let guest_truncated = cache_logs(&config)?;
        let (text, host_truncated) =
            super::tail_log(&paths::instance_dir(name).join("console.log"), lines)?;
        Ok((text, guest_truncated || host_truncated))
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (handle, name, lines);
        bail!("the {WINDOWS_ID} adapter is available only on Windows")
    }
}

#[cfg(target_os = "windows")]
fn cache_logs(config: &UtilityVmConfig) -> Result<bool> {
    match platform::call(
        config,
        &ControlRequest::Logs {
            lines: 0,
            max_bytes: MAX_FRAME_BYTES / 2,
        },
        Duration::from_secs(10),
    )? {
        ControlResponse::Logs { text, truncated } => {
            let path = paths::instance_dir(&config.instance).join("console.log");
            fs::write(&path, text)
                .with_context(|| format!("caching utility-VM log at {}", path.display()))?;
            Ok(truncated)
        }
        ControlResponse::Error { message } => bail!(message),
        other => bail!("utility VM returned {other:?} to logs"),
    }
}

pub(super) fn remove(inst: &Instance) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        let path = paths::instance_dir(&inst.name).join("container-hyperv.json");
        if !path.exists() {
            return Ok(());
        }
        let config = UtilityVmConfig::read(&path)?;
        platform::remove(&config.vm_id)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = inst;
        bail!("the {WINDOWS_ID} adapter is available only on Windows")
    }
}

#[cfg(target_os = "windows")]
fn utility_image_path() -> PathBuf {
    std::env::var_os("ASTERISM_CONTAINER_UTILITY_VM")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            paths::home_dir()
                .join("runtime")
                .join("windows-container-utility.vhdx")
        })
}

#[cfg(target_os = "windows")]
fn digest_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".blake3");
    value.into()
}

#[cfg(target_os = "windows")]
fn verify_utility_image(path: &Path) -> Result<String> {
    let expected = fs::read_to_string(digest_path(path)).with_context(|| {
        format!(
            "the Hyper-V utility image {} has no .blake3 pin",
            path.display()
        )
    })?;
    let expected = expected
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("the Hyper-V utility image digest pin is not a BLAKE3 hash");
    }
    let mut image = fs::File::open(path)
        .with_context(|| format!("opening the Hyper-V utility image at {}", path.display()))?;
    let mut hasher = blake3::Hasher::new();
    std::io::copy(&mut image, &mut hasher)?;
    let actual = hasher.finalize().to_hex().to_string();
    if actual != expected {
        bail!("the Hyper-V utility image digest is {actual}, not its pinned digest {expected}");
    }
    Ok(actual)
}

#[cfg(target_os = "windows")]
fn handle_config(handle: &Handle) -> Result<UtilityVmConfig> {
    let endpoint = handle
        .container_control
        .as_ref()
        .context("container handle has no control endpoint")?;
    let (vm_id, service_id) = match &endpoint.transport {
        ContainerControlTransport::HyperVSocket { vm_id, service_id } => (vm_id, service_id),
        _ => bail!("Windows container handle does not carry a Hyper-V socket endpoint"),
    };
    if service_id != SERVICE_ID {
        bail!("Windows container handle names an unknown Hyper-V socket service");
    }
    let config_path = match &endpoint.isolation {
        ContainerIsolation::UtilityVm {
            vm_id: isolated,
            config,
            ..
        } if isolated == vm_id => config,
        _ => bail!("Windows container handle does not carry matching utility-VM isolation"),
    };
    let config = UtilityVmConfig::read(config_path)?;
    if &config.vm_id != vm_id {
        bail!("Windows container control endpoint does not match its utility-VM config");
    }
    Ok(config)
}

#[cfg(target_os = "windows")]
fn wait_ready(config: &UtilityVmConfig) -> Result<()> {
    let deadline = std::time::Instant::now() + Duration::from_secs(90);
    let mut last = None;
    while std::time::Instant::now() < deadline {
        match platform::call(config, &ControlRequest::Hello, Duration::from_secs(5)) {
            Ok(reply) => return validate_ready(config, reply),
            Err(error) => last = Some(format!("{error:#}")),
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    bail!(
        "the Hyper-V utility VM did not establish its control endpoint: {}",
        last.unwrap_or_else(|| "no connection attempt completed".into())
    )
}

#[cfg(target_os = "windows")]
fn validate_ready(config: &UtilityVmConfig, reply: ControlResponse) -> Result<()> {
    match reply {
        ControlResponse::Ready {
            vm_id,
            utility_digest,
        } if vm_id == config.vm_id && utility_digest == config.utility_digest => Ok(()),
        ControlResponse::Ready {
            vm_id,
            utility_digest,
        } => bail!("utility-VM identity mismatch (vm {vm_id}, image {utility_digest})"),
        ControlResponse::Error { message } => bail!(message),
        other => bail!("utility VM returned {other:?} to readiness probe"),
    }
}

#[cfg(target_os = "windows")]
fn expect(
    reply: ControlResponse,
    predicate: impl FnOnce(&ControlResponse) -> bool,
    operation: &str,
) -> Result<()> {
    if let ControlResponse::Error { message } = reply {
        bail!(message);
    }
    if !predicate(&reply) {
        bail!("utility VM returned {reply:?} to {operation}");
    }
    Ok(())
}

#[cfg(target_os = "windows")]
mod platform {
    use std::ffi::{c_void, OsStr};
    use std::io::{self, Read, Seek, SeekFrom, Write};
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null, null_mut};

    use windows_sys::core::{GUID, HRESULT, PCWSTR, PWSTR};
    use windows_sys::Win32::Foundation::{
        CloseHandle, LocalFree, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, GENERIC_ALL, HANDLE,
        HCS_E_SYSTEM_NOT_FOUND,
    };
    use windows_sys::Win32::Networking::WinSock::{
        closesocket, connect, recv, send, setsockopt, socket, WSACleanup, WSAGetLastError,
        WSAStartup, AF_HYPERV, INVALID_SOCKET, SOCKADDR, SOCKET, SOCKET_ERROR, SOCK_STREAM,
        SOL_SOCKET, SO_RCVTIMEO, SO_SNDTIMEO, WSADATA,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::Storage::Vhd::{
        AttachVirtualDisk, CreateVirtualDisk, DetachVirtualDisk, GetVirtualDiskPhysicalPath,
        ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER, ATTACH_VIRTUAL_DISK_PARAMETERS,
        ATTACH_VIRTUAL_DISK_PARAMETERS_0, ATTACH_VIRTUAL_DISK_PARAMETERS_0_0,
        ATTACH_VIRTUAL_DISK_VERSION_1, CREATE_VIRTUAL_DISK_FLAG_NONE,
        CREATE_VIRTUAL_DISK_PARAMETERS, CREATE_VIRTUAL_DISK_PARAMETERS_0,
        CREATE_VIRTUAL_DISK_PARAMETERS_0_1, CREATE_VIRTUAL_DISK_VERSION_2, VIRTUAL_DISK_ACCESS_ALL,
        VIRTUAL_STORAGE_TYPE, VIRTUAL_STORAGE_TYPE_DEVICE_VHDX,
        VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT,
    };
    use windows_sys::Win32::System::HostComputeSystem::{
        HcsCloseComputeSystem, HcsCloseOperation, HcsCreateComputeSystem, HcsCreateOperation,
        HcsGetComputeSystemProperties, HcsGetServiceProperties, HcsGrantVmAccess,
        HcsOpenComputeSystem, HcsShutDownComputeSystem, HcsStartComputeSystem,
        HcsTerminateComputeSystem, HcsWaitForComputeSystemExit, HcsWaitForOperationResult,
        HCS_OPERATION, HCS_SYSTEM,
    };
    use windows_sys::Win32::System::Hypervisor::{HV_PROTOCOL_RAW, SOCKADDR_HV};
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_MANAGER_CONNECT,
        SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_STATUS_PROCESS,
    };
    use windows_sys::Win32::System::SystemInformation::{
        GetProductInfo, OSVERSIONINFOW, PRODUCT_ENTERPRISE, PRODUCT_ENTERPRISE_E,
        PRODUCT_ENTERPRISE_EVALUATION, PRODUCT_ENTERPRISE_N, PRODUCT_ENTERPRISE_N_EVALUATION,
        PRODUCT_ENTERPRISE_S, PRODUCT_ENTERPRISE_S_EVALUATION, PRODUCT_ENTERPRISE_S_N,
        PRODUCT_ENTERPRISE_S_N_EVALUATION, PRODUCT_PROFESSIONAL, PRODUCT_PROFESSIONAL_E,
        PRODUCT_PROFESSIONAL_N, PRODUCT_PROFESSIONAL_WMC,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use super::*;

    const HCS_TIMEOUT_MS: u32 = 120_000;

    #[link(name = "ntdll")]
    extern "system" {
        fn RtlGetVersion(version: *mut OSVERSIONINFOW) -> i32;
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum VmState {
        Running,
        Stopped,
        Missing,
    }

    pub(super) fn probe() -> Result<HostReady> {
        let mut version = OSVERSIONINFOW::default();
        version.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOW>() as u32;
        let status = unsafe { RtlGetVersion(&mut version) };
        if status < 0 {
            bail!("RtlGetVersion failed with NTSTATUS 0x{:08x}", status as u32);
        }
        let mut product = 0;
        if unsafe {
            GetProductInfo(
                version.dwMajorVersion,
                version.dwMinorVersion,
                0,
                0,
                &mut product,
            )
        } == 0
        {
            return Err(io::Error::last_os_error()).context("GetProductInfo");
        }
        let edition = match product {
            PRODUCT_PROFESSIONAL
            | PRODUCT_PROFESSIONAL_E
            | PRODUCT_PROFESSIONAL_N
            | PRODUCT_PROFESSIONAL_WMC => "Pro",
            PRODUCT_ENTERPRISE
            | PRODUCT_ENTERPRISE_E
            | PRODUCT_ENTERPRISE_EVALUATION
            | PRODUCT_ENTERPRISE_N
            | PRODUCT_ENTERPRISE_N_EVALUATION
            | PRODUCT_ENTERPRISE_S
            | PRODUCT_ENTERPRISE_S_EVALUATION
            | PRODUCT_ENTERPRISE_S_N
            | PRODUCT_ENTERPRISE_S_N_EVALUATION => "Enterprise",
            _ => "Unsupported",
        };
        let vmcompute_running = service_running("vmcompute")?;
        let hcs_api_ready = if vmcompute_running {
            let mut properties: PWSTR = null_mut();
            let query = wide("{}");
            let hr = unsafe { HcsGetServiceProperties(query.as_ptr(), &mut properties) };
            free_local(properties);
            !failed(hr)
        } else {
            false
        };
        Ok(HostReady {
            windows_build: version.dwBuildNumber,
            edition: edition.into(),
            elevated: elevated()?,
            vmcompute_running,
            hcs_api_ready,
        })
    }

    pub(super) fn materialize_vhdx(source: &Path, dest: &Path, size_bytes: u64) -> Result<()> {
        if dest.exists() {
            return Ok(());
        }
        let source_len = fs::metadata(source)?.len();
        if source_len > size_bytes {
            bail!("the OCI filesystem is larger than its requested VHDX");
        }
        let maximum = size_bytes.max(3 << 20).div_ceil(1 << 20) * (1 << 20);
        let storage = VIRTUAL_STORAGE_TYPE {
            DeviceId: VIRTUAL_STORAGE_TYPE_DEVICE_VHDX,
            VendorId: VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT,
        };
        let params = CREATE_VIRTUAL_DISK_PARAMETERS {
            Version: CREATE_VIRTUAL_DISK_VERSION_2,
            Anonymous: CREATE_VIRTUAL_DISK_PARAMETERS_0 {
                Version2: CREATE_VIRTUAL_DISK_PARAMETERS_0_1 {
                    MaximumSize: maximum,
                    ..Default::default()
                },
            },
        };
        let path = wide_path(dest);
        let mut raw: HANDLE = null_mut();
        let rc = unsafe {
            CreateVirtualDisk(
                &storage,
                path.as_ptr(),
                VIRTUAL_DISK_ACCESS_ALL,
                null_mut(),
                CREATE_VIRTUAL_DISK_FLAG_NONE,
                0,
                &params,
                null(),
                &mut raw,
            )
        };
        if rc != ERROR_SUCCESS {
            bail!("CreateVirtualDisk failed with Win32 error {rc}");
        }
        let disk = WinHandle(raw);
        let attach = ATTACH_VIRTUAL_DISK_PARAMETERS {
            Version: ATTACH_VIRTUAL_DISK_VERSION_1,
            Anonymous: ATTACH_VIRTUAL_DISK_PARAMETERS_0 {
                Version1: ATTACH_VIRTUAL_DISK_PARAMETERS_0_0 { Reserved: 0 },
            },
        };
        let rc = unsafe {
            AttachVirtualDisk(
                disk.0,
                null_mut(),
                ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER,
                0,
                &attach,
                null(),
            )
        };
        if rc != ERROR_SUCCESS {
            let _ = fs::remove_file(dest);
            bail!("AttachVirtualDisk failed with Win32 error {rc}");
        }
        let copied = (|| -> Result<()> {
            let mut capacity = 512u32;
            let (buffer, size) = loop {
                let mut size = capacity;
                let mut buffer = vec![0u16; capacity as usize];
                let rc =
                    unsafe { GetVirtualDiskPhysicalPath(disk.0, &mut size, buffer.as_mut_ptr()) };
                if rc == ERROR_SUCCESS {
                    break (buffer, size);
                }
                if rc != ERROR_INSUFFICIENT_BUFFER {
                    bail!("GetVirtualDiskPhysicalPath failed with Win32 error {rc}");
                }
                capacity = size.max(capacity.saturating_mul(2));
            };
            let end = buffer[..(size as usize).min(buffer.len())]
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or((size as usize).min(buffer.len()));
            let physical = String::from_utf16(&buffer[..end])?;
            let mut input = fs::File::open(source)?;
            let mut output = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&physical)?;
            output.seek(SeekFrom::Start(0))?;
            io::copy(&mut input, &mut output)?;
            output.sync_all()?;
            Ok(())
        })();
        let detach = unsafe { DetachVirtualDisk(disk.0, 0, 0) };
        drop(disk);
        if let Err(error) = copied {
            let _ = fs::remove_file(dest);
            return Err(error);
        }
        if detach != ERROR_SUCCESS {
            let _ = fs::remove_file(dest);
            bail!("DetachVirtualDisk failed with Win32 error {detach}");
        }
        Ok(())
    }

    pub(super) fn boot(config: &UtilityVmConfig) -> Result<()> {
        config.validate()?;
        if state(&config.vm_id)? == VmState::Running {
            return Ok(());
        }
        remove(&config.vm_id)?;
        for path in [&config.utility_vhdx, &config.rootfs_vhdx] {
            grant_vm_access(&config.vm_id, path)?;
        }
        let operation = Operation::new()?;
        let id = wide(&config.vm_id);
        let document = wide(&config.hcs_document()?);
        let mut raw: HCS_SYSTEM = null_mut();
        check_hr(
            unsafe {
                HcsCreateComputeSystem(
                    id.as_ptr(),
                    document.as_ptr(),
                    operation.0,
                    null_mut(),
                    &mut raw,
                )
            },
            "creating the container utility VM",
        )?;
        operation.wait("creating the container utility VM")?;
        let system = ComputeSystem(raw);
        action(&system, "starting the container utility VM", |op| unsafe {
            HcsStartComputeSystem(system.0, op, null())
        })
    }

    pub(super) fn state(id: &str) -> Result<VmState> {
        let Some(system) = ComputeSystem::open(id)? else {
            return Ok(VmState::Missing);
        };
        let operation = Operation::new()?;
        let query = wide("{}");
        check_hr(
            unsafe { HcsGetComputeSystemProperties(system.0, operation.0, query.as_ptr()) },
            "querying the container utility VM",
        )?;
        let document = operation
            .wait("querying the container utility VM")?
            .to_ascii_lowercase();
        Ok(
            if document.contains("running") || document.contains("paused") {
                VmState::Running
            } else {
                VmState::Stopped
            },
        )
    }

    pub(super) fn shutdown(id: &str, deadline: Duration) -> Result<()> {
        let Some(system) = ComputeSystem::open(id)? else {
            return Ok(());
        };
        let graceful = action(
            &system,
            "shutting down the container utility VM",
            |op| unsafe { HcsShutDownComputeSystem(system.0, op, null()) },
        );
        if graceful.is_err() {
            action(
                &system,
                "terminating the container utility VM after shutdown refusal",
                |op| unsafe { HcsTerminateComputeSystem(system.0, op, null()) },
            )?;
            wait_exit(&system, Duration::from_secs(5))?;
            return Ok(());
        }
        if wait_exit(&system, deadline).is_ok() {
            return Ok(());
        }
        action(
            &system,
            "terminating the container utility VM after shutdown timeout",
            |op| unsafe { HcsTerminateComputeSystem(system.0, op, null()) },
        )?;
        wait_exit(&system, Duration::from_secs(5))
    }

    fn wait_exit(system: &ComputeSystem, deadline: Duration) -> Result<()> {
        let mut result: PWSTR = null_mut();
        let wait = unsafe {
            HcsWaitForComputeSystemExit(
                system.0,
                deadline.as_millis().min(u32::MAX as u128) as u32,
                &mut result,
            )
        };
        free_local(result);
        if failed(wait) {
            bail!("the container utility VM did not stop before its lifecycle deadline");
        }
        Ok(())
    }

    pub(super) fn remove(id: &str) -> Result<()> {
        let Some(system) = ComputeSystem::open(id)? else {
            return Ok(());
        };
        action(&system, "removing the container utility VM", |op| unsafe {
            HcsTerminateComputeSystem(system.0, op, null())
        })?;
        wait_exit(&system, Duration::from_secs(5))
    }

    pub(super) fn call(
        config: &UtilityVmConfig,
        request: &ControlRequest,
        timeout: Duration,
    ) -> Result<ControlResponse> {
        let socket = HvSocket::connect(&config.vm_id, timeout)?;
        let mut writer = SocketIo(socket.socket);
        serde_json::to_writer(&mut writer, request)?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        let mut reader = io::BufReader::new(SocketIo(socket.socket));
        let mut frame = Vec::new();
        loop {
            use io::BufRead;
            let chunk = reader.fill_buf()?;
            if chunk.is_empty() {
                bail!("the utility VM closed its control endpoint mid-frame");
            }
            let newline = chunk.iter().position(|byte| *byte == b'\n');
            let take = newline.unwrap_or(chunk.len());
            if frame.len() + take > MAX_FRAME_BYTES {
                bail!("the utility VM exceeded the {MAX_FRAME_BYTES}-byte control frame cap");
            }
            frame.extend_from_slice(&chunk[..take]);
            reader.consume(take + usize::from(newline.is_some()));
            if newline.is_some() {
                return serde_json::from_slice(&frame).context("parsing utility-VM control reply");
            }
        }
    }

    fn action(
        system: &ComputeSystem,
        what: &str,
        begin: impl FnOnce(HCS_OPERATION) -> HRESULT,
    ) -> Result<()> {
        let operation = Operation::new()?;
        check_hr(begin(operation.0), what)?;
        operation.wait(what).map(|_| ())
    }

    fn grant_vm_access(id: &str, path: &Path) -> Result<()> {
        let id = wide(id);
        let path = wide_path(path);
        check_hr(
            unsafe { HcsGrantVmAccess(id.as_ptr(), path.as_ptr()) },
            "granting the utility VM access to a disk",
        )
    }

    struct ComputeSystem(HCS_SYSTEM);
    impl ComputeSystem {
        fn open(id: &str) -> Result<Option<Self>> {
            let id = wide(id);
            let mut raw = null_mut();
            let hr = unsafe { HcsOpenComputeSystem(id.as_ptr(), GENERIC_ALL, &mut raw) };
            if hr == HCS_E_SYSTEM_NOT_FOUND {
                return Ok(None);
            }
            check_hr(hr, "opening the container utility VM")?;
            Ok(Some(Self(raw)))
        }
    }
    impl Drop for ComputeSystem {
        fn drop(&mut self) {
            unsafe { HcsCloseComputeSystem(self.0) };
        }
    }

    struct Operation(HCS_OPERATION);
    impl Operation {
        fn new() -> Result<Self> {
            let operation = unsafe { HcsCreateOperation(null(), None) };
            if operation.is_null() {
                bail!("HcsCreateOperation returned a null handle");
            }
            Ok(Self(operation))
        }
        fn wait(&self, what: &str) -> Result<String> {
            let mut document: PWSTR = null_mut();
            let hr = unsafe { HcsWaitForOperationResult(self.0, HCS_TIMEOUT_MS, &mut document) };
            let text = pwstr(document);
            free_local(document);
            if failed(hr) {
                bail!("{what}: HRESULT 0x{:08x}: {}", hr as u32, text.trim());
            }
            Ok(text)
        }
    }
    impl Drop for Operation {
        fn drop(&mut self) {
            unsafe { HcsCloseOperation(self.0) };
        }
    }

    struct WinHandle(HANDLE);
    impl Drop for WinHandle {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    struct ServiceHandle(*mut c_void);
    impl Drop for ServiceHandle {
        fn drop(&mut self) {
            unsafe { CloseServiceHandle(self.0) };
        }
    }

    struct Winsock;
    impl Winsock {
        fn start() -> Result<Self> {
            let mut data = WSADATA::default();
            let rc = unsafe { WSAStartup(0x0202, &mut data) };
            if rc != 0 {
                bail!("WSAStartup failed with error {rc}");
            }
            Ok(Self)
        }
    }
    impl Drop for Winsock {
        fn drop(&mut self) {
            unsafe { WSACleanup() };
        }
    }

    struct HvSocket {
        socket: SOCKET,
        _winsock: Winsock,
    }
    impl HvSocket {
        fn connect(vm_id: &str, timeout: Duration) -> Result<Self> {
            let winsock = Winsock::start()?;
            let socket = unsafe { socket(AF_HYPERV as i32, SOCK_STREAM, HV_PROTOCOL_RAW as i32) };
            if socket == INVALID_SOCKET {
                bail!("creating AF_HYPERV socket: WSA error {}", unsafe {
                    WSAGetLastError()
                });
            }
            let socket = Self {
                socket,
                _winsock: winsock,
            };
            let milliseconds = timeout.as_millis().min(u32::MAX as u128) as u32;
            for option in [SO_RCVTIMEO, SO_SNDTIMEO] {
                if unsafe {
                    setsockopt(
                        socket.socket,
                        SOL_SOCKET,
                        option,
                        &milliseconds as *const u32 as *const u8,
                        std::mem::size_of_val(&milliseconds) as i32,
                    )
                } == SOCKET_ERROR
                {
                    bail!("setting Hyper-V socket timeout: WSA error {}", unsafe {
                        WSAGetLastError()
                    });
                }
            }
            let address = SOCKADDR_HV {
                Family: AF_HYPERV,
                Reserved: 0,
                VmId: guid(vm_id)?,
                ServiceId: guid(SERVICE_ID)?,
            };
            if unsafe {
                connect(
                    socket.socket,
                    &address as *const SOCKADDR_HV as *const SOCKADDR,
                    std::mem::size_of::<SOCKADDR_HV>() as i32,
                )
            } == SOCKET_ERROR
            {
                bail!(
                    "connecting the utility VM control endpoint: WSA error {}",
                    unsafe { WSAGetLastError() }
                );
            }
            Ok(socket)
        }
    }
    impl Drop for HvSocket {
        fn drop(&mut self) {
            unsafe { closesocket(self.socket) };
        }
    }

    struct SocketIo(SOCKET);
    impl Read for SocketIo {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let read = unsafe {
                recv(
                    self.0,
                    buffer.as_mut_ptr(),
                    buffer.len().min(i32::MAX as usize) as i32,
                    0,
                )
            };
            if read == SOCKET_ERROR {
                Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }))
            } else {
                Ok(read as usize)
            }
        }
    }
    impl Write for SocketIo {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            let sent = unsafe {
                send(
                    self.0,
                    buffer.as_ptr(),
                    buffer.len().min(i32::MAX as usize) as i32,
                    0,
                )
            };
            if sent == SOCKET_ERROR {
                Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }))
            } else {
                Ok(sent as usize)
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn elevated() -> Result<bool> {
        let mut token: HANDLE = null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error()).context("OpenProcessToken");
        }
        let token = WinHandle(token);
        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0;
        if unsafe {
            GetTokenInformation(
                token.0,
                TokenElevation,
                &mut elevation as *mut TOKEN_ELEVATION as *mut c_void,
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut returned,
            )
        } == 0
        {
            return Err(io::Error::last_os_error()).context("GetTokenInformation");
        }
        Ok(elevation.TokenIsElevated != 0)
    }

    fn service_running(name: &str) -> Result<bool> {
        let manager = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT) };
        if manager.is_null() {
            return Err(io::Error::last_os_error()).context("OpenSCManagerW");
        }
        let manager = ServiceHandle(manager);
        let name = wide(name);
        let service = unsafe { OpenServiceW(manager.0, name.as_ptr(), SERVICE_QUERY_STATUS) };
        if service.is_null() {
            return Ok(false);
        }
        let service = ServiceHandle(service);
        let mut status = SERVICE_STATUS_PROCESS::default();
        let mut needed = 0;
        if unsafe {
            QueryServiceStatusEx(
                service.0,
                SC_STATUS_PROCESS_INFO,
                &mut status as *mut SERVICE_STATUS_PROCESS as *mut u8,
                std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut needed,
            )
        } == 0
        {
            return Err(io::Error::last_os_error()).context("QueryServiceStatusEx");
        }
        Ok(status.dwCurrentState == SERVICE_RUNNING)
    }

    fn guid(value: &str) -> Result<GUID> {
        Ok(GUID::from_u128(uuid::Uuid::parse_str(value)?.as_u128()))
    }
    fn wide(value: &str) -> Vec<u16> {
        OsStr::new(value).encode_wide().chain(Some(0)).collect()
    }
    fn wide_path(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }
    fn failed(hr: HRESULT) -> bool {
        hr < 0
    }
    fn check_hr(hr: HRESULT, what: &str) -> Result<()> {
        if failed(hr) {
            bail!("{what}: HRESULT 0x{:08x}", hr as u32);
        }
        Ok(())
    }
    fn pwstr(pointer: PCWSTR) -> String {
        if pointer.is_null() {
            return String::new();
        }
        let mut length = 0;
        unsafe {
            while *pointer.add(length) != 0 {
                length += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(pointer, length))
        }
    }
    fn free_local(pointer: PWSTR) {
        if !pointer.is_null() {
            unsafe { LocalFree(pointer as *mut c_void) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> UtilityVmConfig {
        UtilityVmConfig {
            protocol: PROTOCOL_VERSION,
            owner: OWNER.into(),
            vm_id: "6fce7c98-d05d-43c8-8207-141c56ccca18".into(),
            instance: "dev".into(),
            utility_vhdx: r"C:\ProgramData\Asterism\container-utility.vhdx".into(),
            utility_digest: "a5".repeat(32),
            rootfs_vhdx: r"C:\Users\me\.asterism\instances\dev\container-rootfs.vhdx".into(),
            cpus: 2,
            mem_mib: 512,
            argv: vec!["/bin/sleep".into(), "infinity".into()],
            env: vec!["PATH=/usr/bin".into()],
            workdir: Some("/work".into()),
        }
    }

    #[test]
    fn hcs_document_is_native_durable_and_has_only_private_control() {
        let document: serde_json::Value =
            serde_json::from_str(&config().hcs_document().unwrap()).unwrap();
        assert_eq!(
            document["SchemaVersion"],
            serde_json::json!({"Major": 2, "Minor": 1})
        );
        assert_eq!(document["ShouldTerminateOnLastHandleClosed"], false);
        assert_eq!(
            document["VirtualMachine"]["Devices"]["Scsi"]["root"]["Attachments"]["0"]["ReadOnly"],
            true
        );
        assert_eq!(
            document["VirtualMachine"]["Devices"]["Scsi"]["root"]["Attachments"]["1"]["ReadOnly"],
            false
        );
        assert_eq!(
            document["VirtualMachine"]["Devices"]["HvSocket"]["HvSocketConfig"]["ServiceTable"]
                [SERVICE_ID]["AllowWildcardBinds"],
            false
        );
        assert!(document["VirtualMachine"]["Devices"]
            .get("NetworkAdapters")
            .is_none());
    }

    #[test]
    fn control_protocol_covers_the_shared_lifecycle() {
        let requests = [
            ControlRequest::Hello,
            ControlRequest::Start {
                argv: vec!["/bin/true".into()],
                env: vec![],
                workdir: None,
            },
            ControlRequest::Exec {
                argv: vec!["id".into()],
            },
            ControlRequest::Logs {
                lines: 10,
                max_bytes: 4096,
            },
            ControlRequest::Stop,
        ];
        for request in requests {
            let wire = serde_json::to_vec(&request).unwrap();
            assert_eq!(request, serde_json::from_slice(&wire).unwrap());
        }
    }

    #[test]
    fn unsupported_hosts_fail_before_mutation() {
        let mut host = HostReady {
            windows_build: 26_100,
            edition: "Home".into(),
            elevated: true,
            vmcompute_running: true,
            hcs_api_ready: true,
        };
        assert!(host
            .require_supported()
            .unwrap_err()
            .to_string()
            .contains("Pro or Enterprise"));
        host.edition = "Pro".into();
        host.elevated = false;
        assert!(host
            .require_supported()
            .unwrap_err()
            .to_string()
            .contains("elevated"));
        host.elevated = true;
        host.vmcompute_running = false;
        assert!(host
            .require_supported()
            .unwrap_err()
            .to_string()
            .contains("disabled"));
    }

    #[test]
    fn hyperv_endpoint_is_not_a_linux_namespace_placeholder() {
        let endpoint = ContainerControlEndpoint {
            transport: ContainerControlTransport::HyperVSocket {
                vm_id: config().vm_id.clone(),
                service_id: SERVICE_ID.into(),
            },
            isolation: ContainerIsolation::UtilityVm {
                vm_id: config().vm_id,
                config: "container-hyperv.json".into(),
                rootfs: "container-rootfs.vhdx".into(),
            },
        };
        let wire = serde_json::to_string(&endpoint).unwrap();
        assert!(wire.contains("hyper_v_socket"));
        assert!(wire.contains("utility_vm"));
        assert!(!wire.contains("namespace"));
        assert!(!wire.contains("127.0.0.1"));
    }
}
