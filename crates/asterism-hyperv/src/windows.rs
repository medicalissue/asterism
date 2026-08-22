//! Native Windows side of the helper boundary.
//!
//! No caller outside this module sees an HCS/HCN document, Win32 handle, or
//! Hyper-V socket address. The direct APIs here are intentionally boring C
//! adapters: lifecycle belongs to HCS, networking to HCN, VHDX construction
//! to VirtDisk, and guest identity/readiness to the shared authenticated
//! agent protocol over `AF_HYPERV`.

use std::ffi::{c_void, OsStr};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{null, null_mut};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use windows_sys::core::{GUID, HRESULT, PCWSTR, PWSTR};
use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, GENERIC_ALL, HANDLE,
    HCN_E_ENDPOINT_NOT_FOUND, HCN_E_NETWORK_NOT_FOUND, HCS_E_SYSTEM_NOT_FOUND,
};
use windows_sys::Win32::Networking::WinSock::{
    closesocket, connect, recv, send, setsockopt, socket, WSACleanup, WSAGetLastError, WSAStartup,
    AF_HYPERV, INVALID_SOCKET, SOCKADDR, SOCKET, SOCKET_ERROR, SOCK_STREAM, SOL_SOCKET,
    SO_RCVTIMEO, SO_SNDTIMEO, WSADATA,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows_sys::Win32::Storage::Vhd::{
    AttachVirtualDisk, CreateVirtualDisk, DetachVirtualDisk, GetVirtualDiskPhysicalPath,
    ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER, ATTACH_VIRTUAL_DISK_PARAMETERS,
    ATTACH_VIRTUAL_DISK_PARAMETERS_0, ATTACH_VIRTUAL_DISK_PARAMETERS_0_0,
    ATTACH_VIRTUAL_DISK_VERSION_1, CREATE_VIRTUAL_DISK_FLAG_NONE, CREATE_VIRTUAL_DISK_PARAMETERS,
    CREATE_VIRTUAL_DISK_PARAMETERS_0, CREATE_VIRTUAL_DISK_PARAMETERS_0_1,
    CREATE_VIRTUAL_DISK_VERSION_2, VIRTUAL_DISK_ACCESS_ALL, VIRTUAL_STORAGE_TYPE,
    VIRTUAL_STORAGE_TYPE_DEVICE_VHDX, VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::HostComputeNetwork::{
    HcnCloseEndpoint, HcnCloseNetwork, HcnCreateEndpoint, HcnCreateNetwork, HcnDeleteEndpoint,
    HcnEnumerateNetworks, HcnOpenEndpoint, HcnOpenNetwork,
};
use windows_sys::Win32::System::HostComputeSystem::{
    HcsCloseComputeSystem, HcsCloseOperation, HcsCreateComputeSystem,
    HcsCreateEmptyRuntimeStateFile, HcsCreateOperation, HcsGetComputeSystemProperties,
    HcsGetServiceProperties, HcsGrantVmAccess, HcsOpenComputeSystem, HcsSaveComputeSystem,
    HcsShutDownComputeSystem, HcsStartComputeSystem, HcsTerminateComputeSystem,
    HcsWaitForComputeSystemExit, HcsWaitForOperationResult, HCS_OPERATION, HCS_SYSTEM,
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

use asterism_hyperv::{
    build_id, HostReady, Reply, Request, VmConfig, VmState, GUEST_PORT, PROTOCOL_VERSION,
};

const HCS_TIMEOUT_MS: u32 = 120_000;
const GUEST_TIMEOUT: Duration = Duration::from_secs(180);

#[link(name = "ntdll")]
extern "system" {
    fn RtlGetVersion(version: *mut OSVERSIONINFOW) -> i32;
}

pub fn dispatch(request: Request) -> Result<Reply> {
    let host = probe()?;
    if request.mutates() {
        host.require_supported()?;
    }
    match request {
        Request::Probe => Ok(Reply::Ready { host }),
        Request::MaterializeVhdx {
            source_raw,
            dest_vhdx,
            size_bytes,
        } => {
            materialize_vhdx(&source_raw, &dest_vhdx, size_bytes)?;
            Ok(Reply::Materialized)
        }
        Request::Boot { config } => boot(&config),
        Request::State { system_id } => Ok(Reply::State {
            state: state(&system_id)?,
        }),
        Request::Shutdown {
            system_id,
            timeout_ms,
        } => {
            shutdown(&system_id, timeout_ms)?;
            Ok(Reply::Stopped)
        }
        Request::Terminate {
            system_id,
            endpoint_id,
        } => {
            terminate(&system_id)?;
            if let Some(endpoint_id) = endpoint_id {
                delete_endpoint(&endpoint_id)?;
            }
            Ok(Reply::Stopped)
        }
        Request::Save {
            system_id,
            state_path,
        } => {
            save(&system_id, &state_path)?;
            Ok(Reply::Saved)
        }
    }
}

fn probe() -> Result<HostReady> {
    let version = windows_version()?;
    let edition = edition(version.0, version.1)?;
    let elevated = elevated()?;
    let hcs_running = service_running("vmcompute")?;
    let hcn_running = service_running("hns")?;

    // These calls are read-only and prove that the direct DLL entry points
    // are usable, not merely that similarly named services happen to run.
    if hcs_running {
        let mut properties: PWSTR = null_mut();
        let query = wide("{}");
        let hr = unsafe { HcsGetServiceProperties(query.as_ptr(), &mut properties) };
        if failed(hr) {
            bail!("HCS service probe failed: {}", hresult(hr, properties));
        }
        free_local(properties);
    }
    if hcn_running {
        let mut networks: PWSTR = null_mut();
        let mut error: PWSTR = null_mut();
        let query = wide("{}");
        let hr = unsafe { HcnEnumerateNetworks(query.as_ptr(), &mut networks, &mut error) };
        if failed(hr) {
            bail!("HCN service probe failed: {}", hcn_result(hr, error));
        }
        free_com(networks);
        free_com(error);
    }

    Ok(HostReady {
        protocol: PROTOCOL_VERSION,
        build: build_id(),
        windows: format!("{}.{}.{}", version.0, version.1, version.2),
        edition,
        elevated,
        hcs_running,
        hcn_running,
    })
}

fn boot(config: &VmConfig) -> Result<Reply> {
    config.validate()?;
    if let Some(system) = ComputeSystem::open(&config.system_id)? {
        if query_state(&system)? == VmState::Running {
            return wait_for_guest(config);
        }
        drop(system);
    }

    let (_network, _) = ensure_network(config)?;
    let (_endpoint, endpoint_created) = ensure_endpoint(config)?;
    for path in std::iter::once(&config.root_vhdx)
        .chain(std::iter::once(&config.seed_iso))
        .chain(config.data_vhdx.iter().map(|disk| &disk.path))
    {
        grant_vm_access(&config.system_id, path)?;
    }

    let operation = Operation::new()?;
    let id = wide(&config.system_id);
    let document = wide(&config.hcs_document()?);
    let mut raw: HCS_SYSTEM = null_mut();
    let hr = unsafe {
        HcsCreateComputeSystem(
            id.as_ptr(),
            document.as_ptr(),
            operation.0,
            null_mut(),
            &mut raw,
        )
    };
    if failed(hr) {
        if endpoint_created {
            let _ = delete_endpoint(&config.endpoint_id);
        }
        bail!("creating HCS compute system: {}", hresult(hr, null_mut()));
    }
    if let Err(error) = operation.wait("creating HCS compute system") {
        if endpoint_created {
            let _ = delete_endpoint(&config.endpoint_id);
        }
        return Err(error);
    }
    let system = ComputeSystem(raw);
    hcs_action(&system, "starting HCS compute system", |operation| unsafe {
        HcsStartComputeSystem(system.0, operation, null())
    })?;
    drop(system);

    match wait_for_guest(config) {
        Ok(reply) => Ok(reply),
        Err(error) => {
            let _ = terminate(&config.system_id);
            if endpoint_created {
                let _ = delete_endpoint(&config.endpoint_id);
            }
            Err(error)
        }
    }
}

fn state(system_id: &str) -> Result<VmState> {
    let Some(system) = ComputeSystem::open(system_id)? else {
        return Ok(VmState::Missing);
    };
    query_state(&system)
}

fn query_state(system: &ComputeSystem) -> Result<VmState> {
    let operation = Operation::new()?;
    // An empty HCS property query returns the basic compute-system fields.
    // "Basic" is not a member of the schema 2.1 PropertyType enum.
    let query = wide("{}");
    let hr = unsafe { HcsGetComputeSystemProperties(system.0, operation.0, query.as_ptr()) };
    if failed(hr) {
        bail!("querying HCS compute system: {}", hresult(hr, null_mut()));
    }
    let document = operation
        .wait("querying HCS compute system")?
        .to_ascii_lowercase();
    if document.contains("running") || document.contains("paused") {
        Ok(VmState::Running)
    } else if document.contains("saved") {
        Ok(VmState::Saved)
    } else {
        Ok(VmState::Stopped)
    }
}

fn shutdown(system_id: &str, timeout_ms: u32) -> Result<()> {
    let Some(system) = ComputeSystem::open(system_id)? else {
        return Ok(());
    };
    hcs_action(&system, "requesting HCS shutdown", |operation| unsafe {
        HcsShutDownComputeSystem(system.0, operation, null())
    })?;
    let mut result: PWSTR = null_mut();
    let hr = unsafe { HcsWaitForComputeSystemExit(system.0, timeout_ms, &mut result) };
    if failed(hr) {
        free_local(result);
        hcs_action(
            &system,
            "terminating HCS compute system after shutdown timeout",
            |op| unsafe { HcsTerminateComputeSystem(system.0, op, null()) },
        )?;
    } else {
        free_local(result);
    }
    Ok(())
}

fn terminate(system_id: &str) -> Result<()> {
    let Some(system) = ComputeSystem::open(system_id)? else {
        return Ok(());
    };
    hcs_action(
        &system,
        "terminating HCS compute system",
        |operation| unsafe { HcsTerminateComputeSystem(system.0, operation, null()) },
    )
}

fn save(system_id: &str, state_path: &Path) -> Result<()> {
    let system = ComputeSystem::open(system_id)?
        .with_context(|| format!("HCS compute system {system_id} is not running"))?;
    if state_path.exists() {
        std::fs::remove_file(state_path)?;
    }
    let path = wide_path(state_path);
    check_hr(
        unsafe { HcsCreateEmptyRuntimeStateFile(path.as_ptr()) },
        "creating the VMRS state file",
    )?;
    grant_vm_access(system_id, state_path)?;
    let options = wide(
        &serde_json::json!({
            "SaveType": "ToFile",
            "SaveStateFilePath": state_path,
        })
        .to_string(),
    );
    hcs_action(&system, "saving HCS compute system", |operation| unsafe {
        HcsSaveComputeSystem(system.0, operation, options.as_ptr())
    })
}

fn hcs_action(
    _system: &ComputeSystem,
    what: &str,
    start: impl FnOnce(HCS_OPERATION) -> HRESULT,
) -> Result<()> {
    let operation = Operation::new()?;
    let hr = start(operation.0);
    if failed(hr) {
        bail!("{what}: {}", hresult(hr, null_mut()));
    }
    operation.wait(what).map(|_| ())
}

fn grant_vm_access(system_id: &str, path: &Path) -> Result<()> {
    let id = wide(system_id);
    let path = wide_path(path);
    check_hr(
        unsafe { HcsGrantVmAccess(id.as_ptr(), path.as_ptr()) },
        "granting the VM access to a backing file",
    )
}

fn ensure_network(config: &VmConfig) -> Result<(Network, bool)> {
    let id = guid(&config.network_id)?;
    let mut raw = null_mut();
    let mut error = null_mut();
    let opened = unsafe { HcnOpenNetwork(&id, &mut raw, &mut error) };
    if !failed(opened) {
        free_com(error);
        return Ok((Network(raw), false));
    }
    if opened != HCN_E_NETWORK_NOT_FOUND {
        bail!("opening HCN v2 NAT network: {}", hcn_result(opened, error));
    }
    free_com(error);

    let settings = wide(&config.hcn_network_document()?);
    error = null_mut();
    let hr = unsafe { HcnCreateNetwork(&id, settings.as_ptr(), &mut raw, &mut error) };
    if failed(hr) {
        bail!("creating HCN v2 NAT network: {}", hcn_result(hr, error));
    }
    free_com(error);
    Ok((Network(raw), true))
}

fn ensure_endpoint(config: &VmConfig) -> Result<(Endpoint, bool)> {
    let network_id = guid(&config.network_id)?;
    let endpoint_id = guid(&config.endpoint_id)?;
    let mut network_raw = null_mut();
    let mut error = null_mut();
    let hr = unsafe { HcnOpenNetwork(&network_id, &mut network_raw, &mut error) };
    if failed(hr) {
        bail!(
            "opening HCN network for endpoint: {}",
            hcn_result(hr, error)
        );
    }
    free_com(error);
    let network = Network(network_raw);

    let mut raw = null_mut();
    error = null_mut();
    let opened = unsafe { HcnOpenEndpoint(&endpoint_id, &mut raw, &mut error) };
    if !failed(opened) {
        free_com(error);
        return Ok((Endpoint(raw), false));
    }
    if opened != HCN_E_ENDPOINT_NOT_FOUND {
        bail!("opening HCN v2 endpoint: {}", hcn_result(opened, error));
    }
    free_com(error);

    let settings = wide(&config.hcn_endpoint_document()?);
    error = null_mut();
    let hr = unsafe {
        HcnCreateEndpoint(
            network.0,
            &endpoint_id,
            settings.as_ptr(),
            &mut raw,
            &mut error,
        )
    };
    if failed(hr) {
        bail!("creating HCN v2 endpoint: {}", hcn_result(hr, error));
    }
    free_com(error);
    Ok((Endpoint(raw), true))
}

fn delete_endpoint(id: &str) -> Result<()> {
    let id = guid(id)?;
    let mut error = null_mut();
    let hr = unsafe { HcnDeleteEndpoint(&id, &mut error) };
    if hr == HCN_E_ENDPOINT_NOT_FOUND {
        free_com(error);
        return Ok(());
    }
    if failed(hr) {
        bail!("deleting HCN endpoint: {}", hcn_result(hr, error));
    }
    free_com(error);
    Ok(())
}

fn materialize_vhdx(source: &Path, dest: &Path, size_bytes: u64) -> Result<()> {
    if dest.exists() {
        return Ok(());
    }
    let source_len = std::fs::metadata(source)
        .with_context(|| format!("reading raw image metadata at {}", source.display()))?
        .len();
    if source_len > size_bytes {
        bail!(
            "the raw image is {source_len} bytes and does not fit the requested {size_bytes}-byte VHDX"
        );
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
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
        drop(disk);
        let _ = std::fs::remove_file(dest);
        bail!("AttachVirtualDisk failed with Win32 error {rc}");
    }

    let result = (|| -> Result<()> {
        let mut capacity = 512u32;
        let (buffer, size) = loop {
            let mut size = capacity;
            let mut buffer = vec![0u16; capacity as usize];
            let rc = unsafe { GetVirtualDiskPhysicalPath(disk.0, &mut size, buffer.as_mut_ptr()) };
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
        let mut source_file = std::fs::File::open(source)?;
        let mut target = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&physical)
            .with_context(|| format!("opening attached VHDX device {physical}"))?;
        target.seek(SeekFrom::Start(0))?;
        let copied = io::copy(&mut source_file, &mut target)?;
        if copied != source_len {
            bail!("raw-to-VHDX copy stopped at {copied} of {source_len} bytes");
        }
        target.sync_all()?;
        Ok(())
    })();
    let detach = unsafe { DetachVirtualDisk(disk.0, 0, 0) };
    drop(disk);
    if let Err(error) = result {
        let _ = std::fs::remove_file(dest);
        return Err(error);
    }
    if detach != ERROR_SUCCESS {
        let _ = std::fs::remove_file(dest);
        bail!("DetachVirtualDisk failed with Win32 error {detach}");
    }
    Ok(())
}

fn wait_for_guest(config: &VmConfig) -> Result<Reply> {
    let key = AgentKey::read(&config.agent_key)?;
    let deadline = Instant::now() + GUEST_TIMEOUT;
    let mut last = None;
    while Instant::now() < deadline {
        match HvSocket::connect(&config.system_id, Duration::from_secs(25)) {
            Ok(socket) => {
                let mut session = GuestSession::open(
                    BufReader::new(SocketReader(socket.socket)),
                    SocketWriter(socket.socket),
                    &key,
                )?;
                let status = session.ready_within(Duration::from_secs(20))?;
                if let Some(addr) = status.endpoint() {
                    if addr != config.guest_ip {
                        bail!(
                            "the authenticated guest reported {addr}, but its HCN endpoint is {}",
                            config.guest_ip
                        );
                    }
                    return Ok(Reply::Booted { guest_addr: addr });
                }
                last = Some(format!(
                    "agent answered but ssh was not ready (cloud-init: {})",
                    status.cloud_init
                ));
            }
            Err(error) => last = Some(format!("{error:#}")),
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    bail!(
        "the guest did not become ready over Hyper-V Socket within {}s: {}",
        GUEST_TIMEOUT.as_secs(),
        last.unwrap_or_else(|| "no connection attempt completed".into())
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
        check_hr(hr, "opening HCS compute system")?;
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
        let raw = unsafe { HcsCreateOperation(null(), None) };
        if raw.is_null() {
            bail!("HcsCreateOperation returned a null handle");
        }
        Ok(Self(raw))
    }

    fn wait(&self, what: &str) -> Result<String> {
        let mut document: PWSTR = null_mut();
        let hr = unsafe { HcsWaitForOperationResult(self.0, HCS_TIMEOUT_MS, &mut document) };
        let text = pwstr(document);
        free_local(document);
        if failed(hr) {
            bail!("{what}: {}", hresult_text(hr, &text));
        }
        Ok(text)
    }
}

impl Drop for Operation {
    fn drop(&mut self) {
        unsafe { HcsCloseOperation(self.0) };
    }
}

struct Network(*mut c_void);
impl Drop for Network {
    fn drop(&mut self) {
        unsafe { HcnCloseNetwork(self.0) };
    }
}

struct Endpoint(*mut c_void);
impl Drop for Endpoint {
    fn drop(&mut self) {
        unsafe { HcnCloseEndpoint(self.0) };
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

struct HvSocket {
    socket: SOCKET,
    // WSAStartup must remain balanced for the entire socket lifetime.
    _winsock: Winsock,
}

impl HvSocket {
    fn connect(system_id: &str, timeout: Duration) -> Result<Self> {
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
            let rc = unsafe {
                setsockopt(
                    socket.socket,
                    SOL_SOCKET,
                    option,
                    &milliseconds as *const u32 as *const u8,
                    std::mem::size_of_val(&milliseconds) as i32,
                )
            };
            if rc == SOCKET_ERROR {
                bail!("setting Hyper-V Socket timeout: WSA error {}", unsafe {
                    WSAGetLastError()
                });
            }
        }
        let address = SOCKADDR_HV {
            Family: AF_HYPERV,
            Reserved: 0,
            VmId: guid(system_id)?,
            ServiceId: service_guid(GUEST_PORT),
        };
        let rc = unsafe {
            connect(
                socket.socket,
                &address as *const SOCKADDR_HV as *const SOCKADDR,
                std::mem::size_of::<SOCKADDR_HV>() as i32,
            )
        };
        if rc == SOCKET_ERROR {
            bail!("connecting AF_HYPERV guest channel: WSA error {}", unsafe {
                WSAGetLastError()
            });
        }
        Ok(socket)
    }
}

impl Drop for HvSocket {
    fn drop(&mut self) {
        unsafe { closesocket(self.socket) };
    }
}

struct SocketReader(SOCKET);
impl Read for SocketReader {
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

struct SocketWriter(SOCKET);
impl Write for SocketWriter {
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

// The guest-agent wire is shared with the VZ helper by protocol, without
// linking that macOS helper crate (and its Unix socket dependencies) into a
// Windows binary. Keep these additive serde shapes byte-compatible with
// `asterism_vz::guest`; the portable protocol test and static gate pin them.
const GUEST_VERSIONS: &[u32] = &[1];
const MAX_GUEST_FRAME: usize = 64 * 1024;

struct AgentKey([u8; 32]);

impl AgentKey {
    fn read(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading guest agent key at {}", path.display()))?;
        let text = text.trim();
        if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!(
                "{} does not hold a 32-byte hexadecimal guest agent key",
                path.display()
            );
        }
        let mut key = [0u8; 32];
        for (index, byte) in key.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)?;
        }
        Ok(Self(key))
    }

    fn proof(&self, version: u32, side: &str, guest_nonce: &str, host_nonce: &str) -> String {
        let message = format!("asterism-guest/{version} {side} {guest_nonce} {host_nonce}");
        hex(&hmac_sha256(&self.0, message.as_bytes()))
    }
}

#[derive(Deserialize)]
struct GuestHello {
    agent: String,
    versions: Vec<u32>,
    nonce: String,
}

#[derive(Serialize)]
struct GuestAccept {
    version: u32,
    nonce: String,
    proof: String,
}

#[derive(Deserialize)]
struct GuestWelcome {
    ok: bool,
    #[serde(default)]
    proof: String,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Serialize)]
struct GuestRequest {
    id: u64,
    op: &'static str,
    wait_ms: u64,
}

#[derive(Deserialize)]
struct GuestAnswer {
    id: u64,
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    status: Option<GuestStatus>,
}

#[derive(Deserialize)]
struct GuestStatus {
    #[serde(default)]
    addrs: Vec<std::net::IpAddr>,
    #[serde(default)]
    ssh: bool,
    #[serde(default)]
    cloud_init: String,
}

impl GuestStatus {
    fn endpoint(&self) -> Option<std::net::IpAddr> {
        self.ssh
            .then(|| self.addrs.iter().copied().find(is_private_guest))
            .flatten()
    }
}

struct GuestSession<R: io::BufRead, W: Write> {
    reader: R,
    writer: W,
    next_id: u64,
}

impl<R: io::BufRead, W: Write> GuestSession<R, W> {
    fn open(mut reader: R, mut writer: W, key: &AgentKey) -> Result<Self> {
        let hello: GuestHello = read_guest_frame(&mut reader)?;
        if hello.agent != "asterism" {
            bail!(
                "the Hyper-V socket peer calls itself {:?}, not asterism",
                hello.agent
            );
        }
        let version = GUEST_VERSIONS
            .iter()
            .filter(|version| hello.versions.contains(version))
            .max()
            .copied()
            .with_context(|| {
                format!(
                    "no guest protocol version in common (guest {:?}, helper {:?})",
                    hello.versions, GUEST_VERSIONS
                )
            })?;
        let mut nonce_bytes = [0u8; 16];
        getrandom::fill(&mut nonce_bytes).context("minting guest handshake nonce")?;
        let host_nonce = hex(&nonce_bytes);
        write_guest_frame(
            &mut writer,
            &GuestAccept {
                version,
                nonce: host_nonce.clone(),
                proof: key.proof(version, "host", &hello.nonce, &host_nonce),
            },
        )?;
        let welcome: GuestWelcome = read_guest_frame(&mut reader)?;
        if !welcome.ok {
            bail!(
                "the guest agent refused the helper: {}",
                welcome.error.as_deref().unwrap_or("no reason given")
            );
        }
        let expected = key.proof(version, "guest", &hello.nonce, &host_nonce);
        if !constant_time_equal(welcome.proof.as_bytes(), expected.as_bytes()) {
            bail!("the Hyper-V socket peer did not prove this instance's guest key");
        }
        Ok(Self {
            reader,
            writer,
            next_id: 1,
        })
    }

    fn ready_within(&mut self, wait: Duration) -> Result<GuestStatus> {
        let id = self.next_id;
        self.next_id += 1;
        write_guest_frame(
            &mut self.writer,
            &GuestRequest {
                id,
                op: "status",
                wait_ms: wait.as_millis().min(u64::MAX as u128) as u64,
            },
        )?;
        let answer: GuestAnswer = read_guest_frame(&mut self.reader)?;
        if answer.id != id {
            bail!(
                "guest answered request {} while {id} was outstanding",
                answer.id
            );
        }
        if !answer.ok {
            bail!(
                "guest refused status: {}",
                answer.error.as_deref().unwrap_or("no reason given")
            );
        }
        answer
            .status
            .context("guest answered status without status data")
    }
}

fn read_guest_frame<T: serde::de::DeserializeOwned>(reader: &mut impl io::BufRead) -> Result<T> {
    let mut frame = Vec::new();
    loop {
        let chunk = reader.fill_buf()?;
        if chunk.is_empty() {
            bail!("guest closed the Hyper-V socket mid-frame");
        }
        let newline = chunk.iter().position(|byte| *byte == b'\n');
        let take = newline.unwrap_or(chunk.len());
        if frame.len() + take > MAX_GUEST_FRAME {
            bail!("guest sent more than {MAX_GUEST_FRAME} bytes before a newline");
        }
        frame.extend_from_slice(&chunk[..take]);
        reader.consume(take + usize::from(newline.is_some()));
        if newline.is_some() {
            return serde_json::from_slice(&frame).context("parsing guest-agent frame");
        }
    }
}

fn write_guest_frame(writer: &mut impl Write, value: &impl Serialize) -> Result<()> {
    serde_json::to_writer(&mut *writer, value)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

fn is_private_guest(address: &std::net::IpAddr) -> bool {
    match address {
        std::net::IpAddr::V4(address) => {
            address.is_private()
                && !address.is_loopback()
                && !address.is_link_local()
                && !address.is_broadcast()
        }
        std::net::IpAddr::V6(address) => address.segments()[0] & 0xfe00 == 0xfc00,
    }
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut padded = [0u8; BLOCK];
    padded[..key.len()].copy_from_slice(key);
    let mut inner = Sha256::new();
    inner.update(padded.map(|byte| byte ^ 0x36));
    inner.update(message);
    let mut outer = Sha256::new();
    outer.update(padded.map(|byte| byte ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0u8, |different, (left, right)| different | (left ^ right))
            == 0
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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

fn service_guid(port: u32) -> GUID {
    GUID::from_u128(((port as u128) << 96) | 0x0000_0000_facb_11e6_bd58_64006a7986d3)
}

fn windows_version() -> Result<(u32, u32, u32)> {
    let mut version = OSVERSIONINFOW::default();
    version.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOW>() as u32;
    let status = unsafe { RtlGetVersion(&mut version) };
    if status < 0 {
        bail!("RtlGetVersion failed with NTSTATUS 0x{:08x}", status as u32);
    }
    Ok((
        version.dwMajorVersion,
        version.dwMinorVersion,
        version.dwBuildNumber,
    ))
}

fn edition(major: u32, minor: u32) -> Result<String> {
    let mut product = 0;
    if unsafe { GetProductInfo(major, minor, 0, 0, &mut product) } == 0 {
        return Err(io::Error::last_os_error()).context("GetProductInfo");
    }
    let family = match product {
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
    Ok(format!("Windows 11 {family} (product {product})"))
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
        return Err(io::Error::last_os_error()).context("GetTokenInformation(TokenElevation)");
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

fn guid(text: &str) -> Result<GUID> {
    Ok(GUID::from_u128(u128::from_be_bytes(
        asterism_hyperv::parse_guid(text)?,
    )))
}

fn wide(text: &str) -> Vec<u16> {
    OsStr::new(text).encode_wide().chain(Some(0)).collect()
}

fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

fn pwstr(pointer: PCWSTR) -> String {
    if pointer.is_null() {
        return String::new();
    }
    let mut len = 0;
    unsafe {
        while *pointer.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(pointer, len))
    }
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

fn hresult(hr: HRESULT, document: PWSTR) -> String {
    let text = pwstr(document);
    free_local(document);
    hresult_text(hr, &text)
}

fn hresult_text(hr: HRESULT, text: &str) -> String {
    if text.trim().is_empty() {
        format!("HRESULT 0x{:08x}", hr as u32)
    } else {
        format!("HRESULT 0x{:08x}: {}", hr as u32, text.trim())
    }
}

fn hcn_result(hr: HRESULT, error: PWSTR) -> String {
    let text = pwstr(error);
    free_com(error);
    hresult_text(hr, &text)
}

fn free_local(pointer: PWSTR) {
    if !pointer.is_null() {
        unsafe { LocalFree(pointer as *mut c_void) };
    }
}

fn free_com(pointer: PWSTR) {
    if !pointer.is_null() {
        unsafe { CoTaskMemFree(pointer as *const c_void) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vsock_service_guid_matches_the_linux_port_template() {
        let got = service_guid(1023);
        let expected = GUID::from_u128(0x000003ff_facb_11e6_bd58_64006a7986d3);
        assert_eq!(got.data1, expected.data1);
        assert_eq!(got.data2, expected.data2);
        assert_eq!(got.data3, expected.data3);
        assert_eq!(got.data4, expected.data4);
    }
}
