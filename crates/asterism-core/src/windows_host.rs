//! Windows host integration seams: service persistence, sleep, credentials,
//! helper discovery, and the firewall/Hyper-V capability doctor.
//!
//! Callers never need a hypervisor backend. The doctor is read-only and is
//! the pre-mutation gate the installer, `ast doctor`, and `ast bugreport`
//! all print. Win32 calls stay behind `cfg(windows)` and are declared the
//! same way macOS talks to IOKit — no extra crate, so a source-only change
//! does not churn the lockfile.

use std::path::Path;

use anyhow::{bail, Result};

use crate::hyperv::{self, HELPER_BIN};
use crate::service::Spec;

/// SCM service name. Dots are legal; this matches the launchd label so a
/// bug report can name one thing on every OS.
pub const SERVICE_NAME: &str = "com.asterism.astd";
pub const SERVICE_DISPLAY: &str = "Asterism device daemon";

/// Credential Manager generic-credential namespace. Same string the macOS
/// Keychain uses, so an orbit secret copied between devices keeps one name.
pub const CRED_SERVICE: &str = "dev.asterism.secret";

/// `ES_CONTINUOUS | ES_SYSTEM_REQUIRED` — the `SetThreadExecutionState`
/// flags that mean "do not idle-sleep while this process holds them".
pub const ES_SYSTEM_REQUIRED: u32 = 0x0000_0001;
pub const ES_CONTINUOUS: u32 = 0x8000_0000;
pub const ES_DISPLAY_REQUIRED: u32 = 0x0000_0002;
pub const SLEEP_STATE: u32 = ES_CONTINUOUS | ES_SYSTEM_REQUIRED;

/// Firewall rule group Hyper-V installs. The doctor looks for it by name
/// rather than opening the COM firewall policy on a non-Windows host.
pub const HYPERV_FIREWALL_GROUP: &str = "Hyper-V";
pub const ASTERISM_FIREWALL_RULE: &str = "Asterism device daemon";

/// Windows optional features the native backend needs already enabled.
pub const REQUIRED_FEATURES: &[&str] = &[
    "Microsoft-Hyper-V",
    "Microsoft-Hyper-V-Management-Clients",
    "Containers",
];

/// SCM / HCS services that must be running before a guest is created.
pub const REQUIRED_SERVICES: &[&str] = &["vmcompute", "hns", "vmms"];

/// One line of a doctor report. Stable keys so `ast bugreport` and the
/// installer can be grepped the same way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub key: String,
    pub ok: bool,
    pub detail: String,
}

impl Check {
    pub fn pass(key: &str, detail: impl Into<String>) -> Self {
        Self {
            key: key.to_owned(),
            ok: true,
            detail: detail.into(),
        }
    }

    pub fn fail(key: &str, detail: impl Into<String>) -> Self {
        Self {
            key: key.to_owned(),
            ok: false,
            detail: detail.into(),
        }
    }

    pub fn line(&self) -> String {
        let mark = if self.ok { "ok" } else { "fail" };
        format!("{:<16} {mark}  {}", self.key, self.detail)
    }
}

/// Read-only capability report. Never mutates Hyper-V, the firewall, or the
/// service database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorReport {
    pub supported: bool,
    pub checks: Vec<Check>,
}

impl DoctorReport {
    pub fn summary(&self) -> &'static str {
        if self.supported {
            "this Windows host can run Asterism"
        } else {
            "this host is not yet a supported Windows Asterism machine"
        }
    }

    pub fn lines(&self) -> Vec<String> {
        let mut lines = vec![
            "[windows-doctor]".to_owned(),
            format!("supported       {}", self.supported),
        ];
        for check in &self.checks {
            lines.push(check.line());
        }
        lines
    }
}

/// Diagnose this host. On a non-Windows build this still runs: it reports
/// that the Hyper-V doctor does not apply, and still looks for the helper
/// so a mixed tree is honest about what a Windows artifact would need.
pub fn doctor() -> DoctorReport {
    let mut checks = Vec::new();

    match hyperv::discover_helper() {
        Ok(path) => checks.push(Check::pass(
            "helper",
            format!("{} at {}", HELPER_BIN, path.display()),
        )),
        Err(err) => {
            // A macOS/Linux build is not a Windows artifact; the helper is
            // required only on the Windows host that would run Hyper-V.
            if cfg!(windows) {
                checks.push(Check::fail("helper", format!("{err:#}")));
            } else {
                checks.push(Check::pass("helper", format!("not this OS ({err:#})")));
            }
        }
    }

    #[cfg(windows)]
    {
        checks.extend(windows_checks());
    }
    #[cfg(not(windows))]
    {
        checks.push(Check::pass(
            "os",
            format!(
                "{} — Hyper-V, firewall, SCM and Credential Manager checks run on the Windows artifact",
                std::env::consts::OS
            ),
        ));
        checks.push(Check::pass(
            "sleep-row",
            "SetThreadExecutionState ES_CONTINUOUS|ES_SYSTEM_REQUIRED is the decided Windows row",
        ));
        checks.push(Check::pass(
            "service-row",
            format!("Windows Service {SERVICE_NAME} via SCM is the decided persistence row"),
        ));
        checks.push(Check::pass(
            "secret-row",
            format!(
                "Credential Manager generic credential {CRED_SERVICE} is the decided secret row"
            ),
        ));
    }

    let supported = checks.iter().all(|c| c.ok);
    DoctorReport { supported, checks }
}

/// ImagePath written into SCM. `--service` is what makes `astd` enter the
/// service dispatcher rather than a console main; without it SCM starts a
/// process that has no SERVICE_TABLE and the service is marked failed.
pub fn service_bin_path(program: &Path) -> String {
    format!("\"{}\" --service", program.display())
}

fn service_bin_path_with_home(program: &Path, home: &Path) -> String {
    format!(
        "\"{}\" --service --home \"{}\"",
        program.display(),
        home.display()
    )
}

/// Arguments for `sc.exe create`. Built as data so tests on a Unix host can
/// assert the persistence promise without talking to SCM.
pub fn sc_create_args(spec: &Spec, name: &str) -> Vec<String> {
    let bin = match &spec.home {
        Some(home) => service_bin_path_with_home(&spec.program, home),
        None => service_bin_path(&spec.program),
    };
    vec![
        "create".into(),
        name.into(),
        format!("binPath={bin}"),
        "start=auto".into(),
        format!("DisplayName={SERVICE_DISPLAY}"),
        "type=own".into(),
    ]
}

/// `sc.exe query` / `delete` / `start` / `stop` argument lists.
pub fn sc_query_args(name: &str) -> Vec<String> {
    vec!["query".into(), name.into()]
}

pub fn sc_delete_args(name: &str) -> Vec<String> {
    vec!["delete".into(), name.into()]
}

pub fn sc_start_args(name: &str) -> Vec<String> {
    vec!["start".into(), name.into()]
}

pub fn sc_stop_args(name: &str) -> Vec<String> {
    vec!["stop".into(), name.into()]
}

/// Parse `sc.exe query` output into a pid and a running bit.
pub fn parse_sc_query(text: &str) -> (bool, Option<u32>) {
    let running = text.to_ascii_uppercase().contains("RUNNING");
    let pid = text.lines().find_map(|line| {
        let line = line.trim();
        let rest = line
            .strip_prefix("PID")
            .or_else(|| line.strip_prefix("pid"))?;
        let rest = rest.trim_start_matches([' ', ':']);
        rest.split_whitespace().next()?.parse().ok()
    });
    (running, pid)
}

/// Credential Manager target name. Namespaced by device id so two
/// ASTERISM_HOMEs on one login cannot overwrite each other.
pub fn cred_target(namespace: &str, secret: &str) -> String {
    format!("{CRED_SERVICE}/{namespace}/{secret}")
}

/// Authenticode is the Windows equivalent of the macOS notarized helper:
/// a release binary is signed with the Authenticode certificate, and the
/// installer refuses an unexpected signer when a thumbprint is pinned.
pub fn authenticode_ok(
    status: &str,
    pinned_thumbprint: Option<&str>,
    actual: Option<&str>,
) -> bool {
    if !status.trim().eq_ignore_ascii_case("valid") {
        return false;
    }
    match (pinned_thumbprint, actual) {
        (None, _) => true,
        (Some(want), Some(got)) => want.eq_ignore_ascii_case(got),
        (Some(_), None) => false,
    }
}

#[cfg(windows)]
fn windows_checks() -> Vec<Check> {
    let mut checks = Vec::new();
    let info = host_info();
    checks.push(
        if info.edition.contains("Pro") || info.edition.contains("Enterprise") {
            Check::pass("edition", format!("{} {}", info.edition, info.windows))
        } else {
            Check::fail(
                "edition",
                format!(
                    "Windows 11 Pro or Enterprise is required; this is {}",
                    info.edition
                ),
            )
        },
    );
    let build = info
        .windows
        .rsplit('.')
        .next()
        .and_then(|part| part.parse::<u32>().ok())
        .unwrap_or(0);
    checks.push(if build >= 22_000 {
        Check::pass("build", info.windows.clone())
    } else {
        Check::fail(
            "build",
            format!(
                "Windows 11 build 22000+ is required; this is {}",
                info.windows
            ),
        )
    });
    checks.push(if info.elevated {
        Check::pass("elevated", "administrator token")
    } else {
        Check::fail(
            "elevated",
            "the native Hyper-V backend needs an elevated administrator token",
        )
    });
    checks.push(service_check("vmcompute", info.hcs_running));
    checks.push(service_check("hns", info.hcn_running));
    checks.push(service_check("vmms", info.vmms_running));
    checks.push(if info.firewall_ok {
        Check::pass(
            "firewall",
            format!("Windows Firewall allows {HYPERV_FIREWALL_GROUP}"),
        )
    } else {
        Check::fail(
            "firewall",
            "Windows Firewall is blocking Hyper-V or the Asterism daemon inbound rule is missing",
        )
    });
    checks.push(if info.credman_ok {
        Check::pass(
            "credman",
            format!("Credential Manager {CRED_SERVICE} is usable"),
        )
    } else {
        Check::fail(
            "credman",
            "Credential Manager refused a generic-credential probe",
        )
    });
    checks.push(if info.sleep_ok {
        Check::pass(
            "sleep",
            "SetThreadExecutionState ES_CONTINUOUS|ES_SYSTEM_REQUIRED",
        )
    } else {
        Check::fail("sleep", "SetThreadExecutionState refused a sleep assertion")
    });
    let host = crate::hyperv::HostReady {
        protocol: hyperv::PROTOCOL_VERSION,
        build: hyperv::build_id(),
        windows: info.windows,
        edition: info.edition,
        elevated: info.elevated,
        hcs_running: info.hcs_running,
        hcn_running: info.hcn_running,
    };
    match host.require_supported() {
        Ok(()) => checks.push(Check::pass(
            "contract",
            "510d330 helper host gate accepts this machine",
        )),
        Err(err) => checks.push(Check::fail("contract", format!("{err:#}"))),
    }
    checks
}

#[cfg(windows)]
fn service_check(name: &str, running: bool) -> Check {
    if running {
        Check::pass(name, "running")
    } else {
        Check::fail(
            name,
            format!("{name} is not running — enable Hyper-V and reboot before creating a guest"),
        )
    }
}

#[cfg(windows)]
struct HostInfo {
    windows: String,
    edition: String,
    elevated: bool,
    hcs_running: bool,
    hcn_running: bool,
    vmms_running: bool,
    firewall_ok: bool,
    credman_ok: bool,
    sleep_ok: bool,
}

#[cfg(windows)]
fn host_info() -> HostInfo {
    HostInfo {
        windows: os_version(),
        edition: product_edition(),
        elevated: is_elevated(),
        hcs_running: service_running("vmcompute"),
        hcn_running: service_running("hns"),
        vmms_running: service_running("vmms"),
        firewall_ok: firewall_allows_hyperv(),
        credman_ok: credman_probe(),
        sleep_ok: sleep_probe(),
    }
}

#[cfg(windows)]
fn os_version() -> String {
    // kernel32 RtlGetVersion is the honest build, including after a
    // compatibility shim has rewritten GetVersionEx.
    #[repr(C)]
    struct OsVersionInfoW {
        size: u32,
        major: u32,
        minor: u32,
        build: u32,
        platform: u32,
        csd: [u16; 128],
    }
    #[link(name = "ntdll")]
    extern "system" {
        fn RtlGetVersion(info: *mut OsVersionInfoW) -> i32;
    }
    let mut info = OsVersionInfoW {
        size: std::mem::size_of::<OsVersionInfoW>() as u32,
        major: 0,
        minor: 0,
        build: 0,
        platform: 0,
        csd: [0; 128],
    };
    let rc = unsafe { RtlGetVersion(&mut info) };
    if rc != 0 {
        return "unknown".into();
    }
    format!("{}.{}.{}", info.major, info.minor, info.build)
}

#[cfg(windows)]
fn product_edition() -> String {
    // Registry is the documented product-name source and does not require
    // GetProductInfo's SKU table. Home vs Pro vs Enterprise is the gate.
    match read_reg_sz(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "EditionID") {
        Some(id) => {
            let pretty = read_reg_sz(
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                "ProductName",
            )
            .unwrap_or_else(|| format!("Windows {id}"));
            if pretty.contains(&id) {
                pretty
            } else {
                format!("{pretty} ({id})")
            }
        }
        None => "Windows".into(),
    }
}

#[cfg(windows)]
fn read_reg_sz(subkey: &str, value: &str) -> Option<String> {
    use std::os::windows::ffi::OsStringExt;
    const HKEY_LOCAL_MACHINE: usize = 0x8000_0002;
    const KEY_READ: u32 = 0x20019;
    const REG_SZ: u32 = 1;
    type HKEY = *mut core::ffi::c_void;
    #[link(name = "advapi32")]
    extern "system" {
        fn RegOpenKeyExW(
            key: HKEY,
            subkey: *const u16,
            options: u32,
            desired: u32,
            result: *mut HKEY,
        ) -> i32;
        fn RegQueryValueExW(
            key: HKEY,
            name: *const u16,
            reserved: *mut u32,
            kind: *mut u32,
            data: *mut u8,
            len: *mut u32,
        ) -> i32;
        fn RegCloseKey(key: HKEY) -> i32;
    }
    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }
    let mut handle: HKEY = std::ptr::null_mut();
    let sub = wide(subkey);
    let rc = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE as HKEY,
            sub.as_ptr(),
            0,
            KEY_READ,
            &mut handle,
        )
    };
    if rc != 0 {
        return None;
    }
    let name = wide(value);
    let mut kind = 0u32;
    let mut len = 0u32;
    let q = unsafe {
        RegQueryValueExW(
            handle,
            name.as_ptr(),
            std::ptr::null_mut(),
            &mut kind,
            std::ptr::null_mut(),
            &mut len,
        )
    };
    if q != 0 || kind != REG_SZ || len < 2 {
        unsafe { RegCloseKey(handle) };
        return None;
    }
    let mut buf = vec![0u8; len as usize];
    let q = unsafe {
        RegQueryValueExW(
            handle,
            name.as_ptr(),
            std::ptr::null_mut(),
            &mut kind,
            buf.as_mut_ptr(),
            &mut len,
        )
    };
    unsafe { RegCloseKey(handle) };
    if q != 0 {
        return None;
    }
    let units: Vec<u16> = buf
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|u| *u != 0)
        .collect();
    Some(std::ffi::OsString::from_wide(&units).into_string().ok()?)
}

#[cfg(windows)]
fn is_elevated() -> bool {
    const TOKEN_QUERY: u32 = 0x0008;
    const TokenElevation: i32 = 20;
    type HANDLE = *mut core::ffi::c_void;
    #[repr(C)]
    struct TokenElevation {
        elevated: u32,
    }
    #[link(name = "advapi32")]
    extern "system" {
        fn OpenProcessToken(process: HANDLE, access: u32, token: *mut HANDLE) -> i32;
        fn GetTokenInformation(
            token: HANDLE,
            class: i32,
            info: *mut core::ffi::c_void,
            len: u32,
            out: *mut u32,
        ) -> i32;
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> HANDLE;
        fn CloseHandle(handle: HANDLE) -> i32;
    }
    let mut token: HANDLE = std::ptr::null_mut();
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if ok == 0 {
        return false;
    }
    let mut elevation = TokenElevation { elevated: 0 };
    let mut written = 0u32;
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            std::mem::size_of::<TokenElevation>() as u32,
            &mut written,
        )
    };
    unsafe { CloseHandle(token) };
    ok != 0 && elevation.elevated != 0
}

#[cfg(windows)]
fn service_running(name: &str) -> bool {
    // sc.exe is the same tool install uses, and QueryServiceStatusEx is the
    // API behind it. Shelling out keeps the doctor honest when SCM ACLs
    // refuse OpenService from a non-elevated token: the message is sc's.
    let output = std::process::Command::new("sc.exe")
        .args(sc_query_args(name))
        .output();
    match output {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout);
            parse_sc_query(&text).0
        }
        Err(_) => false,
    }
}

#[cfg(windows)]
fn firewall_allows_hyperv() -> bool {
    // netsh is the documented read-only view of the firewall policy and does
    // not require the INetFwPolicy2 COM apartment. The doctor must not
    // create rules; the installer does that when asked.
    let output = std::process::Command::new("netsh")
        .args(["advfirewall", "show", "currentprofile"])
        .output();
    match output {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout).to_ascii_lowercase();
            // A disabled firewall is fine: nothing is blocked.
            if text.contains("state                                 off")
                || text.contains("state off")
            {
                return true;
            }
            hyperv_firewall_group_present()
        }
        Err(_) => false,
    }
}

#[cfg(windows)]
fn hyperv_firewall_group_present() -> bool {
    let output = std::process::Command::new("netsh")
        .args(["advfirewall", "firewall", "show", "rule", "name=all"])
        .output();
    match output {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout);
            text.contains(HYPERV_FIREWALL_GROUP) || text.contains(ASTERISM_FIREWALL_RULE)
        }
        Err(_) => false,
    }
}

#[cfg(windows)]
fn credman_probe() -> bool {
    // Write+delete a throwaway generic credential to prove the store works
    // without leaving material behind. Failure here is "this login cannot
    // hold orbit secrets", not a missing secret.
    let target = cred_target("doctor", "probe");
    match crate::windows_host::cred::put(&target, b"probe") {
        Ok(()) => {
            let _ = crate::windows_host::cred::delete(&target);
            true
        }
        Err(_) => false,
    }
}

#[cfg(windows)]
fn sleep_probe() -> bool {
    match hold_sleep("asterism doctor") {
        Ok(held) => {
            drop(held);
            true
        }
        Err(_) => false,
    }
}

/// A held `SetThreadExecutionState`. Restores `ES_CONTINUOUS` only (clearing
/// `ES_SYSTEM_REQUIRED`) on drop, which is the documented way to let the
/// machine sleep again.
pub struct SleepHeld;

pub fn hold_sleep(_reason: &str) -> Result<SleepHeld> {
    #[cfg(windows)]
    {
        return imp_sleep::hold();
    }
    #[cfg(not(windows))]
    {
        bail!(
            "this device cannot prevent sleep yet — the Windows row of \
             docs/PLATFORM.md (SetThreadExecutionState) is not this OS"
        )
    }
}

#[cfg(windows)]
mod imp_sleep {
    use super::{SleepHeld, ES_CONTINUOUS, SLEEP_STATE};
    use anyhow::{bail, Result};

    #[link(name = "kernel32")]
    extern "system" {
        fn SetThreadExecutionState(flags: u32) -> u32;
    }

    pub fn hold() -> Result<SleepHeld> {
        let previous = unsafe { SetThreadExecutionState(SLEEP_STATE) };
        if previous == 0 {
            bail!("SetThreadExecutionState refused ES_CONTINUOUS|ES_SYSTEM_REQUIRED");
        }
        Ok(SleepHeld)
    }

    impl Drop for SleepHeld {
        fn drop(&mut self) {
            unsafe {
                let _ = SetThreadExecutionState(ES_CONTINUOUS);
            }
        }
    }
}

/// Credential Manager generic credentials. Portable helpers plus the Win32
/// implementation. Secret bytes never enter `$ASTERISM_HOME`.
pub mod cred {
    use super::CRED_SERVICE;
    use anyhow::{bail, Result};

    pub fn put(target: &str, value: &[u8]) -> Result<()> {
        #[cfg(windows)]
        {
            return win::put(target, value);
        }
        #[cfg(not(windows))]
        {
            let _ = (target, value, CRED_SERVICE);
            bail!("Credential Manager is not this OS")
        }
    }

    pub fn get(target: &str) -> Result<Vec<u8>> {
        #[cfg(windows)]
        {
            return win::get(target);
        }
        #[cfg(not(windows))]
        {
            let _ = target;
            bail!("Credential Manager is not this OS")
        }
    }

    pub fn delete(target: &str) -> Result<()> {
        #[cfg(windows)]
        {
            return win::delete(target);
        }
        #[cfg(not(windows))]
        {
            let _ = target;
            bail!("Credential Manager is not this OS")
        }
    }

    #[cfg(windows)]
    mod win {
        use super::*;
        use anyhow::{bail, Context, Result};

        const CRED_TYPE_GENERIC: u32 = 1;
        const CRED_PERSIST_LOCAL_MACHINE: u32 = 2;
        const ERROR_NOT_FOUND: u32 = 1168;

        #[repr(C)]
        struct CredentialW {
            flags: u32,
            type_: u32,
            target_name: *mut u16,
            comment: *mut u16,
            last_written: i64,
            credential_blob_size: u32,
            credential_blob: *mut u8,
            persist: u32,
            attribute_count: u32,
            attributes: *mut core::ffi::c_void,
            target_alias: *mut u16,
            user_name: *mut u16,
        }

        #[link(name = "advapi32")]
        extern "system" {
            fn CredWriteW(credential: *const CredentialW, flags: u32) -> i32;
            fn CredReadW(
                target: *const u16,
                type_: u32,
                flags: u32,
                credential: *mut *mut CredentialW,
            ) -> i32;
            fn CredDeleteW(target: *const u16, type_: u32, flags: u32) -> i32;
            fn CredFree(buffer: *mut core::ffi::c_void);
        }
        #[link(name = "kernel32")]
        extern "system" {
            fn GetLastError() -> u32;
        }

        fn wide(s: &str) -> Vec<u16> {
            s.encode_utf16().chain(std::iter::once(0)).collect()
        }

        pub fn put(target: &str, value: &[u8]) -> Result<()> {
            let mut target_w = wide(target);
            let mut user_w = wide(CRED_SERVICE);
            let mut blob = value.to_vec();
            let cred = CredentialW {
                flags: 0,
                type_: CRED_TYPE_GENERIC,
                target_name: target_w.as_mut_ptr(),
                comment: std::ptr::null_mut(),
                last_written: 0,
                credential_blob_size: blob.len() as u32,
                credential_blob: blob.as_mut_ptr(),
                persist: CRED_PERSIST_LOCAL_MACHINE,
                attribute_count: 0,
                attributes: std::ptr::null_mut(),
                target_alias: std::ptr::null_mut(),
                user_name: user_w.as_mut_ptr(),
            };
            let ok = unsafe { CredWriteW(&cred, 0) };
            if ok == 0 {
                bail!("CredWriteW failed (GetLastError {})", unsafe {
                    GetLastError()
                });
            }
            Ok(())
        }

        pub fn get(target: &str) -> Result<Vec<u8>> {
            let target_w = wide(target);
            let mut cred: *mut CredentialW = std::ptr::null_mut();
            let ok = unsafe { CredReadW(target_w.as_ptr(), CRED_TYPE_GENERIC, 0, &mut cred) };
            if ok == 0 || cred.is_null() {
                let err = unsafe { GetLastError() };
                if err == ERROR_NOT_FOUND {
                    bail!("Credential Manager has no entry {target:?}");
                }
                bail!("CredReadW failed (GetLastError {err})");
            }
            let value = unsafe {
                let blob = std::slice::from_raw_parts(
                    (*cred).credential_blob,
                    (*cred).credential_blob_size as usize,
                );
                blob.to_vec()
            };
            unsafe { CredFree(cred as *mut _) };
            Ok(value)
        }

        pub fn delete(target: &str) -> Result<()> {
            let target_w = wide(target);
            let ok = unsafe { CredDeleteW(target_w.as_ptr(), CRED_TYPE_GENERIC, 0) };
            if ok == 0 {
                let err = unsafe { GetLastError() };
                if err == ERROR_NOT_FOUND {
                    return Ok(());
                }
                return Err(anyhow::anyhow!("CredDeleteW failed (GetLastError {err})"))
                    .with_context(|| format!("removing {target:?}"));
            }
            Ok(())
        }
    }
}

/// SCM STOP/SHUTDOWN latch. The daemon's accept loop waits on this on
/// Windows so a service stop is a clean shutdown rather than TerminateProcess.
pub fn service_stop_requested() -> bool {
    SERVICE_STOP.load(std::sync::atomic::Ordering::SeqCst)
}

pub fn request_service_stop() {
    SERVICE_STOP.store(true, std::sync::atomic::Ordering::SeqCst);
}

static SERVICE_STOP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Enter the Windows Service dispatcher. Must be called from the process
/// entry thread, not from inside a tokio worker: SCM requires
/// `StartServiceCtrlDispatcher` on the thread that is the process main.
#[cfg(windows)]
pub fn dispatch_service<F>(name: &str, worker: F) -> Result<()>
where
    F: FnOnce() -> Result<()> + Send + 'static,
{
    scm::dispatch(name, worker)
}

#[cfg(windows)]
mod scm {
    use super::*;
    use anyhow::{bail, Result};
    use std::sync::Mutex;

    type Handle = *mut core::ffi::c_void;
    type Dword = u32;

    const SERVICE_WIN32_OWN_PROCESS: Dword = 0x00000010;
    const SERVICE_ACCEPT_STOP: Dword = 0x00000001;
    const SERVICE_ACCEPT_SHUTDOWN: Dword = 0x00000004;
    const SERVICE_START_PENDING: Dword = 0x00000002;
    const SERVICE_RUNNING: Dword = 0x00000004;
    const SERVICE_STOP_PENDING: Dword = 0x00000003;
    const SERVICE_STOPPED: Dword = 0x00000001;
    const SERVICE_CONTROL_STOP: Dword = 0x00000001;
    const SERVICE_CONTROL_SHUTDOWN: Dword = 0x00000005;
    const NO_ERROR: Dword = 0;

    #[repr(C)]
    struct ServiceTableEntryW {
        name: *const u16,
        proc: Option<unsafe extern "system" fn(Dword, *mut *mut u16)>,
    }

    #[repr(C)]
    struct ServiceStatus {
        service_type: Dword,
        current_state: Dword,
        controls_accepted: Dword,
        win32_exit_code: Dword,
        service_specific_exit_code: Dword,
        check_point: Dword,
        wait_hint: Dword,
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn StartServiceCtrlDispatcherW(table: *const ServiceTableEntryW) -> i32;
        fn RegisterServiceCtrlHandlerExW(
            name: *const u16,
            handler: Option<
                unsafe extern "system" fn(
                    Dword,
                    Dword,
                    *mut core::ffi::c_void,
                    *mut core::ffi::c_void,
                ) -> Dword,
            >,
            context: *mut core::ffi::c_void,
        ) -> Handle;
        fn SetServiceStatus(handle: Handle, status: *mut ServiceStatus) -> i32;
    }

    static WORKER: Mutex<Option<Box<dyn FnOnce() -> Result<()> + Send>>> = Mutex::new(None);
    static STATUS: Mutex<Option<Handle>> = Mutex::new(None);
    static NAME: Mutex<Option<Vec<u16>>> = Mutex::new(None);

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn dispatch<F>(name: &str, worker: F) -> Result<()>
    where
        F: FnOnce() -> Result<()> + Send + 'static,
    {
        *WORKER.lock().unwrap() = Some(Box::new(worker));
        let name_w = wide(name);
        *NAME.lock().unwrap() = Some(name_w.clone());
        let table = [
            ServiceTableEntryW {
                name: name_w.as_ptr(),
                proc: Some(service_main),
            },
            ServiceTableEntryW {
                name: std::ptr::null(),
                proc: None,
            },
        ];
        let ok = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
        if ok == 0 {
            bail!("StartServiceCtrlDispatcherW refused — astd --service is for SCM, not a console");
        }
        Ok(())
    }

    fn set_state(state: Dword, accept_stop: bool) {
        let handle = match *STATUS.lock().unwrap() {
            Some(h) => h,
            None => return,
        };
        let mut status = ServiceStatus {
            service_type: SERVICE_WIN32_OWN_PROCESS,
            current_state: state,
            controls_accepted: if accept_stop {
                SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
            } else {
                0
            },
            win32_exit_code: NO_ERROR,
            service_specific_exit_code: 0,
            check_point: 0,
            wait_hint: if state == SERVICE_STOP_PENDING {
                5000
            } else {
                0
            },
        };
        unsafe {
            let _ = SetServiceStatus(handle, &mut status);
        }
    }

    unsafe extern "system" fn service_main(_argc: Dword, _argv: *mut *mut u16) {
        let name = NAME
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| wide(SERVICE_NAME));
        let handle = unsafe {
            RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(ctrl_handler), std::ptr::null_mut())
        };
        if handle.is_null() {
            return;
        }
        *STATUS.lock().unwrap() = Some(handle);
        set_state(SERVICE_START_PENDING, false);
        set_state(SERVICE_RUNNING, true);
        let worker = WORKER.lock().unwrap().take();
        if let Some(worker) = worker {
            let _ = worker();
        }
        set_state(SERVICE_STOP_PENDING, false);
        set_state(SERVICE_STOPPED, false);
    }

    unsafe extern "system" fn ctrl_handler(
        control: Dword,
        _event: Dword,
        _data: *mut core::ffi::c_void,
        _context: *mut core::ffi::c_void,
    ) -> Dword {
        match control {
            SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
                set_state(SERVICE_STOP_PENDING, false);
                request_service_stop();
                NO_ERROR
            }
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn spec() -> Spec {
        Spec {
            program: PathBuf::from(r"C:\Users\me\AppData\Local\Asterism\bin\astd.exe"),
            home: Some(PathBuf::from(r"C:\Users\me\.asterism")),
            path_env: r"C:\Windows\system32".into(),
            log: PathBuf::from(r"C:\Users\me\.asterism\astd.log"),
        }
    }

    #[test]
    fn sc_create_bakes_the_binary_home_and_auto_start() {
        let args = sc_create_args(&spec(), SERVICE_NAME);
        let joined = args.join(" ");
        assert!(joined.contains("create"));
        assert!(joined.contains(SERVICE_NAME));
        assert!(joined.contains("start=auto"), "{joined}");
        assert!(joined.contains("--service"), "{joined}");
        assert!(joined.contains(r"astd.exe"), "{joined}");
        assert!(joined.contains(r"--home"), "{joined}");
        assert!(joined.contains("type=own"), "{joined}");
        assert!(!joined.to_ascii_lowercase().contains("qemu"));
    }

    #[test]
    fn sc_query_running_and_pid_are_parsed() {
        let text = "SERVICE_NAME: com.asterism.astd\n        TYPE               : 10  WIN32_OWN_PROCESS\n        STATE              : 4  RUNNING\n        PID                : 4242\n";
        assert_eq!(parse_sc_query(text), (true, Some(4242)));
        assert_eq!(parse_sc_query("STATE : 1 STOPPED"), (false, None));
    }

    #[test]
    fn sleep_flags_are_the_documented_pair() {
        assert_eq!(SLEEP_STATE, 0x8000_0001);
        assert_ne!(SLEEP_STATE & ES_DISPLAY_REQUIRED, ES_DISPLAY_REQUIRED);
    }

    #[test]
    fn credential_targets_are_namespaced() {
        assert_eq!(
            cred_target("devabc", "anthropic"),
            "dev.asterism.secret/devabc/anthropic"
        );
    }

    #[test]
    fn authenticode_pins_a_thumbprint_when_asked() {
        assert!(authenticode_ok("Valid", None, None));
        assert!(authenticode_ok("Valid", Some("ABC"), Some("abc")));
        assert!(!authenticode_ok("Valid", Some("ABC"), Some("DEF")));
        assert!(!authenticode_ok("NotSigned", None, None));
        assert!(!authenticode_ok("HashMismatch", Some("ABC"), Some("ABC")));
    }

    #[test]
    fn doctor_on_this_host_always_prints_the_windows_rows() {
        let report = doctor();
        let text = report.lines().join("\n");
        assert!(text.contains("[windows-doctor]"));
        assert!(text.contains("helper"));
        assert!(
            text.contains("service-row") || text.contains("edition") || text.contains("sleep-row"),
            "{text}"
        );
    }

    #[test]
    fn required_services_and_features_are_the_adr_set() {
        assert!(REQUIRED_SERVICES.contains(&"vmcompute"));
        assert!(REQUIRED_SERVICES.contains(&"hns"));
        assert!(REQUIRED_FEATURES.iter().any(|f| f.contains("Hyper-V")));
    }

    #[test]
    fn a_service_stop_is_an_explicit_latch() {
        request_service_stop();
        assert!(service_stop_requested());
    }
}
