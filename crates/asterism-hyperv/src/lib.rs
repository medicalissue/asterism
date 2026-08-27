//! Protocol between `astd` and the native Windows Hyper-V helper.
//!
//! This crate is intentionally portable. The daemon links these serde types,
//! while only the helper's `cfg(windows)` module links ComputeCore, HCN,
//! VirtDisk, or WinSock. That is the boundary locked in ADR 0002.

use std::io::{BufReader, Read, Write};
use std::net::IpAddr;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

pub const HELPER_BIN: &str = "astd-hyperv";
pub const PROTOCOL_VERSION: u32 = 1;
pub const OWNER: &str = "asterism";
pub const GUEST_PORT: u32 = 1023;
pub const GUEST_SERVICE_ID: &str = "000003ff-facb-11e6-bd58-64006a7986d3";

/// The secret-egress door's Hyper-V Socket port and service GUID.
///
/// `hv_sock` gives every AF_VSOCK port a service GUID by substituting the
/// port into the first double word of the VSOCK template GUID
/// `00000000-facb-11e6-bd58-64006a7986d3` (Linux
/// `Documentation/virt/hyperv/vmbus.rst`, and the same derivation
/// `GUEST_SERVICE_ID` above uses for port 1023). So the guest agent dialling
/// AF_VSOCK port 1021 towards CID 2 arrives here, and nothing above the
/// driver has to know which hypervisor it is on.
pub const EGRESS_PORT: u32 = 1021;
pub const EGRESS_SERVICE_ID: &str = "000003fd-facb-11e6-bd58-64006a7986d3";

/// Immutable identity shared by the daemon-side protocol crate and helper.
/// Release builds set `ASTERISM_BUILD_ID` to their source commit. A source
/// build without an explicit identity is honest about the weaker guarantee.
pub fn build_id() -> String {
    format!(
        "{}+{}",
        env!("CARGO_PKG_VERSION"),
        option_env!("ASTERISM_BUILD_ID").unwrap_or("unknown")
    )
}

/// How this guest's firmware finds something to execute.
///
/// Hyper-V's compute service has two entry points, and which one a guest uses
/// is decided by what is on its disk.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BootSource {
    /// A cloud image: a whole disk carrying its own bootloader, started by the
    /// Generation 2 UEFI firmware, with the NoCloud seed attached beside it as
    /// an ISO.
    #[default]
    Uefi,
    /// An OCI root filesystem, which has no bootloader at all. HCS loads the
    /// kernel and initrd from host files and passes the command line straight
    /// to it — `Chipset.LinuxKernelDirect`, the same entry point Linux
    /// containers on Windows boot through. No firmware is involved, so no
    /// Secure Boot policy applies to it. See ADR 0005.
    LinuxKernel {
        kernel: PathBuf,
        initrd: PathBuf,
        cmdline: String,
    },
}

/// What `astd` needs the helper to do for this instance's egress door.
///
/// The helper binds the door's service GUID against this VM alone and
/// splices what it accepts into `pipe`, a named pipe `astd` created with a
/// descriptor naming only its own identity. Nothing is published on a host
/// interface at either end.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressDoor {
    pub system_id: String,
    pub instance: String,
    /// Full `\\.\pipe\...` name of the door's host end.
    pub pipe: String,
    /// This instance's guest agent key, which both ends of the door prove.
    pub key: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmConfig {
    pub protocol: u32,
    pub owner: String,
    pub system_id: String,
    pub instance: String,
    pub root_vhdx: PathBuf,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub data_vhdx: Vec<DiskAttachment>,
    pub seed_iso: PathBuf,
    /// What the firmware boots. Absent in a config written before OCI guests
    /// existed on this backend, which is exactly the cloud-image arm.
    #[serde(default)]
    pub boot: BootSource,
    pub console: PathBuf,
    pub cpus: u32,
    pub mem_mib: u64,
    pub network_id: String,
    pub endpoint_id: String,
    pub guest_ip: IpAddr,
    pub mac: String,
    pub agent_key: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restore_state: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskAttachment {
    pub path: PathBuf,
    #[serde(default)]
    pub readonly: bool,
}

impl VmConfig {
    pub fn validate(&self) -> Result<()> {
        if self.protocol != PROTOCOL_VERSION {
            bail!(
                "Hyper-V helper protocol {} is not supported (expected {})",
                self.protocol,
                PROTOCOL_VERSION
            );
        }
        if self.owner != OWNER {
            bail!("refusing compute-system owner {:?}", self.owner);
        }
        if self.instance.trim().is_empty() {
            bail!("instance name is empty");
        }
        if self.cpus == 0 || self.mem_mib < 256 {
            bail!("a Hyper-V guest needs at least one CPU and 256 MiB");
        }
        for (name, id) in [
            ("compute-system", &self.system_id),
            ("network", &self.network_id),
            ("endpoint", &self.endpoint_id),
        ] {
            parse_guid(id).with_context(|| format!("invalid {name} id {id:?}"))?;
        }
        if !self.guest_ip.is_ipv4() {
            bail!("the HCN v2 NAT profile currently requires an IPv4 guest address");
        }
        validate_mac(&self.mac)?;
        Ok(())
    }

    pub fn read(path: &std::path::Path) -> Result<Self> {
        let bytes = std::fs::read(path)
            .with_context(|| format!("reading the Hyper-V config at {}", path.display()))?;
        serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing the Hyper-V config at {}", path.display()))
    }

    pub fn write(&self, path: &std::path::Path) -> Result<()> {
        self.validate()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_vec_pretty(self)?)
            .with_context(|| format!("writing the Hyper-V config at {}", path.display()))
    }

    /// Every host file this VM's document names, in the order it names them.
    ///
    /// The VM has to be granted access to each of them before HCS is asked to
    /// create it, and "each of them" is decided by the boot source: an OCI
    /// guest is handed a kernel and an initrd and has no NoCloud seed, and
    /// granting a seed that was never built fails the create with
    /// `ERROR_FILE_NOT_FOUND` rather than being ignored. Derived here, beside
    /// `hcs_document`, so the two cannot drift.
    pub fn backing_files(&self) -> Vec<&std::path::Path> {
        let mut files: Vec<&std::path::Path> = vec![self.root_vhdx.as_path()];
        match &self.boot {
            BootSource::Uefi => files.push(self.seed_iso.as_path()),
            BootSource::LinuxKernel { kernel, initrd, .. } => {
                files.push(kernel.as_path());
                files.push(initrd.as_path());
            }
        }
        files.extend(self.data_vhdx.iter().map(|disk| disk.path.as_path()));
        files
    }

    /// HCS schema 2.1 document. Kept on the protocol side so every platform's
    /// unit tests can inspect the exact Windows configuration without linking
    /// ComputeCore. Only the helper submits it.
    pub fn hcs_document(&self) -> Result<String> {
        self.validate()?;
        let mut attachments = serde_json::json!({
            "0": { "Type": "VirtualDisk", "Path": self.root_vhdx }
        });
        let mut next = 1;
        if matches!(self.boot, BootSource::Uefi) {
            // Only a cloud image has a NoCloud seed to read. Attaching one an
            // OCI guest never had would fail the create with a missing file.
            attachments["1"] =
                serde_json::json!({ "Type": "Iso", "Path": self.seed_iso, "ReadOnly": true });
            next = 2;
        }
        for (index, disk) in self.data_vhdx.iter().enumerate() {
            attachments[(index + next).to_string()] = serde_json::json!({
                "Type": "VirtualDisk",
                "Path": disk.path,
                "ReadOnly": disk.readonly
            });
        }
        let chipset = match &self.boot {
            BootSource::Uefi => serde_json::json!({
                "Uefi": {
                    "BootThis": {
                        "DeviceType": "ScsiDrive",
                        "DevicePath": "root",
                        "DiskNumber": 0
                    },
                    "Console": "ComPort1"
                }
            }),
            BootSource::LinuxKernel {
                kernel,
                initrd,
                cmdline,
            } => serde_json::json!({
                "LinuxKernelDirect": {
                    "KernelFilePath": kernel,
                    "InitRdPath": initrd,
                    "KernelCmdLine": cmdline
                }
            }),
        };
        let mut vm = serde_json::json!({
            "StopOnReset": true,
            "Chipset": chipset,
            "ComputeTopology": {
                "Memory": {
                    "Backing": "Virtual",
                    "SizeInMB": self.mem_mib,
                    "AllowOvercommit": true
                },
                "Processor": { "Count": self.cpus }
            },
            "Devices": {
                "ComPorts": {
                    "0": { "NamedPipe": self.console }
                },
                "Scsi": {
                    "root": {
                        "Attachments": attachments
                    }
                },
                "NetworkAdapters": {
                    "asterism": {
                        "EndpointId": self.endpoint_id,
                        "MacAddress": self.mac.replace(':', "-")
                    }
                },
                "HvSocket": {
                    "HvSocketConfig": {
                        "ServiceTable": {
                            GUEST_SERVICE_ID: service_entry(),
                            // The guest-only secret-egress door. A per-VM
                            // service table entry is what lets a host process
                            // bind this GUID for this VM, which is why there
                            // is no machine-wide registry key to add or clean
                            // up. `AllowWildcardBinds: false` is the load-
                            // bearing half: a listener bound to any other VM
                            // id, or to the wildcard, never sees this guest.
                            EGRESS_SERVICE_ID: service_entry()
                        }
                    }
                }
            }
        });
        if let Some(path) = &self.restore_state {
            vm["RestoreState"] = serde_json::json!({ "SaveStateFilePath": path });
        }
        Ok(serde_json::to_string(&serde_json::json!({
            "SchemaVersion": { "Major": 2, "Minor": 1 },
            "Owner": self.owner,
            "ShouldTerminateOnLastHandleClosed": false,
            "VirtualMachine": vm
        }))?)
    }

    pub fn hcn_network_document(&self) -> Result<String> {
        self.validate()?;
        Ok(serde_json::to_string(&serde_json::json!({
            "SchemaVersion": { "Major": 2, "Minor": 0 },
            "Owner": self.owner,
            "Flags": 0,
            "Name": "asterism-private",
            "Type": "NAT",
            "Ipams": [{
                "Type": "Static",
                "Subnets": [{
                    "IpAddressPrefix": "172.29.64.0/20",
                    "Routes": [{
                        "NextHop": "172.29.64.1",
                        "DestinationPrefix": "0.0.0.0/0"
                    }]
                }]
            }]
        }))?)
    }

    pub fn hcn_endpoint_document(&self) -> Result<String> {
        self.validate()?;
        Ok(serde_json::to_string(&serde_json::json!({
            "SchemaVersion": { "Major": 2, "Minor": 0 },
            "Owner": self.owner,
            "Flags": 0,
            "HostComputeNetwork": self.network_id,
            "Name": format!("asterism-{}", self.instance),
            // HCN's endpoint schema accepts the canonical Windows form; a
            // compact 12-hex string is rejected with E_INVALIDARG.
            "MacAddress": self.mac.replace(':', "-"),
            "IpConfigurations": [{
                "IpAddress": self.guest_ip,
                "PrefixLength": 20
            }],
            "Routes": [{
                "NextHop": "172.29.64.1",
                "DestinationPrefix": "0.0.0.0/0"
            }]
        }))?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Probe,
    MaterializeVhdx {
        source_raw: PathBuf,
        dest_vhdx: PathBuf,
        size_bytes: u64,
    },
    Boot {
        config: Box<VmConfig>,
    },
    State {
        system_id: String,
    },
    Shutdown {
        system_id: String,
        timeout_ms: u32,
    },
    Terminate {
        system_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        endpoint_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        network_id: Option<String>,
    },
    Save {
        system_id: String,
        state_path: PathBuf,
    },
    /// Hold this instance's secret-egress door open until killed.
    ///
    /// The one request that does not return: the helper binds the door's
    /// service GUID against this VM, answers `Serving`, and then serves
    /// accepted connections for as long as the guest runs. Every other
    /// request is one round trip over stdio.
    ServeEgress {
        door: Box<EgressDoor>,
    },
}

impl Request {
    /// Probe is the only request allowed before the host gate succeeds.
    pub fn mutates(&self) -> bool {
        !matches!(self, Request::Probe | Request::State { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostReady {
    pub protocol: u32,
    pub build: String,
    pub windows: String,
    pub edition: String,
    pub elevated: bool,
    pub hcs_running: bool,
    pub hcn_running: bool,
}

impl HostReady {
    pub fn require_supported(&self) -> Result<()> {
        if self.protocol != PROTOCOL_VERSION {
            bail!(
                "astd-hyperv speaks protocol {}, but astd expects {}",
                self.protocol,
                PROTOCOL_VERSION
            );
        }
        let expected_build = build_id();
        if self.build != expected_build {
            bail!(
                "astd-hyperv is build {}, but astd expects {}; reinstall the complete Windows artifact",
                self.build,
                expected_build
            );
        }
        // Edition is diagnostic metadata and nothing else. What decides
        // whether this device can run a guest is whether Hyper-V is present
        // and enabled, which the service probes below ask directly. Every
        // edition that answers those probes runs the same native contract.
        let build = self
            .windows
            .rsplit('.')
            .next()
            .and_then(|part| part.parse::<u32>().ok())
            .context("the Windows probe did not return a numeric build")?;
        if build < 22_000 {
            bail!(
                "the native Hyper-V backend needs Windows 11 build 22000 or newer; this is {}",
                self.windows
            );
        }
        if !self.elevated {
            bail!("the native Hyper-V backend needs an elevated administrator token");
        }
        if !self.hcs_running || !self.hcn_running {
            bail!(
                "Hyper-V is not enabled on this device (vmcompute running: {}, hns running: {}). \
                 To enable it: DISM /Online /Enable-Feature /All /FeatureName:Microsoft-Hyper-V, \
                 then bcdedit /set hypervisorlaunchtype auto, then reboot",
                self.hcs_running,
                self.hcn_running
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmState {
    Running,
    Stopped,
    Saved,
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Reply {
    Ready { host: HostReady },
    Materialized,
    Booted { guest_addr: IpAddr },
    State { state: VmState },
    Stopped,
    Saved,
    Serving,
    Error { message: String },
}

impl Reply {
    pub fn into_result(self) -> Result<Self> {
        match self {
            Reply::Error { message } => bail!(message),
            reply => Ok(reply),
        }
    }
}

/// The one request on this helper's stdin.
pub fn read_request(input: impl Read) -> Result<Request> {
    serde_json::from_reader(BufReader::new(input)).context("reading the Hyper-V helper request")
}

/// One reply, newline framed, flushed. Callers that go on running after it —
/// only [`Request::ServeEgress`] does — depend on the flush.
pub fn write_reply(mut output: impl Write, reply: &Reply) -> Result<()> {
    serde_json::to_writer(&mut output, reply).context("writing the Hyper-V helper reply")?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}

/// One request and one response over inherited stdio. There is no daemon or
/// helper socket to adopt: HCS owns the VM and a later helper reopens its GUID.
pub fn serve_once(
    input: impl Read,
    output: impl Write,
    dispatch: impl FnOnce(Request) -> Result<Reply>,
) -> Result<()> {
    let request = read_request(input)?;
    let reply = dispatch(request).unwrap_or_else(|error| Reply::Error {
        message: format!("{error:#}"),
    });
    write_reply(output, &reply)
}

/// A stable, locally-administered MAC for an instance.
///
/// Same FNV-1a derivation the VZ backend uses, kept here so the Hyper-V
/// daemon path never imports `asterism_vz`. `02:15:5d` is Microsoft's
/// locally-administered Hyper-V OUI.
pub fn mac_for(instance: &str) -> String {
    let h = fnv1a(instance);
    format!(
        "02:15:5d:{:02x}:{:02x}:{:02x}",
        (h >> 16) as u8,
        (h >> 8) as u8,
        h as u8
    )
}

fn fnv1a(s: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// One `HvSocketConfig` service-table entry.
///
/// SYSTEM and the administrators group, and nobody else, may bind or connect
/// this service for this VM. `astd` and its helper run elevated; nothing else
/// on the device does.
fn service_entry() -> serde_json::Value {
    serde_json::json!({
        "AllowWildcardBinds": false,
        "BindSecurityDescriptor": "D:P(A;;FA;;;SY)(A;;FA;;;BA)",
        "ConnectSecurityDescriptor": "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
    })
}

pub fn parse_guid(text: &str) -> Result<[u8; 16]> {
    let compact: String = text.chars().filter(|c| *c != '-').collect();
    if compact.len() != 32 || !compact.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("a GUID is 32 hexadecimal digits");
    }
    let mut bytes = [0; 16];
    for (at, slot) in bytes.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&compact[at * 2..at * 2 + 2], 16)?;
    }
    Ok(bytes)
}

pub fn format_guid(bytes: [u8; 16]) -> String {
    let h = bytes.map(|byte| format!("{byte:02x}"));
    format!(
        "{}{}{}{}-{}{}-{}{}-{}{}-{}{}{}{}{}{}",
        h[0],
        h[1],
        h[2],
        h[3],
        h[4],
        h[5],
        h[6],
        h[7],
        h[8],
        h[9],
        h[10],
        h[11],
        h[12],
        h[13],
        h[14],
        h[15]
    )
}

fn validate_mac(mac: &str) -> Result<()> {
    let octets: Vec<&str> = mac.split(':').collect();
    if octets.len() != 6
        || octets
            .iter()
            .any(|part| part.len() != 2 || !part.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        bail!("MAC address must be six colon-separated hexadecimal octets");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macs_are_stable_local_and_per_instance() {
        let mac = mac_for("dev");
        assert_eq!(mac, mac_for("dev"));
        assert_ne!(mac, mac_for("other"));
        assert!(mac.starts_with("02:15:5d:"), "{mac}");
        let first = u8::from_str_radix(&mac[..2], 16).unwrap();
        assert_eq!(first & 0b10, 0b10);
        assert_eq!(first & 1, 0);
    }

    #[test]
    fn protocol_round_trip_and_mutation_gate_are_explicit() {
        let request = Request::State {
            system_id: "6fce7c98-d05d-43c8-8207-141c56ccca18".into(),
        };
        assert!(!request.mutates());
        let wire = serde_json::to_vec(&request).unwrap();
        assert_eq!(request, serde_json::from_slice(&wire).unwrap());
        let terminate = Request::Terminate {
            system_id: "6fce7c98-d05d-43c8-8207-141c56ccca18".into(),
            endpoint_id: Some("83f8639b-3c23-4b07-b229-144314489fd0".into()),
            network_id: Some("0a9d2db3-51ef-489f-bcac-85e410f769c9".into()),
        };
        assert!(terminate.mutates());
        let wire = serde_json::to_vec(&terminate).unwrap();
        assert_eq!(terminate, serde_json::from_slice(&wire).unwrap());
    }

    /// The gate is capability, not edition: a device whose Hyper-V is
    /// present and enabled passes on whichever Windows it is running.
    #[test]
    fn the_gate_is_hyper_v_being_enabled_not_the_windows_edition() {
        let host = HostReady {
            protocol: PROTOCOL_VERSION,
            build: build_id(),
            windows: "11.0.26100".into(),
            edition: "Windows 11 Home".into(),
            elevated: true,
            hcs_running: true,
            hcn_running: true,
        };
        host.require_supported().unwrap();

        // And the refusal names how to enable it rather than an edition.
        let disabled = HostReady {
            hcs_running: false,
            ..host
        };
        let error = disabled.require_supported().unwrap_err().to_string();
        assert!(error.contains("Hyper-V is not enabled"), "{error}");
        assert!(error.contains("Microsoft-Hyper-V"), "{error}");
        assert!(!error.contains("Pro"), "{error}");
    }

    #[test]
    fn a_helper_from_another_build_is_rejected() {
        let host = HostReady {
            protocol: PROTOCOL_VERSION,
            build: "0.0.2+another-source".into(),
            windows: "11.0.26100".into(),
            edition: "Windows 11 Pro".into(),
            elevated: true,
            hcs_running: true,
            hcn_running: true,
        };
        let error = host.require_supported().unwrap_err().to_string();
        assert!(
            error.contains("reinstall the complete Windows artifact"),
            "{error}"
        );
    }

    #[test]
    fn ids_are_canonical_protocol_data() {
        let id = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        assert_eq!(parse_guid(&format_guid(id)).unwrap(), id);
        assert!(parse_guid("not-a-guid").is_err());
    }

    #[test]
    fn errors_stay_machine_readable_at_the_helper_boundary() {
        let mut output = Vec::new();
        serve_once(br#"{"op":"probe"}"#.as_slice(), &mut output, |_| {
            anyhow::bail!("Hyper-V is disabled")
        })
        .unwrap();
        assert_eq!(
            serde_json::from_slice::<Reply>(&output).unwrap(),
            Reply::Error {
                message: "Hyper-V is disabled".into()
            }
        );
    }

    fn config() -> VmConfig {
        VmConfig {
            protocol: PROTOCOL_VERSION,
            owner: OWNER.into(),
            system_id: "6fce7c98-d05d-43c8-8207-141c56ccca18".into(),
            instance: "dev".into(),
            root_vhdx: r"C:\Users\me\.asterism\instances\dev\disk.vhdx".into(),
            data_vhdx: vec![DiskAttachment {
                path: r"C:\Users\me\.asterism\instances\dev\data.vhdx".into(),
                readonly: true,
            }],
            seed_iso: r"C:\Users\me\.asterism\instances\dev\seed.iso".into(),
            boot: BootSource::Uefi,
            console: r"\\.\pipe\asterism-dev-console".into(),
            cpus: 2,
            mem_mib: 2048,
            network_id: "0a9d2db3-51ef-489f-bcac-85e410f769c9".into(),
            endpoint_id: "83f8639b-3c23-4b07-b229-144314489fd0".into(),
            guest_ip: "172.29.64.19".parse().unwrap(),
            mac: "02:15:5d:01:02:03".into(),
            agent_key: r"C:\Users\me\.asterism\instances\dev\agent.key".into(),
            restore_state: None,
        }
    }

    fn oci_config() -> VmConfig {
        let mut config = config();
        config.boot = BootSource::LinuxKernel {
            kernel: r"C:\Users\me\.asterism\images\kernel\x86_64-vmlinuz".into(),
            initrd: r"C:\Users\me\.asterism\images\kernel\x86_64-initrd".into(),
            cmdline: "root=LABEL=asterism rw console=ttyS0 init=/asterism-init".into(),
        };
        config
    }

    /// An OCI guest is handed its kernel directly. No firmware reads a disk
    /// on its behalf, so no Secure Boot policy applies, and there is no seed.
    #[test]
    fn an_oci_guest_is_handed_its_kernel_rather_than_a_bootloader() {
        let config = oci_config();
        let doc: serde_json::Value = serde_json::from_str(&config.hcs_document().unwrap()).unwrap();
        let chipset = &doc["VirtualMachine"]["Chipset"];
        assert!(
            chipset["Uefi"].is_null(),
            "a direct kernel boot involves no firmware: {chipset}"
        );
        let direct = &chipset["LinuxKernelDirect"];
        assert_eq!(
            direct["KernelFilePath"].as_str().unwrap(),
            r"C:\Users\me\.asterism\images\kernel\x86_64-vmlinuz"
        );
        assert_eq!(
            direct["InitRdPath"].as_str().unwrap(),
            r"C:\Users\me\.asterism\images\kernel\x86_64-initrd"
        );
        assert_eq!(
            direct["KernelCmdLine"].as_str().unwrap(),
            "root=LABEL=asterism rw console=ttyS0 init=/asterism-init"
        );

        let attachments = &doc["VirtualMachine"]["Devices"]["Scsi"]["root"]["Attachments"];
        assert_eq!(
            attachments["0"]["Path"].as_str().unwrap(),
            r"C:\Users\me\.asterism\instances\dev\disk.vhdx"
        );
        // No NoCloud seed: an OCI guest has no cloud-init to read one, and
        // attaching a file that was never built fails the create.
        assert!(attachments
            .as_object()
            .unwrap()
            .values()
            .all(|value| value["Type"] != "Iso"));
        assert_eq!(
            attachments["1"]["Path"].as_str().unwrap(),
            r"C:\Users\me\.asterism\instances\dev\data.vhdx",
            "data disks follow the root filesystem"
        );
    }

    /// A cloud image keeps exactly the document it had, firmware and seed ISO
    /// and all. A config written before OCI boot existed deserializes onto
    /// that arm, which is what makes this an additive protocol change.
    #[test]
    fn a_config_without_a_boot_source_is_still_a_uefi_cloud_image() {
        let mut value = serde_json::to_value(config()).unwrap();
        value.as_object_mut().unwrap().remove("boot");
        let config: VmConfig = serde_json::from_value(value).unwrap();
        assert_eq!(config.boot, BootSource::Uefi);
        let doc: serde_json::Value = serde_json::from_str(&config.hcs_document().unwrap()).unwrap();
        let attachments = &doc["VirtualMachine"]["Devices"]["Scsi"]["root"]["Attachments"];
        assert_eq!(attachments["1"]["Type"], serde_json::json!("Iso"));
        assert_eq!(
            doc["VirtualMachine"]["Chipset"]["Uefi"]["BootThis"]["DeviceType"],
            serde_json::json!("ScsiDrive")
        );
        assert!(doc["VirtualMachine"]["Chipset"]["LinuxKernelDirect"].is_null());
    }

    /// The door's service GUID is the `hv_sock` template with the vsock port
    /// in the first double word, and it is registered per VM — which is what
    /// makes a wildcard bind on this host unable to reach this guest.
    #[test]
    fn the_egress_door_is_registered_against_this_vm_alone() {
        let doc: serde_json::Value =
            serde_json::from_str(&config().hcs_document().unwrap()).unwrap();
        let table = &doc["VirtualMachine"]["Devices"]["HvSocket"]["HvSocketConfig"]["ServiceTable"];
        for id in [GUEST_SERVICE_ID, EGRESS_SERVICE_ID] {
            assert_eq!(
                table[id]["AllowWildcardBinds"],
                serde_json::json!(false),
                "{id}"
            );
            assert!(table[id]["BindSecurityDescriptor"]
                .as_str()
                .unwrap()
                .contains("(A;;FA;;;BA)"));
        }
        assert_eq!(EGRESS_PORT, 1021);
        assert_eq!(
            EGRESS_SERVICE_ID,
            format!("{EGRESS_PORT:08x}-facb-11e6-bd58-64006a7986d3")
        );
        assert_eq!(
            GUEST_SERVICE_ID,
            format!("{GUEST_PORT:08x}-facb-11e6-bd58-64006a7986d3")
        );
    }

    /// The door request round-trips and is a mutation, so the host gate runs
    /// before a helper ever binds a socket against a VM.
    #[test]
    fn serving_the_door_is_a_gated_mutation() {
        let request = Request::ServeEgress {
            door: Box::new(EgressDoor {
                system_id: "6fce7c98-d05d-43c8-8207-141c56ccca18".into(),
                instance: "dev".into(),
                pipe: r"\\.\pipe\asterism-egress-dev".into(),
                key: r"C:\Users\me\.asterism\instances\dev\agent.key".into(),
            }),
        };
        assert!(request.mutates());
        let wire = serde_json::to_vec(&request).unwrap();
        assert_eq!(request, serde_json::from_slice(&wire).unwrap());
    }

    /// The files the VM is granted access to are the files its document
    /// attaches. An OCI guest is granted no seed, because it has none.
    #[test]
    fn the_granted_files_are_exactly_the_attached_ones() {
        use std::path::Path;

        assert_eq!(
            config().backing_files(),
            vec![
                Path::new(r"C:\Users\me\.asterism\instances\dev\disk.vhdx"),
                Path::new(r"C:\Users\me\.asterism\instances\dev\seed.iso"),
                Path::new(r"C:\Users\me\.asterism\instances\dev\data.vhdx"),
            ]
        );

        assert_eq!(
            oci_config().backing_files(),
            vec![
                Path::new(r"C:\Users\me\.asterism\instances\dev\disk.vhdx"),
                Path::new(r"C:\Users\me\.asterism\images\kernel\x86_64-vmlinuz"),
                Path::new(r"C:\Users\me\.asterism\images\kernel\x86_64-initrd"),
                Path::new(r"C:\Users\me\.asterism\instances\dev\data.vhdx"),
            ],
            "an OCI guest has no NoCloud seed to grant, and two files a cloud image has not"
        );

        // Every disk the document attaches is granted, and so is every file
        // the chipset names.
        for config in [config(), oci_config()] {
            let doc: serde_json::Value =
                serde_json::from_str(&config.hcs_document().unwrap()).unwrap();
            let granted: Vec<String> = config
                .backing_files()
                .into_iter()
                .map(|path| path.display().to_string())
                .collect();
            for attachment in doc["VirtualMachine"]["Devices"]["Scsi"]["root"]["Attachments"]
                .as_object()
                .unwrap()
                .values()
            {
                let path = attachment["Path"].as_str().unwrap().to_owned();
                assert!(
                    granted.contains(&path),
                    "{path} is attached but not granted"
                );
            }
            if let Some(direct) = doc["VirtualMachine"]["Chipset"]["LinuxKernelDirect"].as_object()
            {
                for key in ["KernelFilePath", "InitRdPath"] {
                    let path = direct[key].as_str().unwrap().to_owned();
                    assert!(granted.contains(&path), "{path} is loaded but not granted");
                }
            }
        }
    }

    #[test]
    fn hcs_document_is_generation_two_durable_and_native() {
        let doc: serde_json::Value =
            serde_json::from_str(&config().hcs_document().unwrap()).unwrap();
        assert_eq!(
            doc["SchemaVersion"],
            serde_json::json!({"Major": 2, "Minor": 1})
        );
        assert_eq!(doc["ShouldTerminateOnLastHandleClosed"], false);
        assert_eq!(
            doc["VirtualMachine"]["Devices"]["Scsi"]["root"]["Attachments"]["0"]["Type"],
            "VirtualDisk"
        );
        let service = &doc["VirtualMachine"]["Devices"]["HvSocket"]["HvSocketConfig"]
            ["ServiceTable"][GUEST_SERVICE_ID];
        assert_eq!(service["AllowWildcardBinds"], false);
        assert_eq!(
            service["BindSecurityDescriptor"],
            "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
        );
        assert_eq!(
            doc["VirtualMachine"]["Devices"]["Scsi"]["root"]["Attachments"]["2"]["ReadOnly"],
            true
        );
        assert_eq!(
            doc["VirtualMachine"]["Devices"]["NetworkAdapters"]["asterism"]["MacAddress"],
            "02-15-5d-01-02-03"
        );
        let text = doc.to_string().to_ascii_lowercase();
        assert!(!text.contains("qemu"));
        assert!(!text.contains("whpx"));
    }

    #[test]
    fn hcn_documents_are_v2_nat_and_static_endpoint() {
        let network: serde_json::Value =
            serde_json::from_str(&config().hcn_network_document().unwrap()).unwrap();
        let endpoint: serde_json::Value =
            serde_json::from_str(&config().hcn_endpoint_document().unwrap()).unwrap();
        assert_eq!(network["Type"], "NAT");
        assert_eq!(network["SchemaVersion"]["Major"], 2);
        assert_eq!(network["Owner"], OWNER);
        assert_eq!(endpoint["HostComputeNetwork"], config().network_id);
        assert_eq!(endpoint["MacAddress"], "02-15-5d-01-02-03");
        assert_eq!(endpoint["IpConfigurations"][0]["IpAddress"], "172.29.64.19");
    }
}
