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

    /// HCS schema 2.1 document. Kept on the protocol side so every platform's
    /// unit tests can inspect the exact Windows configuration without linking
    /// ComputeCore. Only the helper submits it.
    pub fn hcs_document(&self) -> Result<String> {
        self.validate()?;
        let mut attachments = serde_json::json!({
            "0": { "Type": "VirtualDisk", "Path": self.root_vhdx },
            "1": { "Type": "Iso", "Path": self.seed_iso, "ReadOnly": true }
        });
        for (index, disk) in self.data_vhdx.iter().enumerate() {
            attachments[(index + 2).to_string()] = serde_json::json!({
                "Type": "VirtualDisk",
                "Path": disk.path,
                "ReadOnly": disk.readonly
            });
        }
        let mut vm = serde_json::json!({
            "StopOnReset": true,
            "Chipset": {
                "Uefi": {
                    "BootThis": {
                        "DeviceType": "ScsiDrive",
                        "DevicePath": "root",
                        "DiskNumber": 0
                    },
                    "Console": "ComPort1"
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
                        "MacAddress": self.mac.replace(':', "")
                    }
                },
                "HvSocket": {
                    "HvSocketConfig": {
                        "ServiceTable": {
                            GUEST_SERVICE_ID: {
                                "AllowWildcardBinds": false,
                                "BindSecurityDescriptor": "D:P(A;;FA;;;SY)(A;;FA;;;BA)",
                                "ConnectSecurityDescriptor": "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
                            }
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
            "MacAddress": self.mac.replace(':', ""),
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
        // Product SKU is not a capability. Pro and Enterprise are the
        // Microsoft-supported distribution path, but Home machines on which
        // the required HCS/HCN services are genuinely present can execute the
        // exact same native API contract. The service probes below are the
        // mutation gate; the edition remains diagnostics, never authority.
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
                "Hyper-V is disabled or awaiting a reboot (vmcompute running: {}, hns running: {})",
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

/// One request and one response over inherited stdio. There is no daemon or
/// helper socket to adopt: HCS owns the VM and a later helper reopens its GUID.
pub fn serve_once(
    input: impl Read,
    mut output: impl Write,
    dispatch: impl FnOnce(Request) -> Result<Reply>,
) -> Result<()> {
    let request: Request = serde_json::from_reader(BufReader::new(input))
        .context("reading the Hyper-V helper request")?;
    let reply = dispatch(request).unwrap_or_else(|error| Reply::Error {
        message: format!("{error:#}"),
    });
    serde_json::to_writer(&mut output, &reply).context("writing the Hyper-V helper reply")?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
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

    #[test]
    fn a_home_sku_with_real_hcs_capabilities_is_accepted() {
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
        assert_eq!(endpoint["IpConfigurations"][0]["IpAddress"], "172.29.64.19");
    }
}
