//! Wire types for the opt-in shell a device may offer to its orbit.
//!
//! This is deliberately separate from guest SSH. Guest SSH is an opaque byte
//! splice into a guest-owned SSH server; a device shell executes with the
//! daemon user's authority and therefore keeps an explicit, bounded state
//! machine all the way from the local CLI to the authenticated mesh stream.

use data_encoding::BASE64;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// On-disk policy schema written by `ast device shell enable`.
pub const POLICY_VERSION: u32 = 1;
/// A command is one argument to the target account's login shell.
pub const MAX_COMMAND_BYTES: usize = 32 * 1024;
/// One stdin/stdout/stderr frame. Flow control, rather than an unbounded
/// queue, carries larger streams as several frames.
pub const MAX_DATA_BYTES: usize = 64 * 1024;
/// Largest encoded control/data frame. A full binary payload expands to four
/// base64 bytes per three input bytes; the remainder covers the JSON tag and
/// fixed fields.
pub const MAX_FRAME_BYTES: usize = MAX_DATA_BYTES.div_ceil(3) * 4 + 4096;
/// Environment keys a caller may contribute.
pub const MAX_ENV_VARS: usize = 32;
/// Total bytes across contributed environment names and values.
pub const MAX_ENV_BYTES: usize = 8 * 1024;
/// A single contributed environment value.
pub const MAX_ENV_VALUE_BYTES: usize = 256;
/// Largest encoded opening frame. JSON may spell one decoded byte as a
/// six-byte `\u00xx` escape, so the wire cap covers that worst case plus the
/// fixed frame fields without falling back to the mesh's multi-megabyte RPC
/// ceiling.
pub const MAX_OPEN_FRAME_BYTES: usize = (MAX_COMMAND_BYTES + MAX_ENV_BYTES) * 6 + 4096;
/// Rows and columns outside this range are malformed, not terminal sizes.
pub const MAX_TERMINAL_DIMENSION: u16 = 1000;

/// What the local user asked to do with this device's shell policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShellPolicyAction {
    Status,
    Enable,
    Disable,
}

/// The policy state shown to CLI and future GUI clients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShellPolicyState {
    Disabled,
    EnabledOrbit,
    Active,
    Unavailable,
}

/// One live session, without its command, environment or transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellSessionStatus {
    pub session_id: String,
    pub peer_device_id: String,
    pub peer_name: String,
    pub started_at: u64,
    pub pty: bool,
}

/// The first-class read model for this device's shell offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellPolicyStatus {
    pub state: ShellPolicyState,
    pub epoch: u64,
    /// Unix seconds when the state visible to a reader last changed. This is
    /// a policy change for disabled/enabled, and a session boundary while
    /// active. Older daemons omit it, so clients must accept `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled_at: Option<u64>,
    #[serde(default)]
    pub active: Vec<ShellSessionStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
}

impl ShellPolicyStatus {
    /// A truthful row for a target whose status could not be read. GUI and
    /// hosted consumers use the same wire model instead of inventing a
    /// parallel loading/error state.
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            state: ShellPolicyState::Unavailable,
            epoch: 0,
            changed_at: None,
            enabled_at: None,
            active: Vec::new(),
            unavailable_reason: Some(reason.into()),
        }
    }

    pub fn active_sessions(&self) -> usize {
        self.active.len()
    }
}

/// One environment entry accepted from the CLI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellEnv {
    pub name: String,
    pub value: String,
}

/// The opening request on a dedicated shell stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellOpen {
    /// None opens the account's interactive login shell. Some is passed as
    /// the single argument after `-lc`; it is never interpolated by astd.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    pub pty: bool,
    pub cols: u16,
    pub rows: u16,
    #[serde(default)]
    pub env: Vec<ShellEnv>,
}

impl ShellOpen {
    /// Validate every caller-controlled field before authorization or spawn.
    pub fn validate(&self) -> Result<(), &'static str> {
        if let Some(command) = &self.command {
            if command.as_bytes().contains(&0) {
                return Err("the command contains a NUL byte");
            }
            if command.len() > MAX_COMMAND_BYTES {
                return Err("the command is larger than 32768 bytes");
            }
        }
        if self.pty
            && (!(1..=MAX_TERMINAL_DIMENSION).contains(&self.cols)
                || !(1..=MAX_TERMINAL_DIMENSION).contains(&self.rows))
        {
            return Err("terminal rows and columns must each be between 1 and 1000");
        }
        if !self.pty && (self.cols != 0 || self.rows != 0) {
            return Err("a non-pty shell request cannot carry a terminal size");
        }
        if self.env.len() > MAX_ENV_VARS {
            return Err("a shell request carries more than 32 environment variables");
        }
        let mut total = 0usize;
        for entry in &self.env {
            if !allowed_env_name(&entry.name) {
                return Err("a shell request carries an environment variable that is not allowed");
            }
            if entry.value.as_bytes().contains(&0) || entry.value.len() > MAX_ENV_VALUE_BYTES {
                return Err("a shell environment value is invalid or larger than 256 bytes");
            }
            total = total
                .checked_add(entry.name.len())
                .and_then(|n| n.checked_add(entry.value.len()))
                .ok_or("the shell environment size overflowed")?;
        }
        if total > MAX_ENV_BYTES {
            return Err("the shell environment is larger than 8192 bytes");
        }
        Ok(())
    }
}

/// Only locale and terminal presentation cross from the caller. In
/// particular PATH, HOME, shell hooks, dynamic-loader variables, agent
/// sockets and ASTERISM_* are reconstructed or omitted at the target.
pub fn allowed_env_name(name: &str) -> bool {
    matches!(name, "TERM" | "COLORTERM" | "LANG")
        || name.strip_prefix("LC_").is_some_and(|tail| {
            !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
}

/// Bytes encoded compactly in JSON frames.
#[derive(Clone, PartialEq, Eq)]
pub struct ShellData(Vec<u8>);

impl ShellData {
    pub fn new(bytes: Vec<u8>) -> Result<Self, &'static str> {
        if bytes.len() > MAX_DATA_BYTES {
            return Err("a shell data frame is larger than 65536 bytes");
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl std::fmt::Debug for ShellData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ShellData({} bytes)", self.0.len())
    }
}

impl Serialize for ShellData {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&BASE64.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for ShellData {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        // Four encoded bytes carry at most three raw bytes. Reject before
        // decoding so an attacker cannot choose a large allocation.
        if text.len() > MAX_DATA_BYTES.div_ceil(3) * 4 {
            return Err(serde::de::Error::custom(
                "shell data frame exceeds 65536 bytes",
            ));
        }
        let bytes = BASE64
            .decode(text.as_bytes())
            .map_err(serde::de::Error::custom)?;
        ShellData::new(bytes).map_err(serde::de::Error::custom)
    }
}

/// Which output pipe a non-PTY command wrote. PTY output is always `Pty`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShellOutput {
    Pty,
    Stdout,
    Stderr,
}

/// The target process's terminal result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellExit {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<i32>,
    #[serde(default)]
    pub core_dumped: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Frames after a shell stream's opening request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "frame", rename_all = "snake_case")]
pub enum ShellFrame {
    Accepted {
        session_id: String,
    },
    Refused {
        code: String,
        message: String,
    },
    Stdin {
        data: ShellData,
    },
    StdinEof,
    Resize {
        cols: u16,
        rows: u16,
    },
    Signal {
        signal: i32,
    },
    Close,
    Output {
        stream: ShellOutput,
        data: ShellData,
    },
    Exit {
        exit: ShellExit,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_is_an_allowlist_not_a_denylist() {
        for allowed in ["TERM", "COLORTERM", "LANG", "LC_ALL", "LC_CTYPE"] {
            assert!(allowed_env_name(allowed), "{allowed}");
        }
        for refused in [
            "PATH",
            "HOME",
            "SHELL",
            "USER",
            "LOGNAME",
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
            "BASH_ENV",
            "ENV",
            "IFS",
            "SSH_AUTH_SOCK",
            "ASTERISM_HOME",
            "LC_",
        ] {
            assert!(!allowed_env_name(refused), "{refused}");
        }
    }

    #[test]
    fn shell_data_is_base64_and_bounded_on_deserialization() {
        let data = ShellData::new(vec![0, 1, 2, 255]).unwrap();
        let json = serde_json::to_string(&data).unwrap();
        assert_eq!(json, "\"AAEC/w==\"");
        assert_eq!(serde_json::from_str::<ShellData>(&json).unwrap(), data);
        let too_large = format!("\"{}\"", "A".repeat(MAX_DATA_BYTES.div_ceil(3) * 4 + 1));
        assert!(serde_json::from_str::<ShellData>(&too_large).is_err());
    }

    #[test]
    fn a_full_payload_fits_the_encoded_frame_limit() {
        let frame = ShellFrame::Output {
            stream: ShellOutput::Stdout,
            data: ShellData::new(vec![0; MAX_DATA_BYTES]).unwrap(),
        };
        assert!(serde_json::to_vec(&frame).unwrap().len() <= MAX_FRAME_BYTES);
    }

    #[test]
    fn non_pty_frames_cannot_smuggle_a_resize() {
        let open = ShellOpen {
            command: Some("true".into()),
            pty: false,
            cols: 80,
            rows: 24,
            env: vec![],
        };
        assert!(open.validate().unwrap_err().contains("non-pty"));
    }
}
