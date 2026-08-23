use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use asterism_core::device_shell::{
    ShellFrame, ShellOpen, ShellPolicyState, ShellPolicyStatus, MAX_FRAME_BYTES,
};
use asterism_core::protocol::Request;
use asterism_mesh::iroh_types::{RecvStream, SendStream};
use asterism_mesh::{DeviceId, MeshStream};

use crate::mesh::ClientIo;
use crate::Node;

pub(crate) fn local_only_request(request: &Request) -> bool {
    matches!(
        request,
        Request::DeviceShellPolicy { .. }
            | Request::DeviceShellOpen { .. }
            | Request::DeviceShellInput { .. }
            | Request::DeviceShellEof
            | Request::DeviceShellResize { .. }
            | Request::DeviceShellSignal { .. }
            | Request::DeviceShellClose
    )
}

pub(crate) struct Manager;

impl Manager {
    pub(crate) fn load() -> Arc<Self> {
        Arc::new(Manager)
    }

    pub(crate) fn load_at(_home: &Path) -> Arc<Self> {
        Arc::new(Manager)
    }

    pub(crate) fn status(&self, mesh_available: bool) -> ShellPolicyStatus {
        ShellPolicyStatus {
            state: ShellPolicyState::Unavailable,
            epoch: 0,
            changed_at: None,
            enabled_at: None,
            active: Vec::new(),
            unavailable_reason: Some(if mesh_available {
                "device shell is not available on Windows".into()
            } else {
                "the mesh endpoint is unavailable, so no authenticated device-shell stream can be served".into()
            }),
        }
    }

    pub(crate) fn enable(&self, _ids: Vec<String>) -> Result<ShellPolicyStatus> {
        bail!("device shell is not available on Windows")
    }

    pub(crate) fn disable(&self) -> Result<(ShellPolicyStatus, usize)> {
        Ok((self.status(false), 0))
    }

    pub(crate) fn revoke_peer(&self, _peer_device_id: &str, _reason: &str) -> usize {
        0
    }

    pub(crate) fn revoke_all(&self, _reason: &str) {}
}

pub(crate) async fn serve_mesh(
    _stream: MeshStream,
    _peer: DeviceId,
    _node: &Node,
    _open: ShellOpen,
) -> Result<()> {
    bail!("device shell is not available on Windows")
}

pub(crate) async fn serve_self<'a, 'b>(
    _open: ShellOpen,
    _peer: DeviceId,
    _peer_name: String,
    _node: &Node,
    _io: &'a mut ClientIo<'b>,
) -> Result<()> {
    bail!("device shell is not available on Windows")
}

pub(crate) async fn bridge_client<'a, 'b>(
    _stream: MeshStream,
    _io: &'a mut ClientIo<'b>,
) -> Result<()> {
    bail!("device shell is not available on Windows")
}

pub(crate) async fn write_shell_frame(send: &mut SendStream, frame: &ShellFrame) -> Result<()> {
    let bytes = serde_json::to_vec(frame)?;
    if bytes.len() > MAX_FRAME_BYTES {
        bail!("a device-shell frame is larger than its bounded payload permits");
    }
    send.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    send.write_all(&bytes).await?;
    Ok(())
}

pub(crate) async fn read_shell_frame(recv: &mut RecvStream) -> Result<ShellFrame> {
    let mut len = [0u8; 4];
    recv.read_exact(&mut len).await?;
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_FRAME_BYTES {
        bail!("a device-shell frame is larger than its bounded payload permits");
    }
    let mut bytes = vec![0; n];
    recv.read_exact(&mut bytes).await?;
    Ok(serde_json::from_slice(&bytes)?)
}
