//! The requests that are about the orbit rather than about an instance:
//! which devices are in it, how they are added and dropped, and how a frame
//! is put in front of one of them.
//!
//! These are answered by [`crate::dispatch`] and never by [`crate::handle`],
//! and the distinction is load-bearing rather than tidy. `handle` is the
//! shard-local end of the world — a mesh stream arrives there — so an orbit
//! question answered *there* would let a forwarded request fan out again on
//! the device it landed on, turning the orbit into a network somebody would
//! then have to write routing for. Answering them one step earlier is what
//! keeps the orbit a flat set of peers.
//!
//! The module exists so that adding a device command is an edit to this file
//! and to [`asterism_core::protocol`], and to nothing in `main.rs`. Pairing
//! lives here too, even though it borrows the connection: it is the same
//! subject, and merge conflicts follow subjects rather than control flow.

use std::sync::Arc;

use anyhow::Result;

use asterism_core::device_shell::ShellPolicyAction;
use asterism_core::protocol::{Request, Response};
use asterism_core::registry::OrbitRow;

use crate::mesh::{ClientIo, Mesh};
use crate::{instance, wake, Node};

/// What a daemon whose endpoint never came up has to say about the orbit.
pub(crate) const NO_MESH: &str = "this daemon has no mesh endpoint — see the astd log for why";

/// Is this one of the frames this module answers?
///
/// Asked by [`crate::dispatch`] before anything is resolved or claimed, which
/// is the point: none of these is about an instance, so none of them should
/// go anywhere near the instance namespace.
pub(crate) fn claims(req: &Request) -> bool {
    matches!(
        req,
        Request::Proxy { .. }
            | Request::Devices
            | Request::DeviceFacts
            | Request::DeviceCheck
            | Request::WakeBroadcast { .. }
            | Request::DeviceWake { .. }
            | Request::DevicePing { .. }
            | Request::DeviceRemove { .. }
            | Request::DeviceShellStatus
            | Request::DeviceShellPolicy { .. }
            | Request::PairConfirm { .. }
            | Request::ListOrbit
    )
}

/// Answer one orbit request.
pub(crate) async fn serve(req: Request, node: &Node, mesh: Option<&Arc<Mesh>>) -> Response {
    match req {
        Request::Proxy { device, inner } => match mesh {
            Some(mesh) => reply_or_error(mesh.proxy(&device, *inner).await),
            None => no_mesh(),
        },
        Request::Devices => match mesh {
            Some(mesh) => Response::Devices {
                devices: mesh.devices().await,
            },
            None => no_mesh(),
        },
        // Two questions about this device and nothing else: where it sits on
        // the wire, and what it can honestly promise about being woken.
        // Neither consults the shard or the orbit.
        Request::DeviceFacts => Response::WakeFacts {
            facts: wake::facts(),
        },
        Request::DeviceCheck => Response::WakeCheck {
            device: node.device_name().await,
            rows: wake::check(),
        },
        // Sent by a peer that wants a packet put on *this* device's LAN, and
        // the reason wake is an orbit operation at all. Membership was
        // established by the accept loop before the frame was read, exactly
        // as for every other forwarded request; the lan-id inside it is then
        // checked against this device's own, so a device that has moved
        // declines rather than broadcasting somebody's MAC at strangers.
        Request::WakeBroadcast { mac, lan_id } => match wake::broadcast(&mac, lan_id.as_deref()) {
            Ok(sent) => Response::Wake {
                text: sent.join(", "),
                done: true,
            },
            Err(e) => Response::Error {
                message: format!("{e:#}"),
            },
        },
        // Answered on the connection that asked, in `serve`, because it
        // reports as it goes rather than once at the end.
        Request::DeviceWake { name } => Response::Error {
            message: format!("ast device wake {name} needs a connection of its own"),
        },
        Request::DevicePing { device } => match mesh {
            Some(mesh) => reply_or_error(mesh.ping(&device).await),
            None => no_mesh(),
        },
        Request::DeviceRemove { name } => match mesh {
            Some(mesh) => {
                let device_id = node
                    .orbit
                    .lock()
                    .await
                    .get(&name)
                    .map(|device| device.device_id.clone());
                if let Some(device_id) = &device_id {
                    if let Err(error) = node.exit.revoke_peer(device_id) {
                        return Response::Error {
                            message: format!(
                                "revoking {name:?}'s network-exit authority before membership removal: {error:#}"
                            ),
                        };
                    }
                }
                match mesh.remove_device(&name).await {
                    Ok(removed) => {
                        node.shell.revoke_peer(
                            &removed.device_id,
                            &format!("peer {name:?} was removed from this orbit"),
                        );
                        Response::Ok
                    }
                    Err(e) => Response::Error {
                        message: format!("{e:#}"),
                    },
                }
            }
            None => no_mesh(),
        },
        // A read capability, unlike the mutation request below. It is also
        // served to authenticated mesh callers, which lets every management
        // surface consume the daemon's own model without gaining authority
        // to change the target account's policy.
        Request::DeviceShellStatus => Response::DeviceShellStatus {
            status: node.shell.status(mesh.is_some()),
            revoked: 0,
        },
        Request::DeviceShellPolicy { action } => {
            match action {
                ShellPolicyAction::Status => Response::DeviceShellStatus {
                    status: node.shell.status(mesh.is_some()),
                    revoked: 0,
                },
                ShellPolicyAction::Enable => {
                    let Some(mesh) = mesh else {
                        return Response::Error {
                        message: "device shell cannot be enabled while the mesh endpoint is unavailable".into(),
                    };
                    };
                    let mut ids = vec![mesh.device_id().to_string()];
                    ids.extend(
                        node.orbit
                            .lock()
                            .await
                            .devices()
                            .iter()
                            .map(|device| device.device_id.clone()),
                    );
                    match node.shell.enable(ids) {
                        Ok(status) => Response::DeviceShellStatus { status, revoked: 0 },
                        Err(e) => Response::Error {
                            message: format!("{e:#}"),
                        },
                    }
                }
                ShellPolicyAction::Disable => match node.shell.disable() {
                    Ok((status, revoked)) => Response::DeviceShellStatus { status, revoked },
                    Err(e) => Response::Error {
                        message: format!("{e:#}"),
                    },
                },
            }
        }
        // Only ever arrives inside a pairing conversation, which handles it
        // there; on its own it is a CLI that lost its place.
        Request::PairConfirm { .. } => Response::Error {
            message: "there is no pairing in progress on this connection".into(),
        },
        // The whole registry, not this device's slice of it. `ast ls`.
        Request::ListOrbit => match mesh {
            Some(mesh) => reply_or_error(mesh.orbit_registry(node).await),
            // With no mesh there is no orbit to assemble, but there is still a
            // shard, and it is the honest whole of what this device can see.
            None => local_rows(node).await,
        },
        other => Response::Error {
            message: format!("{other:?} is not an orbit request"),
        },
    }
}

/// The orbit view a daemon with no mesh can honestly produce: its own shard.
async fn local_rows(node: &Node) -> Response {
    let mut shard = node.shard.lock().await;
    instance::reconcile(&mut shard);
    Response::Orbit {
        rows: shard
            .list()
            .into_iter()
            .map(|instance| OrbitRow {
                instance,
                live: true,
            })
            .collect(),
    }
}

/// Drives `ast device invite` / `ast device add`, which need the connection
/// rather than a single reply.
pub(crate) async fn pair(
    request: Request,
    mesh: Option<&Arc<Mesh>>,
    io: &mut ClientIo<'_>,
) -> Result<()> {
    let Some(mesh) = mesh else {
        anyhow::bail!("{NO_MESH}");
    };
    match request {
        Request::DeviceInvite { name, ttl_secs } => mesh.invite(name, ttl_secs, io).await,
        Request::DeviceAdd { ticket, name } => mesh.add(&ticket, name, io).await,
        other => anyhow::bail!("{other:?} is not a pairing request"),
    }
}

pub(crate) fn no_mesh() -> Response {
    Response::Error {
        message: NO_MESH.into(),
    }
}

pub(crate) fn reply_or_error(result: Result<Response>) -> Response {
    match result {
        Ok(response) => response,
        Err(e) => Response::Error {
            message: format!("{e:#}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The orbit's frames stop at [`crate::dispatch`]. If one of them were
    /// left unclaimed it would fall through to the shard, where the answer to
    /// "which devices are in this orbit" is a refusal.
    #[test]
    fn every_frame_about_the_orbit_is_claimed_before_the_shard_sees_it() {
        for req in [
            Request::Devices,
            Request::ListOrbit,
            Request::DevicePing {
                device: "desktop".into(),
            },
            Request::DeviceRemove {
                name: "desktop".into(),
            },
            Request::DeviceShellStatus,
            Request::DeviceShellPolicy {
                action: ShellPolicyAction::Status,
            },
            Request::DeviceFacts,
            Request::DeviceCheck,
            Request::PairConfirm { accept: true },
            Request::Proxy {
                device: "desktop".into(),
                inner: Box::new(Request::List),
            },
        ] {
            assert!(claims(&req), "{req:?}");
            assert_eq!(req.subject(), None, "{req:?} is not about an instance");
        }
    }

    /// `ast ls --local` is one device's shard and `ast ls` is the orbit's
    /// registry. Claiming the first here would answer a question about this
    /// device with an answer assembled from every other one.
    #[test]
    fn a_single_shard_is_not_an_orbit_question() {
        assert!(!claims(&Request::List));
        assert!(!claims(&Request::Status { name: "dev".into() }));
        assert!(!claims(&Request::Up {
            name: "dev".into(),
            restart: None
        }));
    }

    /// The two pairing frames borrow the connection, so they are answered in
    /// [`crate::serve`] and must not be intercepted a step later — a claim
    /// here would turn a conversation into a single reply.
    #[test]
    fn the_pairing_frames_are_left_to_the_connection_that_asked() {
        assert!(!claims(&Request::DeviceInvite {
            name: None,
            ttl_secs: None
        }));
        assert!(!claims(&Request::DeviceAdd {
            ticket: "t".into(),
            name: None
        }));
    }
}
