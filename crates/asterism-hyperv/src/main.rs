use std::process::ExitCode;

use asterism_hyperv::{read_request, write_reply, Reply, Request};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("astd-hyperv: {error:#}");
            ExitCode::FAILURE
        }
    }
}

/// One request on stdin, one reply on stdout — except for the door.
///
/// [`Request::ServeEgress`] is the only request that does not end the
/// process: the helper binds this instance's egress door, answers `Serving`
/// so `astd` knows the door is open before the guest can hold a handle for
/// it, and then serves until it is killed. Everything else stays the single
/// round trip ADR 0002 specifies.
fn run() -> anyhow::Result<()> {
    let request = read_request(std::io::stdin())?;
    if let Request::ServeEgress { door } = request {
        return serve_egress(&door, || write_reply(std::io::stdout(), &Reply::Serving));
    }
    let reply = dispatch(request).unwrap_or_else(|error| Reply::Error {
        message: format!("{error:#}"),
    });
    write_reply(std::io::stdout(), &reply)
}

#[cfg(target_os = "windows")]
fn dispatch(request: Request) -> anyhow::Result<Reply> {
    windows::dispatch(request)
}

#[cfg(not(target_os = "windows"))]
fn dispatch(_request: Request) -> anyhow::Result<Reply> {
    anyhow::bail!("the native Hyper-V helper runs only on a Windows host with HCS and HCN")
}

#[cfg(target_os = "windows")]
fn serve_egress(
    door: &asterism_hyperv::EgressDoor,
    ready: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    windows::serve_egress(door, ready)
}

#[cfg(not(target_os = "windows"))]
fn serve_egress(
    _door: &asterism_hyperv::EgressDoor,
    _ready: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    anyhow::bail!("the secret-egress door needs a Hyper-V Socket, which only a Windows host has")
}

#[cfg(target_os = "windows")]
mod windows;
