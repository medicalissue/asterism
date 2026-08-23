use std::process::ExitCode;

fn main() -> ExitCode {
    let result = asterism_hyperv::serve_once(std::io::stdin(), std::io::stdout(), dispatch);
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("astd-hyperv: {error:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(target_os = "windows")]
fn dispatch(request: asterism_hyperv::Request) -> anyhow::Result<asterism_hyperv::Reply> {
    windows::dispatch(request)
}

#[cfg(not(target_os = "windows"))]
fn dispatch(_request: asterism_hyperv::Request) -> anyhow::Result<asterism_hyperv::Reply> {
    anyhow::bail!("the native Hyper-V helper runs only on Windows 11 Pro or Enterprise")
}

#[cfg(target_os = "windows")]
mod windows;
