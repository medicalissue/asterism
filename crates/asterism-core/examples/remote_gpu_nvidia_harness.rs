//! Deterministic two-device NVIDIA contract runner.
//!
//! This example never claims hardware CUDA. It admits an inventory (the
//! checked-in two-device fixture, or a file written by
//! `scripts/harness-remote-gpu-nvidia.sh`), then proves guest-local
//! `/dev/nvidia0`, ABI 1, fencing, restart, revoke and fail-closed skew
//! through the reference executor. Real CUDA evidence is the `.cu` kernel
//! compiled on the paid NVIDIA host, not this process.

use anyhow::{Context, Result};
use asterism_core::remote_gpu_nvidia::{
    parse_inventory, prove_two_device_nvidia_contract, sample_two_device_inventory,
};

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let inventory = match args.next() {
        Some(flag) if flag == "--inventory" => {
            let path = args.next().context("--inventory requires a path")?;
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("reading NVIDIA inventory {path}"))?;
            parse_inventory(&text).map_err(|error| anyhow::anyhow!("{error}"))?
        }
        Some(other) => anyhow::bail!("unknown argument {other:?}"),
        None => sample_two_device_inventory(),
    };

    let evidence =
        prove_two_device_nvidia_contract(&inventory).map_err(|error| anyhow::anyhow!("{error}"))?;
    for line in evidence.report_lines() {
        println!("{line}");
    }
    if evidence.hardware_cuda_executed {
        anyhow::bail!("reference harness must not set hardware_cuda_executed=true");
    }
    println!("nvidia_gate=contract_only");
    println!("hardware_cuda_executed=false");
    Ok(())
}
