//! One-device hardware CUDA smoke test for an Asterism production executor.
//!
//! This loads the NVIDIA driver API directly, so it needs a working display
//! driver but not `nvcc` or the CUDA toolkit. A hardware PASS is printed only
//! after the checked-in PTX runs and its bytes round-trip through device
//! memory.

use anyhow::{bail, Result};
use asterism_core::remote_gpu::VECTOR_ADD_PTX;
use asterism_core::remote_gpu_cuda::CudaEngine;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let required_uuid = match args.next() {
        Some(flag) if flag == "--uuid" => Some(
            args.next()
                .ok_or_else(|| anyhow::anyhow!("--uuid requires a GPU UUID"))?,
        ),
        Some(other) => bail!("unknown argument {other:?}"),
        None => None,
    };
    if let Some(extra) = args.next() {
        bail!("unexpected argument {extra:?}");
    }

    let mut cuda = CudaEngine::open_live(required_uuid.as_deref())
        .map_err(|error| anyhow::anyhow!(error.message))?;
    if !cuda.is_live_nvidia() {
        bail!("the executor did not open a live NVIDIA driver");
    }
    let identity = cuda.identity().clone();

    let lhs = cuda.alloc(12, 1).map_err(gpu_error)?;
    let rhs = cuda.alloc(12, 2).map_err(gpu_error)?;
    let output = cuda.alloc(12, 3).map_err(gpu_error)?;
    let encode = |values: &[f32]| {
        values
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect::<Vec<_>>()
    };
    cuda.write(lhs, 0, &encode(&[1.0, 2.5, -4.0]), 4)
        .map_err(gpu_error)?;
    cuda.write(rhs, 0, &encode(&[5.0, -0.5, 10.0]), 5)
        .map_err(gpu_error)?;
    cuda.load_ptx(VECTOR_ADD_PTX.as_bytes(), 6)
        .map_err(gpu_error)?;
    let elapsed_ns = cuda
        .launch_vector_add(lhs, rhs, output, 3, 7)
        .map_err(gpu_error)?;
    let bytes = cuda.read(output, 0, 12, 8).map_err(gpu_error)?;
    let values = bytes
        .chunks_exact(4)
        .map(|chunk| f32::from_le_bytes(chunk.try_into().expect("four bytes")))
        .collect::<Vec<_>>();

    cuda.zeroize_and_free(lhs, 12);
    cuda.zeroize_and_free(rhs, 12);
    cuda.zeroize_and_free(output, 12);
    if values != [6.0, 2.0, 6.0] {
        bail!("CUDA vector-add returned {values:?}");
    }

    println!("gpu_uuid={}", identity.uuid);
    println!("gpu_name={}", identity.name);
    println!("driver_version={}", identity.driver_version);
    println!("cuda_driver_api={}", identity.cuda_version);
    println!(
        "compute_capability={}.{}",
        identity.compute_capability.0, identity.compute_capability.1
    );
    println!("device_memory_bytes={}", identity.memory_bytes);
    println!("kernel_elapsed_ns={elapsed_ns}");
    println!("vector_add={values:?}");
    println!("hardware_cuda_executed=true");
    println!("result=verified");
    Ok(())
}

fn gpu_error(error: asterism_core::remote_gpu::GpuError) -> anyhow::Error {
    anyhow::anyhow!("{:?}: {}", error.code, error.message)
}
