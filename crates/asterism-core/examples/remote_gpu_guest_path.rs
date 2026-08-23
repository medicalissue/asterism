//! Source fixture: a real local `/dev/nvidia0` endpoint plus CUDA-semantic
//! calls whose bytes cross an authenticated, token-free mesh path.
//!
//! This is not a LAN listener and not hardware CUDA.

use anyhow::{bail, Context, Result};
use asterism_core::remote_gpu::{
    AuthenticatedPeer, LeaseAuthority, LeaseLimits, ProductionProvider, Provider,
};
use asterism_core::remote_gpu_guest::{
    project_guest_device, CudaCall, CudaResult, GuestDeviceKind, PROJECTION_KIND,
};
use asterism_core::remote_gpu_path::GuestMeshPath;

fn main() -> Result<()> {
    let root = std::env::temp_dir().join(format!("asterism-gpu-guest-{}", std::process::id()));
    std::fs::create_dir_all(&root).context("guest root")?;
    let device = project_guest_device(&root).context("projecting /dev/nvidia0")?;
    let peer = AuthenticatedPeer::from_mesh_identity("a".repeat(64))
        .map_err(|err| anyhow::anyhow!(err.message))?;
    let authority = LeaseAuthority::new(
        "desktop",
        "a".repeat(64),
        "GPU-01234567",
        7,
        LeaseLimits::default(),
    )
    .map_err(|err| anyhow::anyhow!(err.message))?;
    let production = ProductionProvider::new(authority, Provider::reference("desktop"));
    let (mut path, attachment, capability) =
        GuestMeshPath::attach(peer, production, "inst-fixture", 64 * 1024 * 1024, 1_000)
            .map_err(|err| anyhow::anyhow!(err))?;

    if path.crossed_text().contains(&capability) {
        bail!("lease bearer crossed the mesh");
    }
    if attachment.guest_path() != "/dev/nvidia0" {
        bail!("guest path is not /dev/nvidia0");
    }

    path.cuda(CudaCall::Init)
        .map_err(|err| anyhow::anyhow!(err))?;
    let lhs = alloc(&mut path, 16)?;
    let rhs = alloc(&mut path, 16)?;
    let output = alloc(&mut path, 16)?;
    let lhs_bytes: Vec<u8> = [1.0f32, 2.0, 3.0, 4.0]
        .into_iter()
        .flat_map(f32::to_le_bytes)
        .collect();
    let rhs_bytes: Vec<u8> = [10.0f32, 20.0, 30.0, 40.0]
        .into_iter()
        .flat_map(f32::to_le_bytes)
        .collect();
    path.cuda(CudaCall::MemcpyHtoD {
        allocation: lhs.clone(),
        offset: 0,
        data: lhs_bytes,
    })
    .map_err(|err| anyhow::anyhow!(err))?;
    path.cuda(CudaCall::MemcpyHtoD {
        allocation: rhs.clone(),
        offset: 0,
        data: rhs_bytes,
    })
    .map_err(|err| anyhow::anyhow!(err))?;
    let loaded = path
        .cuda(CudaCall::ModuleLoadData {
            image: asterism_core::remote_gpu::VECTOR_ADD_PTX.as_bytes().to_vec(),
        })
        .map_err(|err| anyhow::anyhow!(err))?;
    let CudaResult::Module { pin } = loaded else {
        bail!("module load failed: {loaded:?}");
    };
    path.cuda(CudaCall::LaunchVectorAdd {
        workload_pin: pin,
        lhs,
        rhs,
        output: output.clone(),
        elements: 4,
    })
    .map_err(|err| anyhow::anyhow!(err))?;
    let data = path
        .cuda(CudaCall::MemcpyDtoH {
            allocation: output,
            offset: 0,
            bytes: 16,
        })
        .map_err(|err| anyhow::anyhow!(err))?;
    let CudaResult::Data { data } = data else {
        bail!("read failed: {data:?}");
    };
    let values: Vec<f32> = data
        .chunks(4)
        .map(|chunk| f32::from_le_bytes(chunk.try_into().expect("f32")))
        .collect();
    if values != [11.0, 22.0, 33.0, 44.0] {
        bail!("vector-add result {values:?}");
    }

    println!("guest_visible_device=/dev/nvidia0");
    println!("opened_projection={}", device.path().display());
    println!("projection_kind={PROJECTION_KIND}");
    println!("device_kind={:?}", device.kind());
    println!(
        "cuse_available={}",
        device.kind() == GuestDeviceKind::Cuse
    );
    println!("mesh_frames_crossed={}", path.crossed.len());
    println!("bearer_in_mesh_open=false");
    println!("hardware_cuda_executed=false");
    println!("result=verified");
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

fn alloc(path: &mut GuestMeshPath, bytes: u64) -> Result<String> {
    match path
        .cuda(CudaCall::MemAlloc { bytes })
        .map_err(|err| anyhow::anyhow!(err))?
    {
        CudaResult::Alloc { allocation } => Ok(allocation),
        other => bail!("allocate failed: {other:?}"),
    }
}
