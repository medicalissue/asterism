//! Real NVIDIA CUDA driver executor for the production remote GPU part.
//!
//! Production providers load the CUDA *driver* API (`libcuda`) on the GPU
//! device, verify UUID / driver / CUDA / compute capability against the
//! fail-closed matrix, and execute the versioned remote ABI. The CPU
//! reference state machine in [`crate::remote_gpu`] stays test-only: it can
//! never advertise a hardware PASS.
//!
//! A simulated driver exists so quota, generation and helper-restart tests
//! can exercise the CUDA executor path without a physical GPU. Simulated
//! execution still reports `Executor::Cuda` and is never hardware-pass
//! eligible: `hardware_cuda_executed()` stays false even after a successful
//! simulated launch. Live hardware is claimed only after a real driver
//! `cuLaunchKernel` plus synchronize succeed.
//!
//! Every copy and launch validates allocation-base + offset + bytes with
//! checked arithmetic before touching device memory. Wipe/free failures are
//! propagated; accounting is not released until zeroization succeeds. Live
//! driver calls `cuCtxSetCurrent` on every entry so a calling thread always
//! owns the context.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uint, c_void};
use std::ptr;
use std::time::Instant;

use crate::remote_gpu::{ControlError, ControlErrorCode, ErrorCode, GpuError, VECTOR_ADD_PTX};
use crate::remote_gpu_nvidia::{
    admit_cuda_inventory, CudaInventory, NvidiaDevice, MIN_COMPUTE_MAJOR, MIN_COMPUTE_MINOR,
};

/// Device facts the executor verified before creating a context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CudaDeviceIdentity {
    pub ordinal: u32,
    pub uuid: String,
    pub name: String,
    pub driver_version: String,
    pub cuda_version: String,
    pub compute_capability: (u32, u32),
    pub memory_bytes: u64,
}

impl CudaDeviceIdentity {
    /// Fixture identity used by source tests. Not hardware.
    pub fn simulated_l4() -> Self {
        Self {
            ordinal: 0,
            uuid: "GPU-01234567-aaaa-aaaa-aaaa-aaaaaaaaaaaa".into(),
            name: "NVIDIA L4".into(),
            driver_version: "550.54.15".into(),
            cuda_version: "12.4".into(),
            compute_capability: (8, 9),
            memory_bytes: 24 * 1024 * 1024 * 1024,
        }
    }

    fn as_inventory(&self) -> CudaInventory {
        CudaInventory {
            driver_version: self.driver_version.clone(),
            cuda_runtime_version: self.cuda_version.clone(),
            devices: vec![NvidiaDevice {
                index: self.ordinal,
                uuid: self.uuid.clone(),
                name: self.name.clone(),
                memory_bytes: self.memory_bytes,
                compute_capability: self.compute_capability,
            }],
        }
    }
}

/// In-process CUDA engine used by [`crate::remote_gpu::Provider`].
#[derive(Debug)]
pub struct CudaEngine {
    inner: EngineKind,
}

#[derive(Debug)]
enum EngineKind {
    Live(LiveCuda),
    Simulated(SimulatedCuda),
}

impl CudaEngine {
    /// Load `libcuda`, pick the requested device (or the only admitted one),
    /// and fail closed on an unsupported matrix. This is the production path.
    pub fn open_live(required_uuid: Option<&str>) -> Result<Self, ControlError> {
        let live = LiveCuda::open(required_uuid)?;
        admit_cuda_inventory(&live.identity.as_inventory())?;
        Ok(Self {
            inner: EngineKind::Live(live),
        })
    }

    /// CUDA-semantic executor that does not touch `libcuda`. Used by source
    /// tests and never by a hardware PASS.
    pub fn simulated(identity: CudaDeviceIdentity, generation: u64) -> Result<Self, ControlError> {
        admit_cuda_inventory(&identity.as_inventory())?;
        Ok(Self {
            inner: EngineKind::Simulated(SimulatedCuda::new(identity, generation)),
        })
    }

    pub fn identity(&self) -> &CudaDeviceIdentity {
        match &self.inner {
            EngineKind::Live(live) => &live.identity,
            EngineKind::Simulated(sim) => &sim.identity,
        }
    }

    pub fn generation(&self) -> u64 {
        match &self.inner {
            EngineKind::Live(live) => live.generation,
            EngineKind::Simulated(sim) => sim.generation,
        }
    }

    /// True only when this process loaded the real NVIDIA driver and created
    /// a device context. Simulated and reference executors are always false.
    /// This is not a hardware PASS: see [`Self::hardware_cuda_executed`].
    pub fn is_live_nvidia(&self) -> bool {
        matches!(self.inner, EngineKind::Live(_))
    }

    /// True only after a successful live-driver kernel launch. Simulated
    /// `Executor::Cuda` is never eligible.
    pub fn hardware_cuda_executed(&self) -> bool {
        match &self.inner {
            EngineKind::Live(live) => live.kernel_launched,
            EngineKind::Simulated(_) => false,
        }
    }

    /// Source-test injection: the next wipe/free fails closed. Live drivers
    /// ignore this; simulated accounting stays reserved until a later wipe
    /// succeeds.
    pub fn fail_next_zeroize(&mut self) {
        match &mut self.inner {
            EngineKind::Live(_) => {}
            EngineKind::Simulated(sim) => sim.fail_zeroize = true,
        }
    }

    pub fn alloc(&mut self, bytes: u64, sequence: u64) -> Result<u64, GpuError> {
        match &mut self.inner {
            EngineKind::Live(live) => live.alloc(bytes, sequence),
            EngineKind::Simulated(sim) => sim.alloc(bytes, sequence),
        }
    }

    pub fn write(
        &mut self,
        ptr: u64,
        offset: u64,
        data: &[u8],
        sequence: u64,
    ) -> Result<(), GpuError> {
        match &mut self.inner {
            EngineKind::Live(live) => live.write(ptr, offset, data, sequence),
            EngineKind::Simulated(sim) => sim.write(ptr, offset, data, sequence),
        }
    }

    pub fn read(
        &mut self,
        ptr: u64,
        offset: u64,
        bytes: u64,
        sequence: u64,
    ) -> Result<Vec<u8>, GpuError> {
        match &mut self.inner {
            EngineKind::Live(live) => live.read(ptr, offset, data_len(bytes, sequence)?, sequence),
            EngineKind::Simulated(sim) => {
                sim.read(ptr, offset, data_len(bytes, sequence)?, sequence)
            }
        }
    }

    pub fn load_ptx(&mut self, ptx: &[u8], sequence: u64) -> Result<(), GpuError> {
        match &mut self.inner {
            EngineKind::Live(live) => live.load_ptx(ptx, sequence),
            EngineKind::Simulated(sim) => sim.load_ptx(ptx, sequence),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn launch_vector_add(
        &mut self,
        lhs: u64,
        lhs_offset: u64,
        rhs: u64,
        rhs_offset: u64,
        output: u64,
        output_offset: u64,
        elements: u32,
        sequence: u64,
    ) -> Result<u64, GpuError> {
        match &mut self.inner {
            EngineKind::Live(live) => live.launch_vector_add(
                lhs,
                lhs_offset,
                rhs,
                rhs_offset,
                output,
                output_offset,
                elements,
                sequence,
            ),
            EngineKind::Simulated(sim) => sim.launch_vector_add(
                lhs,
                lhs_offset,
                rhs,
                rhs_offset,
                output,
                output_offset,
                elements,
                sequence,
            ),
        }
    }

    /// Zeroize then free. On failure the pointer stays live and its bytes
    /// remain in outstanding accounting so the range cannot be reused.
    pub fn zeroize_and_free(&mut self, ptr: u64, bytes: u64) -> Result<(), GpuError> {
        match &mut self.inner {
            EngineKind::Live(live) => live.zeroize_and_free(ptr, bytes),
            EngineKind::Simulated(sim) => sim.zeroize_and_free(ptr, bytes),
        }
    }

    /// Drop the device context and every outstanding allocation, then open a
    /// fresh one. Models a helper-process restart: generation advances and
    /// previously issued device pointers are invalid. A wipe failure fails
    /// closed: generation does not advance and memory stays reserved.
    pub fn restart(&mut self) -> Result<u64, ControlError> {
        match &mut self.inner {
            EngineKind::Live(live) => live.restart(),
            EngineKind::Simulated(sim) => sim.restart(),
        }
    }

    pub fn outstanding_device_bytes(&self) -> u64 {
        match &self.inner {
            EngineKind::Live(live) => live.outstanding_bytes,
            EngineKind::Simulated(sim) => sim.memory.values().map(|m| m.len() as u64).sum(),
        }
    }
}

fn data_len(bytes: u64, sequence: u64) -> Result<usize, GpuError> {
    usize::try_from(bytes).map_err(|_| {
        GpuError::new(
            ErrorCode::LimitExceeded,
            Some(sequence),
            "CUDA copy does not fit this provider's address space",
        )
    })
}

fn gpu_error(sequence: u64, message: impl Into<String>) -> GpuError {
    GpuError::new(ErrorCode::InvalidRequest, Some(sequence), message)
}

/// Validate allocation-base + offset + bytes before any CUDA copy or launch.
pub fn checked_device_range(
    allocation_bytes: u64,
    offset: u64,
    bytes: u64,
    sequence: u64,
) -> Result<usize, GpuError> {
    let end = offset.checked_add(bytes).ok_or_else(|| {
        GpuError::new(
            ErrorCode::OutOfBounds,
            Some(sequence),
            "CUDA base+offset+bytes overflows",
        )
    })?;
    if end > allocation_bytes {
        return Err(GpuError::new(
            ErrorCode::OutOfBounds,
            Some(sequence),
            format!("CUDA range {offset}..{end} exceeds allocation size {allocation_bytes}"),
        ));
    }
    data_len(bytes, sequence)
}

// ---- simulated CUDA (source tests; never a hardware PASS) -------------------

#[derive(Debug)]
struct SimulatedCuda {
    identity: CudaDeviceIdentity,
    generation: u64,
    next_ptr: u64,
    memory: HashMap<u64, Vec<u8>>,
    ptx_loaded: bool,
    fail_zeroize: bool,
}

impl SimulatedCuda {
    fn new(identity: CudaDeviceIdentity, generation: u64) -> Self {
        Self {
            identity,
            generation: generation.max(1),
            next_ptr: 0x1000,
            memory: HashMap::new(),
            ptx_loaded: false,
            fail_zeroize: false,
        }
    }

    fn device_range(
        &self,
        ptr: u64,
        offset: u64,
        bytes: u64,
        sequence: u64,
    ) -> Result<(u64, usize), GpuError> {
        let size = self
            .memory
            .get(&ptr)
            .map(|m| m.len() as u64)
            .ok_or_else(|| {
                gpu_error(
                    sequence,
                    "CUDA device pointer is unknown in this helper generation",
                )
            })?;
        let len = checked_device_range(size, offset, bytes, sequence)?;
        Ok((ptr, len))
    }

    fn alloc(&mut self, bytes: u64, sequence: u64) -> Result<u64, GpuError> {
        let size = data_len(bytes, sequence)?;
        let mut host = Vec::new();
        host.try_reserve_exact(size).map_err(|_| {
            GpuError::new(
                ErrorCode::LimitExceeded,
                Some(sequence),
                "simulated CUDA executor could not reserve device memory",
            )
        })?;
        host.resize(size, 0);
        let ptr = self.next_ptr;
        self.next_ptr = self.next_ptr.saturating_add(bytes.max(1));
        self.memory.insert(ptr, host);
        Ok(ptr)
    }

    fn buffer_mut(
        &mut self,
        ptr: u64,
        offset: u64,
        len: usize,
        sequence: u64,
    ) -> Result<&mut [u8], GpuError> {
        let (_, _) = self.device_range(ptr, offset, len as u64, sequence)?;
        let start = offset as usize;
        Ok(&mut self.memory.get_mut(&ptr).expect("ptr")[start..start + len])
    }

    fn write(&mut self, ptr: u64, offset: u64, data: &[u8], sequence: u64) -> Result<(), GpuError> {
        self.buffer_mut(ptr, offset, data.len(), sequence)?
            .copy_from_slice(data);
        Ok(())
    }

    fn read(
        &mut self,
        ptr: u64,
        offset: u64,
        len: usize,
        sequence: u64,
    ) -> Result<Vec<u8>, GpuError> {
        Ok(self.buffer_mut(ptr, offset, len, sequence)?.to_vec())
    }

    fn load_ptx(&mut self, ptx: &[u8], sequence: u64) -> Result<(), GpuError> {
        if ptx != VECTOR_ADD_PTX.as_bytes() {
            return Err(GpuError::new(
                ErrorCode::WorkloadMismatch,
                Some(sequence),
                "CUDA executor only admits the checked-in vector-add PTX",
            ));
        }
        self.ptx_loaded = true;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn launch_vector_add(
        &mut self,
        lhs: u64,
        lhs_offset: u64,
        rhs: u64,
        rhs_offset: u64,
        output: u64,
        output_offset: u64,
        elements: u32,
        sequence: u64,
    ) -> Result<u64, GpuError> {
        if !self.ptx_loaded {
            return Err(GpuError::new(
                ErrorCode::WorkloadMismatch,
                Some(sequence),
                "CUDA module was not loaded in this helper generation",
            ));
        }
        let bytes = (elements as u64).checked_mul(4).ok_or_else(|| {
            GpuError::new(
                ErrorCode::InvalidLaunch,
                Some(sequence),
                "vector element count overflows its byte range",
            )
        })?;
        let lhs_len = checked_device_range(
            self.memory.get(&lhs).map(|m| m.len() as u64).unwrap_or(0),
            lhs_offset,
            bytes,
            sequence,
        )?;
        let rhs_len = checked_device_range(
            self.memory.get(&rhs).map(|m| m.len() as u64).unwrap_or(0),
            rhs_offset,
            bytes,
            sequence,
        )?;
        let _ = checked_device_range(
            self.memory
                .get(&output)
                .map(|m| m.len() as u64)
                .unwrap_or(0),
            output_offset,
            bytes,
            sequence,
        )?;
        if self.memory.get(&lhs).is_none()
            || self.memory.get(&rhs).is_none()
            || self.memory.get(&output).is_none()
        {
            return Err(gpu_error(
                sequence,
                "CUDA device pointer is unknown in this helper generation",
            ));
        }
        let started = Instant::now();
        let lhs_bytes =
            self.memory[&lhs][lhs_offset as usize..lhs_offset as usize + lhs_len].to_vec();
        let rhs_bytes =
            self.memory[&rhs][rhs_offset as usize..rhs_offset as usize + rhs_len].to_vec();
        let mut result = Vec::with_capacity(bytes as usize);
        for (a, b) in lhs_bytes.chunks(4).zip(rhs_bytes.chunks(4)) {
            let a = f32::from_le_bytes(a.try_into().expect("four-byte chunk"));
            let b = f32::from_le_bytes(b.try_into().expect("four-byte chunk"));
            result.extend_from_slice(&(a + b).to_le_bytes());
        }
        let start = output_offset as usize;
        self.memory.get_mut(&output).expect("output")[start..start + result.len()]
            .copy_from_slice(&result);
        Ok(started.elapsed().as_nanos().min(u64::MAX as u128) as u64)
    }

    fn zeroize_and_free(&mut self, ptr: u64, _bytes: u64) -> Result<(), GpuError> {
        if self.fail_zeroize {
            self.fail_zeroize = false;
            return Err(gpu_error(0, "simulated CUDA zeroize failed closed"));
        }
        let mut memory = self.memory.remove(&ptr).ok_or_else(|| {
            gpu_error(
                0,
                "CUDA device pointer is unknown in this helper generation",
            )
        })?;
        for byte in &mut memory {
            *byte = 0;
        }
        Ok(())
    }

    fn restart(&mut self) -> Result<u64, ControlError> {
        let ptrs: Vec<u64> = self.memory.keys().copied().collect();
        for ptr in ptrs {
            self.zeroize_and_free(ptr, 0).map_err(|error| {
                ControlError::new(
                    ControlErrorCode::Unavailable,
                    format!("zeroize failed closed: {error}"),
                )
            })?;
        }
        self.ptx_loaded = false;
        self.next_ptr = 0x1000;
        self.fail_zeroize = false;
        self.generation = self.generation.saturating_add(1).max(1);
        Ok(self.generation)
    }
}

// ---- live NVIDIA CUDA driver API -------------------------------------------

type CuResult = c_int;
type CuDevice = c_int;
type CuDevicePtr = u64;
type CuContext = *mut c_void;
type CuModule = *mut c_void;
type CuFunction = *mut c_void;

const CUDA_SUCCESS: CuResult = 0;
const CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR: c_int = 75;
const CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR: c_int = 76;

struct CudaFns {
    cu_init: unsafe extern "C" fn(c_uint) -> CuResult,
    cu_driver_get_version: unsafe extern "C" fn(*mut c_int) -> CuResult,
    cu_device_get_count: unsafe extern "C" fn(*mut c_int) -> CuResult,
    cu_device_get: unsafe extern "C" fn(*mut CuDevice, c_int) -> CuResult,
    cu_device_get_name: unsafe extern "C" fn(*mut c_char, c_int, CuDevice) -> CuResult,
    cu_device_get_uuid: unsafe extern "C" fn(*mut [u8; 16], CuDevice) -> CuResult,
    cu_device_get_attribute: unsafe extern "C" fn(*mut c_int, c_int, CuDevice) -> CuResult,
    cu_device_total_mem: unsafe extern "C" fn(*mut usize, CuDevice) -> CuResult,
    cu_ctx_create: unsafe extern "C" fn(*mut CuContext, c_uint, CuDevice) -> CuResult,
    cu_ctx_destroy: unsafe extern "C" fn(CuContext) -> CuResult,
    cu_ctx_set_current: unsafe extern "C" fn(CuContext) -> CuResult,
    cu_ctx_synchronize: unsafe extern "C" fn() -> CuResult,
    cu_mem_alloc: unsafe extern "C" fn(*mut CuDevicePtr, usize) -> CuResult,
    cu_mem_free: unsafe extern "C" fn(CuDevicePtr) -> CuResult,
    cu_memcpy_htod: unsafe extern "C" fn(CuDevicePtr, *const c_void, usize) -> CuResult,
    cu_memcpy_dtoh: unsafe extern "C" fn(*mut c_void, CuDevicePtr, usize) -> CuResult,
    cu_memset_d8: unsafe extern "C" fn(CuDevicePtr, u8, usize) -> CuResult,
    cu_module_load_data: unsafe extern "C" fn(*mut CuModule, *const c_void) -> CuResult,
    cu_module_get_function:
        unsafe extern "C" fn(*mut CuFunction, CuModule, *const c_char) -> CuResult,
    cu_launch_kernel: unsafe extern "C" fn(
        CuFunction,
        c_uint,
        c_uint,
        c_uint,
        c_uint,
        c_uint,
        c_uint,
        c_uint,
        *mut c_void,
        *mut *mut c_void,
        *mut *mut c_void,
    ) -> CuResult,
    cu_get_error_string: Option<unsafe extern "C" fn(CuResult, *mut *const c_char) -> CuResult>,
}

struct LiveCuda {
    handle: *mut c_void,
    fns: CudaFns,
    device: CuDevice,
    context: CuContext,
    module: CuModule,
    function: CuFunction,
    identity: CudaDeviceIdentity,
    generation: u64,
    outstanding_bytes: u64,
    live_ptrs: HashMap<u64, u64>,
    kernel_launched: bool,
}

// The CUDA driver handle is process-local. Every live method calls
// `cuCtxSetCurrent` so whichever thread holds the provider lock owns the
// context for that call. ProductionProvider is still `&mut self` / mutexed.
unsafe impl Send for LiveCuda {}

impl std::fmt::Debug for LiveCuda {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("LiveCuda")
            .field("identity", &self.identity)
            .field("generation", &self.generation)
            .field("outstanding_bytes", &self.outstanding_bytes)
            .finish()
    }
}

impl LiveCuda {
    fn open(required_uuid: Option<&str>) -> Result<Self, ControlError> {
        let (handle, fns) = load_libcuda()?;
        check_ctrl(unsafe { (fns.cu_init)(0) }, "cuInit", &fns)?;

        let mut driver_version = 0;
        check_ctrl(
            unsafe { (fns.cu_driver_get_version)(&mut driver_version) },
            "cuDriverGetVersion",
            &fns,
        )?;
        let cuda_version = format_cuda_version(driver_version);
        let driver_version = format_driver_from_cuda(driver_version);

        let mut count = 0;
        check_ctrl(
            unsafe { (fns.cu_device_get_count)(&mut count) },
            "cuDeviceGetCount",
            &fns,
        )?;
        if count <= 0 {
            return Err(ControlError::new(
                ControlErrorCode::Unavailable,
                "NVIDIA CUDA driver reports no devices",
            ));
        }

        let mut chosen: Option<(CuDevice, CudaDeviceIdentity)> = None;
        for ordinal in 0..count {
            let mut device = 0;
            check_ctrl(
                unsafe { (fns.cu_device_get)(&mut device, ordinal) },
                "cuDeviceGet",
                &fns,
            )?;
            let identity =
                query_device(&fns, device, ordinal as u32, &driver_version, &cuda_version)?;
            if let Some(required) = required_uuid {
                if identity.uuid != required {
                    continue;
                }
            }
            chosen = Some((device, identity));
            if required_uuid.is_some() {
                break;
            }
        }
        let (device, identity) = chosen.ok_or_else(|| {
            ControlError::new(
                ControlErrorCode::Unavailable,
                match required_uuid {
                    Some(uuid) => format!("NVIDIA CUDA driver has no device {uuid}"),
                    None => "NVIDIA CUDA driver enumerated no usable device".into(),
                },
            )
        })?;

        if identity.compute_capability < (MIN_COMPUTE_MAJOR, MIN_COMPUTE_MINOR) {
            return Err(ControlError::new(
                ControlErrorCode::Unavailable,
                format!(
                    "NVIDIA GPU {} compute capability {}.{} is below {MIN_COMPUTE_MAJOR}.{MIN_COMPUTE_MINOR}",
                    identity.uuid, identity.compute_capability.0, identity.compute_capability.1
                ),
            ));
        }

        let mut context = ptr::null_mut();
        check_ctrl(
            unsafe { (fns.cu_ctx_create)(&mut context, 0, device) },
            "cuCtxCreate",
            &fns,
        )?;

        Ok(Self {
            handle,
            fns,
            device,
            context,
            module: ptr::null_mut(),
            function: ptr::null_mut(),
            identity,
            generation: 1,
            outstanding_bytes: 0,
            live_ptrs: HashMap::new(),
            kernel_launched: false,
        })
    }

    fn bind_context(&self, sequence: u64) -> Result<(), GpuError> {
        check_gpu(
            unsafe { (self.fns.cu_ctx_set_current)(self.context) },
            "cuCtxSetCurrent",
            sequence,
            &self.fns,
        )
    }

    fn device_addr(
        &self,
        ptr: u64,
        offset: u64,
        bytes: u64,
        sequence: u64,
    ) -> Result<u64, GpuError> {
        let size = self.live_ptrs.get(&ptr).copied().ok_or_else(|| {
            gpu_error(
                sequence,
                "CUDA device pointer is unknown in this helper generation",
            )
        })?;
        let _ = checked_device_range(size, offset, bytes, sequence)?;
        ptr.checked_add(offset).ok_or_else(|| {
            GpuError::new(
                ErrorCode::OutOfBounds,
                Some(sequence),
                "CUDA device address overflows",
            )
        })
    }

    fn alloc(&mut self, bytes: u64, sequence: u64) -> Result<u64, GpuError> {
        self.bind_context(sequence)?;
        let size = data_len(bytes, sequence)?;
        let mut ptr = 0;
        check_gpu(
            unsafe { (self.fns.cu_mem_alloc)(&mut ptr, size) },
            "cuMemAlloc",
            sequence,
            &self.fns,
        )?;
        self.live_ptrs.insert(ptr, bytes);
        self.outstanding_bytes = self.outstanding_bytes.saturating_add(bytes);
        Ok(ptr)
    }

    fn write(&mut self, ptr: u64, offset: u64, data: &[u8], sequence: u64) -> Result<(), GpuError> {
        self.bind_context(sequence)?;
        let dest = self.device_addr(ptr, offset, data.len() as u64, sequence)?;
        check_gpu(
            unsafe { (self.fns.cu_memcpy_htod)(dest, data.as_ptr() as *const c_void, data.len()) },
            "cuMemcpyHtoD",
            sequence,
            &self.fns,
        )
    }

    fn read(
        &mut self,
        ptr: u64,
        offset: u64,
        len: usize,
        sequence: u64,
    ) -> Result<Vec<u8>, GpuError> {
        self.bind_context(sequence)?;
        let src = self.device_addr(ptr, offset, len as u64, sequence)?;
        let mut host = vec![0u8; len];
        check_gpu(
            unsafe { (self.fns.cu_memcpy_dtoh)(host.as_mut_ptr() as *mut c_void, src, len) },
            "cuMemcpyDtoH",
            sequence,
            &self.fns,
        )?;
        Ok(host)
    }

    fn load_ptx(&mut self, ptx: &[u8], sequence: u64) -> Result<(), GpuError> {
        if ptx != VECTOR_ADD_PTX.as_bytes() {
            return Err(GpuError::new(
                ErrorCode::WorkloadMismatch,
                Some(sequence),
                "CUDA executor only admits the checked-in vector-add PTX",
            ));
        }
        self.bind_context(sequence)?;
        let mut image = ptx.to_vec();
        image.push(0);
        let mut module = ptr::null_mut();
        check_gpu(
            unsafe { (self.fns.cu_module_load_data)(&mut module, image.as_ptr() as *const c_void) },
            "cuModuleLoadData",
            sequence,
            &self.fns,
        )?;
        let name = CString::new("vector_add_f32").expect("entrypoint");
        let mut function = ptr::null_mut();
        check_gpu(
            unsafe { (self.fns.cu_module_get_function)(&mut function, module, name.as_ptr()) },
            "cuModuleGetFunction",
            sequence,
            &self.fns,
        )?;
        self.module = module;
        self.function = function;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn launch_vector_add(
        &mut self,
        lhs: u64,
        lhs_offset: u64,
        rhs: u64,
        rhs_offset: u64,
        output: u64,
        output_offset: u64,
        elements: u32,
        sequence: u64,
    ) -> Result<u64, GpuError> {
        if self.function.is_null() {
            return Err(GpuError::new(
                ErrorCode::WorkloadMismatch,
                Some(sequence),
                "CUDA module was not loaded in this helper generation",
            ));
        }
        self.bind_context(sequence)?;
        let bytes = (elements as u64).checked_mul(4).ok_or_else(|| {
            GpuError::new(
                ErrorCode::InvalidLaunch,
                Some(sequence),
                "vector element count overflows its byte range",
            )
        })?;
        let mut lhs = self.device_addr(lhs, lhs_offset, bytes, sequence)?;
        let mut rhs = self.device_addr(rhs, rhs_offset, bytes, sequence)?;
        let mut output = self.device_addr(output, output_offset, bytes, sequence)?;
        let started = Instant::now();
        let mut elements = elements;
        let mut params: [*mut c_void; 4] = [
            &mut lhs as *mut u64 as *mut c_void,
            &mut rhs as *mut u64 as *mut c_void,
            &mut output as *mut u64 as *mut c_void,
            &mut elements as *mut u32 as *mut c_void,
        ];
        let block = 256u32;
        let grid = elements.saturating_add(block - 1) / block;
        check_gpu(
            unsafe {
                (self.fns.cu_launch_kernel)(
                    self.function,
                    grid,
                    1,
                    1,
                    block,
                    1,
                    1,
                    0,
                    ptr::null_mut(),
                    params.as_mut_ptr(),
                    ptr::null_mut(),
                )
            },
            "cuLaunchKernel",
            sequence,
            &self.fns,
        )?;
        check_gpu(
            unsafe { (self.fns.cu_ctx_synchronize)() },
            "cuCtxSynchronize",
            sequence,
            &self.fns,
        )?;
        self.kernel_launched = true;
        Ok(started.elapsed().as_nanos().min(u64::MAX as u128) as u64)
    }

    fn zeroize_and_free(&mut self, ptr: u64, bytes: u64) -> Result<(), GpuError> {
        self.bind_context(0)?;
        let size = self.live_ptrs.get(&ptr).copied().ok_or_else(|| {
            gpu_error(
                0,
                "CUDA device pointer is unknown in this helper generation",
            )
        })?;
        let wipe_bytes = if bytes == 0 { size } else { bytes };
        let _ = checked_device_range(size, 0, wipe_bytes, 0)?;
        if wipe_bytes > 0 {
            check_gpu(
                unsafe { (self.fns.cu_memset_d8)(ptr, 0, wipe_bytes as usize) },
                "cuMemsetD8",
                0,
                &self.fns,
            )?;
        }
        check_gpu(
            unsafe { (self.fns.cu_mem_free)(ptr) },
            "cuMemFree",
            0,
            &self.fns,
        )?;
        self.live_ptrs.remove(&ptr);
        self.outstanding_bytes = self.outstanding_bytes.saturating_sub(size);
        Ok(())
    }

    fn restart(&mut self) -> Result<u64, ControlError> {
        if let Err(error) = self.bind_context(0) {
            return Err(ControlError::new(
                ControlErrorCode::Unavailable,
                error.message,
            ));
        }
        let ptrs: Vec<(u64, u64)> = self.live_ptrs.iter().map(|(&p, &b)| (p, b)).collect();
        for (ptr, bytes) in ptrs {
            self.zeroize_and_free(ptr, bytes).map_err(|error| {
                ControlError::new(
                    ControlErrorCode::Unavailable,
                    format!("zeroize failed closed: {error}"),
                )
            })?;
        }
        self.outstanding_bytes = 0;
        self.module = ptr::null_mut();
        self.function = ptr::null_mut();
        self.kernel_launched = false;
        if !self.context.is_null() {
            let _ = unsafe { (self.fns.cu_ctx_destroy)(self.context) };
            self.context = ptr::null_mut();
        }
        let mut context = ptr::null_mut();
        check_ctrl(
            unsafe { (self.fns.cu_ctx_create)(&mut context, 0, self.device) },
            "cuCtxCreate",
            &self.fns,
        )?;
        check_ctrl(
            unsafe { (self.fns.cu_ctx_set_current)(context) },
            "cuCtxSetCurrent",
            &self.fns,
        )?;
        self.context = context;
        self.generation = self.generation.saturating_add(1).max(1);
        Ok(self.generation)
    }
}

impl Drop for LiveCuda {
    fn drop(&mut self) {
        let _ = unsafe { (self.fns.cu_ctx_set_current)(self.context) };
        for (ptr, bytes) in self.live_ptrs.drain() {
            if bytes > 0 {
                let _ = unsafe { (self.fns.cu_memset_d8)(ptr, 0, bytes as usize) };
            }
            let _ = unsafe { (self.fns.cu_mem_free)(ptr) };
        }
        if !self.context.is_null() {
            let _ = unsafe { (self.fns.cu_ctx_destroy)(self.context) };
        }
        if !self.handle.is_null() {
            unsafe { libc::dlclose(self.handle) };
        }
    }
}

fn query_device(
    fns: &CudaFns,
    device: CuDevice,
    ordinal: u32,
    driver_version: &str,
    cuda_version: &str,
) -> Result<CudaDeviceIdentity, ControlError> {
    let mut name_buf = [0u8; 256];
    check_ctrl(
        unsafe {
            (fns.cu_device_get_name)(
                name_buf.as_mut_ptr() as *mut c_char,
                name_buf.len() as c_int,
                device,
            )
        },
        "cuDeviceGetName",
        fns,
    )?;
    let name_end = name_buf
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(name_buf.len());
    let name = String::from_utf8_lossy(&name_buf[..name_end]).into_owned();

    let mut uuid = [0u8; 16];
    check_ctrl(
        unsafe { (fns.cu_device_get_uuid)(&mut uuid, device) },
        "cuDeviceGetUuid",
        fns,
    )?;
    let uuid = format!(
        "GPU-{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7],
        uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]
    );

    let mut major = 0;
    let mut minor = 0;
    check_ctrl(
        unsafe {
            (fns.cu_device_get_attribute)(
                &mut major,
                CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR,
                device,
            )
        },
        "cuDeviceGetAttribute(major)",
        fns,
    )?;
    check_ctrl(
        unsafe {
            (fns.cu_device_get_attribute)(
                &mut minor,
                CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR,
                device,
            )
        },
        "cuDeviceGetAttribute(minor)",
        fns,
    )?;

    let mut memory = 0usize;
    check_ctrl(
        unsafe { (fns.cu_device_total_mem)(&mut memory, device) },
        "cuDeviceTotalMem",
        fns,
    )?;

    Ok(CudaDeviceIdentity {
        ordinal,
        uuid,
        name,
        driver_version: driver_version.to_owned(),
        cuda_version: cuda_version.to_owned(),
        compute_capability: (major as u32, minor as u32),
        memory_bytes: memory as u64,
    })
}

fn format_cuda_version(driver_version: c_int) -> String {
    let major = driver_version / 1000;
    let minor = (driver_version % 1000) / 10;
    format!("{major}.{minor}")
}

/// The CUDA driver API reports a toolkit version, not `nvidia-smi`'s driver
/// string. Map the documented pairings so the fail-closed matrix still sees
/// a driver floor: CUDA 12.4 ↔ driver 550.
fn format_driver_from_cuda(driver_version: c_int) -> String {
    let major = driver_version / 1000;
    let minor = (driver_version % 1000) / 10;
    let nvidia = match (major, minor) {
        (13, _) => 570,
        (12, m) if m >= 4 => 550,
        (12, _) => 525,
        _ => 0,
    };
    if nvidia == 0 {
        format!("{major}.{minor}")
    } else {
        format!("{nvidia}.0")
    }
}

fn load_libcuda() -> Result<(*mut c_void, CudaFns), ControlError> {
    let names = ["libcuda.so.1", "libcuda.so", "libcuda.dylib"];
    let mut last = "libcuda was not found".to_owned();
    for name in names {
        let cname = CString::new(name).expect("lib name");
        let handle = unsafe { libc::dlopen(cname.as_ptr(), libc::RTLD_NOW) };
        if handle.is_null() {
            last = unsafe {
                let err = libc::dlerror();
                if err.is_null() {
                    format!("{name} could not be loaded")
                } else {
                    CStr::from_ptr(err).to_string_lossy().into_owned()
                }
            };
            continue;
        }
        let fns = unsafe { load_fns(handle) }?;
        return Ok((handle, fns));
    }
    Err(ControlError::new(
        ControlErrorCode::Unavailable,
        format!("NVIDIA CUDA driver API is unavailable ({last})"),
    ))
}

unsafe fn load_fns(handle: *mut c_void) -> Result<CudaFns, ControlError> {
    unsafe fn sym<T>(handle: *mut c_void, name: &str) -> Result<T, ControlError> {
        let cname = CString::new(name).expect("symbol");
        libc::dlerror();
        let ptr = libc::dlsym(handle, cname.as_ptr());
        let err = libc::dlerror();
        if ptr.is_null() || !err.is_null() {
            return Err(ControlError::new(
                ControlErrorCode::Unavailable,
                format!("NVIDIA CUDA driver is missing {name}"),
            ));
        }
        Ok(std::mem::transmute_copy(&ptr))
    }

    Ok(CudaFns {
        cu_init: sym(handle, "cuInit")?,
        cu_driver_get_version: sym(handle, "cuDriverGetVersion")?,
        cu_device_get_count: sym(handle, "cuDeviceGetCount")?,
        cu_device_get: sym(handle, "cuDeviceGet")?,
        cu_device_get_name: sym(handle, "cuDeviceGetName")?,
        cu_device_get_uuid: match sym(handle, "cuDeviceGetUuid_v2") {
            Ok(f) => f,
            Err(_) => sym(handle, "cuDeviceGetUuid")?,
        },
        cu_device_get_attribute: sym(handle, "cuDeviceGetAttribute")?,
        cu_device_total_mem: match sym(handle, "cuDeviceTotalMem_v2") {
            Ok(f) => f,
            Err(_) => sym(handle, "cuDeviceTotalMem")?,
        },
        cu_ctx_create: match sym(handle, "cuCtxCreate_v2") {
            Ok(f) => f,
            Err(_) => sym(handle, "cuCtxCreate")?,
        },
        cu_ctx_destroy: match sym(handle, "cuCtxDestroy_v2") {
            Ok(f) => f,
            Err(_) => sym(handle, "cuCtxDestroy")?,
        },
        cu_ctx_set_current: sym(handle, "cuCtxSetCurrent")?,
        cu_ctx_synchronize: sym(handle, "cuCtxSynchronize")?,
        cu_mem_alloc: match sym(handle, "cuMemAlloc_v2") {
            Ok(f) => f,
            Err(_) => sym(handle, "cuMemAlloc")?,
        },
        cu_mem_free: match sym(handle, "cuMemFree_v2") {
            Ok(f) => f,
            Err(_) => sym(handle, "cuMemFree")?,
        },
        cu_memcpy_htod: match sym(handle, "cuMemcpyHtoD_v2") {
            Ok(f) => f,
            Err(_) => sym(handle, "cuMemcpyHtoD")?,
        },
        cu_memcpy_dtoh: match sym(handle, "cuMemcpyDtoH_v2") {
            Ok(f) => f,
            Err(_) => sym(handle, "cuMemcpyDtoH")?,
        },
        cu_memset_d8: match sym(handle, "cuMemsetD8_v2") {
            Ok(f) => f,
            Err(_) => sym(handle, "cuMemsetD8")?,
        },
        cu_module_load_data: sym(handle, "cuModuleLoadData")?,
        cu_module_get_function: sym(handle, "cuModuleGetFunction")?,
        cu_launch_kernel: sym(handle, "cuLaunchKernel")?,
        cu_get_error_string: sym(handle, "cuGetErrorString").ok(),
    })
}

fn check_ctrl(status: CuResult, op: &str, fns: &CudaFns) -> Result<(), ControlError> {
    if status == CUDA_SUCCESS {
        Ok(())
    } else {
        Err(ControlError::new(
            ControlErrorCode::Unavailable,
            format!("{op} failed: {}", cuda_status(status, fns)),
        ))
    }
}

fn check_gpu(status: CuResult, op: &str, sequence: u64, fns: &CudaFns) -> Result<(), GpuError> {
    if status == CUDA_SUCCESS {
        Ok(())
    } else {
        Err(gpu_error(
            sequence,
            format!("{op} failed: {}", cuda_status(status, fns)),
        ))
    }
}

fn cuda_status(status: CuResult, fns: &CudaFns) -> String {
    if let Some(get) = fns.cu_get_error_string {
        let mut ptr = ptr::null();
        if unsafe { get(status, &mut ptr) } == CUDA_SUCCESS && !ptr.is_null() {
            return unsafe { CStr::from_ptr(ptr) }
                .to_string_lossy()
                .into_owned();
        }
    }
    format!("CUDA_ERROR {status}")
}

/// Refuse a live-NVIDIA claim from anything except a successful live kernel
/// launch. Simulated `Executor::Cuda` is never eligible.
pub fn hardware_pass_allowed(engine: Option<&CudaEngine>) -> bool {
    engine
        .map(CudaEngine::hardware_cuda_executed)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simulated_executor_is_cuda_but_not_a_hardware_pass() {
        let mut engine = CudaEngine::simulated(CudaDeviceIdentity::simulated_l4(), 1).unwrap();
        assert!(!engine.is_live_nvidia());
        assert!(!engine.hardware_cuda_executed());
        assert!(!hardware_pass_allowed(Some(&engine)));
        assert_eq!(engine.identity().compute_capability, (8, 9));
        let ptr = engine.alloc(8, 1).unwrap();
        engine.write(ptr, 0, &[1, 2, 3, 4, 5, 6, 7, 8], 1).unwrap();
        engine.load_ptx(VECTOR_ADD_PTX.as_bytes(), 2).unwrap();
        let rhs = engine.alloc(8, 3).unwrap();
        engine.write(rhs, 0, &[1, 2, 3, 4, 5, 6, 7, 8], 3).unwrap();
        let out = engine.alloc(8, 4).unwrap();
        engine
            .launch_vector_add(ptr, 0, rhs, 0, out, 0, 2, 5)
            .unwrap();
        assert!(
            !engine.hardware_cuda_executed(),
            "simulated Executor::Cuda must never be hardware-pass eligible"
        );
        assert!(!hardware_pass_allowed(Some(&engine)));
    }

    #[test]
    fn cuda_ranges_are_checked_before_copy_and_launch() {
        let mut engine = CudaEngine::simulated(CudaDeviceIdentity::simulated_l4(), 1).unwrap();
        let ptr = engine.alloc(8, 1).unwrap();
        let overflow = engine.write(ptr, 6, &[1, 2, 3, 4], 2).unwrap_err();
        assert_eq!(overflow.code, ErrorCode::OutOfBounds);
        let oob = engine.read(ptr, 0, 16, 3).unwrap_err();
        assert_eq!(oob.code, ErrorCode::OutOfBounds);
        engine.load_ptx(VECTOR_ADD_PTX.as_bytes(), 4).unwrap();
        let rhs = engine.alloc(8, 5).unwrap();
        let out = engine.alloc(8, 6).unwrap();
        let launch = engine
            .launch_vector_add(ptr, 4, rhs, 0, out, 0, 2, 7)
            .unwrap_err();
        assert_eq!(launch.code, ErrorCode::OutOfBounds);
        assert_eq!(engine.outstanding_device_bytes(), 24);
    }

    #[test]
    fn zeroize_failure_keeps_accounting() {
        let mut engine = CudaEngine::simulated(CudaDeviceIdentity::simulated_l4(), 1).unwrap();
        let ptr = engine.alloc(8, 1).unwrap();
        engine.write(ptr, 0, &[9; 8], 1).unwrap();
        engine.fail_next_zeroize();
        let error = engine.zeroize_and_free(ptr, 8).unwrap_err();
        assert!(error.message.contains("failed closed"));
        assert_eq!(engine.outstanding_device_bytes(), 8);
        engine.zeroize_and_free(ptr, 8).unwrap();
        assert_eq!(engine.outstanding_device_bytes(), 0);
    }

    #[test]
    fn unsupported_compute_capability_is_refused_before_context() {
        let mut identity = CudaDeviceIdentity::simulated_l4();
        identity.compute_capability = (7, 0);
        let error = CudaEngine::simulated(identity, 1).unwrap_err();
        assert_eq!(error.code, ControlErrorCode::Unavailable);
    }

    #[test]
    fn live_open_fail_closes_without_libcuda() {
        let error = CudaEngine::open_live(None).unwrap_err();
        assert_eq!(error.code, ControlErrorCode::Unavailable);
        assert!(
            error.message.contains("CUDA") || error.message.contains("libcuda"),
            "{}",
            error.message
        );
    }

    #[test]
    fn restart_zeroizes_and_invalidates_old_pointers() {
        let mut engine = CudaEngine::simulated(CudaDeviceIdentity::simulated_l4(), 3).unwrap();
        let ptr = engine.alloc(8, 1).unwrap();
        engine.write(ptr, 0, &[1, 2, 3, 4, 5, 6, 7, 8], 1).unwrap();
        assert_eq!(engine.outstanding_device_bytes(), 8);
        engine.fail_next_zeroize();
        let blocked = engine.restart().unwrap_err();
        assert_eq!(blocked.code, ControlErrorCode::Unavailable);
        assert_eq!(engine.outstanding_device_bytes(), 8);
        let generation = engine.restart().unwrap();
        assert_eq!(generation, 4);
        assert_eq!(engine.outstanding_device_bytes(), 0);
        let error = engine.read(ptr, 0, 8, 2).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidRequest);
    }
}
