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
//! execution still reports `Executor::Cuda` and still refuses a hardware
//! PASS (`is_live_nvidia() == false`).

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uint, c_void};
use std::ptr;
use std::time::Instant;

use crate::remote_gpu::{ControlError, ControlErrorCode, ErrorCode, GpuError, VECTOR_ADD_PTX};
use crate::remote_gpu_nvidia::{
    admit_cuda_inventory, CudaInventory, NvidiaDevice, MIN_COMPUTE_MAJOR, MIN_COMPUTE_MINOR,
};

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryA(name: *const u8) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    fn FreeLibrary(module: *mut c_void) -> i32;
}

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
    pub fn is_live_nvidia(&self) -> bool {
        matches!(self.inner, EngineKind::Live(_))
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

    pub fn launch_vector_add(
        &mut self,
        lhs: u64,
        rhs: u64,
        output: u64,
        elements: u32,
        sequence: u64,
    ) -> Result<u64, GpuError> {
        match &mut self.inner {
            EngineKind::Live(live) => live.launch_vector_add(lhs, rhs, output, elements, sequence),
            EngineKind::Simulated(sim) => {
                sim.launch_vector_add(lhs, rhs, output, elements, sequence)
            }
        }
    }

    pub fn zeroize_and_free(&mut self, ptr: u64, bytes: u64) {
        match &mut self.inner {
            EngineKind::Live(live) => live.zeroize_and_free(ptr, bytes),
            EngineKind::Simulated(sim) => sim.zeroize_and_free(ptr, bytes),
        }
    }

    /// Drop the device context and every outstanding allocation, then open a
    /// fresh one. Models a helper-process restart: generation advances and
    /// previously issued device pointers are invalid.
    pub fn restart(&mut self) -> Result<u64, ControlError> {
        match &mut self.inner {
            EngineKind::Live(live) => live.restart(),
            EngineKind::Simulated(sim) => {
                sim.restart();
                Ok(sim.generation)
            }
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

// ---- simulated CUDA (source tests; never a hardware PASS) -------------------

#[derive(Debug)]
struct SimulatedCuda {
    identity: CudaDeviceIdentity,
    generation: u64,
    next_ptr: u64,
    memory: HashMap<u64, Vec<u8>>,
    ptx_loaded: bool,
}

impl SimulatedCuda {
    fn new(identity: CudaDeviceIdentity, generation: u64) -> Self {
        Self {
            identity,
            generation: generation.max(1),
            next_ptr: 0x1000,
            memory: HashMap::new(),
            ptx_loaded: false,
        }
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
        let memory = self.memory.get_mut(&ptr).ok_or_else(|| {
            gpu_error(
                sequence,
                "CUDA device pointer is unknown in this helper generation",
            )
        })?;
        let start = usize::try_from(offset).map_err(|_| {
            GpuError::new(
                ErrorCode::OutOfBounds,
                Some(sequence),
                "CUDA copy offset does not fit this provider's address space",
            )
        })?;
        let end = start.checked_add(len).ok_or_else(|| {
            GpuError::new(
                ErrorCode::OutOfBounds,
                Some(sequence),
                "CUDA copy range overflows",
            )
        })?;
        if end > memory.len() {
            return Err(GpuError::new(
                ErrorCode::OutOfBounds,
                Some(sequence),
                "CUDA copy exceeds the device allocation",
            ));
        }
        Ok(&mut memory[start..end])
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

    fn region(&self, addr: u64, len: usize, sequence: u64) -> Result<&[u8], GpuError> {
        for (ptr, memory) in &self.memory {
            if addr >= *ptr {
                let start = (addr - *ptr) as usize;
                if start.saturating_add(len) <= memory.len() {
                    return Ok(&memory[start..start + len]);
                }
            }
        }
        Err(gpu_error(
            sequence,
            "CUDA device pointer is unknown in this helper generation",
        ))
    }

    fn region_mut(&mut self, addr: u64, len: usize, sequence: u64) -> Result<&mut [u8], GpuError> {
        let hit = self.memory.iter().find_map(|(ptr, memory)| {
            if addr >= *ptr {
                let start = (addr - *ptr) as usize;
                if start.saturating_add(len) <= memory.len() {
                    Some(*ptr)
                } else {
                    None
                }
            } else {
                None
            }
        });
        let ptr = hit.ok_or_else(|| {
            gpu_error(
                sequence,
                "CUDA device pointer is unknown in this helper generation",
            )
        })?;
        let start = (addr - ptr) as usize;
        Ok(&mut self.memory.get_mut(&ptr).expect("ptr")[start..start + len])
    }

    fn launch_vector_add(
        &mut self,
        lhs: u64,
        rhs: u64,
        output: u64,
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
        let bytes = (elements as usize).saturating_mul(4);
        let started = Instant::now();
        let lhs_bytes = self.region(lhs, bytes, sequence)?.to_vec();
        let rhs_bytes = self.region(rhs, bytes, sequence)?.to_vec();
        let mut result = Vec::with_capacity(bytes);
        for (a, b) in lhs_bytes.chunks(4).zip(rhs_bytes.chunks(4)) {
            let a = f32::from_le_bytes(a.try_into().expect("four-byte chunk"));
            let b = f32::from_le_bytes(b.try_into().expect("four-byte chunk"));
            result.extend_from_slice(&(a + b).to_le_bytes());
        }
        self.region_mut(output, bytes, sequence)?
            .copy_from_slice(&result);
        Ok(started.elapsed().as_nanos().min(u64::MAX as u128) as u64)
    }

    fn zeroize_and_free(&mut self, ptr: u64, _bytes: u64) {
        if let Some(mut memory) = self.memory.remove(&ptr) {
            memory.fill(0);
        }
    }

    fn restart(&mut self) {
        for (_, mut memory) in self.memory.drain() {
            memory.fill(0);
        }
        self.ptx_loaded = false;
        self.next_ptr = 0x1000;
        self.generation = self.generation.saturating_add(1).max(1);
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
}

// The CUDA driver handle is process-local. `&mut self` serializes calls and
// `make_current` binds the live context to every OS thread before it enters
// the driver, so moving a provider future between Tokio workers is safe.
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
        })
    }

    fn alloc(&mut self, bytes: u64, sequence: u64) -> Result<u64, GpuError> {
        self.make_current(sequence)?;
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
        self.make_current(sequence)?;
        check_gpu(
            unsafe {
                (self.fns.cu_memcpy_htod)(
                    ptr.saturating_add(offset),
                    data.as_ptr() as *const c_void,
                    data.len(),
                )
            },
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
        self.make_current(sequence)?;
        let mut host = vec![0u8; len];
        check_gpu(
            unsafe {
                (self.fns.cu_memcpy_dtoh)(
                    host.as_mut_ptr() as *mut c_void,
                    ptr.saturating_add(offset),
                    len,
                )
            },
            "cuMemcpyDtoH",
            sequence,
            &self.fns,
        )?;
        Ok(host)
    }

    fn load_ptx(&mut self, ptx: &[u8], sequence: u64) -> Result<(), GpuError> {
        self.make_current(sequence)?;
        if ptx != VECTOR_ADD_PTX.as_bytes() {
            return Err(GpuError::new(
                ErrorCode::WorkloadMismatch,
                Some(sequence),
                "CUDA executor only admits the checked-in vector-add PTX",
            ));
        }
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

    fn launch_vector_add(
        &mut self,
        lhs: u64,
        rhs: u64,
        output: u64,
        elements: u32,
        sequence: u64,
    ) -> Result<u64, GpuError> {
        self.make_current(sequence)?;
        if self.function.is_null() {
            return Err(GpuError::new(
                ErrorCode::WorkloadMismatch,
                Some(sequence),
                "CUDA module was not loaded in this helper generation",
            ));
        }
        let started = Instant::now();
        let mut lhs = lhs;
        let mut rhs = rhs;
        let mut output = output;
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
        Ok(started.elapsed().as_nanos().min(u64::MAX as u128) as u64)
    }

    fn zeroize_and_free(&mut self, ptr: u64, bytes: u64) {
        if self.context.is_null()
            || unsafe { (self.fns.cu_ctx_set_current)(self.context) } != CUDA_SUCCESS
        {
            return;
        }
        if bytes > 0 {
            let _ = unsafe { (self.fns.cu_memset_d8)(ptr, 0, bytes as usize) };
        }
        let _ = unsafe { (self.fns.cu_mem_free)(ptr) };
        if let Some(size) = self.live_ptrs.remove(&ptr) {
            self.outstanding_bytes = self.outstanding_bytes.saturating_sub(size);
        }
    }

    fn restart(&mut self) -> Result<u64, ControlError> {
        if !self.context.is_null() {
            check_ctrl(
                unsafe { (self.fns.cu_ctx_set_current)(self.context) },
                "cuCtxSetCurrent",
                &self.fns,
            )?;
        }
        for (ptr, bytes) in self.live_ptrs.drain().collect::<Vec<_>>() {
            self.outstanding_bytes = 0;
            let _ = unsafe { (self.fns.cu_memset_d8)(ptr, 0, bytes as usize) };
            let _ = unsafe { (self.fns.cu_mem_free)(ptr) };
        }
        self.outstanding_bytes = 0;
        self.module = ptr::null_mut();
        self.function = ptr::null_mut();
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
        self.context = context;
        self.generation = self.generation.saturating_add(1).max(1);
        Ok(self.generation)
    }

    fn make_current(&self, sequence: u64) -> Result<(), GpuError> {
        if self.context.is_null() {
            return Err(gpu_error(sequence, "CUDA context is not available"));
        }
        check_gpu(
            unsafe { (self.fns.cu_ctx_set_current)(self.context) },
            "cuCtxSetCurrent",
            sequence,
            &self.fns,
        )
    }
}

impl Drop for LiveCuda {
    fn drop(&mut self) {
        if !self.context.is_null() {
            let _ = unsafe { (self.fns.cu_ctx_set_current)(self.context) };
        }
        for (ptr, bytes) in self.live_ptrs.drain() {
            let _ = unsafe { (self.fns.cu_memset_d8)(ptr, 0, bytes as usize) };
            let _ = unsafe { (self.fns.cu_mem_free)(ptr) };
        }
        if !self.context.is_null() {
            let _ = unsafe { (self.fns.cu_ctx_destroy)(self.context) };
        }
        if !self.handle.is_null() {
            unsafe { close_library(self.handle) };
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
    #[cfg(unix)]
    let names = ["libcuda.so.1", "libcuda.so", "libcuda.dylib"];
    #[cfg(windows)]
    let names = ["nvcuda.dll"];
    let mut last = "libcuda was not found".to_owned();
    for name in names {
        let cname = CString::new(name).expect("lib name");
        let handle = unsafe { open_library(&cname) };
        if handle.is_null() {
            last = library_error(name);
            continue;
        }
        match unsafe { load_fns(handle) } {
            Ok(fns) => return Ok((handle, fns)),
            Err(error) => {
                unsafe { close_library(handle) };
                return Err(error);
            }
        }
    }
    Err(ControlError::new(
        ControlErrorCode::Unavailable,
        format!("NVIDIA CUDA driver API is unavailable ({last})"),
    ))
}

unsafe fn load_fns(handle: *mut c_void) -> Result<CudaFns, ControlError> {
    unsafe fn sym<T>(handle: *mut c_void, name: &str) -> Result<T, ControlError> {
        let cname = CString::new(name).expect("symbol");
        clear_library_error();
        let ptr = library_symbol(handle, &cname);
        if ptr.is_null() {
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

#[cfg(unix)]
unsafe fn open_library(name: &CStr) -> *mut c_void {
    libc::dlopen(name.as_ptr(), libc::RTLD_NOW)
}

#[cfg(windows)]
unsafe fn open_library(name: &CStr) -> *mut c_void {
    LoadLibraryA(name.as_ptr().cast())
}

#[cfg(unix)]
unsafe fn close_library(handle: *mut c_void) {
    libc::dlclose(handle);
}

#[cfg(windows)]
unsafe fn close_library(handle: *mut c_void) {
    FreeLibrary(handle);
}

#[cfg(unix)]
unsafe fn library_symbol(handle: *mut c_void, name: &CStr) -> *mut c_void {
    libc::dlsym(handle, name.as_ptr())
}

#[cfg(windows)]
unsafe fn library_symbol(handle: *mut c_void, name: &CStr) -> *mut c_void {
    GetProcAddress(handle, name.as_ptr().cast())
}

#[cfg(unix)]
unsafe fn clear_library_error() {
    libc::dlerror();
}

#[cfg(windows)]
unsafe fn clear_library_error() {}

#[cfg(unix)]
fn library_error(name: &str) -> String {
    unsafe {
        let error = libc::dlerror();
        if error.is_null() {
            format!("{name} could not be loaded")
        } else {
            CStr::from_ptr(error).to_string_lossy().into_owned()
        }
    }
}

#[cfg(windows)]
fn library_error(name: &str) -> String {
    format!(
        "{name} could not be loaded: {}",
        std::io::Error::last_os_error()
    )
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

/// Refuse a live-NVIDIA claim from anything except a loaded driver context.
pub fn hardware_pass_allowed(engine: Option<&CudaEngine>) -> bool {
    engine.map(CudaEngine::is_live_nvidia).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simulated_executor_is_cuda_but_not_a_hardware_pass() {
        let engine = CudaEngine::simulated(CudaDeviceIdentity::simulated_l4(), 1).unwrap();
        assert!(!engine.is_live_nvidia());
        assert!(!hardware_pass_allowed(Some(&engine)));
        assert_eq!(engine.identity().compute_capability, (8, 9));
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
    fn live_driver_source_rebinds_context_before_every_execution_entrypoint() {
        // Source-only regression: CI has no NVIDIA hardware and this test
        // deliberately makes no execution claim. It prevents removing the
        // per-OS-thread binding from alloc/copy/module/launch operations.
        let source = include_str!("remote_gpu_cuda.rs");
        let implementation = source.split("#[cfg(test)]").next().unwrap();
        assert_eq!(
            implementation
                .matches("self.make_current(sequence)?;")
                .count(),
            5
        );
        assert!(source.contains("cu_ctx_set_current: sym(handle, \"cuCtxSetCurrent\")?"));
        assert!(source.contains("moving a provider future between Tokio workers is safe"));
    }

    #[test]
    fn restart_zeroizes_and_invalidates_old_pointers() {
        let mut engine = CudaEngine::simulated(CudaDeviceIdentity::simulated_l4(), 3).unwrap();
        let ptr = engine.alloc(8, 1).unwrap();
        engine.write(ptr, 0, &[1, 2, 3, 4, 5, 6, 7, 8], 1).unwrap();
        assert_eq!(engine.outstanding_device_bytes(), 8);
        let generation = engine.restart().unwrap();
        assert_eq!(generation, 4);
        assert_eq!(engine.outstanding_device_bytes(), 0);
        let error = engine.read(ptr, 0, 8, 2).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidRequest);
    }
}
