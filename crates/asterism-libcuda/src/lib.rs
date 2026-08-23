//! Generated CUDA Driver ABI. An unmodified CUDA application resolves this
//! crate as `libcuda.so.1`. The export matrix is exactly
//! [`asterism_core::remote_gpu_guest::SUPPORTED_CUDA_DRIVER_SYMBOLS`].
//! Calls outside that matrix return `CUDA_ERROR_NOT_SUPPORTED`. The shim
//! talks to the projected `/dev/nvidia0` endpoint; it never opens a LAN
//! listener and never puts a lease bearer in argv, environment, or logs.

use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_uint, c_void, CStr};
use std::path::Path;
use std::sync::{Arc, Mutex};

use asterism_core::remote_gpu_guest::{
    self as guest, CudaCall, CudaResult, GuestShim, CUDA_DRIVER_VERSION, CUDA_ERROR_INVALID_VALUE,
    CUDA_ERROR_NOT_INITIALIZED, CUDA_ERROR_NOT_SUPPORTED, CUDA_SUCCESS, GUEST_DEVICE_PATH,
};

/// Exact export names matching [`SUPPORTED_CUDA_DRIVER_SYMBOLS`].
pub const EXPORTED_CUDA_DRIVER_SYMBOLS: &[&str] = &[
    "cuInit",
    "cuDriverGetVersion",
    "cuDeviceGetCount",
    "cuDeviceGet",
    "cuDeviceGetName",
    "cuDeviceGetUuid",
    "cuDeviceGetAttribute",
    "cuCtxCreate",
    "cuCtxDestroy",
    "cuCtxGetCurrent",
    "cuCtxSetCurrent",
    "cuCtxSynchronize",
    "cuMemAlloc",
    "cuMemFree",
    "cuMemcpyHtoD",
    "cuMemcpyDtoH",
    "cuModuleLoadData",
    "cuModuleUnload",
    "cuModuleGetFunction",
    "cuLaunchKernel",
    "cuGetErrorString",
    "cuGetErrorName",
    // CUDA's v2 ABI names are what current headers resolve for the six
    // pointer-sized/context entrypoints. Keep their legacy aliases too.
    "cuCtxCreate_v2",
    "cuCtxDestroy_v2",
    "cuMemAlloc_v2",
    "cuMemFree_v2",
    "cuMemcpyHtoD_v2",
    "cuMemcpyDtoH_v2",
];

struct State {
    shim: Arc<GuestShim>,
    mutable: Mutex<MutableState>,
}

struct MutableState {
    ptrs: HashMap<u64, String>,
    next_ptr: u64,
    modules: HashMap<u64, String>,
    next_module: u64,
    functions: HashMap<u64, String>,
    next_function: u64,
    last_pin: Option<String>,
}

static STATE: Mutex<Option<Arc<State>>> = Mutex::new(None);

fn device_path() -> &'static Path {
    Path::new(GUEST_DEVICE_PATH)
}

fn with_state<F>(body: F) -> i32
where
    F: FnOnce(&State) -> i32,
{
    let state = match STATE.lock() {
        Ok(guard) => guard,
        Err(_) => return CUDA_ERROR_NOT_INITIALIZED,
    }
    .as_ref()
    .cloned();
    match state {
        Some(state) => body(&state),
        None => CUDA_ERROR_NOT_INITIALIZED,
    }
}

fn result_code(result: Result<CudaResult, guest::GuestError>) -> i32 {
    match result {
        Ok(CudaResult::Error { cuda, .. }) => cuda,
        Ok(_) => CUDA_SUCCESS,
        Err(_) => CUDA_ERROR_NOT_SUPPORTED,
    }
}

fn intern_ptr(state: &mut MutableState, allocation: String) -> u64 {
    let ptr = state.next_ptr.max(1);
    state.next_ptr = ptr.saturating_add(16);
    state.ptrs.insert(ptr, allocation);
    ptr
}

#[no_mangle]
pub extern "C" fn cuInit(_flags: c_uint) -> i32 {
    let mut guard = match STATE.lock() {
        Ok(guard) => guard,
        Err(_) => return CUDA_ERROR_NOT_INITIALIZED,
    };
    match GuestShim::connect(device_path()) {
        Ok(mut shim) => match shim.open() {
            Ok(_) => match shim.call(CudaCall::Init) {
                Ok(_) => {
                    *guard = Some(Arc::new(State {
                        shim: Arc::new(shim),
                        mutable: Mutex::new(MutableState {
                            ptrs: HashMap::new(),
                            next_ptr: 0x1000,
                            modules: HashMap::new(),
                            next_module: 1,
                            functions: HashMap::new(),
                            next_function: 1,
                            last_pin: None,
                        }),
                    }));
                    CUDA_SUCCESS
                }
                Err(_) => CUDA_ERROR_NOT_SUPPORTED,
            },
            Err(_) => CUDA_ERROR_NOT_INITIALIZED,
        },
        Err(_) => CUDA_ERROR_NOT_INITIALIZED,
    }
}

#[no_mangle]
pub extern "C" fn cuDriverGetVersion(version: *mut c_int) -> i32 {
    if version.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    with_state(|state| match state.shim.call(CudaCall::DriverGetVersion) {
        Ok(CudaResult::DriverVersion { version: n }) => {
            unsafe {
                *version = n;
            }
            CUDA_SUCCESS
        }
        Ok(_) => {
            unsafe {
                *version = CUDA_DRIVER_VERSION;
            }
            CUDA_SUCCESS
        }
        other => result_code(other),
    })
}

#[no_mangle]
pub extern "C" fn cuDeviceGetCount(count: *mut c_int) -> i32 {
    if count.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    with_state(|state| match state.shim.call(CudaCall::DeviceCount) {
        Ok(CudaResult::DeviceCount { count: n }) => {
            unsafe {
                *count = n as c_int;
            }
            CUDA_SUCCESS
        }
        other => result_code(other),
    })
}

#[no_mangle]
pub extern "C" fn cuDeviceGet(device: *mut c_int, ordinal: c_int) -> i32 {
    if device.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    with_state(|state| {
        match state.shim.call(CudaCall::DeviceGet {
            ordinal: ordinal as u32,
        }) {
            Ok(CudaResult::Device { ordinal }) => {
                unsafe {
                    *device = ordinal as c_int;
                }
                CUDA_SUCCESS
            }
            other => result_code(other),
        }
    })
}

#[no_mangle]
pub extern "C" fn cuDeviceGetName(name: *mut c_char, len: c_int, device: c_int) -> i32 {
    if name.is_null() || len <= 0 {
        return CUDA_ERROR_INVALID_VALUE;
    }
    with_state(|state| {
        match state.shim.call(CudaCall::DeviceName {
            ordinal: device as u32,
        }) {
            Ok(CudaResult::DeviceName { name: text }) => {
                let bytes = text.as_bytes();
                let n = (len as usize).saturating_sub(1).min(bytes.len());
                unsafe {
                    std::ptr::copy_nonoverlapping(bytes.as_ptr(), name as *mut u8, n);
                    *name.add(n) = 0;
                }
                CUDA_SUCCESS
            }
            other => result_code(other),
        }
    })
}

#[no_mangle]
pub extern "C" fn cuDeviceGetUuid(uuid: *mut u8, device: c_int) -> i32 {
    if uuid.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    with_state(|state| {
        match state.shim.call(CudaCall::DeviceUuid {
            ordinal: device as u32,
        }) {
            Ok(CudaResult::DeviceUuid { uuid: text }) => {
                let bytes = guest::uuid_bytes_from_text(&text);
                unsafe {
                    std::ptr::copy_nonoverlapping(bytes.as_ptr(), uuid, 16);
                }
                CUDA_SUCCESS
            }
            other => result_code(other),
        }
    })
}

#[no_mangle]
pub extern "C" fn cuDeviceGetAttribute(pi: *mut c_int, attrib: c_int, device: c_int) -> i32 {
    if pi.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    with_state(|state| {
        match state.shim.call(CudaCall::DeviceAttribute {
            ordinal: device as u32,
            attribute: attrib.to_string(),
        }) {
            Ok(CudaResult::DeviceAttribute { value }) => {
                unsafe {
                    *pi = value;
                }
                CUDA_SUCCESS
            }
            other => result_code(other),
        }
    })
}

#[no_mangle]
pub extern "C" fn cuCtxCreate(pctx: *mut u64, flags: c_uint, device: c_int) -> i32 {
    if pctx.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    with_state(|state| {
        match state.shim.call(CudaCall::CtxCreate {
            flags,
            device: device as u32,
        }) {
            Ok(CudaResult::Context { context }) => {
                unsafe {
                    *pctx = context;
                }
                CUDA_SUCCESS
            }
            other => result_code(other),
        }
    })
}

#[no_mangle]
pub extern "C" fn cuCtxDestroy(ctx: u64) -> i32 {
    with_state(|state| result_code(state.shim.call(CudaCall::CtxDestroy { context: ctx })))
}

#[no_mangle]
pub extern "C" fn cuCtxGetCurrent(pctx: *mut u64) -> i32 {
    if pctx.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    with_state(|state| match state.shim.call(CudaCall::CtxGetCurrent) {
        Ok(CudaResult::CurrentContext { context }) => {
            unsafe {
                *pctx = context;
            }
            CUDA_SUCCESS
        }
        other => result_code(other),
    })
}

#[no_mangle]
pub extern "C" fn cuCtxSetCurrent(ctx: u64) -> i32 {
    with_state(|state| result_code(state.shim.call(CudaCall::CtxSetCurrent { context: ctx })))
}

#[no_mangle]
pub extern "C" fn cuCtxSynchronize() -> i32 {
    with_state(|state| result_code(state.shim.call(CudaCall::CtxSynchronize)))
}

#[no_mangle]
pub extern "C" fn cuMemAlloc(dev_ptr: *mut u64, bytes: usize) -> i32 {
    if dev_ptr.is_null() || bytes == 0 {
        return CUDA_ERROR_INVALID_VALUE;
    }
    with_state(|state| {
        match state.shim.call(CudaCall::MemAlloc {
            bytes: bytes as u64,
        }) {
            Ok(CudaResult::Alloc { allocation }) => {
                let mut mutable = match state.mutable.lock() {
                    Ok(mutable) => mutable,
                    Err(_) => return CUDA_ERROR_NOT_INITIALIZED,
                };
                let ptr = intern_ptr(&mut mutable, allocation);
                unsafe {
                    *dev_ptr = ptr;
                }
                CUDA_SUCCESS
            }
            other => result_code(other),
        }
    })
}

#[no_mangle]
pub extern "C" fn cuMemFree(dev_ptr: u64) -> i32 {
    with_state(|state| {
        let allocation = match state.mutable.lock() {
            Ok(mutable) => mutable.ptrs.get(&dev_ptr).cloned(),
            Err(_) => return CUDA_ERROR_NOT_INITIALIZED,
        };
        let Some(allocation) = allocation else {
            return CUDA_ERROR_INVALID_VALUE;
        };
        let result = state.shim.call(CudaCall::MemFree { allocation });
        if result.is_ok() {
            if let Ok(mut mutable) = state.mutable.lock() {
                mutable.ptrs.remove(&dev_ptr);
            }
        }
        result_code(result)
    })
}

#[no_mangle]
pub extern "C" fn cuMemcpyHtoD(dst: u64, src: *const c_void, bytes: usize) -> i32 {
    if src.is_null() || bytes == 0 {
        return CUDA_ERROR_INVALID_VALUE;
    }
    with_state(|state| {
        let allocation = match state.mutable.lock() {
            Ok(mutable) => mutable.ptrs.get(&dst).cloned(),
            Err(_) => return CUDA_ERROR_NOT_INITIALIZED,
        };
        let Some(allocation) = allocation else {
            return CUDA_ERROR_INVALID_VALUE;
        };
        let data = unsafe { std::slice::from_raw_parts(src as *const u8, bytes) }.to_vec();
        result_code(state.shim.call(CudaCall::MemcpyHtoD {
            allocation,
            offset: 0,
            data,
        }))
    })
}

#[no_mangle]
pub extern "C" fn cuMemcpyDtoH(dst: *mut c_void, src: u64, bytes: usize) -> i32 {
    if dst.is_null() || bytes == 0 {
        return CUDA_ERROR_INVALID_VALUE;
    }
    with_state(|state| {
        let allocation = match state.mutable.lock() {
            Ok(mutable) => mutable.ptrs.get(&src).cloned(),
            Err(_) => return CUDA_ERROR_NOT_INITIALIZED,
        };
        let Some(allocation) = allocation else {
            return CUDA_ERROR_INVALID_VALUE;
        };
        match state.shim.call(CudaCall::MemcpyDtoH {
            allocation,
            offset: 0,
            bytes: bytes as u64,
        }) {
            Ok(CudaResult::Data { data }) => {
                let n = data.len().min(bytes);
                unsafe {
                    std::ptr::copy_nonoverlapping(data.as_ptr(), dst as *mut u8, n);
                }
                CUDA_SUCCESS
            }
            other => result_code(other),
        }
    })
}

#[no_mangle]
pub extern "C" fn cuModuleLoadData(module: *mut u64, image: *const c_void) -> i32 {
    if module.is_null() || image.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    // Validate caller bytes before attempting to open transport state. An
    // unavailable guest endpoint must not hide that an unsupported module
    // would otherwise be substituted or accepted on a later retry.
    let expected = asterism_core::remote_gpu::VECTOR_ADD_PTX.as_bytes();
    // CUDA specifies a NUL-terminated image, but scanning for that NUL makes
    // an attacker-controlled pointer an unbounded read. ABI 1 accepts one
    // pinned PTX image, so inspect exactly that bounded length plus its NUL.
    let candidate = unsafe { std::slice::from_raw_parts(image as *const u8, expected.len() + 1) };
    if candidate[..expected.len()] != *expected || candidate[expected.len()] != 0 {
        return CUDA_ERROR_NOT_SUPPORTED;
    }
    let bytes = expected.to_vec();
    with_state(|state| {
        // ABI 1 accepts exactly the audited, content-pinned PTX program.
        // Never replace caller bytes with a built-in payload: that turns an
        // unsupported module into a different successful program.
        match state.shim.call(CudaCall::ModuleLoadData { image: bytes }) {
            Ok(CudaResult::Module { pin }) => {
                let mut mutable = match state.mutable.lock() {
                    Ok(mutable) => mutable,
                    Err(_) => return CUDA_ERROR_NOT_INITIALIZED,
                };
                let handle = mutable.next_module;
                mutable.next_module = handle.saturating_add(1);
                mutable.modules.insert(handle, pin.clone());
                mutable.last_pin = Some(pin);
                unsafe {
                    *module = handle;
                }
                CUDA_SUCCESS
            }
            other => result_code(other),
        }
    })
}

#[no_mangle]
pub extern "C" fn cuModuleUnload(module: u64) -> i32 {
    with_state(|state| {
        let pin = match state.mutable.lock() {
            Ok(mutable) => mutable.modules.get(&module).cloned(),
            Err(_) => return CUDA_ERROR_NOT_INITIALIZED,
        };
        let Some(pin) = pin else {
            return CUDA_ERROR_INVALID_VALUE;
        };
        let result = state.shim.call(CudaCall::ModuleUnload { module: pin });
        if result.is_ok() {
            if let Ok(mut mutable) = state.mutable.lock() {
                mutable.modules.remove(&module);
            }
        }
        result_code(result)
    })
}

#[no_mangle]
pub extern "C" fn cuModuleGetFunction(func: *mut u64, module: u64, name: *const c_char) -> i32 {
    if func.is_null() || name.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    let name = unsafe { CStr::from_ptr(name) }
        .to_str()
        .unwrap_or("")
        .to_owned();
    with_state(|state| {
        let pin = match state.mutable.lock() {
            Ok(mutable) => mutable.modules.get(&module).cloned(),
            Err(_) => return CUDA_ERROR_NOT_INITIALIZED,
        };
        let Some(pin) = pin else {
            return CUDA_ERROR_INVALID_VALUE;
        };
        match state.shim.call(CudaCall::ModuleGetFunction {
            module: pin,
            name: name.clone(),
        }) {
            Ok(CudaResult::Function { function }) => {
                let mut mutable = match state.mutable.lock() {
                    Ok(mutable) => mutable,
                    Err(_) => return CUDA_ERROR_NOT_INITIALIZED,
                };
                let handle = mutable.next_function;
                mutable.next_function = handle.saturating_add(1);
                mutable.functions.insert(handle, function);
                unsafe {
                    *func = handle;
                }
                CUDA_SUCCESS
            }
            other => result_code(other),
        }
    })
}

#[no_mangle]
pub extern "C" fn cuLaunchKernel(
    func: u64,
    grid_x: c_uint,
    grid_y: c_uint,
    grid_z: c_uint,
    block_x: c_uint,
    block_y: c_uint,
    block_z: c_uint,
    shared_mem: c_uint,
    stream: *mut c_void,
    kernel_params: *mut *mut c_void,
    extra: *mut *mut c_void,
) -> i32 {
    if !stream.is_null() || !extra.is_null() || kernel_params.is_null() {
        return CUDA_ERROR_NOT_SUPPORTED;
    }
    with_state(|state| {
        let params = unsafe { std::slice::from_raw_parts(kernel_params, 4) };
        if params.iter().any(|p| p.is_null()) {
            return CUDA_ERROR_INVALID_VALUE;
        }
        let lhs_ptr = unsafe { *(params[0] as *const u64) };
        let rhs_ptr = unsafe { *(params[1] as *const u64) };
        let out_ptr = unsafe { *(params[2] as *const u64) };
        let elements = unsafe { *(params[3] as *const u32) } as u64;
        let handles = match state.mutable.lock() {
            Ok(mutable) => (
                mutable.functions.get(&func).cloned(),
                mutable.ptrs.get(&lhs_ptr).cloned(),
                mutable.ptrs.get(&rhs_ptr).cloned(),
                mutable.ptrs.get(&out_ptr).cloned(),
                mutable.last_pin.clone(),
            ),
            Err(_) => return CUDA_ERROR_NOT_INITIALIZED,
        };
        let (Some(function), Some(lhs), Some(rhs), Some(output), pin) = handles else {
            return CUDA_ERROR_INVALID_VALUE;
        };
        if function != "vector_add_f32" || shared_mem != 0 {
            return CUDA_ERROR_NOT_SUPPORTED;
        }
        let pin = pin.unwrap_or_default();
        let _ = (grid_x, grid_y, grid_z, block_x, block_y, block_z);
        result_code(state.shim.call(CudaCall::LaunchVectorAdd {
            workload_pin: pin,
            lhs,
            rhs,
            output,
            elements,
        }))
    })
}

#[no_mangle]
pub extern "C" fn cuGetErrorName(code: i32, name: *mut *const c_char) -> i32 {
    if name.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    if !guest::cuda_error_is_named(code) {
        return CUDA_ERROR_INVALID_VALUE;
    }
    let text = guest::cuda_error_name(code);
    unsafe {
        *name = text.as_ptr() as *const c_char;
    }
    CUDA_SUCCESS
}

#[no_mangle]
pub extern "C" fn cuGetErrorString(code: i32, text: *mut *const c_char) -> i32 {
    if text.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    if !guest::cuda_error_is_named(code) {
        return CUDA_ERROR_INVALID_VALUE;
    }
    let body = guest::cuda_error_string(code);
    unsafe {
        *text = body.as_ptr() as *const c_char;
    }
    CUDA_SUCCESS
}

// ABI-compatible CUDA v2 names. These are deliberate exported aliases, not
// new semantic operations, so they remain tied to the audited 22-call matrix.
#[export_name = "cuCtxCreate_v2"]
pub extern "C" fn cu_ctx_create_v2(pctx: *mut u64, flags: c_uint, device: c_int) -> i32 {
    cuCtxCreate(pctx, flags, device)
}

#[export_name = "cuCtxDestroy_v2"]
pub extern "C" fn cu_ctx_destroy_v2(ctx: u64) -> i32 {
    cuCtxDestroy(ctx)
}

#[export_name = "cuMemAlloc_v2"]
pub extern "C" fn cu_mem_alloc_v2(dev_ptr: *mut u64, bytes: usize) -> i32 {
    cuMemAlloc(dev_ptr, bytes)
}

#[export_name = "cuMemFree_v2"]
pub extern "C" fn cu_mem_free_v2(dev_ptr: u64) -> i32 {
    cuMemFree(dev_ptr)
}

#[export_name = "cuMemcpyHtoD_v2"]
pub extern "C" fn cu_memcpy_htod_v2(dst: u64, src: *const c_void, bytes: usize) -> i32 {
    cuMemcpyHtoD(dst, src, bytes)
}

#[export_name = "cuMemcpyDtoH_v2"]
pub extern "C" fn cu_memcpy_dtoh_v2(dst: *mut c_void, src: u64, bytes: usize) -> i32 {
    cuMemcpyDtoH(dst, src, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_matrix_matches_supported_symbols() {
        let supported: Vec<&str> = asterism_core::remote_gpu_guest::SUPPORTED_CUDA_DRIVER_SYMBOLS
            .iter()
            .map(|symbol| symbol.as_str())
            .collect();
        assert_eq!(supported, &EXPORTED_CUDA_DRIVER_SYMBOLS[..supported.len()]);
        assert_eq!(supported.len(), 22);
        assert_eq!(EXPORTED_CUDA_DRIVER_SYMBOLS.len(), 28);
        assert!(!EXPORTED_CUDA_DRIVER_SYMBOLS.contains(&"cuMemAllocManaged"));
    }

    #[test]
    fn error_pointers_are_nul_terminated() {
        let mut name: *const c_char = std::ptr::null();
        assert_eq!(cuGetErrorName(CUDA_SUCCESS, &mut name), CUDA_SUCCESS);
        assert!(!name.is_null());
        let cstr = unsafe { CStr::from_ptr(name) };
        assert_eq!(cstr.to_str().unwrap(), "CUDA_SUCCESS");
        let mut text: *const c_char = std::ptr::null();
        assert_eq!(cuGetErrorString(CUDA_SUCCESS, &mut text), CUDA_SUCCESS);
        assert!(!unsafe { CStr::from_ptr(text) }.to_bytes().is_empty());
        assert_eq!(cuGetErrorName(123456, &mut name), CUDA_ERROR_INVALID_VALUE);
    }

    #[test]
    fn unsupported_module_bytes_are_never_replaced_by_the_pinned_ptx() {
        let image = std::ffi::CString::new(".version 99.0\n.not_the_audited_program").unwrap();
        let mut module = 0u64;
        assert_eq!(
            cuModuleLoadData(&mut module, image.as_ptr().cast()),
            CUDA_ERROR_NOT_SUPPORTED
        );
        assert_eq!(module, 0);
    }

    #[test]
    fn module_validation_is_bounded_and_requires_nul_at_the_exact_pin_length() {
        let mut image = asterism_core::remote_gpu::VECTOR_ADD_PTX
            .as_bytes()
            .to_vec();
        image.push(b'x');
        let mut module = 0u64;
        assert_eq!(
            cuModuleLoadData(&mut module, image.as_ptr().cast()),
            CUDA_ERROR_NOT_SUPPORTED
        );
        assert_eq!(module, 0);
    }
}
