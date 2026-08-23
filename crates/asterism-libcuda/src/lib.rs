//! Generated CUDA Driver ABI. Unmodified CUDA applications resolve this
//! crate as `libcuda.so.1`. Calls outside the supported matrix return
//! `CUDA_ERROR_NOT_SUPPORTED`. The shim talks only to the projected local
//! `/dev/nvidia0` endpoint and carries CUDA-semantic frames to `astd`.

use std::collections::HashMap;
use std::ffi::{c_char, c_void, CStr};
use std::path::Path;
use std::ptr;
use std::sync::Mutex;

use asterism_core::remote_gpu_guest::{
    self as guest, CudaCall, CudaDriverSymbol, CudaResult, GuestReply, GuestShim,
    CUDA_ERROR_INVALID_DEVICE, CUDA_ERROR_INVALID_VALUE, CUDA_ERROR_NOT_INITIALIZED,
    CUDA_ERROR_NOT_SUPPORTED, CUDA_SUCCESS, GUEST_DEVICE_PATH,
};

struct ShimState {
    shim: GuestShim,
    allocations: HashMap<u64, String>,
    next_handle: u64,
    workload_pin: Option<String>,
}

impl ShimState {
    fn allocation(&self, handle: u64) -> Result<String, i32> {
        self.allocations
            .get(&handle)
            .cloned()
            .ok_or(guest::CUDA_ERROR_NOT_FOUND)
    }
}

static SHIM: Mutex<Option<ShimState>> = Mutex::new(None);

fn device_path() -> &'static Path {
    Path::new(GUEST_DEVICE_PATH)
}

fn with_state<F>(body: F) -> i32
where
    F: FnOnce(&mut ShimState) -> i32,
{
    let mut guard = match SHIM.lock() {
        Ok(guard) => guard,
        Err(_) => return CUDA_ERROR_NOT_INITIALIZED,
    };
    match guard.as_mut() {
        Some(state) => body(state),
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

#[no_mangle]
pub extern "C" fn cuInit(_flags: u32) -> i32 {
    let mut guard = match SHIM.lock() {
        Ok(guard) => guard,
        Err(_) => return CUDA_ERROR_NOT_INITIALIZED,
    };
    match GuestShim::connect(device_path()) {
        Ok(mut shim) => match shim.open() {
            Ok(GuestReply::Accepted { .. }) => match shim.call(CudaCall::Init) {
                Ok(CudaResult::Init) => {
                    *guard = Some(ShimState {
                        shim,
                        allocations: HashMap::new(),
                        next_handle: 0,
                        workload_pin: None,
                    });
                    CUDA_SUCCESS
                }
                _ => CUDA_ERROR_NOT_SUPPORTED,
            },
            _ => CUDA_ERROR_NOT_INITIALIZED,
        },
        Err(_) => CUDA_ERROR_NOT_INITIALIZED,
    }
}

#[no_mangle]
pub extern "C" fn cuDeviceGetCount(count: *mut i32) -> i32 {
    if count.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    with_state(|state| match state.shim.call(CudaCall::DeviceCount) {
        Ok(CudaResult::DeviceCount { count: n }) => {
            unsafe { *count = n as i32 };
            CUDA_SUCCESS
        }
        other => result_code(other),
    })
}

#[no_mangle]
pub extern "C" fn cuDeviceGet(device: *mut i32, ordinal: i32) -> i32 {
    if device.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    if ordinal != 0 {
        return CUDA_ERROR_INVALID_DEVICE;
    }
    unsafe { *device = 0 };
    CUDA_SUCCESS
}

#[no_mangle]
pub extern "C" fn cuCtxCreate(context: *mut *mut c_void, _flags: u32, device: i32) -> i32 {
    if context.is_null() || device != 0 {
        return CUDA_ERROR_INVALID_VALUE;
    }
    unsafe { *context = 1usize as *mut c_void };
    CUDA_SUCCESS
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
                state.next_handle = match state.next_handle.checked_add(1) {
                    Some(handle) => handle,
                    None => return CUDA_ERROR_NOT_SUPPORTED,
                };
                state.allocations.insert(state.next_handle, allocation);
                unsafe { *dev_ptr = state.next_handle };
                CUDA_SUCCESS
            }
            other => result_code(other),
        }
    })
}

#[no_mangle]
pub extern "C" fn cuMemcpyHtoD(destination: u64, source: *const c_void, bytes: usize) -> i32 {
    if source.is_null() || bytes == 0 {
        return CUDA_ERROR_INVALID_VALUE;
    }
    with_state(|state| {
        let allocation = match state.allocation(destination) {
            Ok(allocation) => allocation,
            Err(code) => return code,
        };
        let data = unsafe { std::slice::from_raw_parts(source as *const u8, bytes) }.to_vec();
        result_code(state.shim.call(CudaCall::MemcpyHtoD {
            allocation,
            offset: 0,
            data,
        }))
    })
}

#[no_mangle]
pub extern "C" fn cuMemcpyDtoH(destination: *mut c_void, source: u64, bytes: usize) -> i32 {
    if destination.is_null() || bytes == 0 {
        return CUDA_ERROR_INVALID_VALUE;
    }
    with_state(|state| {
        let allocation = match state.allocation(source) {
            Ok(allocation) => allocation,
            Err(code) => return code,
        };
        match state.shim.call(CudaCall::MemcpyDtoH {
            allocation,
            offset: 0,
            bytes: bytes as u64,
        }) {
            Ok(CudaResult::Data { data }) if data.len() == bytes => {
                unsafe { ptr::copy_nonoverlapping(data.as_ptr(), destination as *mut u8, bytes) };
                CUDA_SUCCESS
            }
            Ok(CudaResult::Error { cuda, .. }) => cuda,
            _ => CUDA_ERROR_NOT_SUPPORTED,
        }
    })
}

#[no_mangle]
pub extern "C" fn cuModuleLoadData(module: *mut *mut c_void, image: *const c_void) -> i32 {
    if module.is_null() || image.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    let image = unsafe { CStr::from_ptr(image as *const c_char) }
        .to_bytes()
        .to_vec();
    with_state(
        |state| match state.shim.call(CudaCall::ModuleLoadData { image }) {
            Ok(CudaResult::Module { pin }) => {
                state.workload_pin = Some(pin);
                unsafe { *module = 2usize as *mut c_void };
                CUDA_SUCCESS
            }
            other => result_code(other),
        },
    )
}

#[no_mangle]
pub extern "C" fn cuModuleGetFunction(
    function: *mut *mut c_void,
    module: *mut c_void,
    name: *const c_char,
) -> i32 {
    if function.is_null() || module.is_null() || name.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    if unsafe { CStr::from_ptr(name) }.to_bytes() != b"vector_add_f32" {
        return CUDA_ERROR_NOT_SUPPORTED;
    }
    unsafe { *function = 3usize as *mut c_void };
    CUDA_SUCCESS
}

#[no_mangle]
pub extern "C" fn cuLaunchKernel(
    function: *mut c_void,
    _grid_x: u32,
    _grid_y: u32,
    _grid_z: u32,
    _block_x: u32,
    _block_y: u32,
    _block_z: u32,
    _shared: u32,
    _stream: *mut c_void,
    params: *mut *mut c_void,
    _extra: *mut *mut c_void,
) -> i32 {
    if function.is_null() || params.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    let args = unsafe { std::slice::from_raw_parts(params, 4) };
    if args.iter().any(|arg| arg.is_null()) {
        return CUDA_ERROR_INVALID_VALUE;
    }
    let lhs = unsafe { *(args[0] as *const u64) };
    let rhs = unsafe { *(args[1] as *const u64) };
    let output = unsafe { *(args[2] as *const u64) };
    let elements = unsafe { *(args[3] as *const u32) } as u64;
    with_state(|state| {
        let lhs = match state.allocation(lhs) {
            Ok(value) => value,
            Err(code) => return code,
        };
        let rhs = match state.allocation(rhs) {
            Ok(value) => value,
            Err(code) => return code,
        };
        let output = match state.allocation(output) {
            Ok(value) => value,
            Err(code) => return code,
        };
        let workload_pin = match state.workload_pin.clone() {
            Some(pin) => pin,
            None => return CUDA_ERROR_NOT_INITIALIZED,
        };
        result_code(state.shim.call(CudaCall::LaunchVectorAdd {
            workload_pin,
            lhs,
            rhs,
            output,
            elements,
        }))
    })
}

#[no_mangle]
pub extern "C" fn cuCtxSynchronize() -> i32 {
    with_state(|state| result_code(state.shim.call(CudaCall::Synchronize)))
}

#[no_mangle]
pub extern "C" fn cuMemFree(handle: u64) -> i32 {
    with_state(|state| {
        let allocation = match state.allocations.remove(&handle) {
            Some(allocation) => allocation,
            None => return guest::CUDA_ERROR_NOT_FOUND,
        };
        result_code(state.shim.call(CudaCall::MemFree { allocation }))
    })
}

#[no_mangle]
pub extern "C" fn cuMemAllocManaged(_dev_ptr: *mut u64, _bytes: usize, _flags: u32) -> i32 {
    let _ = CudaDriverSymbol::CuMemAlloc;
    CUDA_ERROR_NOT_SUPPORTED
}

#[no_mangle]
pub extern "C" fn cuGetErrorName(code: i32, name: *mut *const i8) -> i32 {
    if name.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    let text: &'static [u8] = match code {
        CUDA_SUCCESS => b"CUDA_SUCCESS\0",
        CUDA_ERROR_INVALID_VALUE => b"CUDA_ERROR_INVALID_VALUE\0",
        CUDA_ERROR_INVALID_DEVICE => b"CUDA_ERROR_INVALID_DEVICE\0",
        CUDA_ERROR_NOT_INITIALIZED => b"CUDA_ERROR_NOT_INITIALIZED\0",
        CUDA_ERROR_NOT_SUPPORTED => b"CUDA_ERROR_NOT_SUPPORTED\0",
        _ => b"CUDA_ERROR_UNKNOWN\0",
    };
    unsafe { *name = text.as_ptr() as *const i8 };
    CUDA_SUCCESS
}

#[no_mangle]
pub extern "C" fn cuGetErrorString(code: i32, text: *mut *const i8) -> i32 {
    cuGetErrorName(code, text)
}
