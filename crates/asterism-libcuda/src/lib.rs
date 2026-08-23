//! Generated CUDA Driver ABI. An unmodified CUDA application resolves this
//! crate as `libcuda.so.1`. Calls outside the supported matrix return
//! `CUDA_ERROR_NOT_SUPPORTED`. The shim talks to the projected `/dev/nvidia0`
//! endpoint; it never opens a LAN listener and never puts a lease bearer in
//! argv, environment, or logs.

use std::path::Path;
use std::sync::Mutex;

use asterism_core::remote_gpu_guest::{
    self as guest, CudaCall, CudaDriverSymbol, CudaResult, GuestShim, CUDA_ERROR_NOT_INITIALIZED,
    CUDA_ERROR_NOT_SUPPORTED, CUDA_SUCCESS, GUEST_DEVICE_PATH,
};

static SHIM: Mutex<Option<GuestShim>> = Mutex::new(None);

fn device_path() -> &'static Path {
    Path::new(GUEST_DEVICE_PATH)
}

fn with_shim<F>(body: F) -> i32
where
    F: FnOnce(&mut GuestShim) -> i32,
{
    let mut guard = match SHIM.lock() {
        Ok(guard) => guard,
        Err(_) => return CUDA_ERROR_NOT_INITIALIZED,
    };
    match guard.as_mut() {
        Some(shim) => body(shim),
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
            Ok(_) => match shim.call(CudaCall::Init) {
                Ok(_) => {
                    *guard = Some(shim);
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
pub extern "C" fn cuDeviceGetCount(count: *mut i32) -> i32 {
    if count.is_null() {
        return guest::CUDA_ERROR_INVALID_VALUE;
    }
    with_shim(|shim| match shim.call(CudaCall::DeviceCount) {
        Ok(CudaResult::DeviceCount { count: n }) => {
            unsafe {
                *count = n as i32;
            }
            CUDA_SUCCESS
        }
        other => result_code(other),
    })
}

#[no_mangle]
pub extern "C" fn cuMemAlloc(dev_ptr: *mut u64, bytes: usize) -> i32 {
    if dev_ptr.is_null() || bytes == 0 {
        return guest::CUDA_ERROR_INVALID_VALUE;
    }
    with_shim(|shim| {
        match shim.call(CudaCall::MemAlloc {
            bytes: bytes as u64,
        }) {
            Ok(CudaResult::Alloc { allocation }) => {
                let mut handle = [0u8; 8];
                let bytes = allocation.as_bytes();
                let n = bytes.len().min(8);
                handle[..n].copy_from_slice(&bytes[..n]);
                unsafe {
                    *dev_ptr = u64::from_le_bytes(handle);
                }
                CUDA_SUCCESS
            }
            other => result_code(other),
        }
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
        return guest::CUDA_ERROR_INVALID_VALUE;
    }
    let text = guest::cuda_error_name(code);
    unsafe {
        *name = text.as_ptr() as *const i8;
    }
    CUDA_SUCCESS
}

#[no_mangle]
pub extern "C" fn cuGetErrorString(code: i32, text: *mut *const i8) -> i32 {
    cuGetErrorName(code, text)
}
