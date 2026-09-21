use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct CudaDeviceInfo {
    pub device_id: i32,
    pub name: String,
    pub total_mem_bytes: usize,
    pub sm_count: i32,
    pub major: i32,
    pub minor: i32,
}

#[cfg(has_cuda)]
extern "C" {
    fn cuda_bridge_get_device_count() -> c_int;
    fn cuda_bridge_get_device_info(
        device_id: c_int,
        name_out: *mut c_char,
        name_len: usize,
        total_mem: *mut usize,
        sm_count: *mut c_int,
        major: *mut c_int,
        minor: *mut c_int,
    ) -> c_int;
    fn cuda_bridge_worker_create(device_id: c_int, total_threads: c_int, nonces_per_thread: c_int) -> *mut c_void;
    fn cuda_bridge_worker_destroy(handle: *mut c_void);
    fn cuda_bridge_worker_run_batch(
        handle: *mut c_void,
        prefix: *const c_char,
        prefix_len: c_int,
        suffix: *const c_char,
        suffix_len: c_int,
        seed: *const c_char,
        seed_len: c_int,
        target_u64: u64,
        target_diff: c_int,
        base_nonce: u64,
        found_nonces_out: *mut u64,
        max_found: c_int,
        found_count_out: *mut c_int,
        hashes_done_out: *mut u64,
    ) -> c_int;
    fn cuda_bridge_self_test(device_id: c_int) -> c_int;
}

pub fn get_cuda_devices() -> Vec<CudaDeviceInfo> {
    #[cfg(has_cuda)]
    unsafe {
        let count = cuda_bridge_get_device_count();
        let mut list = Vec::new();
        for i in 0..count {
            let mut name_buf = [0i8; 256];
            let mut total_mem: usize = 0;
            let mut sm_count: c_int = 0;
            let mut major: c_int = 0;
            let mut minor: c_int = 0;

            if cuda_bridge_get_device_info(
                i,
                name_buf.as_mut_ptr(),
                name_buf.len(),
                &mut total_mem,
                &mut sm_count,
                &mut major,
                &mut minor,
            ) == 0 {
                let name = CStr::from_ptr(name_buf.as_ptr())
                    .to_string_lossy()
                    .into_owned();
                list.push(CudaDeviceInfo {
                    device_id: i,
                    name,
                    total_mem_bytes: total_mem,
                    sm_count,
                    major,
                    minor,
                });
            }
        }
        list
    }
    #[cfg(not(has_cuda))]
    {
        Vec::new()
    }
}

pub fn cuda_self_test(device_id: i32) -> bool {
    #[cfg(has_cuda)]
    unsafe {
        cuda_bridge_self_test(device_id) == 1
    }
    #[cfg(not(has_cuda))]
    {
        let _ = device_id;
        false
    }
}

pub struct CudaWorker {
    #[cfg(has_cuda)]
    handle: *mut c_void,
    #[cfg(not(has_cuda))]
    _unused: (),
}

unsafe impl Send for CudaWorker {}
unsafe impl Sync for CudaWorker {}

impl CudaWorker {
    pub fn new(device_id: i32, total_threads: i32, nonces_per_thread: i32) -> Result<Self, String> {
        #[cfg(has_cuda)]
        unsafe {
            let handle = cuda_bridge_worker_create(device_id, total_threads, nonces_per_thread);
            if handle.is_null() {
                return Err(format!("Failed to initialize CUDA worker for device {}", device_id));
            }
            Ok(Self { handle })
        }
        #[cfg(not(has_cuda))]
        {
            let _ = (device_id, total_threads, nonces_per_thread);
            Err("CUDA backend is not compiled in this binary".to_string())
        }
    }

    pub fn run_batch(
        &mut self,
        prefix: &[u8],
        suffix: &[u8],
        seed: &[u8],
        target_u64: u64,
        target_diff: usize,
        base_nonce: u64,
    ) -> Result<(Vec<u64>, u64), String> {
        #[cfg(has_cuda)]
        unsafe {
            let mut found_buf = [0u64; 32];
            let mut found_count: c_int = 0;
            let mut hashes_done: u64 = 0;

            let res = cuda_bridge_worker_run_batch(
                self.handle,
                prefix.as_ptr() as *const c_char,
                prefix.len() as c_int,
                suffix.as_ptr() as *const c_char,
                suffix.len() as c_int,
                seed.as_ptr() as *const c_char,
                seed.len() as c_int,
                target_u64,
                target_diff as c_int,
                base_nonce,
                found_buf.as_mut_ptr(),
                32,
                &mut found_count,
                &mut hashes_done,
            );

            if res != 0 {
                return Err("CUDA kernel execution error".to_string());
            }

            let mut found_nonces = Vec::with_capacity(found_count as usize);
            for i in 0..(found_count as usize) {
                found_nonces.push(found_buf[i]);
            }
            Ok((found_nonces, hashes_done))
        }
        #[cfg(not(has_cuda))]
        {
            let _ = (prefix, suffix, seed, target_u64, target_diff, base_nonce);
            Err("CUDA backend not available".to_string())
        }
    }
}

#[cfg(has_cuda)]
impl Drop for CudaWorker {
    fn drop(&mut self) {
        unsafe {
            if !self.handle.is_null() {
                cuda_bridge_worker_destroy(self.handle);
            }
        }
    }
}
