use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::sync::OnceLock;

pub type ClInt = isize;
pub type ClUint = u32;
pub type ClUlong = u64;

pub const CL_DEVICE_TYPE_GPU: ClUlong = 1 << 2;
pub const CL_DEVICE_NAME: ClUint = 0x102B;
pub const CL_DEVICE_GLOBAL_MEM_SIZE: ClUint = 0x101F;
pub const CL_DEVICE_MAX_COMPUTE_UNITS: ClUint = 0x1002;
pub const CL_PLATFORM_NAME: ClUint = 0x0902;
pub const CL_MEM_READ_WRITE: ClUlong = 1 << 0;
pub const CL_MEM_WRITE_ONLY: ClUlong = 1 << 1;
pub const CL_MEM_READ_ONLY: ClUlong = 1 << 2;
pub const CL_MEM_COPY_HOST_PTR: ClUlong = 1 << 5;
pub const CL_PROGRAM_BUILD_LOG: ClUint = 0x1114;

type PfnClGetPlatformIDs = unsafe extern "C" fn(ClUint, *mut *mut c_void, *mut ClUint) -> ClInt;
type PfnClGetPlatformInfo = unsafe extern "C" fn(*mut c_void, ClUint, usize, *mut c_void, *mut usize) -> ClInt;
type PfnClGetDeviceIDs = unsafe extern "C" fn(*mut c_void, ClUlong, ClUint, *mut *mut c_void, *mut ClUint) -> ClInt;
type PfnClGetDeviceInfo = unsafe extern "C" fn(*mut c_void, ClUint, usize, *mut c_void, *mut usize) -> ClInt;
type PfnClCreateContext = unsafe extern "C" fn(*const c_void, ClUint, *const *mut c_void, *const c_void, *const c_void, *mut ClInt) -> *mut c_void;
type PfnClCreateCommandQueue = unsafe extern "C" fn(*mut c_void, *mut c_void, ClUlong, *mut ClInt) -> *mut c_void;
type PfnClCreateProgramWithSource = unsafe extern "C" fn(*mut c_void, ClUint, *const *const c_char, *const usize, *mut ClInt) -> *mut c_void;
type PfnClBuildProgram = unsafe extern "C" fn(*mut c_void, ClUint, *const *mut c_void, *const c_char, *const c_void, *const c_void) -> ClInt;
type PfnClGetProgramBuildInfo = unsafe extern "C" fn(*mut c_void, *mut c_void, ClUint, usize, *mut c_void, *mut usize) -> ClInt;
type PfnClCreateKernel = unsafe extern "C" fn(*mut c_void, *const c_char, *mut ClInt) -> *mut c_void;
type PfnClCreateBuffer = unsafe extern "C" fn(*mut c_void, ClUlong, usize, *mut c_void, *mut ClInt) -> *mut c_void;
type PfnClSetKernelArg = unsafe extern "C" fn(*mut c_void, ClUint, usize, *const c_void) -> ClInt;
type PfnClEnqueueNDRangeKernel = unsafe extern "C" fn(*mut c_void, *mut c_void, ClUint, *const usize, *const usize, *const usize, ClUint, *const c_void, *mut c_void) -> ClInt;
type PfnClEnqueueWriteBuffer = unsafe extern "C" fn(*mut c_void, *mut c_void, ClUint, usize, usize, *const c_void, ClUint, *const c_void, *mut c_void) -> ClInt;
type PfnClEnqueueReadBuffer = unsafe extern "C" fn(*mut c_void, *mut c_void, ClUint, usize, usize, *mut c_void, ClUint, *const c_void, *mut c_void) -> ClInt;
type PfnClFinish = unsafe extern "C" fn(*mut c_void) -> ClInt;
type PfnClReleaseMemObject = unsafe extern "C" fn(*mut c_void) -> ClInt;
type PfnClReleaseKernel = unsafe extern "C" fn(*mut c_void) -> ClInt;
type PfnClReleaseProgram = unsafe extern "C" fn(*mut c_void) -> ClInt;
type PfnClReleaseCommandQueue = unsafe extern "C" fn(*mut c_void) -> ClInt;
type PfnClReleaseContext = unsafe extern "C" fn(*mut c_void) -> ClInt;

#[derive(Clone)]
pub struct OpenClLib {
    cl_get_platform_ids: PfnClGetPlatformIDs,
    cl_get_platform_info: PfnClGetPlatformInfo,
    cl_get_device_ids: PfnClGetDeviceIDs,
    cl_get_device_info: PfnClGetDeviceInfo,
    cl_create_context: PfnClCreateContext,
    cl_create_command_queue: PfnClCreateCommandQueue,
    cl_create_program_with_source: PfnClCreateProgramWithSource,
    cl_build_program: PfnClBuildProgram,
    cl_get_program_build_info: PfnClGetProgramBuildInfo,
    cl_create_kernel: PfnClCreateKernel,
    cl_create_buffer: PfnClCreateBuffer,
    cl_set_kernel_arg: PfnClSetKernelArg,
    cl_enqueue_nd_range_kernel: PfnClEnqueueNDRangeKernel,
    cl_enqueue_write_buffer: PfnClEnqueueWriteBuffer,
    cl_enqueue_read_buffer: PfnClEnqueueReadBuffer,
    cl_finish: PfnClFinish,
    cl_release_mem_object: PfnClReleaseMemObject,
    cl_release_kernel: PfnClReleaseKernel,
    cl_release_program: PfnClReleaseProgram,
    cl_release_command_queue: PfnClReleaseCommandQueue,
    cl_release_context: PfnClReleaseContext,
}

unsafe impl Send for OpenClLib {}
unsafe impl Sync for OpenClLib {}

static OPENCL_LIB: OnceLock<Option<OpenClLib>> = OnceLock::new();

pub fn get_opencl_lib() -> Option<&'static OpenClLib> {
    OPENCL_LIB.get_or_init(|| {
        #[cfg(target_os = "windows")]
        let lib_names = ["OpenCL.dll"];
        #[cfg(target_os = "macos")]
        let lib_names = ["/System/Library/Frameworks/OpenCL.framework/OpenCL", "libOpenCL.dylib"];
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        let lib_names = ["libOpenCL.so.1", "libOpenCL.so", "libnvidia-opencl.so.1"];

        for &name in &lib_names {
            let c_name = CString::new(name).unwrap();
            let handle = unsafe { libc::dlopen(c_name.as_ptr(), libc::RTLD_NOW) };
            if !handle.is_null() {
                unsafe {
                    macro_rules! load_sym {
                        ($sym:ident, $type:ty) => {{
                            let s_name = CString::new(stringify!($sym)).unwrap();
                            let p = libc::dlsym(handle, s_name.as_ptr());
                            if p.is_null() {
                                return None;
                            }
                            std::mem::transmute::<*mut c_void, $type>(p)
                        }};
                    }

                    return Some(OpenClLib {
                        cl_get_platform_ids: load_sym!(clGetPlatformIDs, PfnClGetPlatformIDs),
                        cl_get_platform_info: load_sym!(clGetPlatformInfo, PfnClGetPlatformInfo),
                        cl_get_device_ids: load_sym!(clGetDeviceIDs, PfnClGetDeviceIDs),
                        cl_get_device_info: load_sym!(clGetDeviceInfo, PfnClGetDeviceInfo),
                        cl_create_context: load_sym!(clCreateContext, PfnClCreateContext),
                        cl_create_command_queue: load_sym!(clCreateCommandQueue, PfnClCreateCommandQueue),
                        cl_create_program_with_source: load_sym!(clCreateProgramWithSource, PfnClCreateProgramWithSource),
                        cl_build_program: load_sym!(clBuildProgram, PfnClBuildProgram),
                        cl_get_program_build_info: load_sym!(clGetProgramBuildInfo, PfnClGetProgramBuildInfo),
                        cl_create_kernel: load_sym!(clCreateKernel, PfnClCreateKernel),
                        cl_create_buffer: load_sym!(clCreateBuffer, PfnClCreateBuffer),
                        cl_set_kernel_arg: load_sym!(clSetKernelArg, PfnClSetKernelArg),
                        cl_enqueue_nd_range_kernel: load_sym!(clEnqueueNDRangeKernel, PfnClEnqueueNDRangeKernel),
                        cl_enqueue_write_buffer: load_sym!(clEnqueueWriteBuffer, PfnClEnqueueWriteBuffer),
                        cl_enqueue_read_buffer: load_sym!(clEnqueueReadBuffer, PfnClEnqueueReadBuffer),
                        cl_finish: load_sym!(clFinish, PfnClFinish),
                        cl_release_mem_object: load_sym!(clReleaseMemObject, PfnClReleaseMemObject),
                        cl_release_kernel: load_sym!(clReleaseKernel, PfnClReleaseKernel),
                        cl_release_program: load_sym!(clReleaseProgram, PfnClReleaseProgram),
                        cl_release_command_queue: load_sym!(clReleaseCommandQueue, PfnClReleaseCommandQueue),
                        cl_release_context: load_sym!(clReleaseContext, PfnClReleaseContext),
                    });
                }
            }
        }
        None
    }).as_ref()
}

#[derive(Clone, Debug)]
pub struct OpenClDeviceInfo {
    pub platform_idx: usize,
    pub device_idx: usize,
    pub platform_id: usize,
    pub device_id: usize,
    pub platform_name: String,
    pub device_name: String,
    pub total_mem_bytes: usize,
    pub compute_units: u32,
}

pub fn get_opencl_devices() -> Vec<OpenClDeviceInfo> {
    let cl = match get_opencl_lib() {
        Some(lib) => lib,
        None => return Vec::new(),
    };

    let mut devices_list = Vec::new();
    unsafe {
        let mut num_platforms: ClUint = 0;
        if (cl.cl_get_platform_ids)(0, std::ptr::null_mut(), &mut num_platforms) != 0 || num_platforms == 0 {
            return devices_list;
        }

        let mut platforms = vec![std::ptr::null_mut(); num_platforms as usize];
        (cl.cl_get_platform_ids)(num_platforms, platforms.as_mut_ptr(), std::ptr::null_mut());

        for (p_idx, &p) in platforms.iter().enumerate() {
            let mut p_name_buf = [0i8; 256];
            (cl.cl_get_platform_info)(p, CL_PLATFORM_NAME, p_name_buf.len(), p_name_buf.as_mut_ptr() as *mut c_void, std::ptr::null_mut());
            let p_name = CStr::from_ptr(p_name_buf.as_ptr()).to_string_lossy().into_owned();

            let mut num_devices: ClUint = 0;
            if (cl.cl_get_device_ids)(p, CL_DEVICE_TYPE_GPU, 0, std::ptr::null_mut(), &mut num_devices) == 0 && num_devices > 0 {
                let mut devs = vec![std::ptr::null_mut(); num_devices as usize];
                (cl.cl_get_device_ids)(p, CL_DEVICE_TYPE_GPU, num_devices, devs.as_mut_ptr(), std::ptr::null_mut());

                for (d_idx, &d) in devs.iter().enumerate() {
                    let mut d_name_buf = [0i8; 256];
                    (cl.cl_get_device_info)(d, CL_DEVICE_NAME, d_name_buf.len(), d_name_buf.as_mut_ptr() as *mut c_void, std::ptr::null_mut());
                    let d_name = CStr::from_ptr(d_name_buf.as_ptr()).to_string_lossy().into_owned();

                    let mut mem_size: ClUlong = 0;
                    (cl.cl_get_device_info)(d, CL_DEVICE_GLOBAL_MEM_SIZE, 8, &mut mem_size as *mut _ as *mut c_void, std::ptr::null_mut());

                    let mut cu: ClUint = 0;
                    (cl.cl_get_device_info)(d, CL_DEVICE_MAX_COMPUTE_UNITS, 4, &mut cu as *mut _ as *mut c_void, std::ptr::null_mut());

                    devices_list.push(OpenClDeviceInfo {
                        platform_idx: p_idx,
                        device_idx: d_idx,
                        platform_id: p as usize,
                        device_id: d as usize,
                        platform_name: p_name.clone(),
                        device_name: d_name,
                        total_mem_bytes: mem_size as usize,
                        compute_units: cu,
                    });
                }
            }
        }
    }
    devices_list
}

pub static OPENCL_SOURCE: &str = include_str!("opencl_kernel.cl");

pub struct OpenClWorker {
    cl: OpenClLib,
    context: *mut c_void,
    queue: *mut c_void,
    program: *mut c_void,
    kernel: *mut c_void,
    total_threads: usize,
    nonces_per_thread: usize,

    d_prefix: *mut c_void,
    d_suffix: *mut c_void,
    d_seed: *mut c_void,
    d_scratchpads: *mut c_void,
    d_found_count: *mut c_void,
    d_found_nonces: *mut c_void,

    last_prefix: Vec<u8>,
    last_suffix: Vec<u8>,
    last_seed: Vec<u8>,
}

unsafe impl Send for OpenClWorker {}
unsafe impl Sync for OpenClWorker {}

impl OpenClWorker {
    pub fn new(device_info: &OpenClDeviceInfo, total_threads: usize, nonces_per_thread: usize) -> Result<Self, String> {
        let cl = get_opencl_lib().ok_or_else(|| "OpenCL library could not be loaded".to_string())?.clone();
        let device = device_info.device_id as *mut c_void;

        unsafe {
            let mut err: ClInt = 0;
            let context = (cl.cl_create_context)(std::ptr::null(), 1, &device, std::ptr::null(), std::ptr::null(), &mut err);
            if err != 0 || context.is_null() {
                return Err(format!("clCreateContext failed: {}", err));
            }

            let queue = (cl.cl_create_command_queue)(context, device, 0, &mut err);
            if err != 0 || queue.is_null() {
                (cl.cl_release_context)(context);
                return Err(format!("clCreateCommandQueue failed: {}", err));
            }

            let src_c = CString::new(OPENCL_SOURCE).unwrap();
            let src_ptr = src_c.as_ptr();
            let src_len = src_c.as_bytes().len();

            let program = (cl.cl_create_program_with_source)(context, 1, &src_ptr, &src_len, &mut err);
            if err != 0 || program.is_null() {
                (cl.cl_release_command_queue)(queue);
                (cl.cl_release_context)(context);
                return Err(format!("clCreateProgramWithSource failed: {}", err));
            }

            let build_err = (cl.cl_build_program)(program, 1, &device, std::ptr::null(), std::ptr::null(), std::ptr::null());
            if build_err != 0 {
                let mut log_len: usize = 0;
                (cl.cl_get_program_build_info)(program, device, CL_PROGRAM_BUILD_LOG, 0, std::ptr::null_mut(), &mut log_len);
                let mut log = vec![0u8; log_len];
                (cl.cl_get_program_build_info)(program, device, CL_PROGRAM_BUILD_LOG, log_len, log.as_mut_ptr() as *mut c_void, std::ptr::null_mut());
                let log_str = String::from_utf8_lossy(&log).into_owned();
                (cl.cl_release_program)(program);
                (cl.cl_release_command_queue)(queue);
                (cl.cl_release_context)(context);
                return Err(format!("clBuildProgram failed: {}\nLog: {}", build_err, log_str));
            }

            let k_name = CString::new("cortex_opencl_mine").unwrap();
            let kernel = (cl.cl_create_kernel)(program, k_name.as_ptr(), &mut err);
            if err != 0 || kernel.is_null() {
                (cl.cl_release_program)(program);
                (cl.cl_release_command_queue)(queue);
                (cl.cl_release_context)(context);
                return Err(format!("clCreateKernel cortex_opencl_mine failed: {}", err));
            }

            // Allocate buffers
            let d_prefix = (cl.cl_create_buffer)(context, CL_MEM_READ_ONLY, 512, std::ptr::null_mut(), &mut err);
            let d_suffix = (cl.cl_create_buffer)(context, CL_MEM_READ_ONLY, 512, std::ptr::null_mut(), &mut err);
            let d_seed = (cl.cl_create_buffer)(context, CL_MEM_READ_ONLY, 256, std::ptr::null_mut(), &mut err);

            // Scratchpads: total_threads * 4096 * 8 bytes
            let sp_bytes = total_threads * 4096 * 8;
            let d_scratchpads = (cl.cl_create_buffer)(context, CL_MEM_READ_WRITE, sp_bytes, std::ptr::null_mut(), &mut err);
            let d_found_count = (cl.cl_create_buffer)(context, CL_MEM_READ_WRITE, 4, std::ptr::null_mut(), &mut err);
            let d_found_nonces = (cl.cl_create_buffer)(context, CL_MEM_WRITE_ONLY, 32 * 8, std::ptr::null_mut(), &mut err);

            if d_scratchpads.is_null() || d_found_count.is_null() || d_found_nonces.is_null() {
                return Err("Failed to allocate OpenCL GPU VRAM buffers".to_string());
            }

            Ok(Self {
                cl,
                context,
                queue,
                program,
                kernel,
                total_threads,
                nonces_per_thread,
                d_prefix,
                d_suffix,
                d_seed,
                d_scratchpads,
                d_found_count,
                d_found_nonces,
                last_prefix: Vec::new(),
                last_suffix: Vec::new(),
                last_seed: Vec::new(),
            })
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
        let cl = &self.cl;
        unsafe {
            if self.last_prefix.as_slice() != prefix {
                (cl.cl_enqueue_write_buffer)(self.queue, self.d_prefix, 0, 0, prefix.len(), prefix.as_ptr() as *const c_void, 0, std::ptr::null(), std::ptr::null_mut());
                self.last_prefix = prefix.to_vec();
            }
            if self.last_suffix.as_slice() != suffix {
                (cl.cl_enqueue_write_buffer)(self.queue, self.d_suffix, 0, 0, suffix.len(), suffix.as_ptr() as *const c_void, 0, std::ptr::null(), std::ptr::null_mut());
                self.last_suffix = suffix.to_vec();
            }
            if self.last_seed.as_slice() != seed {
                (cl.cl_enqueue_write_buffer)(self.queue, self.d_seed, 0, 0, seed.len(), seed.as_ptr() as *const c_void, 0, std::ptr::null(), std::ptr::null_mut());
                self.last_seed = seed.to_vec();
            }

            // Reset found_count
            let zero_count: i32 = 0;
            (cl.cl_enqueue_write_buffer)(self.queue, self.d_found_count, 0, 0, 4, &zero_count as *const _ as *const c_void, 0, std::ptr::null(), std::ptr::null_mut());

            let p_len = prefix.len() as i32;
            let s_len = suffix.len() as i32;
            let sd_len = seed.len() as i32;
            let t_diff = target_diff as i32;
            let t_u64 = target_u64;
            let b_nonce = base_nonce;
            let n_per_t = self.nonces_per_thread as i32;

            (cl.cl_set_kernel_arg)(self.kernel, 0, 8, &self.d_prefix as *const _ as *const c_void);
            (cl.cl_set_kernel_arg)(self.kernel, 1, 4, &p_len as *const _ as *const c_void);
            (cl.cl_set_kernel_arg)(self.kernel, 2, 8, &self.d_suffix as *const _ as *const c_void);
            (cl.cl_set_kernel_arg)(self.kernel, 3, 4, &s_len as *const _ as *const c_void);
            (cl.cl_set_kernel_arg)(self.kernel, 4, 8, &self.d_seed as *const _ as *const c_void);
            (cl.cl_set_kernel_arg)(self.kernel, 5, 4, &sd_len as *const _ as *const c_void);
            (cl.cl_set_kernel_arg)(self.kernel, 6, 4, &t_diff as *const _ as *const c_void);
            (cl.cl_set_kernel_arg)(self.kernel, 7, 8, &t_u64 as *const _ as *const c_void);
            (cl.cl_set_kernel_arg)(self.kernel, 8, 8, &b_nonce as *const _ as *const c_void);
            (cl.cl_set_kernel_arg)(self.kernel, 9, 4, &n_per_t as *const _ as *const c_void);
            (cl.cl_set_kernel_arg)(self.kernel, 10, 8, &self.d_scratchpads as *const _ as *const c_void);
            (cl.cl_set_kernel_arg)(self.kernel, 11, 8, &self.d_found_count as *const _ as *const c_void);
            (cl.cl_set_kernel_arg)(self.kernel, 12, 8, &self.d_found_nonces as *const _ as *const c_void);

            let global_work = self.total_threads;
            let err = (cl.cl_enqueue_nd_range_kernel)(self.queue, self.kernel, 1, std::ptr::null(), &global_work, std::ptr::null(), 0, std::ptr::null(), std::ptr::null_mut());
            if err != 0 {
                return Err(format!("clEnqueueNDRangeKernel error: {}", err));
            }

            let mut h_count: i32 = 0;
            (cl.cl_enqueue_read_buffer)(self.queue, self.d_found_count, 1, 0, 4, &mut h_count as *mut _ as *mut c_void, 0, std::ptr::null(), std::ptr::null_mut());

            let mut found_nonces = Vec::new();
            if h_count > 0 {
                let copy_count = (h_count as usize).min(32);
                let mut nonces_buf = [0u64; 32];
                (cl.cl_enqueue_read_buffer)(self.queue, self.d_found_nonces, 1, 0, copy_count * 8, nonces_buf.as_mut_ptr() as *mut c_void, 0, std::ptr::null(), std::ptr::null_mut());
                for i in 0..copy_count {
                    found_nonces.push(nonces_buf[i]);
                }
            }

            let hashes_done = (self.total_threads * self.nonces_per_thread) as u64;
            Ok((found_nonces, hashes_done))
        }
    }
}

impl Drop for OpenClWorker {
    fn drop(&mut self) {
        let cl = &self.cl;
        unsafe {
            (cl.cl_finish)(self.queue);
            (cl.cl_release_mem_object)(self.d_prefix);
            (cl.cl_release_mem_object)(self.d_suffix);
            (cl.cl_release_mem_object)(self.d_seed);
            (cl.cl_release_mem_object)(self.d_scratchpads);
            (cl.cl_release_mem_object)(self.d_found_count);
            (cl.cl_release_mem_object)(self.d_found_nonces);
            (cl.cl_release_kernel)(self.kernel);
            (cl.cl_release_program)(self.program);
            (cl.cl_release_command_queue)(self.queue);
            (cl.cl_release_context)(self.context);
        }
    }
}

pub fn opencl_self_test(device_info: &OpenClDeviceInfo) -> bool {
    let cl = match get_opencl_lib() {
        Some(lib) => lib,
        None => return false,
    };
    let device = device_info.device_id as *mut c_void;

    unsafe {
        let mut err: ClInt = 0;
        let context = (cl.cl_create_context)(std::ptr::null(), 1, &device, std::ptr::null(), std::ptr::null(), &mut err);
        if err != 0 || context.is_null() { return false; }

        let queue = (cl.cl_create_command_queue)(context, device, 0, &mut err);
        if err != 0 || queue.is_null() {
            (cl.cl_release_context)(context);
            return false;
        }

        let src_c = CString::new(OPENCL_SOURCE).unwrap();
        let src_ptr = src_c.as_ptr();
        let src_len = src_c.as_bytes().len();

        let program = (cl.cl_create_program_with_source)(context, 1, &src_ptr, &src_len, &mut err);
        if err != 0 || program.is_null() {
            (cl.cl_release_command_queue)(queue);
            (cl.cl_release_context)(context);
            return false;
        }

        if (cl.cl_build_program)(program, 1, &device, std::ptr::null(), std::ptr::null(), std::ptr::null()) != 0 {
            (cl.cl_release_program)(program);
            (cl.cl_release_command_queue)(queue);
            (cl.cl_release_context)(context);
            return false;
        }

        let k_name = CString::new("test_opencl_single_hash").unwrap();
        let kernel = (cl.cl_create_kernel)(program, k_name.as_ptr(), &mut err);
        if err != 0 || kernel.is_null() {
            (cl.cl_release_program)(program);
            (cl.cl_release_command_queue)(queue);
            (cl.cl_release_context)(context);
            return false;
        }

        let seed = b"cortex-randomx-genesis-seed-v1";
        let d_seed = (cl.cl_create_buffer)(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, seed.len(), seed.as_ptr() as *mut c_void, &mut err);
        let d_sp = (cl.cl_create_buffer)(context, CL_MEM_READ_WRITE, 4096 * 8, std::ptr::null_mut(), &mut err);
        let d_out = (cl.cl_create_buffer)(context, CL_MEM_WRITE_ONLY, 32, std::ptr::null_mut(), &mut err);

        // Vector 123
        let hdr123 = b"test_header_123";
        let d_hdr123 = (cl.cl_create_buffer)(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, hdr123.len(), hdr123.as_ptr() as *mut c_void, &mut err);

        let h123_len = hdr123.len() as i32;
        let s_len = seed.len() as i32;
        (cl.cl_set_kernel_arg)(kernel, 0, 8, &d_hdr123 as *const _ as *const c_void);
        (cl.cl_set_kernel_arg)(kernel, 1, 4, &h123_len as *const _ as *const c_void);
        (cl.cl_set_kernel_arg)(kernel, 2, 8, &d_seed as *const _ as *const c_void);
        (cl.cl_set_kernel_arg)(kernel, 3, 4, &s_len as *const _ as *const c_void);
        (cl.cl_set_kernel_arg)(kernel, 4, 8, &d_sp as *const _ as *const c_void);
        (cl.cl_set_kernel_arg)(kernel, 5, 8, &d_out as *const _ as *const c_void);

        let work: usize = 1;
        (cl.cl_enqueue_nd_range_kernel)(queue, kernel, 1, std::ptr::null(), &work, std::ptr::null(), 0, std::ptr::null(), std::ptr::null_mut());
        let mut res123 = [0u8; 32];
        (cl.cl_enqueue_read_buffer)(queue, d_out, 1, 0, 32, res123.as_mut_ptr() as *mut c_void, 0, std::ptr::null(), std::ptr::null_mut());

        let exp123 = hex::decode("b1b9599c0a73a84c5777369c3a2af50e78cc63b6e0c22c30f191c98fc06316a5").unwrap();
        if res123 != exp123.as_slice() {
            return false;
        }

        // Vector 99999
        let hdr99k = b"test_header_99999";
        let d_hdr99k = (cl.cl_create_buffer)(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, hdr99k.len(), hdr99k.as_ptr() as *mut c_void, &mut err);
        let h99k_len = hdr99k.len() as i32;
        (cl.cl_set_kernel_arg)(kernel, 0, 8, &d_hdr99k as *const _ as *const c_void);
        (cl.cl_set_kernel_arg)(kernel, 1, 4, &h99k_len as *const _ as *const c_void);

        (cl.cl_enqueue_nd_range_kernel)(queue, kernel, 1, std::ptr::null(), &work, std::ptr::null(), 0, std::ptr::null(), std::ptr::null_mut());
        let mut res99k = [0u8; 32];
        (cl.cl_enqueue_read_buffer)(queue, d_out, 1, 0, 32, res99k.as_mut_ptr() as *mut c_void, 0, std::ptr::null(), std::ptr::null_mut());

        let exp99k = hex::decode("912f8cb7ed73773658af2f4212aa40bb365d1a5a208eb09cd66e567b3cf70a5c").unwrap();

        (cl.cl_release_mem_object)(d_hdr123);
        (cl.cl_release_mem_object)(d_hdr99k);
        (cl.cl_release_mem_object)(d_seed);
        (cl.cl_release_mem_object)(d_sp);
        (cl.cl_release_mem_object)(d_out);
        (cl.cl_release_kernel)(kernel);
        (cl.cl_release_program)(program);
        (cl.cl_release_command_queue)(queue);
        (cl.cl_release_context)(context);

        res99k == exp99k.as_slice()
    }
}
