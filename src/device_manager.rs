use crate::cuda_backend::{self, CudaDeviceInfo, CudaWorker};
use crate::opencl_backend::{self, OpenClDeviceInfo, OpenClWorker};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BackendType {
    Auto,
    Cuda,
    OpenCl,
}

#[derive(Clone, Debug)]
pub enum AssignedBackend {
    Cuda(CudaDeviceInfo),
    OpenCl(OpenClDeviceInfo),
}

#[derive(Clone, Debug)]
pub struct UnifiedGpuDevice {
    pub id: usize,
    pub name: String,
    pub backend_name: &'static str,
    pub vram_mb: usize,
    pub compute_units: u32,
    pub assigned: AssignedBackend,
}

pub struct DeviceManager;

impl DeviceManager {
    pub fn discover_devices(preferred: BackendType) -> Vec<UnifiedGpuDevice> {
        let cuda_devices = if preferred != BackendType::OpenCl {
            cuda_backend::get_cuda_devices()
        } else {
            Vec::new()
        };

        let opencl_devices = if preferred != BackendType::Cuda {
            opencl_backend::get_opencl_devices()
        } else {
            Vec::new()
        };

        let mut unified_list = Vec::new();
        let mut id_counter = 0;

        // 1. Assign NVIDIA devices to CUDA if available
        for dev in cuda_devices {
            unified_list.push(UnifiedGpuDevice {
                id: id_counter,
                name: dev.name.clone(),
                backend_name: "CUDA (Native Warp)",
                vram_mb: dev.total_mem_bytes / (1024 * 1024),
                compute_units: dev.sm_count as u32,
                assigned: AssignedBackend::Cuda(dev),
            });
            id_counter += 1;
        }

        // 2. Assign OpenCL devices (if not already handled by CUDA)
        for ocl_dev in opencl_devices {
            let is_nvidia = ocl_dev.platform_name.to_lowercase().contains("nvidia")
                || ocl_dev.device_name.to_lowercase().contains("geforce")
                || ocl_dev.device_name.to_lowercase().contains("rtx")
                || ocl_dev.device_name.to_lowercase().contains("gtx")
                || ocl_dev.device_name.to_lowercase().contains("quadro")
                || ocl_dev.device_name.to_lowercase().contains("tesla");

            // If we already have CUDA active for NVIDIA, don't duplicate device via OpenCL
            if is_nvidia && preferred != BackendType::OpenCl && !unified_list.is_empty() {
                continue;
            }

            unified_list.push(UnifiedGpuDevice {
                id: id_counter,
                name: ocl_dev.device_name.clone(),
                backend_name: "OpenCL (Universal JIT)",
                vram_mb: ocl_dev.total_mem_bytes / (1024 * 1024),
                compute_units: ocl_dev.compute_units,
                assigned: AssignedBackend::OpenCl(ocl_dev),
            });
            id_counter += 1;
        }

        unified_list
    }

    pub fn run_self_test(device: &UnifiedGpuDevice) -> bool {
        match &device.assigned {
            AssignedBackend::Cuda(dev) => cuda_backend::cuda_self_test(dev.device_id),
            AssignedBackend::OpenCl(dev) => opencl_backend::opencl_self_test(dev),
        }
    }
}

pub enum ActiveGpuWorker {
    Cuda(CudaWorker),
    OpenCl(OpenClWorker),
}

impl ActiveGpuWorker {
    pub fn new(device: &UnifiedGpuDevice, batch_size: usize, nonces_per_thread: usize) -> Result<Self, String> {
        match &device.assigned {
            AssignedBackend::Cuda(c_dev) => {
                let worker = CudaWorker::new(c_dev.device_id, batch_size as i32, nonces_per_thread as i32)?;
                Ok(Self::Cuda(worker))
            }
            AssignedBackend::OpenCl(o_dev) => {
                let worker = OpenClWorker::new(o_dev, batch_size, nonces_per_thread)?;
                Ok(Self::OpenCl(worker))
            }
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
        match self {
            Self::Cuda(w) => w.run_batch(prefix, suffix, seed, target_u64, target_diff, base_nonce),
            Self::OpenCl(w) => w.run_batch(prefix, suffix, seed, target_u64, target_diff, base_nonce),
        }
    }
}
