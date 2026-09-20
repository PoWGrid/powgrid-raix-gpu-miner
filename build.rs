use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(has_cuda)");
    println!("cargo:rerun-if-changed=cuda_bridge/cortex_cuda_bridge.cu");
    println!("cargo:rerun-if-changed=cuda_bridge/cortex_cuda_bridge.h");
    println!("cargo:rerun-if-changed=cuda_bridge/k256.cuh");
    println!("cargo:rerun-if-changed=cuda_bridge/k512.cuh");
    println!("cargo:rerun-if-changed=cuda_bridge/aes256.cuh");
    println!("cargo:rerun-if-changed=src/opencl_kernel.cl");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Check if nvcc is available
    let nvcc_check = Command::new("nvcc").arg("--version").output();
    let has_nvcc = match nvcc_check {
        Ok(out) => out.status.success(),
        Err(_) => false,
    };

    if has_nvcc {
        println!("cargo:rustc-cfg=has_cuda");
        let cu_file = "cuda_bridge/cortex_cuda_bridge.cu";
        let obj_file = out_dir.join("cortex_cuda_bridge.o");
        let lib_file = out_dir.join("libcortex_cuda.a");

        let status = Command::new("nvcc")
            .arg("-O3")
            .arg("-gencode").arg("arch=compute_75,code=sm_75")
            .arg("-gencode").arg("arch=compute_80,code=sm_80")
            .arg("-gencode").arg("arch=compute_86,code=sm_86")
            .arg("-gencode").arg("arch=compute_89,code=sm_89")
            .arg("-gencode").arg("arch=compute_89,code=compute_89")
            .arg("-Xcompiler")
            .arg("-fPIC")
            .arg("-c")
            .arg(cu_file)
            .arg("-o")
            .arg(&obj_file)
            .status()
            .expect("Failed to execute nvcc");

        if !status.success() {
            panic!("nvcc failed to compile cortex_cuda_bridge.cu");
        }

        let ar_status = Command::new("ar")
            .arg("rcs")
            .arg(&lib_file)
            .arg(&obj_file)
            .status()
            .expect("Failed to execute ar");

        if !ar_status.success() {
            panic!("ar failed to create libcortex_cuda.a");
        }

        println!("cargo:rustc-link-search=native={}", out_dir.display());
        println!("cargo:rustc-link-lib=static=cortex_cuda");
        println!("cargo:rustc-link-search=native=/usr/lib/x86_64-linux-gnu");
        println!("cargo:rustc-link-lib=cudart");
    } else {
        println!("cargo:warning=nvcc compiler not found. Compiling with universal OpenCL backend.");
    }
}
