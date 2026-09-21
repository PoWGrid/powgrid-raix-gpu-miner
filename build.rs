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
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let is_windows = target_os == "windows";

    // Check if nvcc is available
    let nvcc_check = Command::new("nvcc").arg("--version").output();
    let has_nvcc = match nvcc_check {
        Ok(out) => out.status.success() && (!is_windows || env::var("CUDA_PATH").is_ok()),
        Err(_) => false,
    };

    if has_nvcc {
        println!("cargo:rustc-cfg=has_cuda");
        let cu_file = "cuda_bridge/cortex_cuda_bridge.cu";

        if is_windows {
            let lib_file = out_dir.join("cortex_cuda.lib");
            let mut cmd = Command::new("nvcc");
            cmd.arg("-O3")
                .arg("-lib")
                .arg("-gencode").arg("arch=compute_75,code=sm_75")
                .arg("-gencode").arg("arch=compute_80,code=sm_80")
                .arg("-gencode").arg("arch=compute_86,code=sm_86")
                .arg("-gencode").arg("arch=compute_89,code=sm_89")
                .arg("-gencode").arg("arch=compute_89,code=compute_89")
                .arg(cu_file)
                .arg("-o")
                .arg(&lib_file);

            let status = cmd.status().expect("Failed to execute nvcc");
            if !status.success() {
                panic!("nvcc failed to compile cortex_cuda_bridge.cu into static lib");
            }

            println!("cargo:rustc-link-search=native={}", out_dir.display());
            println!("cargo:rustc-link-lib=static=cortex_cuda");
            if let Ok(cuda_path) = env::var("CUDA_PATH") {
                println!("cargo:rustc-link-search=native={}/lib/x64", cuda_path);
            }
            println!("cargo:rustc-link-lib=cudart");
        } else {
            let lib_file = out_dir.join("libcortex_cuda.a");
            let mut cmd = Command::new("nvcc");
            cmd.arg("-O3")
                .arg("-lib")
                .arg("-gencode").arg("arch=compute_75,code=sm_75")
                .arg("-gencode").arg("arch=compute_80,code=sm_80")
                .arg("-gencode").arg("arch=compute_86,code=sm_86")
                .arg("-gencode").arg("arch=compute_89,code=sm_89")
                .arg("-gencode").arg("arch=compute_89,code=compute_89")
                .arg("-Xcompiler")
                .arg("-fPIC")
                .arg(cu_file)
                .arg("-o")
                .arg(&lib_file);

            let status = cmd.status().expect("Failed to execute nvcc");
            if !status.success() {
                panic!("nvcc failed to compile cortex_cuda_bridge.cu into static lib");
            }

            println!("cargo:rustc-link-search=native={}", out_dir.display());
            println!("cargo:rustc-link-lib=static=cortex_cuda");
            println!("cargo:rustc-link-search=native=/usr/lib/x86_64-linux-gnu");
            println!("cargo:rustc-link-lib=cudart");
        }
    } else {
        println!("cargo:warning=nvcc compiler not found. Compiling with universal OpenCL backend.");
    }
}
