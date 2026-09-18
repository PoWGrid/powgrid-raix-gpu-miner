# PowGrid Reticulum AI ($RAIX) GPU Miner

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg)]()
[![Backend](https://img.shields.io/badge/backend-CUDA%20%7C%20OpenCL-green.svg)]()

High-performance, dual-backend GPU mining software for **Reticulum AI ($RAIX)** written from scratch in native Rust with low-level CUDA (C++) and OpenCL compute kernels.

---

## Key Features

- **Dual-Engine Architecture**: Native CUDA backend for NVIDIA GPUs and OpenCL backend for AMD & Intel graphics cards.
- **Auto Hardware Detection**: Intelligently enumerates available GPUs, queries VRAM and compute units, and allocates optimal hashing workloads.
- **100% Bit-Exact RandomX Verification**: Implements exact sponge-hashing and round transitions matching the official Reticulum AI specifications.
- **Real-Time ANSI Dashboard**: Built-in 78-column formatted terminal telemetry showing live per-card hashrates, total network difficulty, accepted shares, latency, and uptime.
- **Zero Hidden Fees**: 100% open source, free of telemetry, backdoors, or dev fees.

---

## Hardware Requirements

- **NVIDIA**: Compute Capability 6.0+ (Pascal, Turing, Ampere, Ada Lovelace, Blackwell). NVIDIA Driver 525+ & CUDA Toolkit 11.8+.
- **AMD / Intel**: OpenCL 1.2+ compatible drivers (ROCm or standard vendor drivers).
- **RAM / VRAM**: Minimum 2 GB free VRAM per active GPU.

---

## Building from Source

### 1. Prerequisites

- **Rust & Cargo**: [https://rustup.rs/](https://rustup.rs/) (version 1.75+ recommended)
- **C/C++ Build Tools**: `build-essential` (Linux) or Visual Studio C++ Build Tools (Windows)
- **NVIDIA CUDA Toolkit**: (Optional, required for CUDA backend) `nvcc` in `$PATH`
- **OpenCL Development Headers**: (Optional, required for OpenCL backend) `ocl-icd-opencl-dev` or `opencl-headers`

On Ubuntu / Debian:
```bash
sudo apt update
sudo apt install -y build-essential ocl-icd-opencl-dev opencl-headers
```

### 2. Compile Release Binary

```bash
git clone https://github.com/powgrid/powgrid-raix-gpu-miner.git
cd powgrid-raix-gpu-miner

cargo build --release
```

The compiled binary will be located at:
```
target/release/powgrid-raix-gpu-miner
```

---

## Usage & Command-Line Arguments

### Quick Start (Default Settings)

```bash
./powgrid-raix-gpu-miner \
  --address <YOUR_RAIX_WALLET_ADDRESS> \
  --worker <WORKER_NAME> \
  --node https://raix.powgrid.xyz
```

### Advanced Options

| Flag | Description | Default |
| :--- | :--- | :--- |
| `--address <ADDR>` | Your Reticulum AI wallet address (`ctx1...`) | *Required* |
| `--worker <NAME>` | Worker identifier for pool stats | `gpu-worker-1` |
| `--node <URL>` | Mining pool or node RPC endpoint | `https://raix.powgrid.xyz` |
| `--backend <TYPE>` | Force backend: `auto`, `cuda`, or `opencl` | `auto` |
| `--devices <IDS>` | Comma-separated GPU indices (e.g. `0,1,2`) | All detected |
| `--threads <NUM>` | Hashing threads per device block | Auto-tuned |

### Examples

**Run with specific NVIDIA GPUs on CUDA:**
```bash
./powgrid-raix-gpu-miner --address ctx1abc... --worker rig-cuda --backend cuda --devices 0,1
```

**Run on AMD GPUs via OpenCL:**
```bash
./powgrid-raix-gpu-miner --address ctx1abc... --worker rig-amd --backend opencl --devices 0
```

---

## License

Dual-licensed under either:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.
