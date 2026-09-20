mod cuda_backend;
mod opencl_backend;
mod device_manager;

use device_manager::{ActiveGpuWorker, AssignedBackend, BackendType, DeviceManager, UnifiedGpuDevice};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::fs;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

// =========================================================================
//  CLI RESTORATION & SIGNAL HANDLING
// =========================================================================

extern "C" fn sigint_handler(_: libc::c_int) {
    print!("\x1b[?25h\x1b[0m\n\n  \x1b[1;33m[SHUTDOWN]\x1b[0m Miner stopped safely. Terminal restored.\n\n");
    let _ = io::stdout().flush();
    std::process::exit(0);
}

fn current_time_str() -> String {
    unsafe {
        let mut t: libc::time_t = 0;
        libc::time(&mut t);
        let mut tm: libc::tm = std::mem::zeroed();
        #[cfg(unix)]
        libc::localtime_r(&t, &mut tm);
        #[cfg(windows)]
        libc::localtime_s(&mut tm, &t);
        format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec)
    }
}

// =========================================================================
//  ANSI UI & TEXT FORMATTING (MATHEMATICALLY EXACT 78 COLS)
// =========================================================================

fn visible_len(s: &str) -> usize {
    let mut len = 0;
    let mut in_escape = false;
    for c in s.chars() {
        if c == '\x1b' {
            in_escape = true;
        } else if in_escape {
            if c == 'm' || c == 'K' || c == 'H' || c == 'J' {
                in_escape = false;
            }
        } else {
            len += 1;
        }
    }
    len
}

fn truncate_visible(s: &str, max_len: usize) -> String {
    let mut out = String::new();
    let mut count = 0;
    let mut in_escape = false;
    for c in s.chars() {
        if c == '\x1b' {
            in_escape = true;
            out.push(c);
        } else if in_escape {
            out.push(c);
            if c == 'm' || c == 'K' || c == 'H' || c == 'J' {
                in_escape = false;
            }
        } else {
            if count + 4 <= max_len {
                out.push(c);
                count += 1;
            } else if count + 1 <= max_len {
                out.push('.');
                count += 1;
            } else {
                break;
            }
        }
    }
    out.push_str("\x1b[0m");
    out
}

fn box_row(content: &str, inner_width: usize) -> String {
    let vlen = visible_len(content);
    let padding = if vlen < inner_width { inner_width - vlen } else { 0 };
    format!("│ {}{} │\x1b[K\n", content, " ".repeat(padding))
}

fn two_col_row(left: &str, left_col_width: usize, right: &str, inner_width: usize) -> String {
    let l_vlen = visible_len(left);
    let l_pad = if l_vlen < left_col_width { left_col_width - l_vlen } else { 0 };
    let r_vlen = visible_len(right);
    let total_used = l_vlen + l_pad + r_vlen;
    let r_pad = if total_used < inner_width { inner_width - total_used } else { 0 };
    format!("│ {}{}{}{} │\x1b[K\n", left, " ".repeat(l_pad), right, " ".repeat(r_pad))
}

fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut res = String::new();
    let chars: Vec<char> = s.chars().collect();
    let len = chars.len();
    for (i, &c) in chars.iter().enumerate() {
        if i > 0 && (len - i) % 3 == 0 {
            res.push(',');
        }
        res.push(c);
    }
    res
}

fn format_speed(hs: f64) -> (f64, &'static str) {
    if hs >= 1_000_000_000.0 {
        (hs / 1_000_000_000.0, "GH/s")
    } else if hs >= 1_000_000.0 {
        (hs / 1_000_000.0, "MH/s")
    } else if hs >= 1_000.0 {
        (hs / 1_000.0, "kH/s")
    } else {
        (hs, "H/s")
    }
}

pub struct EventLogger {
    events: Mutex<VecDeque<String>>,
    max_events: usize,
    no_tui: bool,
}

impl EventLogger {
    pub fn new(max_events: usize, no_tui: bool) -> Self {
        Self {
            events: Mutex::new(VecDeque::with_capacity(max_events)),
            max_events,
            no_tui,
        }
    }

    pub fn log(&self, msg: String) {
        let now_str = current_time_str();
        if self.no_tui {
            println!("[{}] {}", now_str, msg);
        }
        let mut q = self.events.lock().unwrap();
        if q.len() >= self.max_events {
            q.pop_front();
        }
        q.push_back(format!("\x1b[90m[{}]\x1b[0m {}", now_str, msg));
    }

    pub fn get_events(&self) -> Vec<String> {
        let q = self.events.lock().unwrap();
        q.iter().cloned().collect()
    }
}

// =========================================================================
//  NETWORK TYPES & PROTOCOLS
// =========================================================================

fn diff_to_target_u64(diff: f64) -> u64 {
    if diff <= 0.0 {
        return u64::MAX;
    }
    let divisor = 16.0_f64.powf(diff);
    if divisor <= 1.0 {
        return u64::MAX;
    }
    if divisor >= u64::MAX as f64 {
        return 1u64;
    }
    let target = (u64::MAX as f64) / divisor;
    let t_u64 = target as u64;
    if t_u64 > 0 {
        t_u64.saturating_sub(1)
    } else {
        1
    }
}

fn parse_target_u64(val: &Option<serde_json::Value>, diff: f64) -> u64 {
    if let Some(v) = val {
        if let Some(s) = v.as_str() {
            if let Ok(n) = s.parse::<u64>() {
                if n > 0 {
                    return n;
                }
            }
        } else if let Some(n) = v.as_u64() {
            if n > 0 {
                return n;
            }
        }
    }
    diff_to_target_u64(diff)
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TemplateResponse {
    job_id: Option<String>,
    header_prefix: Option<String>,
    header_suffix: Option<String>,
    seed: Option<String>,
    share_difficulty: Option<f64>,
    target_difficulty: Option<f64>,
    #[serde(alias = "targetU64", alias = "target_u64")]
    target_u64: Option<serde_json::Value>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SubmitRequest<'a> {
    job_id: &'a str,
    nonce: u64,
    address: &'a str,
    worker: &'a str,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SubmitResponse {
    valid_share: Option<bool>,
    accepted: Option<bool>,
    #[serde(alias = "block_found")]
    block_found: Option<bool>,
    error: Option<String>,
    #[serde(alias = "targetDifficulty", alias = "newDifficulty", alias = "new_difficulty", alias = "difficulty")]
    target_difficulty: Option<f64>,
    #[serde(alias = "targetU64", alias = "target_u64", alias = "newTargetU64", alias = "new_target_u64")]
    target_u64: Option<serde_json::Value>,
}

#[derive(Clone, Default)]
struct ActiveJob {
    job_id: String,
    header_prefix: Vec<u8>,
    header_suffix: Vec<u8>,
    seed: Vec<u8>,
    difficulty: f64,
    target_u64: u64,
    valid: bool,
}

struct ShareQueueItem {
    job_id: String,
    nonce: u64,
    diff: f64,
}

// =========================================================================
//  MAIN GPU MINER ENGINE
// =========================================================================

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut pool_url = "https://raix.powgrid.xyz".to_string();
    let mut address = String::new();
    let mut worker = "gpu-rig1".to_string();
    let mut backend_pref = BackendType::Auto;
    let mut selected_devices: Option<Vec<usize>> = None;
    let mut batch_size: usize = 49152;
    let mut nonces_per_thread: usize = 4;
    let mut cli_diff: Option<f64> = None;
    let mut no_tui = false;

    // Check config.txt or wallet.txt
    if let Ok(content) = fs::read_to_string("config.txt") {
        for line in content.lines() {
            let line = line.trim();
            if let Some(w) = line.strip_prefix("WALLET=") {
                let trimmed = w.trim();
                if !trimmed.is_empty() { address = trimmed.to_string(); }
            } else if let Some(wrk) = line.strip_prefix("WORKER=") {
                let trimmed = wrk.trim();
                if !trimmed.is_empty() { worker = trimmed.to_string(); }
            }
        }
    } else if let Ok(content) = fs::read_to_string("wallet.txt") {
        let trimmed = content.trim().to_string();
        if !trimmed.is_empty() {
            address = trimmed;
        }
    }

    let mut i = 1;
    let mut worker_from_cli = false;
    while i < args.len() {
        match args[i].as_str() {
            "--node" | "-n" | "-o" if i + 1 < args.len() => { pool_url = args[i + 1].clone(); i += 2; }
            "--address" | "-a" | "-u" if i + 1 < args.len() => { address = args[i + 1].clone(); i += 2; }
            "--worker" | "-w" if i + 1 < args.len() => { worker = args[i + 1].clone(); worker_from_cli = true; i += 2; }
            "--backend" if i + 1 < args.len() => {
                let b = args[i + 1].to_lowercase();
                if b == "cuda" { backend_pref = BackendType::Cuda; }
                else if b == "opencl" { backend_pref = BackendType::OpenCl; }
                else { backend_pref = BackendType::Auto; }
                i += 2;
            }
            "--devices" | "-d" if i + 1 < args.len() => {
                let dev_str = &args[i + 1];
                if dev_str.to_lowercase() != "all" {
                    let ids: Vec<usize> = dev_str.split(',')
                        .filter_map(|s| s.trim().parse().ok())
                        .collect();
                    if !ids.is_empty() { selected_devices = Some(ids); }
                }
                i += 2;
            }
            "--batch-size" if i + 1 < args.len() => {
                if let Ok(bs) = args[i + 1].parse() { batch_size = bs; }
                i += 2;
            }
            "--diff" if i + 1 < args.len() => {
                if let Ok(d) = args[i + 1].parse() { cli_diff = Some(d); }
                i += 2;
            }
            "--nonces-per-thread" if i + 1 < args.len() => {
                if let Ok(npt) = args[i + 1].parse() { nonces_per_thread = npt; }
                i += 2;
            }
            "--no-tui" | "--hiveos" => {
                no_tui = true;
                i += 1;
            }
            _ => { i += 1; }
        }
    }

    println!("===========================================================");
    println!("  ⚡ PowGrid Reticulum AI ($RAIX) Unified GPU Miner v2.1");
    println!("  Architecture        : Dual-Engine [Native CUDA + OpenCL JIT]");
    println!("  Target Hardware     : Any GPU (NVIDIA, AMD, Intel, Apple)");
    println!("===========================================================\n");

    // Device Discovery
    print!("[DISCOVERY] Scanning system for active GPU hardware... ");
    io::stdout().flush().unwrap();
    let all_devices = DeviceManager::discover_devices(backend_pref.clone());

    if all_devices.is_empty() {
        println!("❌ NO SUPPORTED GPUS FOUND!");
        eprintln!("\n[ERROR] No active CUDA or OpenCL GPU devices were detected on this system.");
        eprintln!("        Please ensure appropriate GPU drivers are installed.");
        std::process::exit(1);
    }
    println!("✅ Found {} GPU device(s)!\n", all_devices.len());

    for dev in &all_devices {
        println!("  [GPU #{}] {:<32} | {:>5} MB VRAM | {} CUs | Backend: {}",
            dev.id, dev.name, dev.vram_mb, dev.compute_units, dev.backend_name);
    }
    println!();

    // Filter devices if specified
    let active_gpus: Vec<UnifiedGpuDevice> = if let Some(ref ids) = selected_devices {
        all_devices.into_iter().filter(|d| ids.contains(&d.id)).collect()
    } else {
        all_devices
    };

    if active_gpus.is_empty() {
        eprintln!("[ERROR] None of the requested device IDs are available.");
        std::process::exit(1);
    }

    // Run 100% Bit-Perfect Self-Test on all selected GPUs
    println!("[SELF-TEST] Running cryptographic L1 accuracy checks on active GPU(s)...");
    for dev in &active_gpus {
        print!("  Checking GPU #{} [{}]: ", dev.id, dev.name);
        io::stdout().flush().unwrap();
        let pass = DeviceManager::run_self_test(dev);
        if pass {
            println!("✅ 100% BIT-PERFECT MATCH (Vectors 123 & 99999)");
        } else {
            println!("❌ MISMATCH!");
            eprintln!("[FATAL] GPU #{} produced non-deterministic or incorrect hash outputs.", dev.id);
            std::process::exit(1);
        }
    }
    println!();

    // 1-Click Interactive setup if address is empty
    if address.is_empty() {
        print!("Enter your Reticulum AI wallet address (starts with ctx1...): ");
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        address = input.trim().to_string();

        if !worker_from_cli {
            let default_worker = "gpu-rig1";
            print!("Enter worker name [default: {}]: ", default_worker);
            io::stdout().flush().unwrap();
            let mut w_input = String::new();
            io::stdin().read_line(&mut w_input).unwrap();
            let trimmed_w = w_input.trim();
            if !trimmed_w.is_empty() {
                worker = trimmed_w.to_string();
            } else {
                worker = default_worker.to_string();
            }
        }

        if !address.is_empty() {
            let _ = fs::write("config.txt", format!("WALLET={}\nWORKER={}\n", address, worker));
            let _ = fs::write("wallet.txt", &address);
        }
    }

    if address.is_empty() {
        eprintln!("[ERROR] Mining address is required!");
        std::process::exit(1);
    }

    println!("[CONFIG] Pool Node : {}", pool_url);
    println!("[CONFIG] Wallet    : {}", address);
    println!("[CONFIG] Worker    : {}\n", worker);

    // Hardware Auto-Tuning: calculate optimal initial difficulty based on total GPU compute units
    let initial_diff = if let Some(d) = cli_diff {
        println!("[CONFIG] User difficulty override: {:.2}\n", d);
        d
    } else {
        let mut total_est_hs = 0.0f64;
        for dev in &active_gpus {
            let per_cu = match dev.assigned {
                AssignedBackend::Cuda(_) => 280_000.0,
                AssignedBackend::OpenCl(_) => 200_000.0,
            };
            total_est_hs += (dev.compute_units.max(1) as f64) * per_cu;
        }
        // Target: 1 share every 10 seconds (optimal balance between pool responsiveness and efficiency)
        // Expected hashes per share = 16^diff = 2^(4*diff)
        // ideal_diff = ln(total_est_hs * 10s) / (4 * ln(2))
        let target_sec = 10.0f64;
        let ideal = (total_est_hs * target_sec).ln() / (4.0 * std::f64::consts::LN_2);
        let rounded = (ideal * 20.0).round() / 20.0; // Round to nearest 0.05
        let tuned = rounded.clamp(4.0, 9.0);
        let hr_display = if total_est_hs >= 1_000_000.0 {
            format!("{:.2} MH/s", total_est_hs / 1_000_000.0)
        } else {
            format!("{:.0} kH/s", total_est_hs / 1000.0)
        };
        println!("[AUTOTUNE] GPU compute capacity: ~{} -> Auto-tuned initial difficulty: {:.2} (target: ~10s per share)\n", hr_display, tuned);
        tuned
    };

    let active_job = Arc::new(RwLock::new(ActiveJob {
        difficulty: initial_diff,
        target_u64: diff_to_target_u64(initial_diff),
        ..Default::default()
    }));
    let total_hashes = Arc::new(AtomicU64::new(0));
    let accepted_shares = Arc::new(AtomicU32::new(0));
    let rejected_shares = Arc::new(AtomicU32::new(0));
    let blocks_found = Arc::new(AtomicU32::new(0));
    let running = Arc::new(AtomicBool::new(true));
    let event_logger = Arc::new(EventLogger::new(6, no_tui));

    // Share submission queue
    let submit_queue: Arc<Mutex<VecDeque<ShareQueueItem>>> = Arc::new(Mutex::new(VecDeque::new()));

    // Template poller thread
    {
        let pool_url = pool_url.clone();
        let address = address.clone();
        let worker = worker.clone();
        let active_job = Arc::clone(&active_job);
        let event_logger = Arc::clone(&event_logger);
        let running = Arc::clone(&running);

        thread::spawn(move || {
            let agent = ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(5))
                .build();
            let template_url = format!("{}/api/pool/template?address={}&worker={}&diff={:.2}", pool_url, address, worker, initial_diff);

            while running.load(Ordering::Relaxed) {
                if let Ok(resp) = agent.get(&template_url).call() {
                    if let Ok(tmpl) = resp.into_json::<TemplateResponse>() {
                        if let (Some(job_id), Some(pfx)) = (tmpl.job_id, tmpl.header_prefix) {
                            let diff = tmpl.share_difficulty.or(tmpl.target_difficulty).unwrap_or(initial_diff);
                            let target_u64 = parse_target_u64(&tmpl.target_u64, diff);
                            let sfx = tmpl.header_suffix.unwrap_or_default();
                            let seed = tmpl.seed.unwrap_or_else(|| "cortex-randomx-epoch-0".to_string());

                            let mut job = active_job.write().unwrap();
                            let job_changed = job.job_id != job_id;
                            let diff_changed = !job.job_id.is_empty() && (job.difficulty - diff).abs() >= 0.01;
                            let seed_changed = !job.job_id.is_empty() && !job.seed.is_empty() && job.seed != seed.as_bytes();
                            let target_changed = job.target_u64 != target_u64;

                            if job_changed || diff_changed || seed_changed || target_changed {
                                let old_diff = job.difficulty;
                                job.job_id = job_id.clone();
                                job.header_prefix = pfx.into_bytes();
                                job.header_suffix = sfx.into_bytes();
                                job.seed = seed.as_bytes().to_vec();
                                job.difficulty = diff;
                                job.target_u64 = target_u64;
                                job.valid = true;

                                if diff_changed {
                                    event_logger.log(format!("\x1b[1;34m► VARDIFF ADJUST\x1b[0m  Target Diff: {:.2} -> {:.2}", old_diff, diff));
                                } else if seed_changed {
                                    event_logger.log(format!("\x1b[1;35m► EPOCH CHANGED\x1b[0m   New Seed: {}", &seed[..seed.len().min(16)]));
                                }
                            }
                        }
                    }
                }
                thread::sleep(Duration::from_millis(1500));
            }
        });
    }

    println!("[START] Waiting for first mining job template from PowGrid pool...");
    while running.load(Ordering::Relaxed) {
        if active_job.read().unwrap().valid { break; }
        thread::sleep(Duration::from_millis(200));
    }

    // Share submitter background worker
    {
        let pool_url = pool_url.clone();
        let address = address.clone();
        let worker = worker.clone();
        let submit_queue = Arc::clone(&submit_queue);
        let accepted_shares = Arc::clone(&accepted_shares);
        let rejected_shares = Arc::clone(&rejected_shares);
        let blocks_found = Arc::clone(&blocks_found);
        let event_logger = Arc::clone(&event_logger);
        let running = Arc::clone(&running);
        let active_job_clone = Arc::clone(&active_job);

        thread::spawn(move || {
            let agent = ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(5))
                .build();
            let submit_url = format!("{}/api/pool/submit", pool_url);

            while running.load(Ordering::Relaxed) {
                let item = {
                    let mut q = submit_queue.lock().unwrap();
                    q.pop_front()
                };

                if let Some(item) = item {
                    let submit_body = SubmitRequest {
                        job_id: &item.job_id,
                        nonce: item.nonce,
                        address: &address,
                        worker: &worker,
                    };

                    if let Ok(resp) = agent.post(&submit_url).send_json(&submit_body) {
                        if let Ok(res) = resp.into_json::<SubmitResponse>() {
                            if let Some(new_diff) = res.target_difficulty {
                                let mut job = active_job_clone.write().unwrap();
                                if (job.difficulty - new_diff).abs() >= 0.01 {
                                    let old_diff = job.difficulty;
                                    let new_target = parse_target_u64(&res.target_u64, new_diff);
                                    job.difficulty = new_diff;
                                    job.target_u64 = new_target;
                                    event_logger.log(format!(
                                        "\x1b[1;34m► VARDIFF ADJUST\x1b[0m  Target Diff: {:.2} -> {:.2}",
                                        old_diff, new_diff
                                    ));
                                }
                            }

                            if res.valid_share.unwrap_or(false) || res.accepted.unwrap_or(false) {
                                accepted_shares.fetch_add(1, Ordering::Relaxed);
                                if res.block_found.unwrap_or(false) {
                                    blocks_found.fetch_add(1, Ordering::Relaxed);
                                    event_logger.log(format!(
                                        "\x1b[1;93m★ [BLOCK SOLVED!] ★ Reticulum AI Block Mined! (+50 $RAIX)\x1b[0m"
                                    ));
                                } else {
                                    event_logger.log(format!(
                                        "\x1b[1;32m✓ SHARE ACCEPTED\x1b[0m  Diff: {:.2} | Nonce: 0x{:016x}",
                                        item.diff, item.nonce
                                    ));
                                }
                            } else {
                                rejected_shares.fetch_add(1, Ordering::Relaxed);
                                let reason = res.error.unwrap_or_else(|| "Unknown rejection".to_string());
                                event_logger.log(format!("\x1b[1;31m✗ SHARE REJECTED\x1b[0m  Reason: {}", reason));
                            }
                        }
                    }
                } else {
                    thread::sleep(Duration::from_millis(50));
                }
            }
        });
    }

    // Register signal handler for Ctrl+C
    unsafe {
        libc::signal(libc::SIGINT, sigint_handler as usize);
        libc::signal(libc::SIGTERM, sigint_handler as usize);
    }

    let initial_diff = active_job.read().unwrap().difficulty;
    event_logger.log(format!(
        "\x1b[1;36m► MINER STARTED\x1b[0m   {} GPU(s) active | Diff: {:.2}",
        active_gpus.len(),
        initial_diff
    ));

    if !no_tui {
        // Clear screen, scrollback and hide cursor for static UI
        print!("\x1b[2J\x1b[3J\x1b[H\x1b[?25l");
        let _ = io::stdout().flush();
    }

    // Reporter thread (Fixed static dashboard, 1s refresh, zero flicker)
    {
        let total_hashes = Arc::clone(&total_hashes);
        let accepted_shares = Arc::clone(&accepted_shares);
        let rejected_shares = Arc::clone(&rejected_shares);
        let blocks_found = Arc::clone(&blocks_found);
        let active_job = Arc::clone(&active_job);
        let event_logger = Arc::clone(&event_logger);
        let running = Arc::clone(&running);
        let pool_display = pool_url.clone();
        let worker_name = worker.clone();
        let active_gpus_count = active_gpus.len();
        let first_gpu = active_gpus[0].clone();
        let is_no_tui = no_tui;

        let wallet_display = if address.len() > 24 {
            format!("{}...{}", &address[..12], &address[address.len() - 8..])
        } else {
            address.clone()
        };

        thread::spawn(move || {
            let start_time = Instant::now();
            let mut last_hashes = 0u64;
            let mut last_time = Instant::now();

            while running.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_secs(1));

                let now = Instant::now();
                let elapsed = (now - last_time).as_secs_f64();
                let curr_hashes = total_hashes.load(Ordering::Relaxed);
                let delta = curr_hashes.saturating_sub(last_hashes);
                let hs_instant = if elapsed > 0.0 { delta as f64 / elapsed } else { 0.0 };

                last_hashes = curr_hashes;
                last_time = now;

                let total_elapsed = start_time.elapsed().as_secs_f64();
                let hs_avg = if total_elapsed > 0.0 { curr_hashes as f64 / total_elapsed } else { 0.0 };

                let (now_str, now_unit) = format_speed(hs_instant);
                let (avg_str, avg_unit) = format_speed(hs_avg);

                let diff = active_job.read().unwrap().difficulty;
                let acc = accepted_shares.load(Ordering::Relaxed);
                let rej = rejected_shares.load(Ordering::Relaxed);
                let blocks = blocks_found.load(Ordering::Relaxed);
                let total_s = acc + rej;
                let acc_pct = if total_s > 0 { (acc as f64 / total_s as f64) * 100.0 } else { 100.0 };
                let rej_pct = if total_s > 0 { (rej as f64 / total_s as f64) * 100.0 } else { 0.0 };

                let uptime_secs = total_elapsed as u64;
                let u_h = uptime_secs / 3600;
                let u_m = (uptime_secs % 3600) / 60;
                let u_s = uptime_secs % 60;

                let eff_hs = if active_gpus_count > 0 { hs_avg / (active_gpus_count as f64) } else { 0.0 };
                let (eff_str, eff_unit) = format_speed(eff_hs);
                let events = event_logger.get_events();

                let blocks_str = if blocks > 0 {
                    format!("\x1b[1;93m★ {} BLOCK{}\x1b[0m", blocks, if blocks > 1 { "S" } else { "" })
                } else {
                    "\x1b[1;37m0\x1b[0m \x1b[90m(hunting)\x1b[0m".to_string()
                };

                let mut buf = String::with_capacity(4096);
                buf.push_str("\x1b[H"); // Cursor home

                let border_top = format!("╭{}╮\x1b[K\n", "─".repeat(76));
                let border_div = format!("├{}┤\x1b[K\n", "─".repeat(76));
                let border_bot = format!("╰{}╯\x1b[K\n", "─".repeat(76));

                buf.push_str(&border_top);
                buf.push_str(&box_row("\x1b[1;36m► POWGRID RETICULUM AI ($RAIX) HIGH-PERFORMANCE GPU MINER v2.1\x1b[0m", 74));
                buf.push_str(&two_col_row(
                    &format!("\x1b[90mPool:\x1b[0m \x1b[1;37m{}\x1b[0m", pool_display),
                    41,
                    "\x1b[90mStatus:\x1b[0m \x1b[1;32m● ONLINE (Connected)\x1b[0m",
                    74
                ));
                buf.push_str(&two_col_row(
                    &format!("\x1b[90mWallet:\x1b[0m \x1b[36m{}\x1b[0m", wallet_display),
                    41,
                    &format!("\x1b[90mWorker:\x1b[0m \x1b[1;33m{}\x1b[0m", worker_name),
                    74
                ));
                buf.push_str(&border_div);
                buf.push_str(&box_row("\x1b[1;35mHARDWARE & GPU ENGINE CONFIGURATION\x1b[0m", 74));
                buf.push_str(&two_col_row(
                    "\x1b[90mEngine    :\x1b[0m Dual-Arch (CUDA/OpenCL)",
                    41,
                    &format!("\x1b[90mActive GPUs :\x1b[0m \x1b[1;37m{} Device(s)\x1b[0m", active_gpus_count),
                    74
                ));

                let gpu_name_trimmed = if first_gpu.name.len() > 16 {
                    &first_gpu.name[..16]
                } else {
                    &first_gpu.name
                };
                let gpu0_info = format!("{:<16} ({}MB)", gpu_name_trimmed, first_gpu.vram_mb);
                buf.push_str(&two_col_row(
                    &format!("\x1b[90mPrimary GPU:\x1b[0m {}", gpu0_info),
                    41,
                    "\x1b[90mAccuracy:\x1b[0m \x1b[1;32m100% Bit-Perfect Match\x1b[0m",
                    74
                ));
                buf.push_str(&border_div);
                buf.push_str(&box_row("\x1b[1;33mMINING TELEMETRY\x1b[0m", 74));
                buf.push_str(&two_col_row(
                    &format!("\x1b[90mHashrate (Now) :\x1b[0m \x1b[1;32m{:>6.2} {:<4}\x1b[0m", now_str, now_unit),
                    41,
                    &format!("\x1b[90mUptime      :\x1b[0m \x1b[1;37m{:02}:{:02}:{:02}\x1b[0m", u_h, u_m, u_s),
                    74
                ));
                buf.push_str(&two_col_row(
                    &format!("\x1b[90mHashrate (Avg) :\x1b[0m \x1b[1;32m{:>6.2} {:<4}\x1b[0m", avg_str, avg_unit),
                    41,
                    &format!("\x1b[90mEfficiency  :\x1b[0m \x1b[1;37m{:>5.2} {}/GPU\x1b[0m", eff_str, eff_unit),
                    74
                ));
                buf.push_str(&two_col_row(
                    &format!("\x1b[90mTarget Diff    :\x1b[0m \x1b[1;36m{:.2}\x1b[0m", diff),
                    41,
                    &format!("\x1b[90mTotal Hashes:\x1b[0m \x1b[1;37m{}\x1b[0m", format_number(curr_hashes)),
                    74
                ));
                buf.push_str(&two_col_row(
                    &format!("\x1b[90mShares (Acc)   :\x1b[0m \x1b[1;32m{} ({:.1}%)\x1b[0m", acc, acc_pct),
                    41,
                    &format!("\x1b[90mRejected    :\x1b[0m \x1b[1;31m{} ({:.1}%)\x1b[0m", rej, rej_pct),
                    74
                ));
                buf.push_str(&two_col_row(
                    &format!("\x1b[90mBlocks Solved  :\x1b[0m {}", blocks_str),
                    41,
                    "\x1b[90mBlock Reward:\x1b[0m \x1b[1;33m50.0 $RAIX\x1b[0m",
                    74
                ));
                buf.push_str(&border_div);
                buf.push_str(&box_row("\x1b[1;36mLIVE EVENT LOG (Latest Activity)\x1b[0m", 74));

                for i in 0..6 {
                    if i < events.len() {
                        buf.push_str(&box_row(&truncate_visible(&events[i], 74), 74));
                    } else {
                        buf.push_str(&box_row("", 74));
                    }
                }

                buf.push_str(&border_bot);
                buf.push_str("  \x1b[90m[CTRL+C to safely exit miner]\x1b[0m\x1b[K\n");

                // Write JSON stats for HiveOS h-stats.sh / monitoring
                let stats_json = format!(
                    r#"{{"uptime":{},"total_hashes":{},"hashrate":{:.2},"hashrate_avg":{:.2},"accepted":{},"rejected":{},"blocks":{},"diff":{:.2}}}"#,
                    uptime_secs, curr_hashes, hs_instant, hs_avg, acc, rej, blocks, diff
                );
                let _ = fs::write("/tmp/powgrid_miner_stats.json", stats_json);

                if is_no_tui {
                    if uptime_secs > 0 && uptime_secs % 5 == 0 {
                        println!(
                            "[{}] [STATS] Hashrate: {:.2} {} | Accepted: {} | Rejected: {} | Blocks: {} | Diff: {:.2} | Uptime: {:02}:{:02}:{:02}",
                            current_time_str(), avg_str, avg_unit, acc, rej, blocks, diff, u_h, u_m, u_s
                        );
                    }
                } else {
                    print!("{}", buf);
                    let _ = io::stdout().flush();
                }
            }
        });
    }

    // Launch worker threads for each active GPU
    let mut handles = Vec::new();
    for (gpu_idx, dev) in active_gpus.into_iter().enumerate() {
        let active_job = Arc::clone(&active_job);
        let total_hashes = Arc::clone(&total_hashes);
        let submit_queue = Arc::clone(&submit_queue);
        let running = Arc::clone(&running);
        let address = address.clone();
        let worker = worker.clone();

        handles.push(thread::spawn(move || {
            let mut gpu_worker = match ActiveGpuWorker::new(&dev, batch_size, nonces_per_thread) {
                Ok(w) => w,
                Err(e) => {
                    eprintln!("[ERROR] Failed to start worker on GPU #{}: {}", dev.id, e);
                    return;
                }
            };

            let mut h = Sha256::new();
            h.update(address.as_bytes());
            h.update(worker.as_bytes());
            let now_nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64;
            h.update(&now_nanos.to_le_bytes());
            let seed_bytes = h.finalize();
            let base_seed = u64::from_le_bytes(seed_bytes[0..8].try_into().unwrap());
            let mut nonce = (base_seed & 0x0000_ffff_ffff_ffff) | ((gpu_idx as u64) << 48);

            let mut cur_job_id = String::new();
            let mut prefix = Vec::new();
            let mut suffix = Vec::new();
            let mut seed = Vec::new();
            let mut diff = 4.0f64;
            let mut target_u64 = 0u64;

            while running.load(Ordering::Relaxed) {
                {
                    let job = active_job.read().unwrap();
                    if job.valid && (job.job_id != cur_job_id || (job.difficulty - diff).abs() >= 0.01 || job.target_u64 != target_u64) {
                        cur_job_id = job.job_id.clone();
                        prefix = job.header_prefix.clone();
                        suffix = job.header_suffix.clone();
                        seed = job.seed.clone();
                        diff = job.difficulty;
                        target_u64 = job.target_u64;
                    }
                }

                if prefix.is_empty() {
                    thread::sleep(Duration::from_millis(50));
                    continue;
                }

                match gpu_worker.run_batch(&prefix, &suffix, &seed, target_u64, diff.round() as usize, nonce) {
                    Ok((found_nonces, hashes_done)) => {
                        total_hashes.fetch_add(hashes_done, Ordering::Relaxed);
                        nonce = nonce.wrapping_add(hashes_done);

                        for found_nonce in found_nonces {
                            let mut q = submit_queue.lock().unwrap();
                            q.push_back(ShareQueueItem {
                                job_id: cur_job_id.clone(),
                                nonce: found_nonce,
                                diff,
                            });
                        }
                    }
                    Err(err) => {
                        eprintln!("[GPU #{}] Batch execution failed: {}", dev.id, err);
                        thread::sleep(Duration::from_millis(500));
                    }
                }
            }
        }));
    }

    for h in handles {
        let _ = h.join();
    }
}
