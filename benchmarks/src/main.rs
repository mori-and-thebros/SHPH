use shph_core::{
    absorb_responder_pq, build_hello_with_profile, decode_cell, encode_cell, finalize_initiator_pq,
    HandshakeProfile, IdentityKeyPair, ReceiveCipher, ReplayWindow, SendCipher, BALANCED, BULK,
    LOW_LATENCY, RANDOMIZED_LAB,
};
use shph_transport::{quic_handshake_client_with_profile, quic_handshake_server_with_profile};
use std::alloc::{GlobalAlloc, Layout, System};
use std::env;
use std::hint::black_box;
use std::net::UdpSocket;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Instant;

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

struct CountingAllocator;

static ALLOC_CALLS: AtomicU64 = AtomicU64::new(0);
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Suite {
    All,
    Core,
    DataPlane,
    Resource,
    Shroud,
    Quic,
    Scalability,
}

#[derive(Debug, Clone, Copy)]
struct Options {
    profile: HandshakeProfile,
    suite: Suite,
    iterations: usize,
    frames: usize,
}

#[derive(Debug, Clone, Copy)]
struct LatencyStats {
    min_ns: u128,
    p50_ns: u128,
    p95_ns: u128,
    p99_ns: u128,
    p999_ns: u128,
    max_ns: u128,
    mean_ns: u128,
}

#[derive(Debug, Clone, Copy, Default)]
struct AllocationStats {
    calls: u64,
    bytes: u64,
}

#[derive(Debug, Clone, Copy, Default)]
struct RuntimeStats {
    elapsed_ns: u128,
    cpu_pct: Option<f64>,
    alloc: AllocationStats,
    rss_kib: Option<u64>,
    peak_rss_kib: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
struct MeasurementStart {
    started_at: Instant,
    alloc: AllocationStats,
    rss_kib: Option<u64>,
    peak_rss_kib: Option<u64>,
    cpu_time_ns: Option<u128>,
}

fn main() {
    let options = parse_options();
    print_metadata(options);
    println!("measurement,profile,scenario,payload_bytes,samples,min_ns,p50_ns,p95_ns,p99_ns,p99_9_ns,max_ns,mean_ns,elapsed_ms,goodput_mbps,wire_mbps,cpu_pct,alloc_calls,alloc_bytes,rss_kib,peak_rss_kib,notes");

    if matches!(options.suite, Suite::All | Suite::Core) {
        bench_handshake(options);
        bench_latency_under_load(options);
        bench_replay(options);
    }
    if matches!(options.suite, Suite::All | Suite::DataPlane) {
        for payload_bytes in [1024, 4096, 1400, 1500, 65536] {
            bench_dataplane(options, payload_bytes);
        }
    }
    if matches!(options.suite, Suite::All | Suite::Resource) {
        bench_resource_idle(options);
    }
    if matches!(options.suite, Suite::All | Suite::Shroud) {
        bench_shroud_profiles(options);
    }
    if matches!(options.suite, Suite::All | Suite::Quic) {
        bench_quic_loopback(options);
        bench_quic_impairment(options);
    }
    if matches!(options.suite, Suite::All | Suite::Scalability) {
        bench_long_session(options);
    }
}

fn parse_options() -> Options {
    let mut profile = HandshakeProfile::SecureDefault;
    let mut suite = Suite::All;
    let mut iterations = 100;
    let mut frames = 10_000;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--profile" => {
                profile = args
                    .next()
                    .unwrap_or_else(|| usage("missing value for --profile"))
                    .parse::<HandshakeProfile>()
                    .unwrap_or_else(|err| usage(&err.to_string()));
            }
            "--suite" => {
                suite = parse_suite(
                    &args
                        .next()
                        .unwrap_or_else(|| usage("missing value for --suite")),
                );
            }
            "--iterations" => {
                iterations = parse_positive(
                    &args
                        .next()
                        .unwrap_or_else(|| usage("missing value for --iterations")),
                    "iterations",
                );
            }
            "--frames" => {
                frames = parse_positive(
                    &args
                        .next()
                        .unwrap_or_else(|| usage("missing value for --frames")),
                    "frames",
                );
            }
            "--help" | "-h" => {
                println!("Usage: shph-benchmarks [OPTIONS]");
                println!("  --profile secure-default|classical-lab");
                println!("  --suite all|core|dataplane|resource|shroud|quic|scalability");
                println!("  --iterations N   latency samples (default: 100)");
                println!("  --frames N       sustained/load frames (default: 10000)");
                println!("Output includes p50/p95/p99/p99.9 latency, goodput, wire rate, CPU, RSS, and allocations.");
                std::process::exit(0);
            }
            other => usage(&format!("unknown argument: {other}")),
        }
    }
    Options {
        profile,
        suite,
        iterations,
        frames,
    }
}

fn usage(message: &str) -> ! {
    eprintln!("{message}");
    eprintln!("Use --help for usage.");
    std::process::exit(2);
}

fn parse_positive(value: &str, name: &str) -> usize {
    let parsed = value
        .parse()
        .unwrap_or_else(|_| usage(&format!("{name} must be a positive integer")));
    if parsed == 0 {
        usage(&format!("{name} must be a positive integer"));
    }
    parsed
}

fn parse_suite(value: &str) -> Suite {
    match value.to_ascii_lowercase().as_str() {
        "all" => Suite::All,
        "core" => Suite::Core,
        "dataplane" | "data-plane" => Suite::DataPlane,
        "resource" => Suite::Resource,
        "shroud" => Suite::Shroud,
        "quic" => Suite::Quic,
        "scalability" => Suite::Scalability,
        _ => usage("suite must be all, core, dataplane, resource, shroud, quic, or scalability"),
    }
}

fn print_metadata(options: Options) {
    println!("# platform={}", platform_name());
    println!("# profile={}", options.profile.as_str());
    println!("# suite={options:?}");
    println!("# iterations={}", options.iterations);
    println!("# frames={}", options.frames);
    println!("# commit={}", command_output("git", &["rev-parse", "HEAD"]));
    println!("# rustc={}", command_output("rustc", &["--version"]));
    println!("# kernel={}", command_output("uname", &["-srvm"]));
    println!("# cpu={}", cpu_model());
    println!("# benchmark_clock=std::time::Instant");
    println!("# build_profile=release");
    println!(
        "# tun_native={}",
        env::var("SHPH_TUN_NATIVE").unwrap_or_else(|_| "0".into())
    );
    println!("# note=local operation latency is not network RTT; external TUN and two-host tests are separate");
}

fn platform_name() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        if std::fs::read_to_string("/proc/version")
            .map(|contents| contents.to_ascii_lowercase().contains("microsoft"))
            .unwrap_or(false)
        {
            return "wsl2";
        }
        return "native-linux";
    }

    #[cfg(not(target_os = "linux"))]
    {
        std::env::consts::OS
    }
}

fn command_output(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|output| !output.is_empty())
        .unwrap_or_else(|| "unavailable".to_string())
}

fn cpu_model() -> String {
    #[cfg(target_os = "linux")]
    {
        if let Ok(contents) = std::fs::read_to_string("/proc/cpuinfo") {
            if let Some(model) = contents
                .lines()
                .find_map(|line| line.strip_prefix("model name\t: "))
            {
                return model.to_string();
            }
        }
    }
    "unavailable".to_string()
}

fn reset_allocations() {
    ALLOC_CALLS.store(0, Ordering::Relaxed);
    ALLOC_BYTES.store(0, Ordering::Relaxed);
}

fn allocation_snapshot() -> AllocationStats {
    AllocationStats {
        calls: ALLOC_CALLS.load(Ordering::Relaxed),
        bytes: ALLOC_BYTES.load(Ordering::Relaxed),
    }
}

fn process_rss_kib() -> Option<u64> {
    let contents = std::fs::read_to_string("/proc/self/status").ok()?;
    contents.lines().find_map(|line| {
        line.strip_prefix("VmRSS:")
            .and_then(|value| value.split_whitespace().next())
            .and_then(|value| value.parse().ok())
    })
}

fn process_peak_rss_kib() -> Option<u64> {
    let contents = std::fs::read_to_string("/proc/self/status").ok()?;
    contents.lines().find_map(|line| {
        line.strip_prefix("VmHWM:")
            .and_then(|value| value.split_whitespace().next())
            .and_then(|value| value.parse().ok())
    })
}

#[cfg(target_family = "unix")]
fn process_cpu_time_ns() -> Option<u128> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    let result = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    if result != 0 {
        return None;
    }
    let usage = unsafe { usage.assume_init() };
    let user = timeval_to_ns(usage.ru_utime)?;
    let system = timeval_to_ns(usage.ru_stime)?;
    Some(user.saturating_add(system))
}

#[cfg(target_family = "unix")]
fn timeval_to_ns(value: libc::timeval) -> Option<u128> {
    let seconds = u128::try_from(value.tv_sec).ok()?;
    let micros = u128::try_from(value.tv_usec).ok()?;
    Some(seconds.saturating_mul(1_000_000_000) + micros.saturating_mul(1_000))
}

#[cfg(not(target_family = "unix"))]
fn process_cpu_time_ns() -> Option<u128> {
    None
}

fn begin_measurement() -> MeasurementStart {
    reset_allocations();
    MeasurementStart {
        started_at: Instant::now(),
        alloc: allocation_snapshot(),
        rss_kib: process_rss_kib(),
        peak_rss_kib: process_peak_rss_kib(),
        cpu_time_ns: process_cpu_time_ns(),
    }
}

fn finish_measurement(start: MeasurementStart) -> RuntimeStats {
    let elapsed_ns = start.started_at.elapsed().as_nanos();
    let current_alloc = allocation_snapshot();
    let end_cpu = process_cpu_time_ns();
    let cpu_pct = match (start.cpu_time_ns, end_cpu) {
        (Some(before), Some(after)) if elapsed_ns > 0 => {
            let cpu_seconds = (after.saturating_sub(before) as f64) / 1_000_000_000.0;
            Some(cpu_seconds / (elapsed_ns as f64 / 1_000_000_000.0) * 100.0)
        }
        _ => None,
    };
    RuntimeStats {
        elapsed_ns,
        cpu_pct,
        alloc: AllocationStats {
            calls: current_alloc.calls.saturating_sub(start.alloc.calls),
            bytes: current_alloc.bytes.saturating_sub(start.alloc.bytes),
        },
        rss_kib: process_rss_kib().or(start.rss_kib),
        peak_rss_kib: process_peak_rss_kib().or(start.peak_rss_kib),
    }
}

fn stats_from_samples(samples: &[u128]) -> LatencyStats {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let percentile = |percent: usize, fraction: usize| {
        let index = ((sorted.len().saturating_sub(1) * percent) / fraction).min(sorted.len() - 1);
        sorted[index]
    };
    LatencyStats {
        min_ns: sorted[0],
        p50_ns: percentile(50, 100),
        p95_ns: percentile(95, 100),
        p99_ns: percentile(99, 100),
        p999_ns: percentile(999, 1000),
        max_ns: sorted[sorted.len() - 1],
        mean_ns: sorted.iter().sum::<u128>() / sorted.len() as u128,
    }
}

fn emit_latency(
    name: &str,
    options: Options,
    scenario: &str,
    payload_bytes: usize,
    samples: &[u128],
    runtime: RuntimeStats,
    notes: &str,
) {
    let stats = stats_from_samples(samples);
    let cpu_pct = runtime
        .cpu_pct
        .map_or_else(|| "-".to_string(), |value| format!("{value:.2}"));
    let rss_kib = runtime
        .rss_kib
        .map_or_else(|| "-".to_string(), |value| value.to_string());
    let peak_rss_kib = runtime
        .peak_rss_kib
        .map_or_else(|| "-".to_string(), |value| value.to_string());
    println!(
        "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
        name,
        options.profile.as_str(),
        scenario,
        payload_bytes,
        samples.len(),
        stats.min_ns,
        stats.p50_ns,
        stats.p95_ns,
        stats.p99_ns,
        stats.p999_ns,
        stats.max_ns,
        stats.mean_ns,
        runtime.elapsed_ns / 1_000_000,
        "-",
        "-",
        cpu_pct,
        runtime.alloc.calls,
        runtime.alloc.bytes,
        rss_kib,
        peak_rss_kib,
        notes
    );
}

fn emit_rate(
    options: Options,
    scenario: &str,
    payload_bytes: usize,
    runtime: RuntimeStats,
    goodput_mbps: f64,
    wire_mbps: f64,
    notes: &str,
) {
    let cpu_pct = runtime
        .cpu_pct
        .map_or_else(|| "-".to_string(), |value| format!("{value:.2}"));
    let rss_kib = runtime
        .rss_kib
        .map_or_else(|| "-".to_string(), |value| value.to_string());
    let peak_rss_kib = runtime
        .peak_rss_kib
        .map_or_else(|| "-".to_string(), |value| value.to_string());
    println!(
        "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
        "rate",
        options.profile.as_str(),
        scenario,
        payload_bytes,
        1,
        "-",
        "-",
        "-",
        "-",
        "-",
        "-",
        "-",
        runtime.elapsed_ns / 1_000_000,
        format!("{goodput_mbps:.3}"),
        format!("{wire_mbps:.3}"),
        cpu_pct,
        runtime.alloc.calls,
        runtime.alloc.bytes,
        rss_kib,
        peak_rss_kib,
        notes
    );
}

fn bench_handshake(options: Options) {
    let initiator = IdentityKeyPair::generate().expect("initiator identity");
    let responder = IdentityKeyPair::generate().expect("responder identity");
    let mut samples = Vec::with_capacity(options.iterations);
    let start = begin_measurement();
    for _ in 0..options.iterations {
        let sample_start = Instant::now();
        let mut init = build_hello_with_profile(&initiator, options.profile).expect("init hello");
        let mut resp = build_hello_with_profile(&responder, options.profile).expect("resp hello");
        if options.profile.uses_pqc() {
            let ct = finalize_initiator_pq(&mut init, &resp.local_hello).expect("encapsulate");
            absorb_responder_pq(&mut resp, &ct).expect("decapsulate");
        }
        let init_state = shph_core::verify_and_derive(&initiator, &init, &resp.local_hello, true)
            .expect("init derive");
        let resp_state = shph_core::verify_and_derive(&responder, &resp, &init.local_hello, false)
            .expect("resp derive");
        black_box((init_state, resp_state));
        samples.push(sample_start.elapsed().as_nanos());
    }
    emit_latency(
        "full_handshake",
        options,
        "full_handshake",
        0,
        &samples,
        finish_measurement(start),
        "in_memory_authenticated_setup",
    );
}

fn bench_latency_under_load(options: Options) {
    let payload = vec![0x42; 1024];
    let mut forward_send = SendCipher::new([1u8; 32]);
    let mut forward_recv = ReceiveCipher::new([1u8; 32]);
    let mut reverse_send = SendCipher::new([2u8; 32]);
    let mut reverse_recv = ReceiveCipher::new([2u8; 32]);
    let mut samples = Vec::with_capacity(options.frames);
    let start = begin_measurement();
    for _ in 0..options.frames {
        let sample_start = Instant::now();
        let forward = forward_send.encrypt(&payload).expect("forward encrypt");
        let forward_plain = forward_recv.decrypt(&forward).expect("forward decrypt");
        let reverse = reverse_send
            .encrypt(&forward_plain)
            .expect("reverse encrypt");
        let roundtrip = reverse_recv.decrypt(&reverse).expect("reverse decrypt");
        black_box(roundtrip);
        samples.push(sample_start.elapsed().as_nanos());
    }
    emit_latency(
        "rtt_under_load",
        options,
        "rtt_under_load_1k",
        payload.len(),
        &samples,
        finish_measurement(start),
        "in_memory_bidirectional_echo; p99_9_is_jitter_tail",
    );
}

fn bench_dataplane(options: Options, payload_bytes: usize) {
    let payload = vec![0x33; payload_bytes];
    let mut forward_send = SendCipher::new([3u8; 32]);
    let mut forward_recv = ReceiveCipher::new([3u8; 32]);
    let mut reverse_send = SendCipher::new([4u8; 32]);
    let mut reverse_recv = ReceiveCipher::new([4u8; 32]);
    let start = begin_measurement();
    let mut wire_bytes = 0u64;
    for _ in 0..options.frames {
        let forward = forward_send.encrypt(&payload).expect("forward encrypt");
        wire_bytes += forward.len() as u64;
        let forward_plain = forward_recv.decrypt(&forward).expect("forward decrypt");
        let reverse = reverse_send.encrypt(&payload).expect("reverse encrypt");
        wire_bytes += reverse.len() as u64;
        let reverse_plain = reverse_recv.decrypt(&reverse).expect("reverse decrypt");
        black_box((forward_plain, reverse_plain));
    }
    let runtime = finish_measurement(start);
    let seconds = runtime.elapsed_ns as f64 / 1_000_000_000.0;
    let goodput = (payload.len() * options.frames * 2) as f64 / seconds / 1_000_000.0;
    let wire_rate = wire_bytes as f64 / seconds / 1_000_000.0;
    emit_rate(
        options,
        "dataplane_bidirectional",
        payload_bytes,
        runtime,
        goodput,
        wire_rate,
        "in_memory_aead_goodput; not TUN or socket throughput",
    );
}

fn bench_replay(options: Options) {
    let mut window = ReplayWindow::new(128);
    let mut samples = Vec::with_capacity(options.frames);
    let start = begin_measurement();
    for nonce in 0..options.frames as u64 {
        let sample_start = Instant::now();
        black_box(window.check_and_insert(nonce));
        samples.push(sample_start.elapsed().as_nanos());
    }
    emit_latency(
        "replay_insert",
        options,
        "replay_window_long_session",
        0,
        &samples,
        finish_measurement(start),
        "nonce_window_state_transition",
    );
}

fn bench_resource_idle(options: Options) {
    let start = begin_measurement();
    black_box(Vec::<u8>::with_capacity(1));
    let runtime = finish_measurement(start);
    emit_rate(
        options,
        "resource_idle",
        0,
        runtime,
        0.0,
        0.0,
        "RSS_and_peak_RSS_are_process_values; run sustained suite for saturation",
    );
}

fn bench_shroud_profiles(options: Options) {
    for (name, profile) in [
        ("balanced", BALANCED),
        ("low-latency", LOW_LATENCY),
        ("bulk", BULK),
        ("randomized-lab", RANDOMIZED_LAB),
    ] {
        let payload_bytes = 256.min(profile.payload_capacity());
        let payload = vec![0x5a; payload_bytes];
        let mut samples = Vec::with_capacity(options.iterations);
        let start = begin_measurement();
        for _ in 0..options.iterations {
            let sample_start = Instant::now();
            let cell = encode_cell(profile, 0x01, &payload).expect("encode cell");
            let decoded = decode_cell(profile, &cell).expect("decode cell");
            black_box(decoded);
            samples.push(sample_start.elapsed().as_nanos());
        }
        let overhead_pct = (profile.cell_size as f64 / payload_bytes as f64 - 1.0) * 100.0;
        emit_latency(
            "shroud_profile",
            options,
            &format!("shroud_{name}"),
            payload_bytes,
            &samples,
            finish_measurement(start),
            &format!(
                "cell_bytes={};padding_overhead_pct={overhead_pct:.2};randomized_padding_not_modeled",
                profile.cell_size
            ),
        );
    }
}

fn bench_quic_loopback(options: Options) {
    let mut samples = Vec::with_capacity(options.iterations);
    let start = begin_measurement();
    for _ in 0..options.iterations {
        let sample_start = Instant::now();
        let mut completed = false;
        for _attempt in 0..5 {
            let probe = UdpSocket::bind("127.0.0.1:0").expect("UDP bind");
            let address = probe.local_addr().expect("UDP address");
            drop(probe);
            let server_identity = IdentityKeyPair::generate().expect("server identity");
            let client_identity = IdentityKeyPair::generate().expect("client identity");
            let server_profile = options.profile;
            let server = thread::spawn(move || {
                quic_handshake_server_with_profile(
                    &address.to_string(),
                    &server_identity,
                    1,
                    server_profile,
                )
            });
            let client = quic_handshake_client_with_profile(
                &address.to_string(),
                &client_identity,
                1,
                options.profile,
            );
            let server_result = server.join().expect("QUIC server thread");
            if let (Ok(client), Ok(server_result)) = (client, server_result) {
                black_box((client, server_result));
                completed = true;
                break;
            }
        }
        if !completed {
            panic!("QUIC loopback handshake did not complete after retries");
        }
        samples.push(sample_start.elapsed().as_nanos());
    }
    emit_latency(
        "quic_shim_handshake",
        options,
        "quic_shim_loopback_handshake",
        0,
        &samples,
        finish_measurement(start),
        "UDP_loopback; not standards_compliant_QUIC; no_loss_injection",
    );
}

fn bench_quic_impairment(options: Options) {
    let mut reorder_samples = Vec::with_capacity(options.iterations);
    let mut loss_samples = Vec::with_capacity(options.iterations);
    let start = begin_measurement();
    for iteration in 0..options.iterations {
        let payloads = [
            format!("quic-lab-{iteration}-first").into_bytes(),
            format!("quic-lab-{iteration}-second").into_bytes(),
        ];
        let key = [0x6bu8; 32];
        let mut sender = SendCipher::new(key);
        let first = sender.encrypt(&payloads[0]).expect("first frame");
        let second = sender.encrypt(&payloads[1]).expect("second frame");

        let reorder_start = Instant::now();
        let mut receiver = ReceiveCipher::new_with_replay_window(key, 128);
        let second_plain = receiver.decrypt(&second).expect("reordered second frame");
        let first_plain = receiver.decrypt(&first).expect("reordered first frame");
        assert_eq!(second_plain, payloads[1]);
        assert_eq!(first_plain, payloads[0]);
        reorder_samples.push(reorder_start.elapsed().as_nanos());

        let loss_start = Instant::now();
        let mut loss_receiver = ReceiveCipher::new_with_replay_window(key, 128);
        let delivered = loss_receiver.decrypt(&second).expect("post-loss frame");
        assert_eq!(delivered, payloads[1]);
        loss_samples.push(loss_start.elapsed().as_nanos());
    }
    let runtime = finish_measurement(start);
    emit_latency(
        "quic_shim_impairment",
        options,
        "quic_shim_reordering",
        0,
        &reorder_samples,
        runtime,
        "in_memory_authenticated_reordering; first frame intentionally delayed",
    );
    emit_latency(
        "quic_shim_impairment",
        options,
        "quic_shim_loss_tolerance",
        0,
        &loss_samples,
        runtime,
        "in_memory_one_frame_loss; receiver advances over missing nonce",
    );
    let mut limiter = shph_transport::PeerRateLimiterProbe::new();
    let mut accepted = 0usize;
    let mut rejected = 0usize;
    for _ in 0..(options.iterations.max(8) + 1) {
        if limiter.check("127.0.0.1:7000".parse().expect("probe address")) {
            accepted += 1;
        } else {
            rejected += 1;
        }
    }
    println!(
        "rate,{},{},{},1,,,,,,,,0,-,-,-,-,-,-,-,-,accepted={accepted};rejected={rejected};per_ip_rate_limit_probe",
        options.profile.as_str(),
        "quic_shim_rate_limit",
        0
    );
}

fn bench_long_session(options: Options) {
    let payload = vec![0x17; 64];
    let mut sender = SendCipher::new([8u8; 32]);
    let mut receiver = ReceiveCipher::new([8u8; 32]);
    let start = begin_measurement();
    for _ in 0..options.frames {
        let encrypted = sender.encrypt(&payload).expect("long-session encrypt");
        let decrypted = receiver.decrypt(&encrypted).expect("long-session decrypt");
        black_box(decrypted);
    }
    let runtime = finish_measurement(start);
    let seconds = runtime.elapsed_ns as f64 / 1_000_000_000.0;
    let goodput = (payload.len() * options.frames) as f64 / seconds / 1_000_000.0;
    emit_rate(
        options,
        "long_session",
        payload.len(),
        runtime,
        goodput,
        0.0,
        "single_key_nonce_and_replay_path; use --frames 1000000 for million-frame evidence",
    );
}
