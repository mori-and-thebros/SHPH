use shph_core::{
    absorb_responder_pq, build_hello_with_profile, decode_cell, decode_cell_payload, encode_cell,
    finalize_initiator_pq, HandshakeProfile, IdentityKeyPair, PeerPin, PeerPolicy, PqcKeypair,
    ReceiveCipher, ReplayWindow, SendCipher, StatelessCookieAuthority, BALANCED, BULK, LOW_LATENCY,
    RANDOMIZED_LAB,
};
use shph_identity::{
    DiscoveryProvider, DiscoveryResolver, IdentityEndpoint, IdentityError, IdentityId,
    IdentityRecord, LocalDirectoryProvider, PublishReceipt, VerificationPolicy, MAX_CAPABILITIES,
    MAX_ENDPOINTS, MAX_RECORD_BYTES,
};
use shph_transport::shroud2::{
    decode_batched_datagram, decode_datagram, encode_batched_datagram, encode_datagram,
    MorphologyBatchPolicy, MorphologyBatchPushResult, MorphologyBatcher, MorphologyEngine,
    MorphologyProfile,
};
use shph_transport::{
    quic_handshake_client_with_profile, quic_handshake_server_on_socket_with_profile,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::{BTreeSet, VecDeque};
use std::env;
use std::hint::black_box;
use std::net::{SocketAddr, UdpSocket};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

struct CountingAllocator;

static ALLOC_CALLS: AtomicU64 = AtomicU64::new(0);
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);
static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

struct StaticIdentityProvider {
    id: &'static str,
    records: Vec<IdentityRecord>,
}

impl DiscoveryProvider for StaticIdentityProvider {
    fn provider_id(&self) -> &str {
        self.id
    }

    fn publish(&self, record: &IdentityRecord) -> shph_identity::Result<PublishReceipt> {
        Ok(PublishReceipt {
            record_hash: record.record_hash()?,
        })
    }

    fn fetch(&self, _subject: &IdentityId) -> shph_identity::Result<Vec<IdentityRecord>> {
        Ok(self.records.clone())
    }
}

struct FailingIdentityProvider;

impl DiscoveryProvider for FailingIdentityProvider {
    fn provider_id(&self) -> &str {
        "failing"
    }

    fn publish(&self, _record: &IdentityRecord) -> shph_identity::Result<PublishReceipt> {
        Err(IdentityError::ProviderUnavailable(
            "benchmark provider unavailable".into(),
        ))
    }

    fn fetch(&self, _subject: &IdentityId) -> shph_identity::Result<Vec<IdentityRecord>> {
        Err(IdentityError::ProviderUnavailable(
            "benchmark provider unavailable".into(),
        ))
    }
}

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
    Identity,
    Wire,
    Evidence,
    Extended,
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

#[derive(Debug, Clone, Copy, Default)]
struct WireMetrics {
    wire_bytes_per_packet: Option<f64>,
    overhead_bytes: Option<f64>,
    overhead_pct: Option<f64>,
    packets_per_sec: Option<f64>,
}

const WIRE_UDP_IPV4_PAYLOAD_MTU: usize = 1_472;
const WIRE_AEAD_OVERHEAD: usize = 12 + 16;
const WIRE_MAX_AEAD_PAYLOAD: usize = WIRE_UDP_IPV4_PAYLOAD_MTU - WIRE_AEAD_OVERHEAD;
const WIRE_PAYLOAD_SIZES: &[usize] = &[
    64,
    256,
    1_024,
    1_200,
    1_280,
    1_400,
    1_420,
    WIRE_MAX_AEAD_PAYLOAD,
];
const WIRE_PATH_MTU: usize = WIRE_UDP_IPV4_PAYLOAD_MTU;
const EVIDENCE_OVERHEAD_PACKETS: usize = 5_000;
const EVIDENCE_COOKIE_PACKETS: usize = 50_000;
const EVIDENCE_REPLAY_PACKETS: usize = 500_000;
const EVIDENCE_MORPHOLOGY_PATH_MTU: usize = 1_472;
const EXTENDED_PATH_MTUS: &[usize] = &[1_200, 1_280, 1_360, 1_400, 1_472];
const EXTENDED_LOSS_PCTS: &[usize] = &[0, 1, 5, 10];
const EXTENDED_BATCH_SIZES: &[usize] = &[1, 2, 4, 8];
const EXTENDED_WORKERS: &[usize] = &[1, 2, 4, 8];
const EXTENDED_SESSION_COUNTS: &[usize] = &[1, 4, 16];
const EXTENDED_PATH_MTU: usize = 1_472;

fn main() {
    let options = parse_options();
    print_metadata(options);
    println!("measurement,profile,scenario,payload_bytes,samples,min_ns,p50_ns,p95_ns,p99_ns,p99_9_ns,max_ns,mean_ns,elapsed_ms,goodput_mbps,wire_mbps,cpu_pct,alloc_calls,alloc_bytes,rss_kib,peak_rss_kib,wire_bytes_per_packet,overhead_bytes,overhead_pct,packets_per_sec,notes");

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
        bench_shroud2_morphology(options);
        bench_shroud2_delay(options);
        bench_shroud2_long_session(options);
        bench_shroud2_impairment(options);
    }
    if matches!(options.suite, Suite::All | Suite::Quic) {
        bench_quic_loopback(options);
        bench_quic_impairment(options);
    }
    if matches!(options.suite, Suite::All | Suite::Scalability) {
        bench_long_session(options);
    }
    if matches!(options.suite, Suite::All | Suite::Identity) {
        bench_identity(options);
    }
    if matches!(options.suite, Suite::All | Suite::Wire) {
        bench_wire(options);
    }
    if matches!(options.suite, Suite::All | Suite::Evidence) {
        bench_evidence(options);
    }
    if matches!(options.suite, Suite::Extended) {
        bench_extended(options);
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
                println!(
                    "  --suite all|core|dataplane|resource|shroud|quic|scalability|identity|wire|evidence|extended"
                );
                println!("  --iterations N   latency samples (default: 100)");
                println!("  --frames N       sustained/load frames (default: 10000)");
                println!("Output includes latency, goodput, wire rate, packet overhead, CPU, RSS, and allocations.");
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
        "identity" => Suite::Identity,
        "wire" => Suite::Wire,
        "evidence" => Suite::Evidence,
        "extended" => Suite::Extended,
        _ => usage(
            "suite must be all, core, dataplane, resource, shroud, quic, scalability, identity, wire, evidence, or extended",
        ),
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
        "native-linux"
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
    emit_latency_with_wire(
        name,
        options,
        scenario,
        payload_bytes,
        samples,
        runtime,
        WireMetrics::default(),
        notes,
    );
}

#[allow(clippy::too_many_arguments)]
fn emit_latency_with_wire(
    name: &str,
    options: Options,
    scenario: &str,
    payload_bytes: usize,
    samples: &[u128],
    runtime: RuntimeStats,
    wire: WireMetrics,
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
    let wire_bytes = format_wire_metric(wire.wire_bytes_per_packet);
    let overhead_bytes = format_wire_metric(wire.overhead_bytes);
    let overhead_pct = format_wire_metric(wire.overhead_pct);
    let packets_per_sec = format_wire_metric(wire.packets_per_sec);
    println!(
        "{name},{profile},{scenario},{payload_bytes},{samples},{min},{p50},{p95},{p99},{p999},{max},{mean},{elapsed},-,-,{cpu},{alloc_calls},{alloc_bytes},{rss},{peak},{wire_bytes},{overhead_bytes},{overhead_pct},{packets_per_sec},{notes}",
        name = name,
        profile = options.profile.as_str(),
        scenario = scenario,
        payload_bytes = payload_bytes,
        samples = samples.len(),
        min = stats.min_ns,
        p50 = stats.p50_ns,
        p95 = stats.p95_ns,
        p99 = stats.p99_ns,
        p999 = stats.p999_ns,
        max = stats.max_ns,
        mean = stats.mean_ns,
        elapsed = runtime.elapsed_ns / 1_000_000,
        cpu = cpu_pct,
        alloc_calls = runtime.alloc.calls,
        alloc_bytes = runtime.alloc.bytes,
        rss = rss_kib,
        peak = peak_rss_kib,
        wire_bytes = wire_bytes,
        overhead_bytes = overhead_bytes,
        overhead_pct = overhead_pct,
        packets_per_sec = packets_per_sec,
        notes = notes,
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
    emit_rate_with_wire(
        options,
        scenario,
        payload_bytes,
        runtime,
        goodput_mbps,
        wire_mbps,
        WireMetrics::default(),
        notes,
    );
}

#[allow(clippy::too_many_arguments)]
fn emit_rate_with_wire(
    options: Options,
    scenario: &str,
    payload_bytes: usize,
    runtime: RuntimeStats,
    goodput_mbps: f64,
    wire_mbps: f64,
    wire_metrics: WireMetrics,
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
    let goodput = format!("{goodput_mbps:.3}");
    let wire = format!("{wire_mbps:.3}");
    let wire_bytes = format_wire_metric(wire_metrics.wire_bytes_per_packet);
    let overhead_bytes = format_wire_metric(wire_metrics.overhead_bytes);
    let overhead_pct = format_wire_metric(wire_metrics.overhead_pct);
    let packets_per_sec = format_wire_metric(wire_metrics.packets_per_sec);
    println!(
        "rate,{},{},{},1,-,-,-,-,-,-,-,{},{},{},{},{},{},{},{},{},{},{},{},{}",
        options.profile.as_str(),
        scenario,
        payload_bytes,
        runtime.elapsed_ns / 1_000_000,
        goodput,
        wire,
        cpu_pct,
        runtime.alloc.calls,
        runtime.alloc.bytes,
        rss_kib,
        peak_rss_kib,
        wire_bytes,
        overhead_bytes,
        overhead_pct,
        packets_per_sec,
        notes
    );
}

fn format_wire_metric(value: Option<f64>) -> String {
    value.map_or_else(|| "-".to_string(), |value| format!("{value:.3}"))
}

fn wire_latency_metrics(payload_bytes: usize, wire_bytes: usize) -> WireMetrics {
    let overhead_bytes = wire_bytes.saturating_sub(payload_bytes);
    WireMetrics {
        wire_bytes_per_packet: Some(wire_bytes as f64),
        overhead_bytes: Some(overhead_bytes as f64),
        overhead_pct: if payload_bytes == 0 {
            None
        } else {
            Some(overhead_bytes as f64 / payload_bytes as f64 * 100.0)
        },
        packets_per_sec: None,
    }
}

fn wire_rate_metrics(
    payload_bytes: usize,
    wire_bytes: usize,
    packets: usize,
    elapsed_ns: u128,
) -> WireMetrics {
    let seconds = elapsed_ns as f64 / 1_000_000_000.0;
    let packets_per_sec = packets as f64 / seconds;
    let wire_bytes_per_packet = wire_bytes as f64 / packets as f64;
    let overhead_bytes = (wire_bytes as f64 / packets as f64) - payload_bytes as f64;
    WireMetrics {
        wire_bytes_per_packet: Some(wire_bytes_per_packet),
        overhead_bytes: Some(overhead_bytes),
        overhead_pct: if payload_bytes == 0 {
            None
        } else {
            Some(overhead_bytes / payload_bytes as f64 * 100.0)
        },
        packets_per_sec: Some(packets_per_sec),
    }
}

fn aggregate_wire_metrics(
    payload_bytes: usize,
    wire_bytes: usize,
    packets: usize,
    elapsed_ns: u128,
) -> WireMetrics {
    let seconds = elapsed_ns as f64 / 1_000_000_000.0;
    let payload_per_packet = payload_bytes as f64 / packets as f64;
    let wire_bytes_per_packet = wire_bytes as f64 / packets as f64;
    let overhead_bytes = wire_bytes_per_packet - payload_per_packet;
    WireMetrics {
        wire_bytes_per_packet: Some(wire_bytes_per_packet),
        overhead_bytes: Some(overhead_bytes),
        overhead_pct: if payload_bytes == 0 {
            None
        } else {
            Some(overhead_bytes / payload_per_packet * 100.0)
        },
        packets_per_sec: Some(packets as f64 / seconds),
    }
}

fn bench_identity(options: Options) {
    let now = 1_800_000_000;
    let identity = IdentityKeyPair::generate().expect("identity benchmark key");
    let baseline = IdentityRecord::from_current_identity(
        &identity,
        1,
        now - 10,
        now + 3_600,
        vec![IdentityEndpoint::new("tcp", "198.51.100.10:51820", 10).expect("benchmark endpoint")],
        vec!["transport:tcp".into(), "kem:ml-kem-768".into()],
    )
    .expect("identity benchmark record");
    let baseline_json = baseline.to_json_bytes().expect("identity benchmark JSON");
    let policy = VerificationPolicy::at(now);

    let mut signing_samples = Vec::with_capacity(options.iterations);
    let signing_start = begin_measurement();
    for _ in 0..options.iterations {
        let sample_start = Instant::now();
        let signed = IdentityRecord::from_current_identity(
            &identity,
            1,
            now - 10,
            now + 3_600,
            Vec::new(),
            Vec::new(),
        )
        .expect("identity record sign");
        black_box(signed);
        signing_samples.push(sample_start.elapsed().as_nanos());
    }
    emit_latency(
        "identity_record_sign",
        options,
        "identity_record_sign",
        baseline_json.len(),
        &signing_samples,
        finish_measurement(signing_start),
        "local_ed25519_record_construction_and_signing",
    );

    let mut verify_samples = Vec::with_capacity(options.iterations);
    let verify_start = begin_measurement();
    for _ in 0..options.iterations {
        let sample_start = Instant::now();
        black_box(baseline.verify(policy).expect("identity record verify"));
        verify_samples.push(sample_start.elapsed().as_nanos());
    }
    emit_latency(
        "identity_record_verify",
        options,
        "identity_record_verify",
        baseline_json.len(),
        &verify_samples,
        finish_measurement(verify_start),
        "local_signature_freshness_and_structure_verification",
    );

    let mut parse_samples = Vec::with_capacity(options.iterations);
    let parse_start = begin_measurement();
    for _ in 0..options.iterations {
        let sample_start = Instant::now();
        black_box(IdentityRecord::from_json_bytes(&baseline_json).expect("identity record parse"));
        parse_samples.push(sample_start.elapsed().as_nanos());
    }
    emit_latency(
        "identity_record_parse",
        options,
        "identity_record_parse",
        baseline_json.len(),
        &parse_samples,
        finish_measurement(parse_start),
        "bounded_json_decode_and_structure_validation",
    );

    let provider_root = loop {
        let candidate = std::env::temp_dir().join(format!(
            "shph-identity-benchmark-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("benchmark clock")
                .as_nanos(),
            TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        match std::fs::create_dir(&candidate) {
            Ok(()) => break candidate,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("create identity benchmark directory: {error}"),
        }
    };
    let provider =
        LocalDirectoryProvider::new(&provider_root).expect("identity benchmark provider");
    provider
        .publish(&baseline)
        .expect("identity benchmark publish");
    let providers: [&dyn DiscoveryProvider; 1] = [&provider];
    let mut resolver = DiscoveryResolver::new();
    let mut resolve_samples = Vec::with_capacity(options.iterations);
    let resolve_start = begin_measurement();
    for _ in 0..options.iterations {
        let sample_start = Instant::now();
        black_box(
            resolver
                .resolve(&baseline.subject, &providers, policy)
                .expect("identity benchmark resolve"),
        );
        resolve_samples.push(sample_start.elapsed().as_nanos());
    }
    emit_latency(
        "identity_provider_resolve",
        options,
        "identity_provider_resolve",
        baseline_json.len(),
        &resolve_samples,
        finish_measurement(resolve_start),
        "local_plugin_fetch_verify_and_idempotent_resolve",
    );

    let mut publish_samples = Vec::with_capacity(options.iterations);
    let publish_start = begin_measurement();
    for _ in 0..options.iterations {
        let sample_start = Instant::now();
        black_box(
            provider
                .publish(&baseline)
                .expect("identity benchmark publish"),
        );
        publish_samples.push(sample_start.elapsed().as_nanos());
    }
    emit_latency(
        "identity_provider_publish",
        options,
        "identity_provider_publish_filesystem_idempotent",
        baseline_json.len(),
        &publish_samples,
        finish_measurement(publish_start),
        "local_plugin_idempotent_publish_and_conflict_check",
    );

    let memory_provider = StaticIdentityProvider {
        id: "memory",
        records: vec![baseline.clone()],
    };
    let memory_providers: [&dyn DiscoveryProvider; 1] = [&memory_provider];
    let mut memory_resolver = DiscoveryResolver::new();
    let mut memory_samples = Vec::with_capacity(options.iterations);
    let memory_start = begin_measurement();
    for _ in 0..options.iterations {
        let sample_start = Instant::now();
        black_box(
            memory_resolver
                .resolve(&baseline.subject, &memory_providers, policy)
                .expect("in-memory identity resolution"),
        );
        memory_samples.push(sample_start.elapsed().as_nanos());
    }
    emit_latency(
        "identity_provider_resolve",
        options,
        "identity_provider_resolve_in_memory",
        baseline_json.len(),
        &memory_samples,
        finish_measurement(memory_start),
        "in_memory_plugin_fetch_verify_and_idempotent_resolve",
    );

    let failing_provider = FailingIdentityProvider;
    let fanout_providers: [&dyn DiscoveryProvider; 2] = [&memory_provider, &failing_provider];
    let mut fanout_resolver = DiscoveryResolver::new();
    let mut fanout_samples = Vec::with_capacity(options.iterations);
    let fanout_start = begin_measurement();
    for _ in 0..options.iterations {
        let sample_start = Instant::now();
        black_box(
            fanout_resolver
                .resolve(&baseline.subject, &fanout_providers, policy)
                .expect("healthy provider should survive one failed provider"),
        );
        fanout_samples.push(sample_start.elapsed().as_nanos());
    }
    emit_latency(
        "identity_provider_resolve",
        options,
        "identity_provider_resolve_fanout_one_failure",
        baseline_json.len(),
        &fanout_samples,
        finish_measurement(fanout_start),
        "two_plugin_fanout_with_one_provider_failure",
    );

    let descriptor = memory_provider.descriptor();
    let mut descriptor_samples = Vec::with_capacity(options.iterations);
    let descriptor_start = begin_measurement();
    for _ in 0..options.iterations {
        let sample_start = Instant::now();
        black_box(descriptor.validate().is_ok());
        descriptor_samples.push(sample_start.elapsed().as_nanos());
    }
    emit_latency(
        "identity_plugin_descriptor_validate",
        options,
        "identity_plugin_descriptor_validate",
        0,
        &descriptor_samples,
        finish_measurement(descriptor_start),
        "bounded_plugin_api_and_capability_metadata_validation",
    );

    let malformed_json = br#"{"version":1,"keys":"invalid"}"#;
    let mut malformed_samples = Vec::with_capacity(options.iterations);
    let malformed_start = begin_measurement();
    for _ in 0..options.iterations {
        let sample_start = Instant::now();
        black_box(IdentityRecord::from_json_bytes(malformed_json).is_err());
        malformed_samples.push(sample_start.elapsed().as_nanos());
    }
    emit_latency(
        "identity_record_reject",
        options,
        "identity_record_reject_malformed",
        malformed_json.len(),
        &malformed_samples,
        finish_measurement(malformed_start),
        "malformed_record_fail_closed",
    );

    let oversized_json = vec![b'x'; MAX_RECORD_BYTES + 1];
    let mut oversized_samples = Vec::with_capacity(options.iterations);
    let oversized_start = begin_measurement();
    for _ in 0..options.iterations {
        let sample_start = Instant::now();
        black_box(IdentityRecord::from_json_bytes(&oversized_json).is_err());
        oversized_samples.push(sample_start.elapsed().as_nanos());
    }
    emit_latency(
        "identity_record_reject",
        options,
        "identity_record_reject_oversized",
        oversized_json.len(),
        &oversized_samples,
        finish_measurement(oversized_start),
        "record_size_limit_rejection",
    );

    let bounded_endpoints = (0..MAX_ENDPOINTS)
        .map(|index| {
            IdentityEndpoint::new(
                "tcp",
                format!("198.51.100.{}:51820", index % 255),
                index as u16,
            )
            .expect("bounded endpoint")
        })
        .collect();
    let bounded_capabilities = (0..MAX_CAPABILITIES)
        .map(|index| format!("capability-{index}-{}", "x".repeat(220)))
        .collect();
    let bounded_record = IdentityRecord::from_current_identity(
        &identity,
        1,
        now - 10,
        now + 3_600,
        bounded_endpoints,
        bounded_capabilities,
    )
    .expect("bounded identity record");
    let bounded_json = bounded_record
        .to_json_bytes()
        .expect("bounded identity JSON");

    let mut bounded_parse_samples = Vec::with_capacity(options.iterations);
    let bounded_parse_start = begin_measurement();
    for _ in 0..options.iterations {
        let sample_start = Instant::now();
        black_box(IdentityRecord::from_json_bytes(&bounded_json).expect("bounded parse"));
        bounded_parse_samples.push(sample_start.elapsed().as_nanos());
    }
    emit_latency(
        "identity_record_parse",
        options,
        "identity_record_parse_near_structure_limits",
        bounded_json.len(),
        &bounded_parse_samples,
        finish_measurement(bounded_parse_start),
        "maximum_endpoint_and_capability_counts",
    );

    let mut bounded_verify_samples = Vec::with_capacity(options.iterations);
    let bounded_verify_start = begin_measurement();
    for _ in 0..options.iterations {
        let sample_start = Instant::now();
        black_box(
            bounded_record
                .verify(policy)
                .expect("bounded identity verification"),
        );
        bounded_verify_samples.push(sample_start.elapsed().as_nanos());
    }
    emit_latency(
        "identity_record_verify",
        options,
        "identity_record_verify_near_structure_limits",
        bounded_json.len(),
        &bounded_verify_samples,
        finish_measurement(bounded_verify_start),
        "maximum_endpoint_and_capability_counts",
    );

    let other_identity = IdentityKeyPair::generate().expect("invalid-candidate identity");
    let invalid_candidate = IdentityRecord::from_current_identity(
        &other_identity,
        1,
        now - 10,
        now + 3_600,
        Vec::new(),
        Vec::new(),
    )
    .expect("invalid candidate record");
    let invalid_size = invalid_candidate
        .to_json_bytes()
        .expect("invalid candidate JSON")
        .len();
    let invalid_provider = StaticIdentityProvider {
        id: "invalid",
        records: vec![invalid_candidate],
    };
    let invalid_providers: [&dyn DiscoveryProvider; 1] = [&invalid_provider];
    let mut invalid_samples = Vec::with_capacity(options.iterations);
    let invalid_start = begin_measurement();
    for _ in 0..options.iterations {
        let sample_start = Instant::now();
        let mut resolver = DiscoveryResolver::new();
        black_box(
            resolver
                .resolve(&baseline.subject, &invalid_providers, policy)
                .is_err(),
        );
        invalid_samples.push(sample_start.elapsed().as_nanos());
    }
    emit_latency(
        "identity_provider_reject",
        options,
        "identity_provider_reject_subject_mismatch",
        invalid_size,
        &invalid_samples,
        finish_measurement(invalid_start),
        "candidate_subject_mismatch_rejected_before_signature_verification",
    );

    let mut conflict = baseline.clone();
    conflict.endpoints[0].priority = conflict.endpoints[0].priority.saturating_add(1);
    conflict.signatures.clear();
    conflict
        .sign_with_identity(&identity)
        .expect("conflicting identity record");
    let conflict_left = StaticIdentityProvider {
        id: "conflict-left",
        records: vec![baseline.clone()],
    };
    let conflict_right = StaticIdentityProvider {
        id: "conflict-right",
        records: vec![conflict.clone()],
    };
    let conflict_providers: [&dyn DiscoveryProvider; 2] = [&conflict_left, &conflict_right];
    let mut conflict_samples = Vec::with_capacity(options.iterations);
    let conflict_start = begin_measurement();
    for _ in 0..options.iterations {
        let sample_start = Instant::now();
        let mut resolver = DiscoveryResolver::new();
        black_box(
            resolver
                .resolve(&baseline.subject, &conflict_providers, policy)
                .is_err(),
        );
        conflict_samples.push(sample_start.elapsed().as_nanos());
    }
    emit_latency(
        "identity_provider_reject",
        options,
        "identity_provider_reject_conflicting_same_sequence",
        bounded_json.len(),
        &conflict_samples,
        finish_measurement(conflict_start),
        "same_sequence_conflict_fail_closed",
    );

    std::fs::remove_dir_all(provider_root).ok();
}

fn bench_handshake(options: Options) {
    let initiator = IdentityKeyPair::generate().expect("initiator identity");
    let responder = IdentityKeyPair::generate().expect("responder identity");
    let mut samples = Vec::with_capacity(options.iterations);
    let mut initial_hello_min = usize::MAX;
    let mut initial_hello_max = 0usize;
    let start = begin_measurement();
    for _ in 0..options.iterations {
        let sample_start = Instant::now();
        let mut init = build_hello_with_profile(&initiator, options.profile).expect("init hello");
        let mut resp = build_hello_with_profile(&responder, options.profile).expect("resp hello");
        for hello in [&init.local_hello, &resp.local_hello] {
            let hello_bytes = serde_json::to_vec(hello)
                .expect("serialize initial handshake hello")
                .len();
            initial_hello_min = initial_hello_min.min(hello_bytes);
            initial_hello_max = initial_hello_max.max(hello_bytes);
        }
        let initiator_hello = init.local_hello.clone();
        if options.profile.uses_pqc() {
            let ct = finalize_initiator_pq(
                &initiator,
                &mut init,
                &resp.local_hello,
                &shph_core::PeerPolicy::single(shph_core::PeerPin::for_identity(&responder)),
            )
            .expect("encapsulate");
            absorb_responder_pq(
                &responder,
                &mut resp,
                &initiator_hello,
                &ct,
                &PeerPolicy::single(PeerPin::for_identity(&initiator)),
            )
            .expect("decapsulate");
        }
        let init_state = shph_core::verify_and_derive(
            &initiator,
            &init,
            &resp.local_hello,
            true,
            &shph_core::PeerPolicy::single(shph_core::PeerPin::for_identity(&responder)),
        )
        .expect("init derive");
        let resp_state = shph_core::verify_and_derive(
            &responder,
            &resp,
            &initiator_hello,
            false,
            &shph_core::PeerPolicy::single(shph_core::PeerPin::for_identity(&initiator)),
        )
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
        &format!(
            "in_memory_authenticated_setup;canonical_initial_hello_bytes={initial_hello_min}..{initial_hello_max};tcp_stream_framing_not_single_tun_frame"
        ),
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

fn bench_wire(options: Options) {
    for &payload_bytes in WIRE_PAYLOAD_SIZES {
        bench_wire_aead_latency(options, payload_bytes);
        bench_wire_aead_rate(options, payload_bytes);
        bench_wire_udp_loopback(options, payload_bytes);
    }
    bench_wire_shroud2(options);
}

fn bench_wire_aead_latency(options: Options, payload_bytes: usize) {
    let payload = vec![0x4d; payload_bytes];
    let mut sender = SendCipher::new([0x51; 32]);
    let mut encode_samples = Vec::with_capacity(options.iterations);
    let mut wire_bytes = 0usize;
    let encode_start = begin_measurement();
    for _ in 0..options.iterations {
        let sample_start = Instant::now();
        let encrypted = sender.encrypt(&payload).expect("wire AEAD encode");
        wire_bytes = encrypted.len();
        black_box(encrypted);
        encode_samples.push(sample_start.elapsed().as_nanos());
    }
    emit_latency_with_wire(
        "wire_aead_encode",
        options,
        &format!("aead_encode_{payload_bytes}"),
        payload_bytes,
        &encode_samples,
        finish_measurement(encode_start),
        wire_latency_metrics(payload_bytes, wire_bytes),
        "in_memory_chacha20_poly1305_encode;udp_ip_headers_excluded;aead_overhead_bytes=28",
    );

    let mut preparation_sender = SendCipher::new([0x52; 32]);
    let frames = (0..options.iterations)
        .map(|_| {
            preparation_sender
                .encrypt(&payload)
                .expect("wire AEAD frame")
        })
        .collect::<Vec<_>>();
    let wire_bytes = frames.first().map_or(0, Vec::len);
    let mut receiver = ReceiveCipher::new_with_replay_window([0x52; 32], 128);
    let mut decode_samples = Vec::with_capacity(options.iterations);
    let decode_start = begin_measurement();
    for frame in &frames {
        let sample_start = Instant::now();
        let decrypted = receiver.decrypt(frame).expect("wire AEAD decode");
        black_box(decrypted);
        decode_samples.push(sample_start.elapsed().as_nanos());
    }
    emit_latency_with_wire(
        "wire_aead_decode",
        options,
        &format!("aead_decode_{payload_bytes}"),
        payload_bytes,
        &decode_samples,
        finish_measurement(decode_start),
        wire_latency_metrics(payload_bytes, wire_bytes),
        "in_memory_chacha20_poly1305_decode;udp_ip_headers_excluded;aead_overhead_bytes=28",
    );
}

fn bench_wire_aead_rate(options: Options, payload_bytes: usize) {
    let payload = vec![0x4d; payload_bytes];
    let mut sender = SendCipher::new([0x53; 32]);
    let mut receiver = ReceiveCipher::new_with_replay_window([0x53; 32], 128);
    let start = begin_measurement();
    let mut wire_bytes = 0usize;
    for _ in 0..options.frames {
        let encrypted = sender.encrypt(&payload).expect("wire AEAD encode");
        wire_bytes += encrypted.len();
        let decrypted = receiver.decrypt(&encrypted).expect("wire AEAD decode");
        black_box(decrypted);
    }
    let runtime = finish_measurement(start);
    let seconds = runtime.elapsed_ns as f64 / 1_000_000_000.0;
    emit_rate_with_wire(
        options,
        &format!("aead_roundtrip_{payload_bytes}"),
        payload_bytes,
        runtime,
        payload.len() as f64 * options.frames as f64 / seconds / 1_000_000.0,
        wire_bytes as f64 / seconds / 1_000_000.0,
        wire_rate_metrics(
            payload_bytes,
            wire_bytes,
            options.frames,
            runtime.elapsed_ns,
        ),
        "in_memory_chacha20_poly1305_encode_decode;one_packet_per_frame;udp_ip_headers_excluded;aead_overhead_bytes=28",
    );
}

fn bench_wire_udp_loopback(options: Options, payload_bytes: usize) {
    let receiver_socket = UdpSocket::bind("127.0.0.1:0").expect("wire UDP receiver bind");
    let sender_socket = UdpSocket::bind("127.0.0.1:0").expect("wire UDP sender bind");
    let receiver_addr = receiver_socket
        .local_addr()
        .expect("wire UDP receiver address");
    let sender_addr = sender_socket.local_addr().expect("wire UDP sender address");
    sender_socket
        .connect(receiver_addr)
        .expect("wire UDP sender connect");
    receiver_socket
        .connect(sender_addr)
        .expect("wire UDP receiver connect");
    sender_socket
        .set_write_timeout(Some(Duration::from_secs(2)))
        .expect("wire UDP write timeout");
    receiver_socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("wire UDP read timeout");

    let payload = vec![0x4e; payload_bytes];
    let mut sender = SendCipher::new([0x54; 32]);
    let mut receiver = ReceiveCipher::new_with_replay_window([0x54; 32], 128);
    let mut receive_buffer = vec![0u8; payload_bytes + 64];
    let start = begin_measurement();
    let mut wire_bytes = 0usize;
    for _ in 0..options.frames {
        let encrypted = sender.encrypt(&payload).expect("wire UDP encode");
        let sent = sender_socket.send(&encrypted).expect("wire UDP send");
        assert_eq!(sent, encrypted.len());
        let received = receiver_socket
            .recv(&mut receive_buffer)
            .expect("wire UDP receive");
        assert_eq!(received, encrypted.len());
        wire_bytes += sent;
        let decrypted = receiver
            .decrypt(&receive_buffer[..received])
            .expect("wire UDP decode");
        black_box(decrypted);
    }
    let runtime = finish_measurement(start);
    let seconds = runtime.elapsed_ns as f64 / 1_000_000_000.0;
    emit_rate_with_wire(
        options,
        &format!("udp_loopback_{payload_bytes}"),
        payload_bytes,
        runtime,
        payload.len() as f64 * options.frames as f64 / seconds / 1_000_000.0,
        wire_bytes as f64 / seconds / 1_000_000.0,
        wire_rate_metrics(payload_bytes, wire_bytes, options.frames, runtime.elapsed_ns),
        &format!(
            "connected_udp_loopback;authenticated_send_receive;udp_ip_headers_excluded;ipv4_udp_payload_mtu={WIRE_UDP_IPV4_PAYLOAD_MTU};aead_overhead_bytes={WIRE_AEAD_OVERHEAD}"
        ),
    );
}

fn bench_wire_shroud2(options: Options) {
    for &payload_bytes in WIRE_PAYLOAD_SIZES {
        let payload = vec![0x4f; payload_bytes];
        let mut morphology = MorphologyEngine::from_seed(
            MorphologyProfile::WebBrowsingLab,
            0x5749_5245 ^ payload_bytes as u64,
        );
        let start = begin_measurement();
        let mut wire_bytes = 0usize;
        let mut target_min = usize::MAX;
        let mut target_max = 0usize;
        for _ in 0..options.frames {
            let target = morphology
                .target_size(payload.len(), WIRE_PATH_MTU)
                .expect("wire Shroud2 target");
            let datagram =
                encode_datagram(&payload, target, WIRE_PATH_MTU).expect("wire Shroud2 encode");
            target_min = target_min.min(datagram.len());
            target_max = target_max.max(datagram.len());
            wire_bytes += datagram.len();
            let decoded = decode_datagram(&datagram, WIRE_PATH_MTU).expect("wire Shroud2 decode");
            assert_eq!(decoded, payload);
            black_box(decoded);
        }
        let runtime = finish_measurement(start);
        let seconds = runtime.elapsed_ns as f64 / 1_000_000_000.0;
        emit_rate_with_wire(
            options,
            &format!("shroud2_envelope_{payload_bytes}"),
            payload_bytes,
            runtime,
            payload.len() as f64 * options.frames as f64 / seconds / 1_000_000.0,
            wire_bytes as f64 / seconds / 1_000_000.0,
            wire_rate_metrics(payload_bytes, wire_bytes, options.frames, runtime.elapsed_ns),
            &format!(
                "in_memory_shroud2_encode_decode;profile=web-browsing-lab;path_mtu={WIRE_PATH_MTU};target_min={target_min};target_max={target_max};outer_envelope_bytes=7;udp_ip_headers_excluded;ipv4_ethernet_mtu=1500"
            ),
        );
    }
}

fn bench_evidence(options: Options) {
    bench_evidence_overhead_matrix(options);
    bench_evidence_cookie_gate(options);
    bench_evidence_replay_window(options);
}

fn bench_evidence_overhead_matrix(options: Options) {
    for (name, profile, seed) in [
        ("bulk", MorphologyProfile::BulkLab, 0x4255_4c4b),
        ("video", MorphologyProfile::VideoStreamingLab, 0x5649_4445),
        ("web", MorphologyProfile::WebBrowsingLab, 0x5745_4242),
        ("voip", MorphologyProfile::LowLatency, 0x564f_4950),
        ("ssh", MorphologyProfile::LowLatency, 0x5353_4821),
    ] {
        let mut morphology = MorphologyEngine::from_seed(profile, seed);
        let mut raw_bytes = 0usize;
        let mut wire_bytes = 0usize;
        let mut wire_sizes = BTreeSet::new();
        let start = begin_measurement();
        for packet in 0..EVIDENCE_OVERHEAD_PACKETS {
            let payload_len = evidence_payload_len(name, packet);
            let payload = vec![0x5a; payload_len];
            let target = morphology
                .target_size(payload.len(), EVIDENCE_MORPHOLOGY_PATH_MTU)
                .expect("evidence morphology target");
            let datagram = shph_transport::shroud2::encode_datagram(
                &payload,
                target,
                EVIDENCE_MORPHOLOGY_PATH_MTU,
            )
            .expect("evidence morphology encode");
            assert_eq!(
                shph_transport::shroud2::decode_datagram(&datagram, EVIDENCE_MORPHOLOGY_PATH_MTU)
                    .expect("evidence morphology decode"),
                payload
            );
            raw_bytes += payload.len();
            wire_bytes += datagram.len();
            wire_sizes.insert(datagram.len());
        }
        let runtime = finish_measurement(start);
        let seconds = runtime.elapsed_ns as f64 / 1_000_000_000.0;
        let raw_rate = raw_bytes as f64 / seconds / 1_000_000.0;
        let wire_rate = wire_bytes as f64 / seconds / 1_000_000.0;
        let metrics = aggregate_wire_metrics(
            raw_bytes,
            wire_bytes,
            EVIDENCE_OVERHEAD_PACKETS,
            runtime.elapsed_ns,
        );
        let size_set = wire_sizes
            .iter()
            .map(|size| size.to_string())
            .collect::<Vec<_>>()
            .join("|");
        let extra_bytes = wire_bytes.saturating_sub(raw_bytes);
        let selection = match profile {
            MorphologyProfile::LowLatency => {
                "weighted_smallest_fit;classes=128|256|512|1024;weights=65|25|8|2;mtu_cap=path_mtu"
            }
            MorphologyProfile::WebBrowsingLab => {
                "weighted_smallest_fit;classes=384|768|1024|1280|1536;weights=45|30|15|8|2;mtu_cap=path_mtu"
            }
            MorphologyProfile::VideoStreamingLab => {
                "weighted_smallest_fit;classes=1024|1280|1536|2048|4096;weights=45|30|15|8|2;mtu_cap=path_mtu"
            }
            MorphologyProfile::BulkLab => "uniform_profile_classes",
        };
        emit_rate_with_wire(
            options,
            &format!("shroud2_overhead_{name}"),
            raw_bytes / EVIDENCE_OVERHEAD_PACKETS,
            runtime,
            raw_rate,
            wire_rate,
            metrics,
            &format!(
                "packets={EVIDENCE_OVERHEAD_PACKETS};raw_total_bytes={raw_bytes};shroud2_total_bytes={wire_bytes};extra_bytes={extra_bytes};distinct_wire_sizes={};wire_size_set={size_set};profile={profile:?};selection={selection};path_mtu={EVIDENCE_MORPHOLOGY_PATH_MTU};raw_is_payload_only;ip_udp_headers_excluded",
                wire_sizes.len()
            ),
        );
    }
}

fn evidence_payload_len(profile: &str, packet: usize) -> usize {
    let mixed = evidence_mix64(
        packet as u64
            ^ match profile {
                "bulk" => 0x4255_4c4b,
                "video" => 0x5649_4445,
                "web" => 0x5745_4242,
                "voip" => 0x564f_4950,
                "ssh" => 0x5353_4821,
                _ => 0,
            },
    );
    match profile {
        "bulk" => 900 + (mixed % 501) as usize,
        "video" => 800 + (mixed % 601) as usize,
        "web" if packet.is_multiple_of(20) => 1_000 + (mixed % 401) as usize,
        "web" => 32 + (mixed % 768) as usize,
        "voip" => 24 + (mixed % 96) as usize,
        "ssh" => 1 + (mixed % 80) as usize,
        _ => 1,
    }
}

fn evidence_mix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn bench_evidence_cookie_gate(options: Options) {
    let responder = PqcKeypair::generate().expect("evidence ML-KEM keypair");
    let (ciphertext, _) =
        PqcKeypair::encapsulate_against(&responder.encap_public_bytes()).expect("evidence ML-KEM");
    let direct_start = begin_measurement();
    for _ in 0..EVIDENCE_COOKIE_PACKETS {
        let shared = responder
            .decapsulate(&ciphertext)
            .expect("evidence ML-KEM decapsulation");
        black_box(shared);
    }
    let direct_runtime = finish_measurement(direct_start);
    let direct_rate =
        EVIDENCE_COOKIE_PACKETS as f64 / (direct_runtime.elapsed_ns as f64 / 1_000_000_000.0);
    emit_rate_with_wire(
        options,
        "antidos_direct_mlkem_decapsulation",
        ciphertext.len(),
        direct_runtime,
        0.0,
        0.0,
        WireMetrics {
            packets_per_sec: Some(direct_rate),
            ..WireMetrics::default()
        },
        &format!(
            "packets={EVIDENCE_COOKIE_PACKETS};mlkem=ML-KEM-768;in_memory_crypto_only;not_network_flood_capacity"
        ),
    );

    let mut authority = StatelessCookieAuthority::new().expect("evidence cookie authority");
    let cookie_start = begin_measurement();
    let mut rejected = 0usize;
    for packet in 0..EVIDENCE_COOKIE_PACKETS {
        let peer = SocketAddr::from(([198, 51, 100, 7], 10_000 + packet as u16));
        let mut forged = authority.issue(peer).expect("evidence cookie issue");
        forged[0] ^= 1;
        if !authority
            .verify(peer, &forged)
            .expect("evidence cookie verify")
        {
            rejected += 1;
        }
    }
    let cookie_runtime = finish_measurement(cookie_start);
    let cookie_rate =
        EVIDENCE_COOKIE_PACKETS as f64 / (cookie_runtime.elapsed_ns as f64 / 1_000_000_000.0);
    emit_rate_with_wire(
        options,
        "antidos_stateless_cookie_gate",
        32,
        cookie_runtime,
        0.0,
        0.0,
        WireMetrics {
            packets_per_sec: Some(cookie_rate),
            ..WireMetrics::default()
        },
        &format!(
            "packets={EVIDENCE_COOKIE_PACKETS};rejected={rejected};cookie=rotating_HMAC-SHA256;issue_plus_invalid_verify;in_memory_crypto_only;not_network_flood_capacity"
        ),
    );

    let mut limiter = shph_transport::PeerRateLimiterProbe::new();
    let limiter_start = begin_measurement();
    let mut accepted = 0usize;
    for packet in 0..EVIDENCE_COOKIE_PACKETS {
        let peer = SocketAddr::from(([198, 51, 100, 7], 1_000 + packet as u16));
        if limiter.check(peer) {
            accepted += 1;
        }
    }
    let limiter_runtime = finish_measurement(limiter_start);
    let limiter_rate =
        EVIDENCE_COOKIE_PACKETS as f64 / (limiter_runtime.elapsed_ns as f64 / 1_000_000_000.0);
    emit_rate_with_wire(
        options,
        "antidos_per_source_rate_limiter",
        0,
        limiter_runtime,
        0.0,
        0.0,
        WireMetrics {
            packets_per_sec: Some(limiter_rate),
            ..WireMetrics::default()
        },
        &format!(
            "packets={EVIDENCE_COOKIE_PACKETS};accepted={accepted};rejected={};per_source_window=10s;limit=8;in_memory_pre_auth_path",
            EVIDENCE_COOKIE_PACKETS.saturating_sub(accepted)
        ),
    );
    println!(
        "# antidos_cookie_vs_direct_rate_factor={:.3};comparison_is_local_cpu_only",
        cookie_rate / direct_rate
    );
}

fn bench_evidence_replay_window(options: Options) {
    let mut window = ReplayWindow::new(128);
    let start = begin_measurement();
    let mut accepted = 0usize;
    let mut rejected = 0usize;
    for packet in 0..EVIDENCE_REPLAY_PACKETS {
        if window.check_and_insert(evidence_replay_nonce(packet)) {
            accepted += 1;
        } else {
            rejected += 1;
        }
    }
    let runtime = finish_measurement(start);
    let packets_per_sec =
        EVIDENCE_REPLAY_PACKETS as f64 / (runtime.elapsed_ns as f64 / 1_000_000_000.0);
    emit_rate_with_wire(
        options,
        "replay_window_128bit_evidence",
        0,
        runtime,
        0.0,
        0.0,
        WireMetrics {
            packets_per_sec: Some(packets_per_sec),
            ..WireMetrics::default()
        },
        &format!(
            "packets={EVIDENCE_REPLAY_PACKETS};accepted={accepted};rejected={rejected};window_bits=128;out_of_order_packets={};duplicate_replays={};single_threaded_Rust;in_memory_nonce_validation_only",
            EVIDENCE_REPLAY_PACKETS / 10,
            EVIDENCE_REPLAY_PACKETS / 20
        ),
    );
}

fn evidence_replay_nonce(packet: usize) -> u64 {
    let block = packet / 20;
    let position = packet % 20;
    let jittered = match position {
        8 => 9,
        9 => 8,
        other => other,
    };
    let effective = if jittered == 19 { 18 } else { jittered };
    (block * 20 + effective) as u64
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
        ("extreme-lab", shph_core::EXTREME_LAB),
    ] {
        let payload_bytes = 256.min(profile.max_payload_chunk);
        let payload = vec![0x5a; payload_bytes];
        let overhead_pct = (profile.cell_size as f64 / payload_bytes as f64 - 1.0) * 100.0;
        let framing_samples = measure_shroud_framing(profile, &payload, options.iterations);
        emit_latency(
            "shroud_framing",
            options,
            &format!("shroud_{name}_encode_decode"),
            payload_bytes,
            &framing_samples,
            runtime_for_samples(&framing_samples),
            &format!(
                "cell_bytes={};padding_overhead_pct={overhead_pct:.2};raw_cell_only",
                profile.cell_size
            ),
        );
        let aead_payload = shroud_aead_plaintext(profile, &payload);
        let aead_samples = measure_shroud_aead(&aead_payload, options.iterations);
        emit_latency(
            "shroud_aead",
            options,
            &format!("shroud_{name}_fixed_cell_aead"),
            payload_bytes,
            &aead_samples,
            runtime_for_samples(&aead_samples),
            &format!(
                "plaintext_bytes={};ciphertext_bytes={};fixed_cell_crypto_only",
                aead_payload.len(),
                aead_payload.len() + 12 + 16
            ),
        );
        let combined_samples = measure_shroud_framing(profile, &aead_payload, options.iterations);
        emit_latency(
            "shroud_profile",
            options,
            &format!("shroud_{name}"),
            payload_bytes,
            &combined_samples,
            runtime_for_samples(&combined_samples),
            &format!(
                "cell_bytes={};padding_overhead_pct={overhead_pct:.2};combined_raw_cell_path",
                profile.cell_size,
            ),
        );
        bench_shroud_decode_alloc(options, name, profile, &aead_payload);
    }
}

fn bench_shroud2_morphology(options: Options) {
    let payload = vec![0x5a; 1_024];
    let path_mtu = 1_450;
    for (name, profile) in [
        ("low-latency", MorphologyProfile::LowLatency),
        ("web-browsing-lab", MorphologyProfile::WebBrowsingLab),
        ("video-streaming-lab", MorphologyProfile::VideoStreamingLab),
        ("bulk-lab", MorphologyProfile::BulkLab),
    ] {
        let mut morphology = MorphologyEngine::from_seed(profile, 0x5348_524f_5544);
        let mut samples = Vec::with_capacity(options.iterations);
        let mut minimum_target = usize::MAX;
        let mut maximum_target = 0usize;
        let start = begin_measurement();
        for _ in 0..options.iterations {
            let sample_start = Instant::now();
            let target = morphology
                .target_size(payload.len(), path_mtu)
                .expect("morphology target");
            let datagram = encode_datagram(&payload, target, path_mtu).expect("morphology encode");
            let decoded = decode_datagram(&datagram, path_mtu).expect("morphology decode");
            black_box(decoded);
            minimum_target = minimum_target.min(target);
            maximum_target = maximum_target.max(target);
            samples.push(sample_start.elapsed().as_nanos());
        }
        emit_latency(
            "shroud2_morphology",
            options,
            &format!("shroud2_{name}_encode_decode"),
            payload.len(),
            &samples,
            finish_measurement(start),
            &format!(
                "path_mtu={path_mtu};target_min={minimum_target};target_max={maximum_target};random_padding=true;authenticated_quic_datagram_path"
            ),
        );
    }
}

fn bench_shroud2_delay(options: Options) {
    for (name, profile) in [
        ("low-latency", MorphologyProfile::LowLatency),
        ("web-browsing-lab", MorphologyProfile::WebBrowsingLab),
        ("video-streaming-lab", MorphologyProfile::VideoStreamingLab),
        ("bulk-lab", MorphologyProfile::BulkLab),
    ] {
        let mut morphology = MorphologyEngine::from_seed(profile, 0x5348_524f_5544);
        let start = begin_measurement();
        let samples = (0..options.iterations)
            .map(|_| morphology.next_delay().as_nanos())
            .collect::<Vec<_>>();
        let min_delay = samples.iter().copied().min().unwrap_or_default();
        let max_delay = samples.iter().copied().max().unwrap_or_default();
        emit_latency(
            "shroud2_delay",
            options,
            &format!("shroud2_{name}_sampled_delay"),
            0,
            &samples,
            finish_measurement(start),
            &format!(
                "sampled_inter_datagram_delay;min_delay_ns={min_delay};max_delay_ns={max_delay};no_scheduler_sleep"
            ),
        );
    }
}

fn bench_shroud2_long_session(options: Options) {
    let payload = vec![0x17; 1_024];
    let path_mtu = 1_450;
    let profile = MorphologyProfile::WebBrowsingLab;
    let mut morphology = MorphologyEngine::from_seed(profile, 0x4c4f_4e47);
    let mut delivered_bytes = 0usize;
    let mut wire_bytes = 0usize;
    let mut intended_delay_ns = 0u128;
    let start = begin_measurement();
    for _ in 0..options.frames {
        let target = morphology
            .target_size(payload.len(), path_mtu)
            .expect("long-session target");
        let datagram = encode_datagram(&payload, target, path_mtu).expect("long-session encode");
        let decoded = decode_datagram(&datagram, path_mtu).expect("long-session decode");
        assert_eq!(decoded, payload);
        delivered_bytes += decoded.len();
        wire_bytes += datagram.len();
        intended_delay_ns += morphology.next_delay().as_nanos();
    }
    let runtime = finish_measurement(start);
    let seconds = runtime.elapsed_ns as f64 / 1_000_000_000.0;
    emit_rate(
        options,
        "shroud2_long_session",
        payload.len(),
        runtime,
        delivered_bytes as f64 / seconds / 1_000_000.0,
        wire_bytes as f64 / seconds / 1_000_000.0,
        &format!(
            "profile=web-browsing-lab;frames={};intended_delay_ns={intended_delay_ns};local_encode_decode_only",
            options.frames
        ),
    );
}

fn bench_shroud2_impairment(options: Options) {
    let payload_size = 8;
    let path_mtu = 1_450;
    let profile = MorphologyProfile::WebBrowsingLab;
    let queue_capacity = 8usize;
    let mut morphology = MorphologyEngine::from_seed(profile, 0x494d_5041);
    let mut queue = VecDeque::with_capacity(queue_capacity);
    let mut delivered = 0usize;
    let mut injected_loss = 0usize;
    let mut congestion_drops = 0usize;
    let mut reordered = 0usize;
    let mut decode_failures = 0usize;
    let mut last_sequence = None;
    let start = begin_measurement();

    for sequence in 0..options.frames {
        if sequence % 17 == 0 {
            injected_loss += 1;
            continue;
        }
        if queue.len() >= queue_capacity {
            congestion_drops += 1;
            continue;
        }
        let payload = sequence.to_be_bytes();
        let target = morphology
            .target_size(payload_size, path_mtu)
            .expect("impairment target");
        let datagram = encode_datagram(&payload, target, path_mtu).expect("impairment encode");
        if sequence % 7 == 0 && !queue.is_empty() {
            queue.push_front((sequence, datagram));
        } else {
            queue.push_back((sequence, datagram));
        }

        if sequence % 16 == 15 {
            for _ in 0..3 {
                let Some((delivered_sequence, datagram)) = queue.pop_front() else {
                    break;
                };
                match last_sequence {
                    Some(previous) if delivered_sequence < previous => reordered += 1,
                    _ => {}
                }
                last_sequence = Some(delivered_sequence);
                match decode_datagram(&datagram, path_mtu) {
                    Ok(payload) if payload.len() == 8 => delivered += 1,
                    Ok(_) | Err(_) => decode_failures += 1,
                }
            }
        }
    }

    while let Some((delivered_sequence, datagram)) = queue.pop_front() {
        match last_sequence {
            Some(previous) if delivered_sequence < previous => reordered += 1,
            _ => {}
        }
        last_sequence = Some(delivered_sequence);
        match decode_datagram(&datagram, path_mtu) {
            Ok(payload) if payload.len() == 8 => delivered += 1,
            Ok(_) | Err(_) => decode_failures += 1,
        }
    }

    let runtime = finish_measurement(start);
    let seconds = runtime.elapsed_ns as f64 / 1_000_000_000.0;
    let goodput = delivered as f64 * payload_size as f64 / seconds / 1_000_000.0;
    let wire_rate = delivered as f64 * path_mtu as f64 / seconds / 1_000_000.0;
    emit_rate(
        options,
        "shroud2_impairment",
        payload_size,
        runtime,
        goodput,
        wire_rate,
        &format!(
            "profile=web-browsing-lab;frames={};queue_capacity={queue_capacity};injected_loss={injected_loss};congestion_drops={congestion_drops};reordered={reordered};delivered={delivered};decode_failures={decode_failures};deterministic_local_emulator",
            options.frames
        ),
    );
}

fn bench_extended(options: Options) {
    bench_batching_api(options);
    bench_adaptive_batching_api(options);
    bench_mtu_loss_matrix(options);
    bench_concurrent_sessions(options);
    bench_session_churn(options);
    bench_extended_repeatability_marker();
}

fn bench_batching_api(options: Options) {
    for (name, profile, maximum_batch_size) in [
        ("ssh", MorphologyProfile::LowLatency, 8usize),
        ("voip", MorphologyProfile::LowLatency, 8usize),
        ("web", MorphologyProfile::WebBrowsingLab, 4usize),
        ("video", MorphologyProfile::VideoStreamingLab, 4usize),
    ] {
        for &requested_batch_size in EXTENDED_BATCH_SIZES {
            if requested_batch_size > maximum_batch_size {
                continue;
            }
            let mut morphology =
                MorphologyEngine::from_seed(profile, 0x4241_5443 ^ requested_batch_size as u64);
            let mut processed = 0usize;
            let mut application_bytes = 0usize;
            let mut wire_bytes = 0usize;
            let mut delivered_messages = 0usize;
            let start = begin_measurement();

            while processed < options.frames {
                let message_count = requested_batch_size.min(options.frames - processed);
                let (messages, raw_application_bytes) =
                    make_extended_batch(name, processed, message_count);
                let datagram =
                    encode_batched_datagram(&mut morphology, &messages, EXTENDED_PATH_MTU)
                        .expect("batching API encode");
                let decoded = decode_batched_datagram(&datagram, EXTENDED_PATH_MTU)
                    .expect("batching API decode");
                assert_eq!(decoded.len(), message_count);
                let decoded_application_bytes = decoded.iter().map(Vec::len).sum::<usize>();
                assert_eq!(decoded_application_bytes, raw_application_bytes);
                application_bytes += decoded_application_bytes;
                wire_bytes += datagram.len();
                delivered_messages += message_count;
                processed += message_count;
                black_box(decoded);
            }

            let runtime = finish_measurement(start);
            let seconds = runtime.elapsed_ns as f64 / 1_000_000_000.0;
            let metrics = aggregate_wire_metrics(
                application_bytes,
                wire_bytes,
                delivered_messages,
                runtime.elapsed_ns,
            );
            emit_rate_with_wire(
                options,
                &format!("shroud2_batching_{name}_{requested_batch_size}"),
                application_bytes / delivered_messages.max(1),
                runtime,
                application_bytes as f64 / seconds / 1_000_000.0,
                wire_bytes as f64 / seconds / 1_000_000.0,
                metrics,
                &format!(
                    "authenticated_shroud2_batch_api;application_only_not_tun_batching;profile={profile:?};requested_batch_messages={requested_batch_size};batch_prefix_bytes=2;application_messages={delivered_messages};path_mtu={EXTENDED_PATH_MTU};in_memory_shroud2_encode_decode"
                ),
            );
        }
    }
}

fn bench_adaptive_batching_api(options: Options) {
    for (name, profile) in [
        ("ssh", MorphologyProfile::LowLatency),
        ("voip", MorphologyProfile::LowLatency),
        ("web", MorphologyProfile::WebBrowsingLab),
        ("video", MorphologyProfile::VideoStreamingLab),
    ] {
        let policy = MorphologyBatchPolicy::recommended(profile);
        let mut morphology = MorphologyEngine::from_seed(profile, 0x4144_5054 ^ name.len() as u64);
        let mut batcher = MorphologyBatcher::with_policy(policy);
        let mut application_bytes = 0usize;
        let mut wire_bytes = 0usize;
        let mut delivered_messages = 0usize;
        let mut batches = 0usize;
        let start = begin_measurement();

        for packet in 0..options.frames {
            let payload_len = extended_payload_len(name, packet);
            let payload = extended_payload(name, packet, payload_len);
            match batcher
                .push(&payload, EXTENDED_PATH_MTU)
                .expect("adaptive batching push")
            {
                MorphologyBatchPushResult::Buffered => {}
                MorphologyBatchPushResult::Flush(messages) => {
                    let datagram =
                        encode_batched_datagram(&mut morphology, &messages, EXTENDED_PATH_MTU)
                            .expect("adaptive batching encode");
                    let decoded = decode_batched_datagram(&datagram, EXTENDED_PATH_MTU)
                        .expect("adaptive batching decode");
                    assert_eq!(decoded, messages);
                    application_bytes += decoded.iter().map(Vec::len).sum::<usize>();
                    wire_bytes += datagram.len();
                    delivered_messages += decoded.len();
                    batches += 1;
                    black_box(decoded);
                }
            }
        }
        if let Some(messages) = batcher.flush() {
            let datagram = encode_batched_datagram(&mut morphology, &messages, EXTENDED_PATH_MTU)
                .expect("adaptive final batch encode");
            let decoded = decode_batched_datagram(&datagram, EXTENDED_PATH_MTU)
                .expect("adaptive final batch decode");
            assert_eq!(decoded, messages);
            application_bytes += decoded.iter().map(Vec::len).sum::<usize>();
            wire_bytes += datagram.len();
            delivered_messages += decoded.len();
            batches += 1;
            black_box(decoded);
        }

        let runtime = finish_measurement(start);
        let seconds = runtime.elapsed_ns as f64 / 1_000_000_000.0;
        let metrics = aggregate_wire_metrics(
            application_bytes,
            wire_bytes,
            delivered_messages,
            runtime.elapsed_ns,
        );
        emit_rate_with_wire(
            options,
            &format!("shroud2_adaptive_batching_{name}"),
            application_bytes / delivered_messages.max(1),
            runtime,
            application_bytes as f64 / seconds / 1_000_000.0,
            wire_bytes as f64 / seconds / 1_000_000.0,
            metrics,
            &format!(
                "authenticated_shroud2_batch_api;application_only_not_tun_batching;profile={profile:?};policy_max_messages={};policy_max_wait_ms={};batches={batches};application_messages={delivered_messages};path_mtu={EXTENDED_PATH_MTU};latency_deadline_is_caller_driven;in_memory_shroud2_encode_decode",
                policy.max_messages(),
                policy.max_wait().as_millis(),
            ),
        );
    }
}

fn bench_mtu_loss_matrix(options: Options) {
    for &path_mtu in EXTENDED_PATH_MTUS {
        for &loss_pct in EXTENDED_LOSS_PCTS {
            let mut morphology = MorphologyEngine::from_seed(
                MorphologyProfile::WebBrowsingLab,
                0x4d54_5500 ^ path_mtu as u64 ^ loss_pct as u64,
            );
            let mut attempted_bytes = 0usize;
            let mut wire_bytes = 0usize;
            let mut delivered_bytes = 0usize;
            let mut delivered_packets = 0usize;
            let mut dropped_packets = 0usize;
            let mut decode_failures = 0usize;
            let start = begin_measurement();

            for packet in 0..options.frames {
                let payload_len = extended_payload_len("web", packet);
                let payload = extended_payload("web", packet, payload_len);
                let target = morphology
                    .target_size(payload.len(), path_mtu)
                    .expect("MTU matrix target");
                let datagram =
                    encode_datagram(&payload, target, path_mtu).expect("MTU matrix encode");
                attempted_bytes += payload.len();
                wire_bytes += datagram.len();

                if extended_loss_hit(packet, path_mtu, loss_pct) {
                    dropped_packets += 1;
                    continue;
                }

                match decode_datagram(&datagram, path_mtu) {
                    Ok(decoded) if decoded.as_slice() == payload.as_slice() => {
                        delivered_packets += 1;
                        delivered_bytes += decoded.len();
                        black_box(decoded);
                    }
                    Ok(decoded) => {
                        decode_failures += 1;
                        black_box(decoded);
                    }
                    Err(_) => decode_failures += 1,
                }
            }

            let runtime = finish_measurement(start);
            let seconds = runtime.elapsed_ns as f64 / 1_000_000_000.0;
            let metrics = aggregate_wire_metrics(
                attempted_bytes,
                wire_bytes,
                options.frames,
                runtime.elapsed_ns,
            );
            emit_rate_with_wire(
                options,
                &format!("shroud2_mtu_loss_{path_mtu}_{loss_pct}"),
                attempted_bytes / options.frames,
                runtime,
                delivered_bytes as f64 / seconds / 1_000_000.0,
                wire_bytes as f64 / seconds / 1_000_000.0,
                metrics,
                &format!(
                    "local_deterministic_impairment_model;profile=WebBrowsingLab;path_mtu={path_mtu};loss_pct={loss_pct};attempted_packets={};delivered_packets={delivered_packets};dropped_packets={dropped_packets};decode_failures={decode_failures};not_network_path",
                    options.frames
                ),
            );
        }
    }
}

#[derive(Debug, Default)]
struct ExtendedSessionTotals {
    application_bytes: usize,
    wire_bytes: usize,
    delivered_packets: usize,
    decode_failures: usize,
}

fn bench_concurrent_sessions(options: Options) {
    for &worker_count in EXTENDED_WORKERS {
        let frames_per_worker = options.frames;
        let start = begin_measurement();
        let handles = (0..worker_count)
            .map(|worker| {
                thread::spawn(move || {
                    let mut totals = ExtendedSessionTotals::default();
                    let mut morphology = MorphologyEngine::from_seed(
                        MorphologyProfile::WebBrowsingLab,
                        0x434f_4e43 ^ worker as u64,
                    );
                    for frame in 0..frames_per_worker {
                        let payload_len = extended_payload_len(
                            "web",
                            worker
                                .saturating_mul(frames_per_worker)
                                .saturating_add(frame),
                        );
                        let sequence = worker
                            .saturating_mul(frames_per_worker)
                            .saturating_add(frame);
                        let payload = extended_payload("web", sequence, payload_len);
                        let target = morphology
                            .target_size(payload.len(), EXTENDED_PATH_MTU)
                            .expect("concurrency target");
                        let datagram = encode_datagram(&payload, target, EXTENDED_PATH_MTU)
                            .expect("concurrency encode");
                        totals.application_bytes += payload.len();
                        totals.wire_bytes += datagram.len();
                        match decode_datagram(&datagram, EXTENDED_PATH_MTU) {
                            Ok(decoded) if decoded.as_slice() == payload.as_slice() => {
                                totals.delivered_packets += 1;
                                black_box(decoded);
                            }
                            Ok(decoded) => {
                                totals.decode_failures += 1;
                                black_box(decoded);
                            }
                            Err(_) => totals.decode_failures += 1,
                        }
                    }
                    totals
                })
            })
            .collect::<Vec<_>>();
        let mut totals = ExtendedSessionTotals::default();
        for handle in handles {
            let worker_totals = handle.join().expect("concurrency worker");
            totals.application_bytes += worker_totals.application_bytes;
            totals.wire_bytes += worker_totals.wire_bytes;
            totals.delivered_packets += worker_totals.delivered_packets;
            totals.decode_failures += worker_totals.decode_failures;
        }
        let runtime = finish_measurement(start);
        let seconds = runtime.elapsed_ns as f64 / 1_000_000_000.0;
        let metrics = aggregate_wire_metrics(
            totals.application_bytes,
            totals.wire_bytes,
            totals.delivered_packets,
            runtime.elapsed_ns,
        );
        emit_rate_with_wire(
            options,
            &format!("shroud2_concurrent_sessions_{worker_count}"),
            totals.application_bytes / totals.delivered_packets.max(1),
            runtime,
            totals.application_bytes as f64 / seconds / 1_000_000.0,
            totals.wire_bytes as f64 / seconds / 1_000_000.0,
            metrics,
            &format!(
                "in_memory_concurrent_sessions;workers={worker_count};frames_per_worker={frames_per_worker};decode_failures={};thread_spawn_and_join_included;not_socket_or_tun_throughput",
                totals.decode_failures
            ),
        );
    }
}

fn bench_session_churn(options: Options) {
    for &requested_sessions in EXTENDED_SESSION_COUNTS {
        let session_count = requested_sessions.min(options.frames);
        let mut remaining_frames = options.frames;
        let mut application_bytes = 0usize;
        let mut wire_bytes = 0usize;
        let mut delivered_packets = 0usize;
        let mut decode_failures = 0usize;
        let start = begin_measurement();

        for session in 0..session_count {
            let sessions_left = session_count - session;
            let frames_this_session = remaining_frames.div_ceil(sessions_left);
            remaining_frames -= frames_this_session;
            let mut morphology = MorphologyEngine::from_seed(
                MorphologyProfile::WebBrowsingLab,
                0x4348_5552 ^ session as u64,
            );
            for frame in 0..frames_this_session {
                let sequence = session.saturating_mul(options.frames).saturating_add(frame);
                let payload_len = extended_payload_len("web", sequence);
                let payload = extended_payload("web", sequence, payload_len);
                let target = morphology
                    .target_size(payload.len(), EXTENDED_PATH_MTU)
                    .expect("session churn target");
                let datagram = encode_datagram(&payload, target, EXTENDED_PATH_MTU)
                    .expect("session churn encode");
                application_bytes += payload.len();
                wire_bytes += datagram.len();
                match decode_datagram(&datagram, EXTENDED_PATH_MTU) {
                    Ok(decoded) if decoded.as_slice() == payload.as_slice() => {
                        delivered_packets += 1;
                        black_box(decoded);
                    }
                    Ok(decoded) => {
                        decode_failures += 1;
                        black_box(decoded);
                    }
                    Err(_) => decode_failures += 1,
                }
            }
        }

        let runtime = finish_measurement(start);
        let seconds = runtime.elapsed_ns as f64 / 1_000_000_000.0;
        let metrics = aggregate_wire_metrics(
            application_bytes,
            wire_bytes,
            delivered_packets,
            runtime.elapsed_ns,
        );
        emit_rate_with_wire(
            options,
            &format!("shroud2_session_churn_{session_count}"),
            application_bytes / delivered_packets.max(1),
            runtime,
            application_bytes as f64 / seconds / 1_000_000.0,
            wire_bytes as f64 / seconds / 1_000_000.0,
            metrics,
            &format!(
                "sequential_session_churn_model;sessions={session_count};frames={};fresh_engine_per_session;decode_failures={decode_failures};not_network_reconnect_evidence",
                options.frames
            ),
        );
    }
}

fn bench_extended_repeatability_marker() {
    println!(
        "# extended_repeatability=use_scripts/benchmark_repeat.ps1_or_external_runner;the_binary_is_deterministically_seeded_but_padding_uses_os_randomness"
    );
    println!(
        "# extended_scope=authenticated_shroud2_batch_api_for_application_messages;native_tun_two_host_and_live_network_results_require_operator_runs"
    );
}

fn make_extended_batch(profile: &str, start: usize, message_count: usize) -> (Vec<Vec<u8>>, usize) {
    let mut messages = Vec::with_capacity(message_count);
    let mut application_bytes = 0usize;
    for message in 0..message_count {
        let sequence = start.saturating_add(message);
        let payload_len = extended_payload_len(profile, sequence);
        let payload = extended_payload(profile, sequence, payload_len);
        application_bytes += payload.len();
        messages.push(payload);
    }
    (messages, application_bytes)
}

fn extended_payload_len(profile: &str, packet: usize) -> usize {
    let mixed = evidence_mix64(
        packet as u64
            ^ match profile {
                "ssh" => 0x5353_4821,
                "voip" => 0x564f_4950,
                "web" => 0x5745_4242,
                "video" => 0x5649_4445,
                _ => 0,
            },
    );
    match profile {
        "ssh" => 1 + (mixed % 80) as usize,
        "voip" => 24 + (mixed % 96) as usize,
        "web" if packet.is_multiple_of(16) => 96 + (mixed % 96) as usize,
        "web" => 16 + (mixed % 80) as usize,
        "video" => 96 + (mixed % 112) as usize,
        _ => 1,
    }
}

fn extended_payload(profile: &str, packet: usize, payload_len: usize) -> Vec<u8> {
    let seed = evidence_mix64(packet as u64 ^ profile.len() as u64);
    vec![(seed & 0xff) as u8; payload_len]
}

fn extended_loss_hit(packet: usize, path_mtu: usize, loss_pct: usize) -> bool {
    loss_pct > 0
        && evidence_mix64(packet as u64 ^ ((path_mtu as u64) << 16)) % 100 < loss_pct as u64
}

fn shroud_aead_plaintext(profile: shph_core::ShroudProfile, payload: &[u8]) -> Vec<u8> {
    let plaintext_capacity = profile.payload_capacity() - (12 + 16);
    let mut padded = vec![0u8; plaintext_capacity];
    padded[..2].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    padded[2..2 + payload.len()].copy_from_slice(payload);
    padded
}

fn measure_shroud_framing(
    profile: shph_core::ShroudProfile,
    payload: &[u8],
    iterations: usize,
) -> Vec<u128> {
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let sample_start = Instant::now();
        let cell =
            encode_cell(profile, shph_core::SHROUD_FRAME_DATA, payload).expect("encode cell");
        let decoded = decode_cell(profile, &cell).expect("decode cell");
        black_box(decoded);
        samples.push(sample_start.elapsed().as_nanos());
    }
    samples
}

fn bench_shroud_decode_alloc(
    options: Options,
    name: &str,
    profile: shph_core::ShroudProfile,
    payload: &[u8],
) {
    let cell = encode_cell(profile, shph_core::SHROUD_FRAME_DATA, payload).expect("encode cell");

    let mut owned_samples = Vec::with_capacity(options.iterations);
    let owned_start = begin_measurement();
    for _ in 0..options.iterations {
        let sample_start = Instant::now();
        let decoded = decode_cell(profile, &cell).expect("owned decode");
        black_box(decoded);
        owned_samples.push(sample_start.elapsed().as_nanos());
    }
    emit_latency(
        "shroud_decode_owned",
        options,
        &format!("shroud_{name}_owned"),
        payload.len(),
        &owned_samples,
        finish_measurement(owned_start),
        "owned_payload_copy; allocation baseline",
    );

    let mut borrowed_samples = Vec::with_capacity(options.iterations);
    let borrowed_start = begin_measurement();
    for _ in 0..options.iterations {
        let sample_start = Instant::now();
        let decoded = decode_cell_payload(profile, &cell).expect("borrowed decode");
        black_box(decoded);
        borrowed_samples.push(sample_start.elapsed().as_nanos());
    }
    emit_latency(
        "shroud_decode_borrowed",
        options,
        &format!("shroud_{name}_borrowed"),
        payload.len(),
        &borrowed_samples,
        finish_measurement(borrowed_start),
        "borrowed_payload_view; no decode allocation",
    );
}

fn measure_shroud_aead(plaintext: &[u8], iterations: usize) -> Vec<u128> {
    let key = [0x42u8; 32];
    let mut sender = shph_core::SendCipher::new(key);
    let mut receiver = shph_core::ReceiveCipher::new_with_replay_window(key, 128);
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let sample_start = Instant::now();
        let encrypted = sender.encrypt(plaintext).expect("encrypt");
        let decrypted = receiver.decrypt(&encrypted).expect("decrypt");
        black_box(decrypted);
        samples.push(sample_start.elapsed().as_nanos());
    }
    samples
}

fn runtime_for_samples(samples: &[u128]) -> RuntimeStats {
    RuntimeStats {
        elapsed_ns: samples.iter().sum(),
        ..RuntimeStats::default()
    }
}

fn bench_quic_loopback(options: Options) {
    let mut samples = Vec::with_capacity(options.iterations);
    let start = begin_measurement();
    for _ in 0..options.iterations {
        let sample_start = Instant::now();
        let mut completed = false;
        for _attempt in 0..5 {
            let server_socket = UdpSocket::bind("127.0.0.1:0").expect("UDP bind");
            let address = server_socket.local_addr().expect("UDP address");
            let server_identity = IdentityKeyPair::generate().expect("server identity");
            let client_identity = IdentityKeyPair::generate().expect("client identity");
            let server_policy = PeerPolicy::single(PeerPin::for_identity(&client_identity));
            let client_policy = PeerPolicy::single(PeerPin::for_identity(&server_identity));
            let server_profile = options.profile;
            let server = thread::spawn(move || {
                quic_handshake_server_on_socket_with_profile(
                    server_socket,
                    &server_identity,
                    &server_policy,
                    1,
                    server_profile,
                )
            });
            let client = quic_handshake_client_with_profile(
                &address.to_string(),
                &client_identity,
                &client_policy,
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
        "rate,{},quic_shim_rate_limit,0,1,-,-,-,-,-,-,-,0,-,-,-,-,-,-,-,-,-,-,-,accepted={accepted};rejected={rejected};per_ip_rate_limit_probe",
        options.profile.as_str()
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

#[cfg(test)]
mod tests {
    use super::{
        evidence_payload_len, evidence_replay_nonce, extended_loss_hit, make_extended_batch,
        wire_latency_metrics, wire_rate_metrics, WIRE_AEAD_OVERHEAD, WIRE_MAX_AEAD_PAYLOAD,
        WIRE_PAYLOAD_SIZES, WIRE_UDP_IPV4_PAYLOAD_MTU,
    };

    #[test]
    fn wire_payload_matrix_stays_inside_ipv4_udp_budget() {
        assert_eq!(
            WIRE_MAX_AEAD_PAYLOAD + WIRE_AEAD_OVERHEAD,
            WIRE_UDP_IPV4_PAYLOAD_MTU
        );
        assert!(WIRE_PAYLOAD_SIZES
            .iter()
            .all(|payload| *payload + WIRE_AEAD_OVERHEAD <= WIRE_UDP_IPV4_PAYLOAD_MTU));
    }

    #[test]
    fn wire_metrics_report_fixed_aead_overhead() {
        let latency = wire_latency_metrics(1_000, 1_028);
        assert_eq!(latency.wire_bytes_per_packet, Some(1_028.0));
        assert_eq!(latency.overhead_bytes, Some(28.0));
        assert!((latency.overhead_pct.expect("latency overhead") - 2.8).abs() < 1e-9);
        assert_eq!(latency.packets_per_sec, None);

        let rate = wire_rate_metrics(1_000, 10_280, 10, 1_000_000_000);
        assert_eq!(rate.wire_bytes_per_packet, Some(1_028.0));
        assert_eq!(rate.overhead_bytes, Some(28.0));
        assert!((rate.overhead_pct.expect("rate overhead") - 2.8).abs() < 1e-9);
        assert_eq!(rate.packets_per_sec, Some(10.0));
    }

    #[test]
    fn evidence_payload_generators_are_bounded() {
        for profile in ["bulk", "video", "web", "voip", "ssh"] {
            for packet in 0..5_000 {
                let payload = evidence_payload_len(profile, packet);
                assert!(payload > 0);
                assert!(payload + 7 <= super::EVIDENCE_MORPHOLOGY_PATH_MTU);
            }
        }
    }

    #[test]
    fn evidence_replay_sequence_contains_the_declared_mix() {
        let first_block = (0..20).map(evidence_replay_nonce).collect::<Vec<_>>();
        assert_eq!(
            first_block,
            vec![0, 1, 2, 3, 4, 5, 6, 7, 9, 8, 10, 11, 12, 13, 14, 15, 16, 17, 18, 18]
        );
    }

    #[test]
    fn extended_batch_framing_round_trips_and_fits_the_path_mtu() {
        for (profile, batch_size) in [
            ("ssh", 8usize),
            ("voip", 8usize),
            ("web", 4usize),
            ("video", 4usize),
        ] {
            let (messages, application_bytes) = make_extended_batch(profile, 17, batch_size);
            let batch =
                shph_transport::shroud2::encode_batch_payload(&messages, super::EXTENDED_PATH_MTU)
                    .expect("batch payload");
            assert!(batch.len() + 7 <= super::EXTENDED_PATH_MTU);
            assert_eq!(
                shph_transport::shroud2::decode_batch_payload(&batch)
                    .expect("batch decode")
                    .iter()
                    .map(Vec::len)
                    .sum::<usize>(),
                application_bytes
            );
        }
    }

    #[test]
    fn extended_loss_model_is_disabled_at_zero_percent() {
        assert!((0..10_000).all(|packet| !extended_loss_hit(packet, super::EXTENDED_PATH_MTU, 0)));
    }
}
