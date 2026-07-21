use shph_core::{
    absorb_responder_pq, build_hello_with_profile, decode_cell, encode_cell, finalize_initiator_pq,
    HandshakeProfile, IdentityKeyPair, ReplayWindow, SendCipher, BALANCED,
};
use std::env;
use std::hint::black_box;
use std::process::Command;
use std::time::Instant;

#[derive(Debug, Clone, Copy)]
struct Options {
    profile: HandshakeProfile,
    iterations: usize,
}

#[derive(Debug, Clone, Copy)]
struct LatencyStats {
    min_ns: u128,
    p50_ns: u128,
    p95_ns: u128,
    p99_ns: u128,
    max_ns: u128,
    mean_ns: u128,
}

fn main() {
    let options = parse_options();
    print_metadata(options);
    println!(
        "benchmark,profile,payload_bytes,iterations,min_ns,p50_ns,p95_ns,p99_ns,max_ns,mean_ns"
    );
    bench_handshake(options);
    for payload_bytes in [64, 256, 1024, 4096] {
        bench_framing(options, payload_bytes);
        bench_aead(options, payload_bytes);
    }
    bench_replay(options);
}

fn parse_options() -> Options {
    let mut profile = HandshakeProfile::SecureDefault;
    let mut iterations = 100;
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
            "--iterations" => {
                iterations = args
                    .next()
                    .unwrap_or_else(|| usage("missing value for --iterations"))
                    .parse()
                    .unwrap_or_else(|_| usage("iterations must be a positive integer"));
                if iterations == 0 {
                    usage("iterations must be a positive integer");
                }
            }
            "--help" | "-h" => {
                println!(
                    "Usage: shph-benchmarks [--profile secure-default|classical-lab] [--iterations N]"
                );
                println!("Measures handshake latency, framing, AEAD, and replay operations.");
                println!("Output columns include min/p50/p95/p99/max/mean nanoseconds.");
                std::process::exit(0);
            }
            other => usage(&format!("unknown argument: {other}")),
        }
    }
    Options {
        profile,
        iterations,
    }
}

fn usage(message: &str) -> ! {
    eprintln!("{message}");
    eprintln!("Usage: shph-benchmarks [--profile secure-default|classical-lab] [--iterations N]");
    std::process::exit(2);
}

fn print_metadata(options: Options) {
    println!("# platform={}", platform_name());
    println!("# profile={}", options.profile.as_str());
    println!("# iterations={}", options.iterations);
    println!("# commit={}", command_output("git", &["rev-parse", "HEAD"]));
    println!("# rustc={}", command_output("rustc", &["--version"]));
    println!("# kernel={}", command_output("uname", &["-srvm"]));
    println!("# cpu={}", cpu_model());
    println!("# benchmark_clock=std::time::Instant");
    println!("# build_profile=release");
    println!("# note=measurements are local operation latency, not network RTT");
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

fn report_samples(name: &str, options: Options, payload_bytes: usize, samples: Vec<u128>) {
    report_stats(name, options, payload_bytes, stats_from_samples(&samples));
}

fn report_stats(name: &str, options: Options, payload_bytes: usize, stats: LatencyStats) {
    println!(
        "{name},{},{},{},{},{},{},{},{},{}",
        options.profile.as_str(),
        payload_bytes,
        options.iterations,
        stats.min_ns,
        stats.p50_ns,
        stats.p95_ns,
        stats.p99_ns,
        stats.max_ns,
        stats.mean_ns
    );
}

fn stats_from_samples(samples: &[u128]) -> LatencyStats {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let percentile = |percent: usize| {
        let index = ((sorted.len().saturating_sub(1) * percent) / 100).min(sorted.len() - 1);
        sorted[index]
    };
    LatencyStats {
        min_ns: sorted[0],
        p50_ns: percentile(50),
        p95_ns: percentile(95),
        p99_ns: percentile(99),
        max_ns: sorted[sorted.len() - 1],
        mean_ns: sorted.iter().sum::<u128>() / sorted.len() as u128,
    }
}

fn bench_handshake(options: Options) {
    let initiator = IdentityKeyPair::generate().expect("initiator identity");
    let responder = IdentityKeyPair::generate().expect("responder identity");
    let mut samples = Vec::with_capacity(options.iterations);
    for _ in 0..options.iterations {
        let start = Instant::now();
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
        samples.push(start.elapsed().as_nanos());
    }
    report_samples("full_handshake", options, 0, samples);
}

fn bench_framing(options: Options, payload_bytes: usize) {
    let payload = vec![0x5a; payload_bytes.min(BALANCED.payload_capacity())];
    let mut samples = Vec::with_capacity(options.iterations);
    for _ in 0..options.iterations {
        let start = Instant::now();
        let cell = encode_cell(BALANCED, 0x01, &payload).expect("encode cell");
        let decoded = decode_cell(BALANCED, &cell).expect("decode cell");
        black_box(decoded);
        samples.push(start.elapsed().as_nanos());
    }
    report_samples("framing_roundtrip", options, payload.len(), samples);
}

fn bench_aead(options: Options, payload_bytes: usize) {
    let payload = vec![0x33; payload_bytes];
    let mut samples = Vec::with_capacity(options.iterations);
    for _ in 0..options.iterations {
        let mut cipher = SendCipher::new([7u8; 32]);
        let start = Instant::now();
        black_box(cipher.encrypt(&payload).expect("encrypt"));
        samples.push(start.elapsed().as_nanos());
    }
    report_samples("aead_encrypt", options, payload_bytes, samples);
}

fn bench_replay(options: Options) {
    let mut window = ReplayWindow::new(128);
    let mut samples = Vec::with_capacity(options.iterations);
    for nonce in 0..options.iterations as u64 {
        let start = Instant::now();
        black_box(window.check_and_insert(nonce));
        samples.push(start.elapsed().as_nanos());
    }
    report_samples("replay_insert", options, 0, samples);
}
