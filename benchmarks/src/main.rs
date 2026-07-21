use shph_core::{
    absorb_responder_pq, build_hello_with_profile, decode_cell, encode_cell, finalize_initiator_pq,
    HandshakeProfile, IdentityKeyPair, ReplayWindow, SendCipher, BALANCED,
};
use std::env;
use std::hint::black_box;
use std::process::Command;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
struct Options {
    profile: HandshakeProfile,
    iterations: usize,
}

fn main() {
    let options = parse_options();
    print_metadata(options);
    println!("benchmark,profile,iterations,total_ns,mean_ns");
    bench_handshake(options);
    bench_framing(options);
    bench_aead(options);
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
    println!("# platform=native-linux");
    println!("# profile={}", options.profile.as_str());
    println!("# iterations={}", options.iterations);
    println!("# commit={}", command_output("git", &["rev-parse", "HEAD"]));
    println!("# rustc={}", command_output("rustc", &["--version"]));
    println!("# kernel={}", command_output("uname", &["-srvm"]));
    println!("# cpu={}", cpu_model());
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

fn report(name: &str, options: Options, elapsed: Duration) {
    let total_ns = elapsed.as_nanos();
    let mean_ns = total_ns / options.iterations as u128;
    println!(
        "{name},{},{},{total_ns},{mean_ns}",
        options.profile.as_str(),
        options.iterations
    );
}

fn bench_handshake(options: Options) {
    let initiator = IdentityKeyPair::generate().expect("initiator identity");
    let responder = IdentityKeyPair::generate().expect("responder identity");
    let start = Instant::now();
    for _ in 0..options.iterations {
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
    }
    report("full_handshake", options, start.elapsed());
}

fn bench_framing(options: Options) {
    let payload = vec![0x5a; 256];
    let start = Instant::now();
    for _ in 0..options.iterations {
        let cell = encode_cell(BALANCED, 0x01, &payload).expect("encode cell");
        let decoded = decode_cell(BALANCED, &cell).expect("decode cell");
        black_box(decoded);
    }
    report("framing_roundtrip", options, start.elapsed());
}

fn bench_aead(options: Options) {
    let mut cipher = SendCipher::new([7u8; 32]);
    let payload = vec![0x33; 1024];
    let start = Instant::now();
    for _ in 0..options.iterations {
        black_box(cipher.encrypt(&payload).expect("encrypt"));
    }
    report("aead_encrypt_1k", options, start.elapsed());
}

fn bench_replay(options: Options) {
    let mut window = ReplayWindow::new(128);
    let start = Instant::now();
    for nonce in 0..options.iterations as u64 {
        black_box(window.check_and_insert(nonce));
    }
    report("replay_insert", options, start.elapsed());
}
