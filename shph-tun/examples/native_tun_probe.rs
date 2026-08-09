#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("native TUN probe is Linux-only");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() {
    let hold_ms = std::env::args()
        .skip(1)
        .collect::<Vec<_>>()
        .windows(2)
        .find(|args| args[0] == "--hold-ms")
        .and_then(|args| args[1].parse::<u64>().ok())
        .unwrap_or(250);

    let device = match shph_tun::AsyncTunDevice::open_native("shphasync0").await {
        Ok(device) => device,
        Err(error) => {
            eprintln!("native TUN probe failed: {error}");
            std::process::exit(1);
        }
    };

    println!("native_tun_probe interface={}", device.name());
    tokio::time::sleep(std::time::Duration::from_millis(hold_ms)).await;
}
