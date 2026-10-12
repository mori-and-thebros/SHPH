use clap::Parser;
use shph_transport::onion::{relay_tls_acceptor, serve_relay, RelayLimits, RelayServerConfig};
use std::fs::File;
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::watch;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Parser)]
#[command(
    name = "shph-onion-relay",
    about = "Run one explicitly configured SHPH onion relay hop"
)]
struct Args {
    /// Numeric bind address; use operator-managed firewall restrictions.
    #[arg(long)]
    bind: SocketAddr,
    /// DER-encoded TLS server certificate.
    #[arg(long)]
    cert_der: PathBuf,
    /// DER-encoded PKCS#8 private key.
    #[arg(long)]
    key_pkcs8_der: PathBuf,
    /// Owner-protected file containing exactly 32 random authorization bytes.
    #[arg(long)]
    token_file: PathBuf,
    /// Exact numeric next-hop or destination socket; repeat for a small fixed allowlist.
    #[arg(long = "allow-target", required = true)]
    allow_targets: Vec<SocketAddr>,
    /// Maximum simultaneous circuits (1..=512).
    #[arg(long, default_value_t = 32)]
    max_circuits: usize,
    /// Maximum route setup duration in seconds (1..=30).
    #[arg(long, default_value_t = 10)]
    setup_timeout_secs: u64,
    /// Maximum lifetime of each circuit in seconds (1..=3600).
    #[arg(long, default_value_t = 300)]
    max_lifetime_secs: u64,
    /// Maximum bytes forwarded per circuit (1..=1 GiB).
    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    max_bytes_per_circuit: u64,
}

fn read_bounded(path: &Path, maximum: usize, label: &str) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::with_capacity(maximum.min(16 * 1024));
    File::open(path)
        .and_then(|file| file.take(maximum as u64 + 1).read_to_end(&mut bytes))
        .map_err(|error| format!("read {label}: {error}"))?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(format!(
            "{label} is empty or exceeds its {maximum}-byte limit"
        ));
    }
    Ok(bytes)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let certificate = read_bounded(&args.cert_der, 16 * 1024, "certificate")?;
    let private_key = read_bounded(&args.key_pkcs8_der, 16 * 1024, "private key")?;
    let mut token_bytes =
        Zeroizing::new(read_bounded(&args.token_file, 32, "authorization token")?);
    if token_bytes.len() != 32 {
        token_bytes.fill(0);
        return Err("authorization token must contain exactly 32 bytes".into());
    }
    let token: Zeroizing<[u8; 32]> = Zeroizing::new(
        token_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "authorization token must contain exactly 32 bytes")?,
    );
    token_bytes.zeroize();

    let limits = RelayLimits {
        max_circuits: args.max_circuits,
        setup_timeout: Duration::from_secs(args.setup_timeout_secs),
        max_lifetime: Duration::from_secs(args.max_lifetime_secs),
        max_bytes_per_circuit: args.max_bytes_per_circuit,
    };
    let config = RelayServerConfig::new(*token, args.allow_targets, limits)?;
    drop(token);
    let acceptor = relay_tls_acceptor(certificate, private_key)?;
    let listener = TcpListener::bind(args.bind).await?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = shutdown_tx.send(true);
    });
    serve_relay(listener, acceptor, config, shutdown_rx).await?;
    Ok(())
}
