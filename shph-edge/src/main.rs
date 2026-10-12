use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
#[cfg(feature = "http3")]
use shph_edge::carrier::{open_socks5_http3_until, serve_http3_until};
use shph_edge::{
    capability::CapabilityVerifier,
    carrier::{
        open_socks5_until, serve_http2_until, validate_h2_uri_with_path,
        MAX_CAPABILITY_TOKEN_FILE_BYTES,
    },
    config::EdgeConfig,
    file::{read_bounded_private_file, read_bounded_regular_file},
    frontdoor::FrontDoor,
};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Parser)]
#[command(name = "shph-edge", about = "Owned-domain Phantom One edge relay")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Serve {
        #[arg(long, value_enum, default_value_t = CarrierArg::H2)]
        carrier: CarrierArg,
        #[arg(long)]
        listen: std::net::SocketAddr,
        #[arg(long)]
        backend: String,
        #[arg(long)]
        audience: String,
        #[arg(long)]
        public_key_file: PathBuf,
        #[arg(long)]
        cert: Option<PathBuf>,
        #[arg(long)]
        key: Option<PathBuf>,
        #[arg(long, default_value = "/phantom-one/v1")]
        relay_path: String,
        #[arg(long, default_value_t = 64 * 1024 * 1024)]
        max_stream_bytes: u64,
        #[arg(long, default_value_t = 256)]
        max_capability_verifications_per_second: u64,
        #[arg(long, default_value_t = shph_edge::config::DEFAULT_HTTP2_IDLE_TIMEOUT_MS)]
        http2_idle_timeout_ms: u64,
        /// Normalize denied request status/body; timing equivalence is not implied.
        #[arg(long)]
        uniform_fallback: bool,
    },
    Connect {
        #[arg(long, value_enum, default_value_t = CarrierArg::H2)]
        carrier: CarrierArg,
        #[arg(long)]
        listen: std::net::SocketAddr,
        #[arg(long)]
        edge: http::Uri,
        #[arg(long)]
        token_file: PathBuf,
        #[arg(long)]
        ca_cert: PathBuf,
        #[arg(long, default_value = "edge.invalid")]
        server_name: String,
        #[arg(long, default_value = "/phantom-one/v1")]
        relay_path: String,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CarrierArg {
    H2,
    H3,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();
    match Cli::parse().command {
        Command::Serve {
            carrier,
            listen,
            backend,
            audience,
            public_key_file,
            cert,
            key,
            relay_path,
            max_stream_bytes,
            max_capability_verifications_per_second,
            http2_idle_timeout_ms,
            uniform_fallback,
        } => {
            if cert.is_none() || key.is_none() {
                anyhow::bail!(
                    "HTTP edge serving requires both --cert and --key; use an owned TLS endpoint"
                );
            }
            let public_key = read_public_key(&public_key_file)?;
            let config = EdgeConfig {
                listen,
                backend,
                audience: audience.clone(),
                public_key: String::new(),
                relay_path,
                tls: shph_edge::config::TlsConfig {
                    cert,
                    key,
                    ca: None,
                    server_name: "edge.invalid".into(),
                },
                limits: shph_edge::config::Limits {
                    max_stream_bytes,
                    max_capability_verifications_per_second,
                    http2_idle_timeout_ms,
                    ..Default::default()
                },
                socks: Default::default(),
            };
            config.validate().context("invalid serve configuration")?;
            let verifier = CapabilityVerifier::new(
                public_key,
                audience,
                config.max_lifetime(),
                Duration::from_secs(config.limits.clock_skew_secs),
            )?;
            let shutdown = CancellationToken::new();
            let signal_task = install_shutdown_listener(shutdown.clone());
            let front_door = Arc::new(
                FrontDoor::with_path(
                    verifier,
                    config.limits.max_token_bytes,
                    config.relay_path.clone(),
                )
                .context("invalid relay path")?
                .with_replay_capacity(config.limits.replay_capacity)
                .context("invalid replay capacity")?
                .with_max_verifications_per_second(
                    config.limits.max_capability_verifications_per_second,
                )
                .context("invalid capability verification rate")?
                .with_uniform_fallback(uniform_fallback),
            );
            let result = match carrier {
                CarrierArg::H2 => {
                    serve_http2_until(Arc::new(config.clone()), front_door, shutdown).await
                }
                CarrierArg::H3 => {
                    #[cfg(feature = "http3")]
                    {
                        serve_http3_until(Arc::new(config.clone()), front_door, shutdown).await
                    }
                    #[cfg(not(feature = "http3"))]
                    {
                        anyhow::bail!(
                            "HTTP/3 support was not compiled; rebuild shph-edge with --features http3"
                        );
                    }
                }
            };
            signal_task.abort();
            result?;
        }
        Command::Connect {
            carrier,
            listen,
            edge,
            token_file,
            ca_cert,
            server_name,
            relay_path,
        } => {
            let token = String::from_utf8(
                read_bounded_private_file(&token_file, MAX_CAPABILITY_TOKEN_FILE_BYTES as u64)
                    .with_context(|| "read capability token")?,
            )
            .context("capability token is not UTF-8")?
            .trim()
            .to_owned();
            if token.is_empty() || token.len() > MAX_CAPABILITY_TOKEN_FILE_BYTES {
                anyhow::bail!(
                    "capability token is empty or exceeds {} bytes",
                    MAX_CAPABILITY_TOKEN_FILE_BYTES
                );
            }
            validate_h2_uri_with_path(&edge, &relay_path).context("invalid edge URI")?;
            let config = EdgeConfig {
                listen,
                backend: "127.0.0.1:1".into(),
                audience: "unused".into(),
                public_key: String::new(),
                relay_path,
                tls: shph_edge::config::TlsConfig {
                    cert: None,
                    key: None,
                    ca: Some(ca_cert.clone()),
                    server_name,
                },
                limits: Default::default(),
                socks: shph_edge::config::SocksConfig {
                    listen,
                    ..Default::default()
                },
            };
            let shutdown = CancellationToken::new();
            let signal_task = install_shutdown_listener(shutdown.clone());
            let result = match carrier {
                CarrierArg::H2 => {
                    open_socks5_until(Arc::new(config), edge, token, &ca_cert, shutdown).await
                }
                CarrierArg::H3 => {
                    #[cfg(feature = "http3")]
                    {
                        open_socks5_http3_until(Arc::new(config), edge, token, &ca_cert, shutdown)
                            .await
                    }
                    #[cfg(not(feature = "http3"))]
                    {
                        anyhow::bail!(
                            "HTTP/3 support was not compiled; rebuild shph-edge with --features http3"
                        );
                    }
                }
            };
            signal_task.abort();
            result?;
        }
    }
    Ok(())
}

fn install_shutdown_listener(shutdown: CancellationToken) -> JoinHandle<()> {
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut terminate) => {
                    tokio::select! {
                        result = tokio::signal::ctrl_c() => {
                            if result.is_err() {
                                tracing::error!("failed to receive Ctrl+C");
                            }
                        }
                        _ = terminate.recv() => {}
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, "failed to install SIGTERM handler; waiting for Ctrl+C");
                    if tokio::signal::ctrl_c().await.is_err() {
                        tracing::error!("failed to receive Ctrl+C");
                    }
                }
            }
        }
        #[cfg(not(unix))]
        if tokio::signal::ctrl_c().await.is_err() {
            tracing::error!("failed to receive Ctrl+C");
        }
        shutdown.cancel();
    })
}

fn read_public_key(path: &Path) -> Result<[u8; 32]> {
    let bytes = read_bounded_regular_file(path, 4096).with_context(|| "read Ed25519 public key")?;
    if bytes.len() == 32 {
        return Ok(bytes.try_into().expect("length checked"));
    }
    let text = String::from_utf8(bytes).context("public key must be raw 32 bytes or hex")?;
    let decoded = hex_decode(text.trim()).context("public key must be raw 32 bytes or hex")?;
    decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("public key must be exactly 32 bytes"))
}

fn hex_decode(value: &str) -> Result<Vec<u8>> {
    if value.len() != 64 {
        anyhow::bail!("hex public key must contain 64 characters");
    }
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).map_err(Into::into))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serve_accepts_an_explicit_http2_idle_timeout() {
        let cli = Cli::try_parse_from([
            "shph-edge",
            "serve",
            "--listen",
            "127.0.0.1:8443",
            "--backend",
            "127.0.0.1:9000",
            "--audience",
            "edge-a",
            "--public-key-file",
            "public-key.hex",
            "--http2-idle-timeout-ms",
            "12000",
        ])
        .expect("valid serve arguments");

        match cli.command {
            Command::Serve {
                http2_idle_timeout_ms,
                ..
            } => assert_eq!(http2_idle_timeout_ms, 12_000),
            Command::Connect { .. } => panic!("expected serve command"),
        }
    }
}
