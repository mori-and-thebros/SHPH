//! SHPH CLI - Command-line interface for Shroud-Phantom VPN.

mod shutdown;
mod ticket;

use base64::Engine as _;
use clap::{Parser, Subcommand};
use rand::Rng;
use serde::{Deserialize, Serialize};
use shph_config::{
    Config, ControlPlaneConfig, PeerConfig, ReconnectConfig, SessionConfig, SessionRole,
    StealthConfig,
};
use shph_core::{
    append_ratchet_audit_event, build_hello, compute_fingerprint_hex, ensure_no_reparse_components,
    read_ratchet_audit_events, recover_secret_from_shares,
    roadmap::{DataMuleConfig, OfflineMeshConfig, RoadmapConfig},
    split_secret, validate_identity_provider, validate_roadmap, verify_and_derive, Contact,
    Endpoint, HandshakeProfile, HandshakeState, KeyStore, KeyStoreConfig, MetricsCollector,
    PeerPin, PeerPolicy, Result, ShamirShare, ShphError,
};
#[cfg(target_os = "linux")]
use shph_transport::standards_tun;
use shph_transport::{
    accept_secure_session_lab_with_profile, connect_secure_session_lab_with_profile,
    data_mule_accept_and_handshake_with_profile, data_mule_accept_secure_session_with_profile,
    data_mule_connect_and_handshake_with_profile, data_mule_connect_secure_session_with_profile,
    offline_mesh_accept_and_handshake_with_profile,
    offline_mesh_accept_secure_session_with_profile,
    offline_mesh_connect_and_handshake_with_profile,
    offline_mesh_connect_secure_session_with_profile, quic_handshake_client_with_profile,
    quic_handshake_server_with_profile, standards_quic, tcp_handshake_client_with_profile,
    tcp_handshake_server_with_profile, QuicLabConfig, SecureReceiver, SecureSender, SecureSession,
    TransportMode,
};
use shph_tun::firewall::FirewallTransport;
#[cfg(target_os = "linux")]
use shph_tun::firewall::{
    build_linux_killswitch_cleanup_commands, build_linux_killswitch_commands,
    build_linux_mss_clamp_cleanup_commands, build_linux_mss_clamp_commands,
    build_linux_nat_cleanup_commands, build_linux_nat_commands, KILLSWITCH_TABLE_NAME,
    MSS_CLAMP_TABLE_NAME, NAT_TABLE_NAME,
};
#[cfg(target_os = "linux")]
use shph_tun::AsyncTunDevice;
use shph_tun::{
    validate_tun_mtu, validate_tun_name, TunDevice, DEFAULT_TUN_MTU_BYTES, TUN_READ_BUFFER_BYTES,
};
#[cfg(target_os = "windows")]
use shph_tun::{WindowsFirewallTransport, WindowsKillswitchGuard};
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::net::{IpAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
#[cfg(not(test))]
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{future::Future, net::SocketAddr};
use zeroize::Zeroize;

use ticket::{render_qr, JoinTicket};

const MAX_STDIN_LINE_BYTES: usize = 64 * 1024;
const MAX_SHAMIR_SECRET_BYTES: u64 = 64 * 1024;
const MAX_SHAMIR_SHARE_FILES: usize = 255;
const MAX_SHAMIR_SHARE_FILE_BYTES: u64 = 256 * 1024;
const MAX_SHAMIR_TOTAL_BYTES: u64 = 8 * 1024 * 1024;
const MAX_SHAMIR_TOTAL_SHARES: usize = 255;
const MAX_CONTROL_PLANE_STATE_BYTES: u64 = 64 * 1024;
const QUIC_PAYLOAD_ACK: &[u8] = b"shph/standards-quic/payload-ack-v1";
const EXIT_FAILURE: i32 = 1;
const EXIT_USAGE: i32 = 2;
const EXIT_NOT_FOUND: i32 = 66;
const EXIT_UNAVAILABLE: i32 = 69;
const EXIT_TEMPORARY: i32 = 75;
const EXIT_PERMISSION: i32 = 77;
const EXIT_CONFIG: i32 = 78;

fn phase_a1_now_ms() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ShphError::Internal("system clock before unix epoch".into()))?
        .as_millis() as u64)
}

struct LiveStatusBar {
    stop: Option<Arc<AtomicBool>>,
    worker: Option<thread::JoinHandle<()>>,
}

impl LiveStatusBar {
    fn start(
        endpoint: &str,
        interface_name: &str,
        profile: HandshakeProfile,
        handshake_ms: u128,
        metrics: &MetricsCollector,
    ) -> Self {
        if !io::stderr().is_terminal() {
            return Self {
                stop: None,
                worker: None,
            };
        }

        let stop = Arc::new(AtomicBool::new(false));
        let stop_worker = Arc::clone(&stop);
        let endpoint = sanitize_status_label(endpoint);
        let interface_name = sanitize_status_label(interface_name);
        let metrics = metrics.clone();
        let worker = thread::spawn(move || {
            let mut previous = metrics.snapshot();
            while !stop_worker.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_secs(1));
                if stop_worker.load(Ordering::Relaxed) {
                    break;
                }
                let current = metrics.snapshot();
                let tx_rate = current.bytes_sent.saturating_sub(previous.bytes_sent) as f64;
                let rx_rate = current.bytes_recv.saturating_sub(previous.bytes_recv) as f64;
                previous = current.clone();
                let line = format!(
                    "[✓] SHPH v{} | CONNECTED TO {} | SECURE ({}) | Interface: {} | Handshake: {} ms | Tx: {} (↑ {}/s) | Rx: {} (↓ {}/s) | Ctrl+C to disconnect",
                    env!("CARGO_PKG_VERSION"),
                    endpoint,
                    if profile.uses_pqc() {
                        "ML-KEM-768"
                    } else {
                        "classical-lab"
                    },
                    interface_name,
                    handshake_ms,
                    format_bytes(current.bytes_sent),
                    format_bytes(tx_rate as u64),
                    format_bytes(current.bytes_recv),
                    format_bytes(rx_rate as u64),
                );
                let _ = write!(io::stderr(), "\r{line}\x1b[K");
                let _ = io::stderr().flush();
            }
        });
        Self {
            stop: Some(stop),
            worker: Some(worker),
        }
    }
}

impl Drop for LiveStatusBar {
    fn drop(&mut self) {
        let active = self.stop.is_some() || self.worker.is_some();
        if !active {
            return;
        }
        if let Some(stop) = self.stop.take() {
            stop.store(true, Ordering::Relaxed);
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        if io::stderr().is_terminal() {
            let _ = write!(io::stderr(), "\r\x1b[K");
            let _ = io::stderr().flush();
        }
    }
}

fn sanitize_status_label(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                '?'
            } else {
                character
            }
        })
        .take(48)
        .collect()
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", bytes, UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "shph",
    version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("SHPH_BUILD_ID"), ")"),
    about = "SHPH (Shroud-Phantom): Layer 3 VPN with stealth/shroud features",
    long_about = "SHPH is a testable, VPN-first secure transport for controlled lab environments.",
    arg_required_else_help = true,
    after_help = "Examples:\n  shph init\n  shph doctor\n  shph --json status\n  shph up --transport tcp"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable additional diagnostic output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Use a specific configuration file
    #[arg(short, long, value_name = "PATH", global = true)]
    config: Option<PathBuf>,

    /// Emit machine-readable JSON reports and errors
    #[arg(long, global = true)]
    json: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialize a new identity and configuration
    Init {
        /// Force overwrite existing identity/config
        #[arg(long)]
        new: bool,
    },
    /// Start a host listener and print a shareable join ticket
    Host {
        /// TCP/UDP listener port
        #[arg(long, default_value_t = 443)]
        port: u16,
        /// Public host or host:port embedded in the join ticket
        #[arg(long)]
        advertise: Option<String>,
        /// Transport override (tcp|quic)
        #[arg(long, default_value = "tcp")]
        transport: String,
        /// Discrete traffic-shaping profile
        #[arg(long, default_value = "medium")]
        shroud_profile: String,
        /// Run without opening a native TUN interface
        #[arg(long)]
        no_tun: bool,
        /// Do not install Linux forwarding/NAT rules
        #[arg(long)]
        no_nat: bool,
    },
    /// Join a host from a shph://v1 ticket
    Join {
        ticket: String,
        /// Run without opening a native TUN interface
        #[arg(long)]
        no_tun: bool,
    },
    /// Show local identity material and a shareable host ticket
    Id {
        /// Render the shareable ticket as an ANSI terminal QR code
        #[arg(long)]
        qr: bool,
    },
    /// Bring up the VPN tunnel
    Up {
        /// Connect directly to a peer without editing the saved config
        #[arg(long)]
        to: Option<String>,
        /// Optional transport override (tcp|quic|quic-standard|offline-mesh|data-mule)
        #[arg(long)]
        transport: Option<String>,
        /// Discrete traffic-shaping profile (off|low|medium|high|extreme-lab)
        #[arg(long)]
        shroud_profile: Option<String>,
        /// Run without opening a native TUN interface
        #[arg(long)]
        no_tun: bool,
        /// DER certificate path for standards QUIC; servers write it and clients trust it out of band
        #[arg(long)]
        quic_cert: Option<PathBuf>,
        /// Handshake profile (secure-default or classical-lab)
        #[arg(long)]
        handshake_profile: Option<String>,
        /// Install a persistent, fail-closed host firewall policy before opening TUN
        #[arg(long)]
        killswitch: bool,
        /// Print killswitch commands without applying them
        #[arg(long, requires = "killswitch")]
        killswitch_dry_run: bool,
        /// Install bidirectional TCP SYN MSS clamping for the native TUN
        #[arg(long)]
        mss_clamp: bool,
    },
    /// Bring down the VPN tunnel
    Down,
    /// Apply configured routes and DNS
    Apply,
    /// Reconcile configured routes and DNS
    Reconcile,
    /// Undo previously applied routes and DNS
    Undo,
    /// Show VPN and configuration status
    Status,
    /// Check configuration, identity, peers, and host prerequisites
    Doctor {
        /// Exit non-zero when any check fails
        #[arg(long)]
        strict: bool,
    },
    /// Show peer fingerprint
    #[command(alias = "fingerprint")]
    ShowFingerprint,
    /// Show the local identity public key
    ShowPublicKey,
    /// Show the local Ed25519 handshake-signing public key
    ShowSigningPublicKey,
    /// List configured peers
    #[command(alias = "peers")]
    ListPeers,
    /// Add a new peer
    AddPeer {
        alias: String,
        host: String,
        port: u16,
        pubkey: String,
        /// Ed25519 signing public key (base64, 32-byte raw)
        #[arg(long)]
        sign_pubkey: String,
    },
    /// Show configuration
    #[command(alias = "config")]
    ShowConfig {
        /// Include plaintext credential fields in the output.
        #[arg(long)]
        show_secrets: bool,
    },
    /// Validate optional roadmap adapters and trust configuration
    ValidateRoadmap,
    /// Split a secret into configured Shamir shares
    ShamirSplit {
        /// Read the secret from a protected file. Use "-" for stdin.
        #[arg(
            long,
            conflicts_with = "secret_stdin",
            required_unless_present = "secret_stdin"
        )]
        secret_file: Option<PathBuf>,
        /// Read the secret bytes from stdin.
        #[arg(long, conflicts_with = "secret_file")]
        secret_stdin: bool,
        /// Directory where owner-only share files are written.
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Recover a secret from Shamir share JSON files
    ShamirRecover {
        #[arg(required = true)]
        shares: Vec<PathBuf>,
        /// Owner-only output file for the recovered secret.
        #[arg(long)]
        output_file: PathBuf,
    },
    /// Export ratchet audit journal as JSON
    RatchetAuditExport,
    /// Perform local handshake simulation against a peer pubkey
    HandshakeSim {
        /// Peer identity public key (base64, 32-byte raw)
        #[arg(long)]
        peer_pubkey_b64: String,
    },
    /// Listen for one inbound handshake and print session summary
    Listen {
        #[arg(long, default_value = "0.0.0.0:7000")]
        bind: String,
        #[arg(long, default_value_t = 5)]
        timeout_secs: u64,
        /// Optional transport override (tcp|quic|quic-standard|offline-mesh|data-mule)
        #[arg(long)]
        transport: Option<String>,
        /// DER certificate path for standards QUIC; clients must receive the server certificate out of band
        #[arg(long)]
        quic_cert: Option<PathBuf>,
        /// Handshake profile (secure-default or classical-lab)
        #[arg(long)]
        handshake_profile: Option<String>,
    },
    /// Connect to a peer and perform one TCP handshake
    Connect {
        #[arg(long)]
        peer: String,
        #[arg(long, default_value_t = 5)]
        timeout_secs: u64,
        /// Optional transport override (tcp|quic|quic-standard|offline-mesh|data-mule)
        #[arg(long)]
        transport: Option<String>,
        /// DER certificate path for standards QUIC; clients must receive the server certificate out of band
        #[arg(long)]
        quic_cert: Option<PathBuf>,
        /// Handshake profile (secure-default or classical-lab)
        #[arg(long)]
        handshake_profile: Option<String>,
    },
    /// Send one encrypted payload over a freshly established TCP session
    SendOnce {
        #[arg(long)]
        peer: String,
        #[arg(long)]
        text: String,
        #[arg(long, default_value_t = 5)]
        timeout_secs: u64,
        /// Optional transport override (tcp|quic|quic-standard|offline-mesh|data-mule)
        #[arg(long)]
        transport: Option<String>,
        /// DER certificate path for standards QUIC; clients must receive the server certificate out of band
        #[arg(long)]
        quic_cert: Option<PathBuf>,
        /// Handshake profile (secure-default or classical-lab)
        #[arg(long)]
        handshake_profile: Option<String>,
    },
    /// Receive one encrypted payload after TCP handshake
    RecvOnce {
        #[arg(long, default_value = "0.0.0.0:7000")]
        bind: String,
        #[arg(long, default_value_t = 5)]
        timeout_secs: u64,
        /// Optional transport override (tcp|quic|quic-standard|offline-mesh|data-mule)
        #[arg(long)]
        transport: Option<String>,
        /// DER certificate path for standards QUIC; clients must receive the server certificate out of band
        #[arg(long)]
        quic_cert: Option<PathBuf>,
        /// Handshake profile (secure-default or classical-lab)
        #[arg(long)]
        handshake_profile: Option<String>,
    },
}

#[derive(Debug, Serialize)]
struct HandshakeSimOut {
    peer_fingerprint_hex: String,
    transcript_hash_hex: String,
}

#[derive(Debug, Serialize)]
struct CliErrorOutput {
    ok: bool,
    error: String,
    code: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    hint: Option<&'static str>,
}

fn main() {
    let cli = Cli::parse();
    let json = cli.json;
    if let Err(error) = run_cli(cli) {
        let code = cli_exit_code(&error);
        if json {
            let output = CliErrorOutput {
                ok: false,
                error: error.to_string(),
                code,
                hint: cli_error_hint(&error),
            };
            match serde_json::to_string(&output) {
                Ok(output) => eprintln!("{output}"),
                Err(_) => eprintln!(
                    r#"{{"ok":false,"error":"failed to serialize CLI error","code":{code}}}"#
                ),
            }
        } else {
            eprintln!("Error: {error}");
            if let Some(hint) = cli_error_hint(&error) {
                eprintln!("Hint: {hint}");
            }
        }
        std::process::exit(code);
    }
}

fn run_cli(cli: Cli) -> Result<()> {
    if cli.verbose && std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "info");
    }
    tracing_subscriber::fmt::init();
    shutdown::install_signal_handlers();

    let config_path = cli.config.unwrap_or_else(Config::default_config_path);
    let keystore_path = keystore_path_from_config(&config_path);
    let json = cli.json;

    match cli.command {
        Commands::Init { new } => handle_init(&config_path, &keystore_path, new)?,
        Commands::Host {
            port,
            advertise,
            transport,
            shroud_profile,
            no_tun,
            no_nat,
        } => handle_host(
            &config_path,
            &keystore_path,
            port,
            advertise.as_deref(),
            &transport,
            &shroud_profile,
            no_tun,
            no_nat,
        )?,
        Commands::Join { ticket, no_tun } => {
            handle_join(&config_path, &keystore_path, &ticket, no_tun)?
        }
        Commands::Id { qr } => handle_id(&config_path, &keystore_path, qr)?,
        Commands::Up {
            to,
            transport,
            shroud_profile,
            no_tun,
            quic_cert,
            handshake_profile,
            killswitch,
            killswitch_dry_run,
            mss_clamp,
        } => {
            let mut config = if to.is_some() {
                ensure_workspace(&config_path, &keystore_path)?.0
            } else {
                load_config(&config_path)?
            };
            if let Some(peer) = to {
                config.session = Some(SessionConfig {
                    role: SessionRole::Connect,
                    bind: None,
                    peer: Some(peer),
                    timeout_secs: Some(5),
                    handshake_profile: None,
                    reconnect: None,
                    startup_payload: None,
                });
            }
            let mode = resolve_transport_mode(transport.as_deref(), config.roadmap.as_ref())?;
            let profile = resolve_handshake_profile(
                handshake_profile.as_deref(),
                config
                    .session
                    .as_ref()
                    .and_then(|session| session.handshake_profile),
            )?;
            let shroud_profile = resolve_shroud_profile(
                shroud_profile.as_deref(),
                config
                    .stealth
                    .as_ref()
                    .map(|stealth| stealth.shroud_profile.as_str()),
            )?;
            let path_keystore = keystore_path_from_config(&config_path);
            handle_up(
                &config_path,
                &path_keystore,
                &config,
                UpOptions {
                    transport: mode,
                    profile,
                    shroud_profile,
                    quic_cert_path: quic_cert.as_deref(),
                    killswitch,
                    killswitch_dry_run,
                    mss_clamp,
                    tun: !no_tun,
                    host_bootstrap: false,
                    nat: false,
                },
            )?
        }
        Commands::Down => handle_down(&config_path)?,
        Commands::Apply => handle_control_plane_apply(&config_path)?,
        Commands::Reconcile => handle_control_plane_reconcile(&config_path)?,
        Commands::Undo => handle_control_plane_undo(&config_path)?,
        Commands::Status => handle_status(&config_path, &keystore_path, json)?,
        Commands::Doctor { strict } => handle_doctor(&config_path, &keystore_path, json, strict)?,
        Commands::ShowFingerprint => handle_show_fingerprint(&keystore_path)?,
        Commands::ShowPublicKey => handle_show_public_key(&keystore_path)?,
        Commands::ShowSigningPublicKey => handle_show_signing_public_key(&keystore_path)?,
        Commands::ListPeers => handle_list_peers(&config_path, json)?,
        Commands::AddPeer {
            alias,
            host,
            port,
            pubkey,
            sign_pubkey,
        } => handle_add_peer(
            &config_path,
            &keystore_path,
            alias,
            host,
            port,
            pubkey,
            sign_pubkey,
        )?,
        Commands::ShowConfig { show_secrets } => handle_show_config(&config_path, show_secrets)?,
        Commands::ValidateRoadmap => handle_validate_roadmap(&config_path)?,
        Commands::ShamirSplit {
            secret_file,
            secret_stdin,
            output_dir,
        } => handle_shamir_split(
            &config_path,
            secret_file.as_deref(),
            secret_stdin,
            &output_dir,
        )?,
        Commands::ShamirRecover {
            shares,
            output_file,
        } => handle_shamir_recover(&config_path, &shares, &output_file)?,
        Commands::RatchetAuditExport => handle_ratchet_audit_export(&config_path)?,
        Commands::HandshakeSim { peer_pubkey_b64 } => {
            handle_handshake_sim(&keystore_path, &peer_pubkey_b64)?
        }
        Commands::Listen {
            bind,
            timeout_secs,
            transport,
            quic_cert,
            handshake_profile,
        } => {
            let config = load_config(&config_path)?;
            handle_listen(
                &keystore_path,
                &bind,
                timeout_secs,
                transport,
                quic_cert.as_deref(),
                resolve_handshake_profile(
                    handshake_profile.as_deref(),
                    config
                        .session
                        .as_ref()
                        .and_then(|session| session.handshake_profile),
                )?,
                config.roadmap.as_ref(),
            )?
        }
        Commands::Connect {
            peer,
            timeout_secs,
            transport,
            quic_cert,
            handshake_profile,
        } => {
            let config = load_config(&config_path)?;
            handle_connect(
                &keystore_path,
                &peer,
                timeout_secs,
                transport,
                quic_cert.as_deref(),
                resolve_handshake_profile(
                    handshake_profile.as_deref(),
                    config
                        .session
                        .as_ref()
                        .and_then(|session| session.handshake_profile),
                )?,
                config.roadmap.as_ref(),
            )?
        }
        Commands::SendOnce {
            peer,
            text,
            timeout_secs,
            transport,
            quic_cert,
            handshake_profile,
        } => {
            let config = load_config(&config_path)?;
            handle_send_once(
                &keystore_path,
                &peer,
                &text,
                timeout_secs,
                transport,
                quic_cert.as_deref(),
                resolve_handshake_profile(
                    handshake_profile.as_deref(),
                    config
                        .session
                        .as_ref()
                        .and_then(|session| session.handshake_profile),
                )?,
                config.roadmap.as_ref(),
            )?
        }
        Commands::RecvOnce {
            bind,
            timeout_secs,
            transport,
            quic_cert,
            handshake_profile,
        } => {
            let config = load_config(&config_path)?;
            handle_recv_once(
                &keystore_path,
                &bind,
                timeout_secs,
                transport,
                quic_cert.as_deref(),
                resolve_handshake_profile(
                    handshake_profile.as_deref(),
                    config
                        .session
                        .as_ref()
                        .and_then(|session| session.handshake_profile),
                )?,
                config.roadmap.as_ref(),
            )?
        }
    }

    Ok(())
}

fn cli_error_hint(error: &ShphError) -> Option<&'static str> {
    match error {
        ShphError::Io(error) if error.kind() == io::ErrorKind::NotFound => {
            Some("Check --config and file paths, or run `shph init` to create a workspace.")
        }
        ShphError::Config(_) | ShphError::KeyStore(_) => {
            Some("Run `shph doctor` for a focused configuration and identity diagnosis.")
        }
        ShphError::InvalidArgument(_) => {
            Some("Run the command with `--help` to review valid arguments and examples.")
        }
        ShphError::PermissionDenied(_) | ShphError::Tun(_) => {
            Some("Check host privileges and native-TUN prerequisites before retrying.")
        }
        ShphError::Unsupported(_) => {
            Some("Review the selected transport and host prerequisites in `docs/TESTING.md`.")
        }
        _ => None,
    }
}

/// Map failures to stable sysexits-style values so scripts can distinguish
/// invalid input, unavailable services, permissions, and transient failures.
fn cli_exit_code(error: &ShphError) -> i32 {
    match error {
        ShphError::InvalidArgument(_) => EXIT_USAGE,
        ShphError::Config(_) | ShphError::KeyStore(_) => EXIT_CONFIG,
        ShphError::Io(error) if error.kind() == io::ErrorKind::NotFound => EXIT_NOT_FOUND,
        ShphError::Io(error) if error.kind() == io::ErrorKind::PermissionDenied => EXIT_PERMISSION,
        ShphError::Io(_) | ShphError::Serialization(_) | ShphError::Internal(_) => EXIT_FAILURE,
        ShphError::PermissionDenied(_)
        | ShphError::Auth(_)
        | ShphError::Crypto(_)
        | ShphError::Handshake(_)
        | ShphError::Tun(_) => EXIT_PERMISSION,
        ShphError::Unsupported(_) | ShphError::NotConnected | ShphError::AlreadyConnected => {
            EXIT_UNAVAILABLE
        }
        ShphError::Timeout
        | ShphError::ConnectionClosed
        | ShphError::Transport(_)
        | ShphError::ResourceExhausted(_) => EXIT_TEMPORARY,
        ShphError::Protocol(_) | ShphError::Obfuscation(_) | ShphError::Stealth(_) => EXIT_FAILURE,
    }
}

fn handle_init(config_path: &Path, keystore_path: &Path, force_new: bool) -> Result<()> {
    if !force_new && (config_path.exists() || keystore_path.exists()) {
        return Err(ShphError::InvalidArgument(
            "config/keystore already exists (use --new to overwrite)".into(),
        ));
    }

    let keystore = KeyStore::new(KeyStoreConfig::default())?;
    keystore.save(keystore_path)?;

    let mut config = Config::default();
    if !keystore.contacts.is_empty() {
        config.peers = to_peer_configs(&keystore);
    }
    save_config(&config, config_path)?;

    println!("Initialized SHPH");
    println!("  Config: {}", config_path.display());
    println!("  Keystore: {}", keystore_path.display());
    println!("  Fingerprint: {}", keystore.fingerprint_hex());
    Ok(())
}

fn ensure_workspace(config_path: &Path, keystore_path: &Path) -> Result<(Config, KeyStore)> {
    let keystore = if keystore_path.exists() {
        KeyStore::load(keystore_path, None)?
    } else {
        let keystore = KeyStore::new(KeyStoreConfig::default())?;
        keystore.save(keystore_path)?;
        keystore
    };

    let config = if config_path.exists() {
        load_config(config_path)?
    } else {
        let config = Config {
            peers: to_peer_configs(&keystore),
            ..Config::default()
        };
        save_config(&config, config_path)?;
        config
    };

    Ok((config, keystore))
}

#[allow(clippy::too_many_arguments)]
fn handle_host(
    config_path: &Path,
    keystore_path: &Path,
    port: u16,
    advertise: Option<&str>,
    transport: &str,
    shroud_profile: &str,
    no_tun: bool,
    no_nat: bool,
) -> Result<()> {
    if port == 0 {
        return Err(ShphError::InvalidArgument(
            "host port must be greater than zero".into(),
        ));
    }
    let mode = TransportMode::parse(transport)?;
    if !matches!(mode, TransportMode::Tcp | TransportMode::Quic) {
        return Err(ShphError::InvalidArgument(
            "host supports only tcp and quic transports".into(),
        ));
    }
    let profile = resolve_shroud_profile(Some(shroud_profile), None)?;
    let advertised_endpoint = advertised_endpoint(advertise, port)?;
    let bind = format_endpoint("0.0.0.0", port);
    let (mut config, keystore) = ensure_workspace(config_path, keystore_path)?;

    config.local_endpoint = bind.clone();
    config.stealth = Some(StealthConfig {
        profile: "steady".into(),
        shroud_profile: profile.clone(),
    });
    config.session = Some(SessionConfig {
        role: SessionRole::Listen,
        bind: Some(bind),
        peer: None,
        timeout_secs: Some(300),
        handshake_profile: Some(HandshakeProfile::SecureDefault),
        reconnect: Some(ReconnectConfig {
            enabled: Some(true),
            max_attempts: Some(10),
            initial_delay_ms: Some(250),
            max_delay_ms: Some(4000),
        }),
        startup_payload: None,
    });
    save_config(&config, config_path)?;
    std::env::set_var("SHPH_SHROUD_PROFILE", &profile);

    let ticket = JoinTicket {
        endpoint: advertised_endpoint,
        transport: transport_mode_to_str(mode).into(),
        shroud_profile: profile.clone(),
        server_identity_b64: keystore.identity.public_key_b64(),
        server_signing_b64: keystore.identity.signing_public_b64(),
    }
    .encode()?;

    println!("SHPH host ready");
    println!("  Identity: {}", keystore.fingerprint_hex());
    println!("  Transport: {}", transport_mode_to_str(mode));
    println!("  Shroud profile: {profile}");
    println!("  Join ticket: {ticket}");
    if no_nat {
        println!("  NAT: disabled");
    } else {
        println!("  NAT: enabled when native Linux TUN is active");
    }

    handle_up(
        config_path,
        keystore_path,
        &config,
        UpOptions {
            transport: mode,
            profile: HandshakeProfile::SecureDefault,
            shroud_profile: profile,
            quic_cert_path: None,
            killswitch: false,
            killswitch_dry_run: false,
            mss_clamp: false,
            tun: !no_tun,
            host_bootstrap: true,
            nat: !no_nat,
        },
    )
}

fn handle_join(
    config_path: &Path,
    keystore_path: &Path,
    ticket_value: &str,
    no_tun: bool,
) -> Result<()> {
    let ticket = JoinTicket::decode(ticket_value)?;
    let mode = TransportMode::parse(&ticket.transport)?;
    let profile = resolve_shroud_profile(Some(&ticket.shroud_profile), None)?;
    let endpoint = Endpoint::parse(&ticket.endpoint)
        .map_err(|error| ShphError::InvalidArgument(format!("invalid ticket endpoint: {error}")))?;
    let (mut config, mut keystore) = ensure_workspace(config_path, keystore_path)?;

    ensure_peer_pin(
        &mut config,
        &mut keystore,
        "host",
        &ticket.endpoint,
        &ticket.server_identity_b64,
        &ticket.server_signing_b64,
    )?;
    config.session = Some(SessionConfig {
        role: SessionRole::Connect,
        bind: None,
        peer: Some(ticket.endpoint.clone()),
        timeout_secs: Some(10),
        handshake_profile: Some(HandshakeProfile::SecureDefault),
        reconnect: Some(ReconnectConfig {
            enabled: Some(true),
            max_attempts: Some(10),
            initial_delay_ms: Some(250),
            max_delay_ms: Some(4000),
        }),
        startup_payload: None,
    });
    config.stealth = Some(StealthConfig {
        profile: "steady".into(),
        shroud_profile: profile.clone(),
    });
    save_config(&config, config_path)?;
    keystore.save(keystore_path)?;
    std::env::set_var("SHPH_SHROUD_PROFILE", &profile);

    println!(
        "SHPH joining {}",
        format_endpoint(&endpoint.host, endpoint.port)
    );
    println!(
        "  Host identity: {}",
        shorten_key(&ticket.server_identity_b64)
    );
    println!("  Transport: {}", transport_mode_to_str(mode));
    println!("  Shroud profile: {profile}");

    handle_up(
        config_path,
        keystore_path,
        &config,
        UpOptions {
            transport: mode,
            profile: HandshakeProfile::SecureDefault,
            shroud_profile: profile,
            quic_cert_path: None,
            killswitch: false,
            killswitch_dry_run: false,
            mss_clamp: false,
            tun: !no_tun,
            host_bootstrap: false,
            nat: false,
        },
    )
}

fn handle_id(config_path: &Path, keystore_path: &Path, qr: bool) -> Result<()> {
    let keystore = KeyStore::load(keystore_path, None)?;
    let config = if config_path.exists() {
        load_config(config_path)?
    } else {
        Config::default()
    };
    let profile = resolve_shroud_profile(
        None,
        config
            .stealth
            .as_ref()
            .map(|stealth| stealth.shroud_profile.as_str()),
    )?;
    let endpoint = shareable_endpoint(&config)?;
    let mode = resolve_transport_mode(None, config.roadmap.as_ref())?;
    let mode = if matches!(mode, TransportMode::Tcp | TransportMode::Quic) {
        mode
    } else {
        TransportMode::Tcp
    };
    let ticket = JoinTicket {
        endpoint,
        transport: transport_mode_to_str(mode).into(),
        shroud_profile: profile,
        server_identity_b64: keystore.identity.public_key_b64(),
        server_signing_b64: keystore.identity.signing_public_b64(),
    }
    .encode()?;

    println!("Identity: {}", keystore.fingerprint_hex());
    println!(
        "Public Key:  {}",
        shorten_key(&keystore.identity.public_key_b64())
    );
    println!(
        "Signing Key: {}",
        shorten_key(&keystore.identity.signing_public_b64())
    );
    println!();
    println!("Shareable Link:");
    println!("{ticket}");
    if qr {
        println!();
        println!("{}", render_qr(&ticket)?);
    }
    Ok(())
}

fn ensure_peer_pin(
    config: &mut Config,
    keystore: &mut KeyStore,
    alias: &str,
    endpoint: &str,
    public_key: &str,
    signing_key: &str,
) -> Result<()> {
    if let Some(existing) = keystore.contacts.get(alias) {
        if existing.pubkey_b64 != public_key
            || existing.sign_pubkey_b64.as_deref() != Some(signing_key)
            || format_endpoint(&existing.endpoint.host, existing.endpoint.port) != endpoint
        {
            return Err(ShphError::Auth(format!(
                "peer pin '{alias}' changed; refusing to overwrite it"
            )));
        }
    } else {
        let parsed = Endpoint::parse(endpoint).map_err(|error| {
            ShphError::InvalidArgument(format!("invalid peer endpoint: {error}"))
        })?;
        keystore.add_contact(shph_core::Contact {
            alias: alias.into(),
            endpoint: parsed,
            pubkey_b64: public_key.into(),
            sign_pubkey_b64: Some(signing_key.into()),
        });
    }

    if let Some(existing) = config.peers.iter().find(|peer| peer.alias == alias) {
        if existing.pubkey != public_key
            || existing.sign_pubkey.as_deref() != Some(signing_key)
            || existing.endpoint != endpoint
        {
            return Err(ShphError::Auth(format!(
                "configured peer pin '{alias}' changed; refusing to overwrite it"
            )));
        }
    } else {
        config.peers.push(PeerConfig {
            alias: alias.into(),
            endpoint: endpoint.into(),
            pubkey: public_key.into(),
            sign_pubkey: Some(signing_key.into()),
        });
    }
    Ok(())
}

fn enroll_inbound_peer(
    config_path: &Path,
    keystore_path: &Path,
    endpoint: &str,
    state: &HandshakeState,
) -> Result<()> {
    let mut config = load_config(config_path)?;
    let mut keystore = KeyStore::load(keystore_path, None)?;
    let alias = format!(
        "peer-{}",
        state
            .peer_fingerprint_hex
            .get(..12)
            .unwrap_or(&state.peer_fingerprint_hex)
    );
    ensure_peer_pin(
        &mut config,
        &mut keystore,
        &alias,
        endpoint,
        &state.peer_identity_pubkey_b64,
        &state.peer_signing_pubkey_b64,
    )?;
    save_config(&config, config_path)?;
    keystore.save(keystore_path)?;
    println!("  Bootstrap enrollment: pinned {alias}");
    Ok(())
}

fn advertised_endpoint(advertise: Option<&str>, port: u16) -> Result<String> {
    let raw = advertise.unwrap_or("127.0.0.1").trim();
    let endpoint = match Endpoint::parse(raw) {
        Ok(endpoint) => endpoint,
        Err(error) if raw.contains(':') && !raw.starts_with('[') => {
            return Err(ShphError::InvalidArgument(format!(
                "invalid advertised endpoint '{raw}': {error}"
            )));
        }
        Err(_) => Endpoint {
            host: raw
                .strip_prefix('[')
                .and_then(|value| value.strip_suffix(']'))
                .unwrap_or(raw)
                .to_string(),
            port,
        },
    };
    if endpoint.host.is_empty() || endpoint.port == 0 {
        return Err(ShphError::InvalidArgument(
            "advertised endpoint must include a host and non-zero port".into(),
        ));
    }
    if endpoint
        .host
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(ShphError::InvalidArgument(
            "advertised endpoint host contains whitespace or control characters".into(),
        ));
    }
    Ok(format_endpoint(&endpoint.host, endpoint.port))
}

fn shareable_endpoint(config: &Config) -> Result<String> {
    let raw = config
        .session
        .as_ref()
        .and_then(|session| session.bind.as_deref().or(session.peer.as_deref()))
        .unwrap_or(&config.local_endpoint);
    let endpoint = Endpoint::parse(raw)
        .map_err(|error| ShphError::InvalidArgument(format!("invalid local endpoint: {error}")))?;
    let host = match endpoint.host.as_str() {
        "0.0.0.0" | "::" => "127.0.0.1",
        value => value,
    };
    Ok(format_endpoint(host, endpoint.port))
}

struct UpOptions<'a> {
    transport: TransportMode,
    profile: HandshakeProfile,
    shroud_profile: String,
    quic_cert_path: Option<&'a Path>,
    killswitch: bool,
    killswitch_dry_run: bool,
    mss_clamp: bool,
    tun: bool,
    host_bootstrap: bool,
    nat: bool,
}

fn handle_up(
    config_path: &Path,
    keystore_path: &Path,
    config: &Config,
    options: UpOptions<'_>,
) -> Result<()> {
    let UpOptions {
        transport,
        profile,
        shroud_profile,
        quic_cert_path,
        killswitch,
        killswitch_dry_run,
        mss_clamp,
        tun,
        host_bootstrap,
        nat,
    } = options;
    std::env::set_var("SHPH_SHROUD_PROFILE", &shroud_profile);
    validate_config_roadmap(config)?;
    validate_tun_name(&config.interface_name)?;
    if control_plane_state_path(config_path).exists() {
        return Err(ShphError::Config(
            "recorded control-plane state exists; run `shph reconcile` or `shph undo` before `shph up`"
                .into(),
        ));
    }
    if transport == TransportMode::QuicStandard
        && config
            .session
            .as_ref()
            .and_then(|session| session.reconnect.as_ref())
            .and_then(|reconnect| reconnect.enabled)
            .unwrap_or(false)
    {
        return Err(ShphError::Config(
            "quic-standard native TUN reconnect is not supported yet: the listener certificate must remain stable across reconnects".into(),
        ));
    }
    announce_handshake_profile(profile);
    let mut killswitch_guard = if killswitch {
        apply_killswitch(config, transport, killswitch_dry_run)?
    } else {
        FirewallGuard::default()
    };
    let tun = match if tun {
        TunDevice::open(&config.interface_name)
    } else {
        TunDevice::open_stub(&config.interface_name)
    } {
        Ok(tun) => tun,
        Err(error) => {
            let _ = killswitch_guard.cleanup();
            return Err(error);
        }
    };
    if transport == TransportMode::QuicStandard && !tun.is_native() {
        let _ = killswitch_guard.cleanup();
        return Err(ShphError::Unsupported(
            "quic-standard up requires native TUN; set SHPH_TUN_NATIVE=1".into(),
        ));
    }
    if killswitch && !tun.is_native() && !killswitch_dry_run {
        let _ = killswitch_guard.cleanup();
        return Err(ShphError::Unsupported(
            "the host killswitch requires native TUN; set SHPH_TUN_NATIVE=1".into(),
        ));
    }
    if mss_clamp && !tun.is_native() && !killswitch_dry_run {
        let _ = killswitch_guard.cleanup();
        return Err(ShphError::Unsupported(
            "MSS clamping requires native TUN; set SHPH_TUN_NATIVE=1".into(),
        ));
    }
    if killswitch {
        killswitch_guard.allow_interface(tun.name())?;
    }
    if tun.is_native() {
        configure_native_tun_mtu(tun.name(), DEFAULT_TUN_MTU_BYTES)?;
    }
    let mut nat_guard = if nat && tun.is_native() {
        match apply_nat(tun.name(), killswitch_dry_run) {
            Ok(guard) => guard,
            Err(error) => {
                let _ = killswitch_guard.cleanup();
                return Err(error);
            }
        }
    } else {
        if nat {
            println!("  NAT: skipped (native TUN is disabled)");
        }
        NatGuard::default()
    };
    let mut mss_guard = if mss_clamp {
        match apply_mss_clamp(tun.name(), killswitch_dry_run) {
            Ok(guard) => guard,
            Err(error) => {
                let _ = killswitch_guard.cleanup();
                return Err(error);
            }
        }
    } else {
        FirewallGuard::default()
    };
    println!("SHPH up");
    println!("  Interface: {}", tun.name());
    println!("  Local endpoint: {}", config.local_endpoint);
    println!("  Peer count: {}", config.peers.len());
    print_control_plane_status(config);
    let mut control_guard = apply_control_plane(config, tun.name())?;
    let interface_name = tun.name().to_string();
    let control_state_recorded = !control_guard.dry_run
        && (!control_guard.added_routes.is_empty()
            || !control_guard.applied_dns_servers.is_empty());
    if control_state_recorded {
        if let Err(err) = save_control_plane_state(
            config_path,
            &state_from_guard(&interface_name, &control_guard),
        ) {
            let cleanup_result = control_guard.cleanup();
            return match cleanup_result {
                Ok(()) => Err(err),
                Err(clean_err) => Err(ShphError::Internal(format!(
                    "control-plane state save error: {err}; rollback error: {clean_err}"
                ))),
            };
        }
    }
    let session_result = (|| -> Result<()> {
        if let Some(session) = &config.session {
            let timeout_secs = session.timeout_secs.unwrap_or(5);
            let reconnect_enabled = session
                .reconnect
                .as_ref()
                .and_then(|r| r.enabled)
                .unwrap_or(false);
            let max_attempts = session
                .reconnect
                .as_ref()
                .and_then(|r| r.max_attempts)
                .unwrap_or(1)
                .max(1);
            let initial_delay = session
                .reconnect
                .as_ref()
                .and_then(|r| r.initial_delay_ms)
                .unwrap_or(250)
                .max(1);
            let max_delay = session
                .reconnect
                .as_ref()
                .and_then(|r| r.max_delay_ms)
                .unwrap_or(4000)
                .max(initial_delay);
            match session.role {
                SessionRole::Listen => {
                    let bind = session.bind.as_deref().unwrap_or("0.0.0.0:7000");
                    let roadmap = config.roadmap.as_ref();
                    println!("  Session mode: listen ({bind})");
                    if session.startup_payload.is_some() {
                        handle_recv_once(
                            keystore_path,
                            bind,
                            timeout_secs,
                            Some(transport_mode_to_str(transport).to_string()),
                            quic_cert_path,
                            profile,
                            roadmap,
                        )?;
                    } else {
                        run_with_reconnect(
                            reconnect_enabled,
                            max_attempts,
                            initial_delay,
                            max_delay,
                            || {
                                run_listen_loop(
                                    keystore_path,
                                    config_path,
                                    &tun,
                                    bind,
                                    timeout_secs,
                                    transport,
                                    profile,
                                    config.roadmap.as_ref(),
                                    quic_cert_path,
                                    host_bootstrap,
                                )
                            },
                        )?;
                    }
                }
                SessionRole::Connect => {
                    let peer = session.peer.as_deref().ok_or_else(|| {
                        ShphError::Config("session.peer required for connect mode".into())
                    })?;
                    let roadmap = config.roadmap.as_ref();
                    println!("  Session mode: connect ({peer})");
                    if let Some(payload) = session.startup_payload.as_deref() {
                        handle_send_once(
                            keystore_path,
                            peer,
                            payload,
                            timeout_secs,
                            Some(transport_mode_to_str(transport).to_string()),
                            quic_cert_path,
                            profile,
                            roadmap,
                        )?;
                    } else {
                        run_with_reconnect(
                            reconnect_enabled,
                            max_attempts,
                            initial_delay,
                            max_delay,
                            || {
                                run_connect_loop(
                                    keystore_path,
                                    &tun,
                                    peer,
                                    timeout_secs,
                                    transport,
                                    profile,
                                    config.roadmap.as_ref(),
                                    quic_cert_path,
                                )
                            },
                        )?;
                    }
                }
            }
        }
        Ok(())
    })();
    match session_result {
        Ok(()) => {
            control_guard.cleanup()?;
            mss_guard.cleanup()?;
            nat_guard.cleanup()?;
            killswitch_guard.cleanup()?;
            if control_state_recorded {
                remove_control_plane_state(config_path)?;
            }
            Ok(())
        }
        Err(err) => {
            let cleanup_result = control_guard.cleanup();
            let mss_cleanup_result = mss_guard.cleanup();
            let killswitch_cleanup_result = killswitch_guard.cleanup();
            if let Err(clean_err) = cleanup_result {
                return Err(ShphError::Internal(format!(
                    "session error: {err}; control-plane cleanup error: {clean_err}"
                )));
            }
            if let Err(clean_err) = mss_cleanup_result {
                return Err(ShphError::Internal(format!(
                    "session error: {err}; MSS-clamp cleanup error: {clean_err}"
                )));
            }
            if let Err(clean_err) = nat_guard.cleanup() {
                return Err(ShphError::Internal(format!(
                    "session error: {err}; NAT cleanup error: {clean_err}"
                )));
            }
            if let Err(clean_err) = killswitch_cleanup_result {
                return Err(ShphError::Internal(format!(
                    "session error: {err}; killswitch cleanup error: {clean_err}"
                )));
            }
            if control_state_recorded {
                remove_control_plane_state(config_path)?;
            }
            Err(err)
        }
    }
}

fn bounded_cli_timeout(timeout_secs: u64) -> Duration {
    Duration::from_secs(timeout_secs.clamp(1, 300))
}

fn parse_socket_addr(value: &str) -> Result<SocketAddr> {
    value
        .to_socket_addrs()
        .map_err(|_| ShphError::Config(format!("invalid socket address: {value}")))?
        .next()
        .ok_or_else(|| ShphError::Config(format!("unable to resolve socket address: {value}")))
}

fn run_async<F, T>(future: F) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| ShphError::Internal(format!("create async runtime: {err}")))?;
    runtime.block_on(future)
}

const MAX_QUIC_CERTIFICATE_BYTES: u64 = 64 * 1024;

fn read_quic_certificate(path: &Path) -> Result<Vec<u8>> {
    ensure_no_reparse_components(path)?;
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(ShphError::Io)?
    };
    #[cfg(not(unix))]
    let file = {
        let metadata = fs::symlink_metadata(path).map_err(ShphError::Io)?;
        if metadata.file_type().is_symlink() {
            return Err(ShphError::InvalidArgument(
                "refusing to read symlinked QUIC certificate".into(),
            ));
        }
        fs::File::open(path).map_err(ShphError::Io)?
    };

    let metadata = file.metadata().map_err(ShphError::Io)?;
    if !metadata.file_type().is_file() {
        return Err(ShphError::InvalidArgument(
            "QUIC certificate path must reference a regular file".into(),
        ));
    }
    if metadata.len() == 0 || metadata.len() > MAX_QUIC_CERTIFICATE_BYTES {
        return Err(ShphError::Config(format!(
            "QUIC certificate must be between 1 and {MAX_QUIC_CERTIFICATE_BYTES} bytes"
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_QUIC_CERTIFICATE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(ShphError::Io)?;
    if bytes.len() as u64 > MAX_QUIC_CERTIFICATE_BYTES {
        return Err(ShphError::Config(
            "QUIC certificate exceeds size limit".into(),
        ));
    }
    Ok(bytes)
}

fn write_quic_certificate(path: &Path, certificate: &[u8]) -> Result<()> {
    if certificate.is_empty() || certificate.len() as u64 > MAX_QUIC_CERTIFICATE_BYTES {
        return Err(ShphError::Config(
            "generated QUIC certificate has an invalid size".into(),
        ));
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err(ShphError::InvalidArgument(
                "refusing to replace symlinked QUIC certificate".into(),
            ));
        }
    }
    ensure_no_reparse_components(path)?;
    write_owner_only_file(path, certificate)
}

fn handle_down(config_path: &Path) -> Result<()> {
    println!("SHPH down");
    let control_result = handle_control_plane_undo(config_path);
    let firewall_result = cleanup_firewall_state();
    match (control_result, firewall_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(control_error), Ok(())) => Err(control_error),
        (Ok(()), Err(firewall_error)) => Err(firewall_error),
        (Err(control_error), Err(firewall_error)) => Err(ShphError::Internal(
            format!("control-plane cleanup error: {control_error}; firewall cleanup error: {firewall_error}"),
        )),
    }
}

#[derive(Debug, Clone, Serialize)]
struct StatusItem {
    state: String,
    detail: String,
}

#[derive(Debug, Clone, Serialize)]
struct StatusReport {
    config_path: String,
    keystore_path: String,
    config: StatusItem,
    identity: StatusItem,
    tunnel: StatusItem,
    peers: usize,
    interface_name: Option<String>,
    local_endpoint: Option<String>,
    session: Option<String>,
    control_plane: StatusItem,
}

#[derive(Debug, Clone, Serialize)]
struct DoctorCheck {
    name: String,
    status: String,
    detail: String,
    hint: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct DoctorReport {
    ok: bool,
    config_path: String,
    keystore_path: String,
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, Clone, Serialize)]
struct PeerSummary {
    alias: String,
    endpoint: String,
    public_key: String,
    signing_key: String,
}

fn status_item(state: &str, detail: impl Into<String>) -> StatusItem {
    StatusItem {
        state: state.to_string(),
        detail: detail.into(),
    }
}

fn handle_status(config_path: &Path, keystore_path: &Path, json: bool) -> Result<()> {
    let config_result = Config::load(config_path);
    let config = config_result.as_ref().ok();
    let config_status = match &config_result {
        Ok(_) => status_item("ready", "configuration loaded"),
        Err(error) => status_item("error", error.to_string()),
    };

    let identity_status = if !keystore_path.exists() {
        status_item("missing", "identity keystore not found")
    } else {
        match KeyStore::load(keystore_path, None) {
            Ok(keystore) => status_item(
                "ready",
                format!(
                    "identity loaded; fingerprint {}",
                    keystore.fingerprint_hex()
                ),
            ),
            Err(error) => status_item("error", error.to_string()),
        }
    };

    let control_plane_status = if !control_plane_state_path(config_path).exists() {
        status_item("inactive", "no persisted route/DNS state")
    } else {
        match load_control_plane_state(config_path) {
            Ok(state) => status_item(
                "active",
                format!(
                    "{} route(s), {} DNS server(s) recorded on {}",
                    state.routes.len(),
                    state.dns_servers.len(),
                    state.interface_name
                ),
            ),
            Err(error) => status_item("error", error.to_string()),
        }
    };

    let session = config
        .and_then(|config| config.session.as_ref())
        .map(|session| match session.role {
            SessionRole::Listen => format!(
                "listen ({})",
                session.bind.as_deref().unwrap_or("0.0.0.0:7000")
            ),
            SessionRole::Connect => format!(
                "connect ({})",
                session.peer.as_deref().unwrap_or("peer not configured")
            ),
        });

    let report = StatusReport {
        config_path: config_path.display().to_string(),
        keystore_path: keystore_path.display().to_string(),
        config: config_status,
        identity: identity_status,
        tunnel: status_item(
            "not_tracked",
            "live session state is not persisted; use `shph up` to start a session",
        ),
        peers: config.map_or(0, |config| config.peers.len()),
        interface_name: config.map(|config| config.interface_name.clone()),
        local_endpoint: config.map(|config| config.local_endpoint.clone()),
        session,
        control_plane: control_plane_status,
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("SHPH status");
    print_status_item("Config", &report.config);
    print_status_item("Identity", &report.identity);
    print_status_item("Tunnel", &report.tunnel);
    println!("  Peers: {}", report.peers);
    if let Some(interface_name) = &report.interface_name {
        println!("  Interface: {interface_name}");
    }
    if let Some(local_endpoint) = &report.local_endpoint {
        println!("  Local endpoint: {local_endpoint}");
    }
    if let Some(session) = &report.session {
        println!("  Session: {session}");
    }
    print_status_item("Control plane", &report.control_plane);
    Ok(())
}

fn print_status_item(label: &str, item: &StatusItem) {
    println!("  {label}: {} ({})", item.state, item.detail);
}

fn doctor_check(
    checks: &mut Vec<DoctorCheck>,
    name: impl Into<String>,
    status: &str,
    detail: impl Into<String>,
    hint: Option<String>,
) {
    checks.push(DoctorCheck {
        name: name.into(),
        status: status.to_string(),
        detail: detail.into(),
        hint,
    });
}

fn handle_doctor(config_path: &Path, keystore_path: &Path, json: bool, strict: bool) -> Result<()> {
    let mut checks = Vec::new();
    let config_result = Config::load(config_path);
    let config = config_result.as_ref().ok();

    match &config_result {
        Ok(_) => doctor_check(
            &mut checks,
            "config",
            "pass",
            format!("loaded {}", config_path.display()),
            None,
        ),
        Err(error) => doctor_check(
            &mut checks,
            "config",
            "fail",
            error.to_string(),
            Some(format!(
                "create it with `shph --config {} init`",
                config_path.display()
            )),
        ),
    }

    match KeyStore::load(keystore_path, None) {
        Ok(keystore) => doctor_check(
            &mut checks,
            "identity",
            "pass",
            format!(
                "loaded {}; fingerprint {}",
                keystore_path.display(),
                keystore.fingerprint_hex()
            ),
            None,
        ),
        Err(error) => doctor_check(
            &mut checks,
            "identity",
            "fail",
            error.to_string(),
            Some(format!(
                "create a new identity with `shph --config {} init --new`",
                config_path.display()
            )),
        ),
    }

    if let Some(config) = config {
        match validate_tun_name(&config.interface_name) {
            Ok(()) => doctor_check(
                &mut checks,
                "interface",
                "pass",
                format!("{} is a valid SHPH interface name", config.interface_name),
                None,
            ),
            Err(error) => doctor_check(
                &mut checks,
                "interface",
                "fail",
                error.to_string(),
                Some("choose a short alphanumeric interface name such as `shph0`".into()),
            ),
        }

        let mut peer_errors = Vec::new();
        for peer in &config.peers {
            if let Err(error) = validate_pubkey_b64_named(&peer.pubkey, "peer public key") {
                peer_errors.push(format!("{}: {error}", peer.alias));
            }
            if let Some(sign_pubkey) = &peer.sign_pubkey {
                if let Err(error) =
                    validate_pubkey_b64_named(sign_pubkey, "peer signing public key")
                {
                    peer_errors.push(format!("{} signing key: {error}", peer.alias));
                }
            }
        }
        if peer_errors.is_empty() {
            doctor_check(
                &mut checks,
                "peers",
                "pass",
                format!(
                    "{} configured peer(s) have valid key shapes",
                    config.peers.len()
                ),
                None,
            );
        } else {
            doctor_check(
                &mut checks,
                "peers",
                "fail",
                peer_errors.join("; "),
                Some("review the peer keys with `shph list-peers`".into()),
            );
        }

        match &config.roadmap {
            Some(_) => match validate_config_roadmap(config) {
                Ok(()) => doctor_check(
                    &mut checks,
                    "roadmap",
                    "pass",
                    "optional transport and trust settings are valid",
                    None,
                ),
                Err(error) => doctor_check(
                    &mut checks,
                    "roadmap",
                    "fail",
                    error.to_string(),
                    Some("run `shph validate-roadmap` for the detailed roadmap check".into()),
                ),
            },
            None => doctor_check(
                &mut checks,
                "roadmap",
                "info",
                "no optional roadmap settings configured",
                None,
            ),
        }

        if let Some(control) = &config.control_plane {
            match build_control_plane_plan(control, &config.interface_name) {
                Ok(plan) => doctor_check(
                    &mut checks,
                    "control-plane",
                    "pass",
                    format!(
                        "{} route(s), {} DNS server(s) pass preflight",
                        plan.routes.len(),
                        plan.dns_servers.len()
                    ),
                    None,
                ),
                Err(error) => doctor_check(
                    &mut checks,
                    "control-plane",
                    "fail",
                    error.to_string(),
                    Some("run `shph show-config` and correct the route/DNS settings".into()),
                ),
            }
        } else {
            doctor_check(
                &mut checks,
                "control-plane",
                "info",
                "no route/DNS mutation configured",
                None,
            );
        }

        match &config.session {
            Some(session) => {
                let session_error = match session.role {
                    SessionRole::Listen => None,
                    SessionRole::Connect if session.peer.is_none() => {
                        Some("session.peer is required for connect mode")
                    }
                    SessionRole::Connect => None,
                };
                if let Some(error) = session_error {
                    doctor_check(
                        &mut checks,
                        "session",
                        "fail",
                        error,
                        Some("set [session].peer to the remote endpoint".into()),
                    );
                } else {
                    doctor_check(
                        &mut checks,
                        "session",
                        "pass",
                        format!("{:?} session is configured", session.role),
                        None,
                    );
                }
            }
            None => doctor_check(
                &mut checks,
                "session",
                "info",
                "no persistent session configured",
                Some("use `shph listen` or `shph connect` for one-shot operations".into()),
            ),
        }
    } else {
        doctor_check(
            &mut checks,
            "config-dependent checks",
            "info",
            "skipped until the configuration loads",
            None,
        );
    }

    if control_plane_state_path(config_path).exists() {
        match load_control_plane_state(config_path) {
            Ok(state) => doctor_check(
                &mut checks,
                "persisted-control-plane",
                "pass",
                format!("state recorded for {}", state.interface_name),
                None,
            ),
            Err(error) => doctor_check(
                &mut checks,
                "persisted-control-plane",
                "fail",
                error.to_string(),
                Some("run `shph undo` after reviewing the state file".into()),
            ),
        }
    } else {
        doctor_check(
            &mut checks,
            "persisted-control-plane",
            "info",
            "no applied route/DNS state recorded",
            None,
        );
    }

    let native_tun = std::env::var("SHPH_TUN_NATIVE").ok().as_deref() == Some("1");
    doctor_check(
        &mut checks,
        "native-tun",
        "info",
        if native_tun {
            "native TUN mode requested by SHPH_TUN_NATIVE=1"
        } else {
            "stub/config-only TUN mode; set SHPH_TUN_NATIVE=1 for native packet I/O"
        },
        None,
    );

    let ok = !checks.iter().any(|check| check.status == "fail");
    let report = DoctorReport {
        ok,
        config_path: config_path.display().to_string(),
        keystore_path: keystore_path.display().to_string(),
        checks,
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("SHPH doctor");
        for check in &report.checks {
            println!(
                "  [{:>4}] {:<24} {}",
                check.status.to_uppercase(),
                check.name,
                check.detail
            );
            if let Some(hint) = &check.hint {
                println!("         hint: {hint}");
            }
        }
        println!(
            "\nResult: {}",
            if report.ok {
                "ready for the configured scope"
            } else {
                "issues found"
            }
        );
    }

    if strict && !report.ok {
        return Err(ShphError::Config(
            "doctor found failing checks; fix the reported issues and rerun `shph doctor`".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct PersistedControlPlaneState {
    interface_name: String,
    routes: Vec<String>,
    dns_servers: Vec<String>,
}

fn control_plane_state_path(config_path: &Path) -> PathBuf {
    let mut state_path = config_path.to_path_buf();
    state_path.set_extension("control-plane.json");
    state_path
}

fn load_control_plane_state(config_path: &Path) -> Result<PersistedControlPlaneState> {
    let state_path = control_plane_state_path(config_path);
    let file = open_control_plane_state_readonly(&state_path).map_err(ShphError::Io)?;
    let metadata = file.metadata().map_err(ShphError::Io)?;
    if metadata.len() > MAX_CONTROL_PLANE_STATE_BYTES {
        return Err(ShphError::Protocol(format!(
            "control-plane state exceeds {MAX_CONTROL_PLANE_STATE_BYTES} bytes"
        )));
    }
    let mut contents = Vec::new();
    file.take(MAX_CONTROL_PLANE_STATE_BYTES + 1)
        .read_to_end(&mut contents)
        .map_err(ShphError::Io)?;
    if contents.len() as u64 > MAX_CONTROL_PLANE_STATE_BYTES {
        return Err(ShphError::Protocol(format!(
            "control-plane state exceeds {MAX_CONTROL_PLANE_STATE_BYTES} bytes"
        )));
    }
    let contents = String::from_utf8(contents)
        .map_err(|_| ShphError::Protocol("control-plane state is not valid UTF-8".into()))?;
    serde_json::from_str(&contents).map_err(ShphError::Serialization)
}

fn open_control_plane_state_readonly(path: &Path) -> io::Result<fs::File> {
    shph_core::ensure_no_reparse_components(path)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::fs::PermissionsExt;
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        if !file.metadata()?.file_type().is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "control-plane state path must reference a regular file",
            ));
        }
        let mode = file.metadata()?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "control-plane state is group/other accessible (mode {mode:o}); refusing to load"
                ),
            ));
        }
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        shph_core::ensure_not_reparse_point(path)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "refusing to load a symlinked control-plane state",
            ));
        }
        shph_core::enforce_owner_only_file_permissions(path)
            .map_err(|error| io::Error::new(io::ErrorKind::PermissionDenied, error.to_string()))?;
        let file = fs::File::open(path)?;
        if !file.metadata()?.file_type().is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "control-plane state path must reference a regular file",
            ));
        }
        Ok(file)
    }
}

fn save_control_plane_state(config_path: &Path, state: &PersistedControlPlaneState) -> Result<()> {
    let state_path = control_plane_state_path(config_path);
    if let Some(parent) = state_path.parent() {
        ensure_no_reparse_components(parent)?;
        fs::create_dir_all(parent).map_err(ShphError::Io)?;
        ensure_no_reparse_components(parent)?;
    }
    ensure_no_reparse_components(&state_path)?;
    let contents = serde_json::to_vec_pretty(state)?;
    let mut temp_path = state_path.clone();
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ShphError::Internal("system clock before unix epoch".into()))?
        .as_nanos();
    temp_path.set_extension(format!(
        "control-plane.json.tmp.{}.{}",
        std::process::id(),
        suffix
    ));
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp_path)
        .map_err(ShphError::Io)?;
    if let Err(err) = restrict_state_file_perms(&temp_path) {
        drop(file);
        let _ = fs::remove_file(&temp_path);
        return Err(err);
    }
    use std::io::Write as _;
    if let Err(err) = file.write_all(&contents).map_err(ShphError::Io) {
        drop(file);
        let _ = fs::remove_file(&temp_path);
        return Err(err);
    }
    if let Err(err) = file.sync_all().map_err(ShphError::Io) {
        drop(file);
        let _ = fs::remove_file(&temp_path);
        return Err(err);
    }
    drop(file);
    if let Some(parent) = state_path.parent() {
        if let Err(err) = ensure_no_reparse_components(parent) {
            let _ = fs::remove_file(&temp_path);
            return Err(err);
        }
    }
    if let Err(err) = ensure_no_reparse_components(&state_path) {
        let _ = fs::remove_file(&temp_path);
        return Err(err);
    }
    if let Err(err) = fs::rename(&temp_path, &state_path).map_err(ShphError::Io) {
        let _ = fs::remove_file(&temp_path);
        return Err(err);
    }
    #[cfg(unix)]
    if let Some(parent) = state_path.parent() {
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(ShphError::Io)?;
    }
    Ok(())
}

fn remove_control_plane_state(config_path: &Path) -> Result<()> {
    let state_path = control_plane_state_path(config_path);
    ensure_no_reparse_components(&state_path)?;
    match fs::remove_file(state_path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(ShphError::Io(err)),
    }
}

fn restrict_state_file_perms(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(ShphError::Io)?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn state_from_guard(interface_name: &str, guard: &ControlPlaneGuard) -> PersistedControlPlaneState {
    PersistedControlPlaneState {
        interface_name: interface_name.to_string(),
        routes: guard
            .added_routes
            .iter()
            .map(|(route, _)| route.clone())
            .collect(),
        dns_servers: guard.applied_dns_servers.clone(),
    }
}

fn guard_from_state(state: &PersistedControlPlaneState) -> ControlPlaneGuard {
    ControlPlaneGuard {
        added_routes: state
            .routes
            .iter()
            .map(|route| (route.clone(), state.interface_name.clone()))
            .collect(),
        applied_dns_servers: state.dns_servers.clone(),
        dns_interface_name: (!state.dns_servers.is_empty()).then(|| state.interface_name.clone()),
        dry_run: false,
    }
}

fn handle_control_plane_apply(config_path: &Path) -> Result<()> {
    let config = load_config(config_path)?;
    let Some(control) = &config.control_plane else {
        println!("Control plane: no configuration");
        return Ok(());
    };
    let interface_name = config.interface_name.trim();
    if interface_name.is_empty() {
        return Err(ShphError::InvalidArgument(
            "interface name required for control-plane apply".into(),
        ));
    }
    let plan = build_control_plane_plan(control, interface_name)?;
    let desired = PersistedControlPlaneState {
        interface_name: interface_name.to_string(),
        routes: plan.routes.clone(),
        dns_servers: plan.dns_servers.clone(),
    };

    let state_path = control_plane_state_path(config_path);
    if state_path.exists() {
        let existing = load_control_plane_state(config_path)?;
        if existing == desired {
            println!("Control plane: already reconciled");
            return Ok(());
        }
        return Err(ShphError::Config(
            "recorded control-plane state differs; run reconcile".into(),
        ));
    }

    let guard = apply_control_plane(&config, interface_name)?;
    if control.dry_run.unwrap_or(true) {
        return Ok(());
    }
    save_control_plane_state(config_path, &state_from_guard(interface_name, &guard))?;
    println!(
        "Control plane: applied routes={} dns={}",
        desired.routes.len(),
        desired.dns_servers.len()
    );
    Ok(())
}

fn handle_control_plane_reconcile(config_path: &Path) -> Result<()> {
    if control_plane_state_path(config_path).exists() {
        let state = load_control_plane_state(config_path)?;
        let mut guard = guard_from_state(&state);
        guard.cleanup()?;
        remove_control_plane_state(config_path)?;
        println!("Control plane: previous state undone");
    }
    handle_control_plane_apply(config_path)
}

fn handle_control_plane_undo(config_path: &Path) -> Result<()> {
    let state_path = control_plane_state_path(config_path);
    if !state_path.exists() {
        println!("Control plane: no applied state");
        return Ok(());
    }
    let state = load_control_plane_state(config_path)?;
    let mut guard = guard_from_state(&state);
    guard.cleanup()?;
    remove_control_plane_state(config_path)?;
    println!("Control plane: undone");
    Ok(())
}

fn handle_show_fingerprint(keystore_path: &Path) -> Result<()> {
    let keystore = KeyStore::load(keystore_path, None)?;
    println!("{}", keystore.fingerprint_hex());
    Ok(())
}

fn handle_show_public_key(keystore_path: &Path) -> Result<()> {
    let keystore = KeyStore::load(keystore_path, None)?;
    println!("{}", keystore.public_key_b64());
    Ok(())
}

fn handle_show_signing_public_key(keystore_path: &Path) -> Result<()> {
    let keystore = KeyStore::load(keystore_path, None)?;
    println!("{}", keystore.identity.signing_public_b64());
    Ok(())
}

fn handle_list_peers(config_path: &Path, json: bool) -> Result<()> {
    let config = load_config(config_path)?;
    let peers: Vec<PeerSummary> = config
        .peers
        .iter()
        .map(|peer| PeerSummary {
            alias: peer.alias.clone(),
            endpoint: peer.endpoint.clone(),
            public_key: peer.pubkey.clone(),
            signing_key: if peer.sign_pubkey.is_some() {
                "configured".into()
            } else {
                "missing".into()
            },
        })
        .collect();

    if json {
        println!("{}", serde_json::to_string_pretty(&peers)?);
        return Ok(());
    }

    if config.peers.is_empty() {
        println!("No peers configured.");
        println!("Add one with: shph add-peer <alias> <host> <port> <pubkey> --sign-pubkey <key>");
        return Ok(());
    }

    println!("Configured peers ({})", peers.len());
    for peer in peers {
        println!("  {} -> {}", peer.alias, peer.endpoint);
        println!("    public key: {}", shorten_key(&peer.public_key));
        println!("    signing key: {}", peer.signing_key);
    }
    Ok(())
}

fn shorten_key(value: &str) -> String {
    const EDGE: usize = 10;
    if value.len() <= EDGE * 2 + 3 {
        return value.to_string();
    }
    format!("{}...{}", &value[..EDGE], &value[value.len() - EDGE..])
}

fn handle_add_peer(
    config_path: &Path,
    keystore_path: &Path,
    alias: String,
    host: String,
    port: u16,
    pubkey_b64: String,
    sign_pubkey_b64: String,
) -> Result<()> {
    if alias.trim().is_empty() {
        return Err(ShphError::InvalidArgument("alias cannot be empty".into()));
    }
    if port == 0 {
        return Err(ShphError::InvalidArgument("port must be > 0".into()));
    }
    validate_pubkey_b64(&pubkey_b64)?;
    validate_pubkey_b64_named(&sign_pubkey_b64, "sign_pubkey")?;

    let mut config = if config_path.exists() {
        load_config(config_path)?
    } else {
        Config::default()
    };

    if config.peers.iter().any(|p| p.alias == alias) {
        return Err(ShphError::InvalidArgument(
            "peer alias already exists".into(),
        ));
    }

    let endpoint = format_endpoint(&host, port);
    config.peers.push(PeerConfig {
        alias: alias.clone(),
        endpoint: endpoint.clone(),
        pubkey: pubkey_b64.clone(),
        sign_pubkey: Some(sign_pubkey_b64.clone()),
    });
    save_config(&config, config_path)?;

    let mut keystore = if keystore_path.exists() {
        KeyStore::load(keystore_path, None)?
    } else {
        KeyStore::new(KeyStoreConfig::default())?
    };
    keystore.add_contact(Contact {
        alias: alias.clone(),
        endpoint: Endpoint { host, port },
        pubkey_b64,
        sign_pubkey_b64: Some(sign_pubkey_b64),
    });
    keystore.save(keystore_path)?;

    println!("Peer added: {alias} ({endpoint})");
    Ok(())
}

fn handle_show_config(config_path: &Path, show_secrets: bool) -> Result<()> {
    let config = load_config(config_path)?;
    if show_secrets {
        eprintln!(
            "WARNING: --show-secrets prints credential-like configuration fields; protect the terminal and any redirected output."
        );
    }
    let rendered = render_config_for_display(&config, show_secrets)?;
    println!("{rendered}");
    Ok(())
}

fn render_config_for_display(config: &Config, show_secrets: bool) -> Result<String> {
    let mut value =
        toml::Value::try_from(config).map_err(|error| ShphError::Config(error.to_string()))?;
    if !show_secrets {
        redact_config_value(&mut value);
    }
    toml::to_string_pretty(&value).map_err(|error| ShphError::Config(error.to_string()))
}

fn redact_config_value(value: &mut toml::Value) {
    match value {
        toml::Value::Array(values) => {
            for value in values {
                redact_config_value(value);
            }
        }
        toml::Value::Table(table) => {
            for (key, value) in table {
                if is_sensitive_config_key(key) {
                    *value = toml::Value::String("<redacted>".into());
                } else {
                    redact_config_value(value);
                }
            }
        }
        _ => {}
    }
}

fn is_sensitive_config_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    matches!(
        key.as_str(),
        "password"
            | "pin"
            | "secret"
            | "private_key"
            | "private_key_b64"
            | "signing_seed"
            | "signing_seed_b64"
            | "sign_seed"
            | "sign_seed_b64"
            | "token"
    ) || key.ends_with("_password")
        || key.ends_with("_secret")
        || key.ends_with("_private_key")
        || key.ends_with("_token")
}

fn handle_validate_roadmap(config_path: &Path) -> Result<()> {
    let config = load_config(config_path)?;
    let Some(roadmap) = config.roadmap.as_ref() else {
        println!("Roadmap: no optional configuration");
        return Ok(());
    };
    validate_config_roadmap(&config)?;
    println!("Roadmap: valid");
    println!("  Transport: {:?}", roadmap.transport);
    println!("  Identity provider: {:?}", roadmap.identity);
    println!("  Shamir enabled: {}", roadmap.shamir.enabled);
    println!(
        "  Ratchet audit journal: {}",
        roadmap.ratchet_audit.journal_path
    );
    Ok(())
}

fn configured_roadmap(config_path: &Path) -> Result<RoadmapConfig> {
    let config = load_config(config_path)?;
    let roadmap = config
        .roadmap
        .ok_or_else(|| ShphError::Config("roadmap configuration is required".into()))?;
    validate_roadmap(&roadmap)?;
    validate_identity_provider(&roadmap.identity)?;
    Ok(roadmap)
}

fn validate_config_roadmap(config: &Config) -> Result<()> {
    if let Some(roadmap) = config.roadmap.as_ref() {
        validate_roadmap(roadmap)?;
        validate_identity_provider(&roadmap.identity)?;
    }
    if let Some(stealth) = &config.stealth {
        if !shph_core::stealth_profiles()
            .iter()
            .any(|profile| profile.name == stealth.profile)
        {
            return Err(ShphError::Config(format!(
                "unknown stealth profile: {}",
                stealth.profile
            )));
        }
        if shph_core::shroud_profile_by_selection(&stealth.shroud_profile).is_none() {
            return Err(ShphError::Config(format!(
                "unknown shroud profile: {}",
                stealth.shroud_profile
            )));
        }
    }
    Ok(())
}

fn handle_shamir_split(
    config_path: &Path,
    secret_file: Option<&Path>,
    secret_stdin: bool,
    output_dir: &Path,
) -> Result<()> {
    let roadmap = configured_roadmap(config_path)?;
    if !roadmap.shamir.enabled {
        return Err(ShphError::Config(
            "Shamir is disabled in roadmap configuration".into(),
        ));
    }
    let mut secret = read_shamir_secret(secret_file, secret_stdin)?;
    if secret.is_empty() {
        return Err(ShphError::InvalidArgument("secret cannot be empty".into()));
    }
    let shares = split_secret(&secret, &roadmap.shamir)?;
    write_shamir_shares(output_dir, &shares)?;
    secret.zeroize();
    println!(
        "Wrote {} Shamir share files to {}",
        shares.len(),
        output_dir.display()
    );
    Ok(())
}

fn handle_shamir_recover(config_path: &Path, paths: &[PathBuf], output_file: &Path) -> Result<()> {
    let roadmap = configured_roadmap(config_path)?;
    if !roadmap.shamir.enabled {
        return Err(ShphError::Config(
            "Shamir is disabled in roadmap configuration".into(),
        ));
    }
    if paths.is_empty() {
        return Err(ShphError::InvalidArgument(
            "at least one share file is required".into(),
        ));
    }
    if paths.len() > MAX_SHAMIR_SHARE_FILES {
        return Err(ShphError::InvalidArgument(format!(
            "too many Shamir share files (maximum {MAX_SHAMIR_SHARE_FILES})"
        )));
    }
    let mut shares = Vec::with_capacity(paths.len());
    let mut total_bytes = 0u64;
    for path in paths {
        let file = open_secret_input(path)?;
        let length = file.metadata()?.len();
        if length > MAX_SHAMIR_SHARE_FILE_BYTES
            || total_bytes.saturating_add(length) > MAX_SHAMIR_TOTAL_BYTES
        {
            return Err(ShphError::InvalidArgument(
                "Shamir share input exceeds the configured size limits".into(),
            ));
        }
        total_bytes = total_bytes.saturating_add(length);
        let mut bytes = Vec::with_capacity(length as usize);
        file.take(MAX_SHAMIR_SHARE_FILE_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_SHAMIR_SHARE_FILE_BYTES {
            return Err(ShphError::InvalidArgument(
                "Shamir share input exceeds the configured size limits".into(),
            ));
        }
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        if value.is_array() {
            let file_shares: Vec<ShamirShare> = serde_json::from_value(value)?;
            shares.extend(file_shares);
        } else {
            shares.push(serde_json::from_value(value)?);
        }
        if shares.len() > MAX_SHAMIR_TOTAL_SHARES {
            return Err(ShphError::InvalidArgument(
                "too many decoded Shamir shares".into(),
            ));
        }
    }
    let mut recovered = recover_secret_from_shares(&shares, &roadmap.shamir)?;
    write_owner_only_file(output_file, &recovered)?;
    recovered.zeroize();
    println!("Wrote recovered secret to {}", output_file.display());
    Ok(())
}

fn read_shamir_secret(
    path: Option<&Path>,
    from_stdin: bool,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let mut file = if from_stdin || path.is_some_and(|value| value == Path::new("-")) {
        None
    } else {
        Some(open_secret_input(path.ok_or_else(|| {
            ShphError::InvalidArgument("secret file is required".into())
        })?)?)
    };
    let mut bytes = Vec::new();
    if let Some(file) = file.as_mut() {
        let length = file.metadata()?.len();
        if length > MAX_SHAMIR_SECRET_BYTES {
            return Err(ShphError::InvalidArgument(
                "Shamir secret file exceeds the 64 KiB safety limit".into(),
            ));
        }
        file.take(MAX_SHAMIR_SECRET_BYTES + 1)
            .read_to_end(&mut bytes)?;
    } else {
        io::stdin()
            .take(MAX_SHAMIR_SECRET_BYTES + 1)
            .read_to_end(&mut bytes)?;
    }
    if bytes.len() as u64 > MAX_SHAMIR_SECRET_BYTES {
        return Err(ShphError::InvalidArgument(
            "Shamir secret exceeds the 64 KiB safety limit".into(),
        ));
    }
    Ok(zeroize::Zeroizing::new(bytes))
}

fn open_secret_input(path: &Path) -> Result<fs::File> {
    ensure_no_reparse_components(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(ShphError::Io)?;
        if !file
            .metadata()
            .map_err(ShphError::Io)?
            .file_type()
            .is_file()
        {
            return Err(ShphError::InvalidArgument(
                "secret input path must reference a regular file".into(),
            ));
        }
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        shph_core::ensure_not_reparse_point(path)?;
        let metadata = fs::symlink_metadata(path).map_err(ShphError::Io)?;
        if metadata.file_type().is_symlink() {
            return Err(ShphError::InvalidArgument(
                "refusing to read a symlinked secret input".into(),
            ));
        }
        let file = fs::File::open(path).map_err(ShphError::Io)?;
        if !file
            .metadata()
            .map_err(ShphError::Io)?
            .file_type()
            .is_file()
        {
            return Err(ShphError::InvalidArgument(
                "secret input path must reference a regular file".into(),
            ));
        }
        Ok(file)
    }
}

fn write_shamir_shares(output_dir: &Path, shares: &[ShamirShare]) -> Result<()> {
    ensure_no_reparse_components(output_dir)?;
    fs::create_dir_all(output_dir)?;
    ensure_no_reparse_components(output_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(output_dir, fs::Permissions::from_mode(0o700))?;
    }
    for (offset, share) in shares.iter().enumerate() {
        let path = output_dir.join(format!("share-{:03}.json", offset + 1));
        let data = serde_json::to_vec_pretty(share)?;
        write_owner_only_file(&path, &data)?;
    }
    Ok(())
}

fn write_owner_only_file(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    ensure_no_reparse_components(parent)?;
    fs::create_dir_all(parent)?;
    ensure_no_reparse_components(parent)?;
    ensure_no_reparse_components(path)?;
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("secret");
    let temp = parent.join(format!(
        ".{filename}.tmp.{}.{}",
        std::process::id(),
        phase_a1_now_ms()?
    ));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temp, fs::Permissions::from_mode(0o600))?;
    }
    if let Err(error) = (|| -> Result<()> {
        shph_core::enforce_owner_only_file_permissions(&temp)?;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        ensure_no_reparse_components(parent)?;
        ensure_no_reparse_components(path)?;
        fs::rename(&temp, path)?;
        Ok(())
    })() {
        let _ = fs::remove_file(&temp);
        return Err(error);
    }
    Ok(())
}

fn append_handshake_audit(
    roadmap: Option<&RoadmapConfig>,
    local_identity: &shph_core::IdentityKeyPair,
    peer: &str,
    state: &HandshakeState,
    role: &str,
    transport: TransportMode,
) -> Result<()> {
    if let Some(roadmap) = roadmap {
        append_ratchet_audit_event(
            &roadmap.ratchet_audit,
            compute_fingerprint_hex(&local_identity.public_key_bytes()),
            state.peer_fingerprint_hex.clone(),
            state.transcript_hash_hex.clone(),
            role,
            transport_mode_to_str(transport),
        )?;
        println!("  Ratchet audit: recorded peer {peer}");
    }
    Ok(())
}

fn handle_ratchet_audit_export(config_path: &Path) -> Result<()> {
    let roadmap = configured_roadmap(config_path)?;
    let records = read_ratchet_audit_events(&roadmap.ratchet_audit)?;
    println!("{}", serde_json::to_string_pretty(&records)?);
    Ok(())
}

fn handle_handshake_sim(keystore_path: &Path, peer_pubkey_b64: &str) -> Result<()> {
    validate_pubkey_b64(peer_pubkey_b64)?;
    let keystore = KeyStore::load(keystore_path, None)?;
    let material = build_hello(&keystore.identity)?;

    // Simulate peer hello with deterministic fields for local validation.
    let peer_identity = shph_core::IdentityKeyPair::from_base64(
        &base64::engine::general_purpose::STANDARD.encode(
            base64::engine::general_purpose::STANDARD
                .decode(peer_pubkey_b64.as_bytes())
                .map_err(|_| ShphError::Handshake("invalid peer public key base64".into()))?,
        ),
        None,
    )?;
    let peer_material = build_hello(&peer_identity)?;
    let policy = PeerPolicy::single(PeerPin::for_identity(&peer_identity));
    let state: HandshakeState = verify_and_derive(
        &keystore.identity,
        &material,
        &peer_material.local_hello,
        true,
        &policy,
    )?;
    let out = HandshakeSimOut {
        peer_fingerprint_hex: state.peer_fingerprint_hex,
        transcript_hash_hex: state.transcript_hash_hex,
    };
    let json = serde_json::to_string_pretty(&out)?;
    println!("{json}");
    Ok(())
}

fn handle_listen(
    keystore_path: &Path,
    bind: &str,
    timeout_secs: u64,
    transport: Option<String>,
    quic_cert_path: Option<&Path>,
    profile: HandshakeProfile,
    roadmap: Option<&RoadmapConfig>,
) -> Result<()> {
    if let Some(roadmap) = roadmap {
        validate_roadmap(roadmap)?;
        validate_identity_provider(&roadmap.identity)?;
    }
    let mode = resolve_transport_mode(transport.as_deref(), roadmap)?;
    announce_handshake_profile(profile);
    let keystore = KeyStore::load(keystore_path, None)?;
    let policy = peer_policy_for_endpoint(&keystore, bind, false)?;
    if mode == TransportMode::QuicStandard {
        let cert_path = quic_cert_path.ok_or_else(|| {
            ShphError::Config(
                "--quic-cert is required with --transport quic-standard on listen".into(),
            )
        })?;
        let bind_addr = parse_socket_addr(bind)?;
        let timeout = bounded_cli_timeout(timeout_secs);
        let state = run_async(async {
            let server = standards_quic::server_endpoint(
                bind_addr,
                standards_quic::StandardsQuicConfig::default(),
            )?;
            write_quic_certificate(cert_path, &server.certificate_der)?;
            println!("  Standards QUIC certificate: {}", cert_path.display());
            let connection =
                standards_quic::accept(&server, &keystore.identity, &policy, profile, timeout)
                    .await?;
            Ok(connection.handshake)
        })?;
        enforce_peer_policy(keystore_path, bind, &state, false)?;
        append_handshake_audit(roadmap, &keystore.identity, bind, &state, "listen", mode)?;
        print_handshake_state("listen", bind, &state);
        return Ok(());
    }
    let state = match mode {
        TransportMode::Tcp => tcp_handshake_server_with_profile(
            bind,
            &keystore.identity,
            &policy,
            timeout_secs,
            profile,
        )?,
        TransportMode::Quic => {
            let (_socket, _peer, state) = quic_handshake_server_with_profile(
                bind,
                &keystore.identity,
                &policy,
                timeout_secs,
                profile,
            )?;
            state
        }
        TransportMode::OfflineMesh => {
            let cfg = roadmap_offline_mesh_config(roadmap)?;
            offline_mesh_accept_and_handshake_with_profile(
                &cfg,
                &keystore.identity,
                &policy,
                timeout_secs,
                profile,
            )?
        }
        TransportMode::DataMule => {
            let cfg = roadmap_data_mule_config(roadmap)?;
            data_mule_accept_and_handshake_with_profile(
                &cfg,
                &keystore.identity,
                &policy,
                timeout_secs,
                profile,
            )?
        }
        TransportMode::QuicStandard => {
            return Err(ShphError::Unsupported(
                "quic-standard uses the async standards_quic API".into(),
            ))
        }
    };
    enforce_peer_policy(keystore_path, bind, &state, false)?;
    append_handshake_audit(roadmap, &keystore.identity, bind, &state, "listen", mode)?;
    print_handshake_state("listen", bind, &state);
    Ok(())
}

fn handle_connect(
    keystore_path: &Path,
    peer: &str,
    timeout_secs: u64,
    transport: Option<String>,
    quic_cert_path: Option<&Path>,
    profile: HandshakeProfile,
    roadmap: Option<&RoadmapConfig>,
) -> Result<()> {
    if let Some(roadmap) = roadmap {
        validate_roadmap(roadmap)?;
        validate_identity_provider(&roadmap.identity)?;
    }
    let mode = resolve_transport_mode(transport.as_deref(), roadmap)?;
    announce_handshake_profile(profile);
    let keystore = KeyStore::load(keystore_path, None)?;
    let policy = peer_policy_for_endpoint(&keystore, peer, true)?;
    if mode == TransportMode::QuicStandard {
        let cert_path = quic_cert_path.ok_or_else(|| {
            ShphError::Config(
                "--quic-cert is required with --transport quic-standard on connect".into(),
            )
        })?;
        let certificate = read_quic_certificate(cert_path)?;
        let peer_addr = parse_socket_addr(peer)?;
        let timeout_duration = bounded_cli_timeout(timeout_secs);
        let state = run_async(async {
            let endpoint = standards_quic::client_endpoint(
                "0.0.0.0:0".parse().expect("valid ephemeral endpoint"),
                &certificate,
                standards_quic::StandardsQuicConfig::default(),
            )?;
            let connection = standards_quic::connect(
                &endpoint,
                peer_addr,
                "localhost",
                &keystore.identity,
                &policy,
                profile,
                timeout_duration,
            )
            .await?;
            let state = connection.handshake;
            endpoint.close(0u32.into(), b"handshake complete");
            endpoint.wait_idle().await;
            Ok(state)
        })?;
        enforce_peer_policy(keystore_path, peer, &state, true)?;
        append_handshake_audit(roadmap, &keystore.identity, peer, &state, "connect", mode)?;
        print_handshake_state("connect", peer, &state);
        return Ok(());
    }
    let state = match mode {
        TransportMode::Tcp => tcp_handshake_client_with_profile(
            peer,
            &keystore.identity,
            &policy,
            timeout_secs,
            profile,
        )?,
        TransportMode::Quic => {
            let (_socket, _peer_addr, state) = quic_handshake_client_with_profile(
                peer,
                &keystore.identity,
                &policy,
                timeout_secs,
                profile,
            )?;
            state
        }
        TransportMode::OfflineMesh => {
            let cfg = roadmap_offline_mesh_config(roadmap)?;
            offline_mesh_connect_and_handshake_with_profile(
                &cfg,
                &keystore.identity,
                &policy,
                timeout_secs,
                profile,
            )?
        }
        TransportMode::DataMule => {
            let cfg = roadmap_data_mule_config(roadmap)?;
            data_mule_connect_and_handshake_with_profile(
                &cfg,
                &keystore.identity,
                peer,
                &policy,
                timeout_secs,
                profile,
            )?
        }
        TransportMode::QuicStandard => {
            return Err(ShphError::Unsupported(
                "quic-standard uses the async standards_quic API".into(),
            ))
        }
    };
    enforce_peer_policy(keystore_path, peer, &state, true)?;
    append_handshake_audit(roadmap, &keystore.identity, peer, &state, "connect", mode)?;
    print_handshake_state("connect", peer, &state);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_send_once(
    keystore_path: &Path,
    peer: &str,
    text: &str,
    timeout_secs: u64,
    transport: Option<String>,
    quic_cert_path: Option<&Path>,
    profile: HandshakeProfile,
    roadmap: Option<&RoadmapConfig>,
) -> Result<()> {
    if let Some(roadmap) = roadmap {
        validate_roadmap(roadmap)?;
        validate_identity_provider(&roadmap.identity)?;
    }
    let start_ms = phase_a1_now_ms()?;
    let session_id = format!("send-once-{peer}-{start_ms}");
    let metrics = MetricsCollector::new();
    println!("  Session id: {session_id}");
    println!("  Session start: {start_ms}ms");
    println!("  Initial metrics: {:?}", metrics.snapshot());
    let mode = resolve_transport_mode(transport.as_deref(), roadmap)?;
    let lab = quic_lab_config()?;
    announce_handshake_profile(profile);
    let keystore = KeyStore::load(keystore_path, None)?;
    let policy = peer_policy_for_endpoint(&keystore, peer, true)?;
    if mode == TransportMode::QuicStandard {
        let cert_path = quic_cert_path.ok_or_else(|| {
            ShphError::Config(
                "--quic-cert is required with --transport quic-standard on send-once".into(),
            )
        })?;
        let certificate = read_quic_certificate(cert_path)?;
        let peer_addr = parse_socket_addr(peer)?;
        let state = run_async(async {
            let endpoint = standards_quic::client_endpoint(
                "0.0.0.0:0".parse().expect("valid ephemeral endpoint"),
                &certificate,
                standards_quic::StandardsQuicConfig::default(),
            )?;
            let mut connection = standards_quic::connect(
                &endpoint,
                peer_addr,
                "localhost",
                &keystore.identity,
                &policy,
                profile,
                bounded_cli_timeout(timeout_secs),
            )
            .await?;
            enforce_peer_policy(keystore_path, peer, &connection.handshake, true)?;
            connection.send_datagram_wait(text.as_bytes()).await?;
            let ack =
                tokio::time::timeout(bounded_cli_timeout(timeout_secs), connection.recv_control())
                    .await
                    .map_err(|_| ShphError::Timeout)??;
            if ack != QUIC_PAYLOAD_ACK {
                return Err(ShphError::Protocol(
                    "unexpected QUIC one-shot payload acknowledgement".into(),
                ));
            }
            let state = connection.handshake;
            endpoint.close(0u32.into(), b"payload sent");
            endpoint.wait_idle().await;
            Ok(state)
        })?;
        append_handshake_audit(roadmap, &keystore.identity, peer, &state, "send", mode)?;
        metrics.inc_bytes_sent(text.len());
        print_handshake_state("send-once", peer, &state);
        println!("  Sent bytes: {}", text.len());
        println!("  Session id: {session_id}");
        println!("  Session end: {}ms", phase_a1_now_ms()?);
        println!("  Final metrics: {:?}", metrics.snapshot());
        return Ok(());
    }
    let (mut session, state) = match mode {
        TransportMode::Tcp => connect_secure_session_lab_with_profile(
            peer,
            &keystore.identity,
            &policy,
            timeout_secs,
            mode,
            lab,
            profile,
        )?,
        TransportMode::Quic => connect_secure_session_lab_with_profile(
            peer,
            &keystore.identity,
            &policy,
            timeout_secs,
            mode,
            lab,
            profile,
        )?,
        TransportMode::OfflineMesh => {
            let cfg = roadmap_offline_mesh_config(roadmap)?;
            offline_mesh_connect_secure_session_with_profile(
                &cfg,
                &keystore.identity,
                &policy,
                timeout_secs,
                profile,
            )?
        }
        TransportMode::DataMule => {
            let cfg = roadmap_data_mule_config(roadmap)?;
            data_mule_connect_secure_session_with_profile(
                &cfg,
                &keystore.identity,
                peer,
                &policy,
                timeout_secs,
                profile,
            )?
        }
        TransportMode::QuicStandard => {
            return Err(ShphError::Unsupported(
                "quic-standard uses the async standards_quic API".into(),
            ))
        }
    };
    enforce_peer_policy(keystore_path, peer, &state, true)?;
    let keystore = KeyStore::load(keystore_path, None)?;
    append_handshake_audit(roadmap, &keystore.identity, peer, &state, "send", mode)?;
    session.send_frame(text.as_bytes())?;
    metrics.inc_bytes_sent(text.len());
    print_handshake_state("send-once", peer, &state);
    println!("  Sent bytes: {}", text.len());
    println!("  Session id: {session_id}");
    println!("  Session end: {}ms", phase_a1_now_ms()?);
    println!("  Final metrics: {:?}", metrics.snapshot());
    Ok(())
}

fn handle_recv_once(
    keystore_path: &Path,
    bind: &str,
    timeout_secs: u64,
    transport: Option<String>,
    quic_cert_path: Option<&Path>,
    profile: HandshakeProfile,
    roadmap: Option<&RoadmapConfig>,
) -> Result<()> {
    if let Some(roadmap) = roadmap {
        validate_roadmap(roadmap)?;
        validate_identity_provider(&roadmap.identity)?;
    }
    let start_ms = phase_a1_now_ms()?;
    let session_id = format!("recv-once-{bind}-{start_ms}");
    let metrics = MetricsCollector::new();
    println!("  Session id: {session_id}");
    println!("  Session start: {start_ms}ms");
    println!("  Initial metrics: {:?}", metrics.snapshot());
    let mode = resolve_transport_mode(transport.as_deref(), roadmap)?;
    let lab = quic_lab_config()?;
    announce_handshake_profile(profile);
    let keystore = KeyStore::load(keystore_path, None)?;
    let policy = peer_policy_for_endpoint(&keystore, bind, false)?;
    if mode == TransportMode::QuicStandard {
        let cert_path = quic_cert_path.ok_or_else(|| {
            ShphError::Config(
                "--quic-cert is required with --transport quic-standard on recv-once".into(),
            )
        })?;
        let bind_addr = parse_socket_addr(bind)?;
        let result = run_async(async {
            let server = standards_quic::server_endpoint(
                bind_addr,
                standards_quic::StandardsQuicConfig::default(),
            )?;
            write_quic_certificate(cert_path, &server.certificate_der)?;
            println!("  Standards QUIC certificate: {}", cert_path.display());
            let mut connection = standards_quic::accept(
                &server,
                &keystore.identity,
                &policy,
                profile,
                bounded_cli_timeout(timeout_secs),
            )
            .await?;
            enforce_peer_policy(keystore_path, bind, &connection.handshake, false)?;
            let payload = connection.recv_datagram().await?;
            connection.send_control(QUIC_PAYLOAD_ACK).await?;
            let peer_connection = connection.connection.clone();
            let _ =
                tokio::time::timeout(bounded_cli_timeout(timeout_secs), peer_connection.closed())
                    .await;
            Ok((connection.handshake, payload.to_vec()))
        })?;
        let (state, payload) = result;
        append_handshake_audit(roadmap, &keystore.identity, bind, &state, "recv", mode)?;
        metrics.inc_bytes_recv(payload.len());
        let plaintext = String::from_utf8(payload)
            .map_err(|_| ShphError::Protocol("payload not valid utf8".into()))?;
        print_handshake_state("recv-once", bind, &state);
        println!("  Payload: {plaintext}");
        println!("  Session id: {session_id}");
        println!("  Session end: {}ms", phase_a1_now_ms()?);
        println!("  Final metrics: {:?}", metrics.snapshot());
        return Ok(());
    }
    let (mut session, state) = match mode {
        TransportMode::Tcp => accept_secure_session_lab_with_profile(
            bind,
            &keystore.identity,
            &policy,
            timeout_secs,
            mode,
            lab,
            profile,
        )?,
        TransportMode::Quic => accept_secure_session_lab_with_profile(
            bind,
            &keystore.identity,
            &policy,
            timeout_secs,
            mode,
            lab,
            profile,
        )?,
        TransportMode::OfflineMesh => {
            let cfg = roadmap_offline_mesh_config(roadmap)?;
            offline_mesh_accept_secure_session_with_profile(
                &cfg,
                &keystore.identity,
                &policy,
                timeout_secs,
                profile,
            )?
        }
        TransportMode::DataMule => {
            let cfg = roadmap_data_mule_config(roadmap)?;
            data_mule_accept_secure_session_with_profile(
                &cfg,
                &keystore.identity,
                &policy,
                timeout_secs,
                profile,
            )?
        }
        TransportMode::QuicStandard => {
            return Err(ShphError::Unsupported(
                "quic-standard uses the async standards_quic API".into(),
            ))
        }
    };
    enforce_peer_policy(keystore_path, bind, &state, false)?;
    let keystore = KeyStore::load(keystore_path, None)?;
    append_handshake_audit(roadmap, &keystore.identity, bind, &state, "recv", mode)?;
    let payload = session.recv_frame()?;
    metrics.inc_bytes_recv(payload.len());
    let plaintext = String::from_utf8(payload)
        .map_err(|_| ShphError::Protocol("payload not valid utf8".into()))?;
    print_handshake_state("recv-once", bind, &state);
    println!("  Payload: {plaintext}");
    println!("  Session id: {session_id}");
    println!("  Session end: {}ms", phase_a1_now_ms()?);
    println!("  Final metrics: {:?}", metrics.snapshot());
    Ok(())
}

fn to_peer_configs(keystore: &KeyStore) -> Vec<PeerConfig> {
    keystore
        .contacts
        .values()
        .map(|contact| PeerConfig {
            alias: contact.alias.clone(),
            endpoint: format!("{}:{}", contact.endpoint.host, contact.endpoint.port),
            pubkey: contact.pubkey_b64.clone(),
            sign_pubkey: contact.sign_pubkey_b64.clone(),
        })
        .collect()
}

fn keystore_path_from_config(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("keystore.json")
}

fn validate_pubkey_b64(input: &str) -> Result<()> {
    validate_pubkey_b64_named(input, "pubkey")
}

fn validate_pubkey_b64_named(input: &str, label: &str) -> Result<()> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(input.as_bytes())
        .map_err(|_| ShphError::InvalidArgument(format!("{label} must be base64")))?;
    if raw.len() != 32 {
        return Err(ShphError::InvalidArgument(format!(
            "{label} must decode to 32 bytes"
        )));
    }
    Ok(())
}

fn transport_mode_to_str(mode: TransportMode) -> &'static str {
    match mode {
        TransportMode::Tcp => "tcp",
        TransportMode::Quic => "quic",
        TransportMode::QuicStandard => "quic-standard",
        TransportMode::OfflineMesh => "offline-mesh",
        TransportMode::DataMule => "data-mule",
    }
}

fn resolve_handshake_profile(
    cli_value: Option<&str>,
    config_value: Option<HandshakeProfile>,
) -> Result<HandshakeProfile> {
    let profile = match cli_value {
        Some(value) => value.parse()?,
        None => config_value.unwrap_or_default(),
    };
    Ok(profile)
}

fn announce_handshake_profile(profile: HandshakeProfile) {
    println!("  Handshake profile: {}", profile.as_str());
    if profile == HandshakeProfile::ClassicalLab {
        println!(
            "  WARNING: classical-lab is benchmark-only and removes ML-KEM; both peers must opt in"
        );
    }
}

fn resolve_transport_mode(
    transport: Option<&str>,
    roadmap: Option<&RoadmapConfig>,
) -> Result<TransportMode> {
    if let Some(raw) = transport {
        return TransportMode::parse(raw);
    }

    if let Some(roadmap) = roadmap {
        resolve_transport_from_roadmap(roadmap)
    } else {
        Ok(TransportMode::Tcp)
    }
}

fn resolve_transport_from_roadmap(cfg: &RoadmapConfig) -> Result<TransportMode> {
    match &cfg.transport {
        shph_core::roadmap::TransportAdapterConfig::Tcp => Ok(TransportMode::Tcp),
        shph_core::roadmap::TransportAdapterConfig::OfflineMesh { .. } => {
            Ok(TransportMode::OfflineMesh)
        }
        shph_core::roadmap::TransportAdapterConfig::DataMule { .. } => Ok(TransportMode::DataMule),
    }
}

fn resolve_shroud_profile(cli_value: Option<&str>, config_value: Option<&str>) -> Result<String> {
    let value = cli_value.or(config_value).unwrap_or("medium");
    let normalized = value.trim().to_ascii_lowercase();
    parse_shroud_profile_name(&normalized)?;
    Ok(match normalized.as_str() {
        "none" | "disabled" => "off".into(),
        "low-latency" => "low".into(),
        "balanced" => "medium".into(),
        "bulk" => "high".into(),
        "extreme" => "extreme-lab".into(),
        other => other.into(),
    })
}

fn quic_lab_config() -> Result<QuicLabConfig> {
    let Some(name) = std::env::var("SHPH_SHROUD_PROFILE").ok() else {
        return Ok(QuicLabConfig::default());
    };
    let profile = parse_shroud_profile_name(&name)?;
    Ok(QuicLabConfig {
        shroud_profile: profile,
    })
}

fn parse_shroud_profile_name(name: &str) -> Result<Option<shph_core::ShroudProfile>> {
    shph_core::shroud_profile_by_selection(name).ok_or_else(|| {
        ShphError::Config(format!(
            "unknown SHPH_SHROUD_PROFILE '{name}'; expected off, low, medium, high, extreme-lab, or a named lab profile"
        ))
    })
}

fn roadmap_offline_mesh_config(roadmap: Option<&RoadmapConfig>) -> Result<OfflineMeshConfig> {
    roadmap
        .ok_or_else(|| {
            ShphError::Config(
                "offline-mesh transport requested but roadmap transport config missing".into(),
            )
        })?
        .transport
        .as_offline_mesh()
        .ok_or_else(|| {
            ShphError::Config("roadmap transport is not configured as offline-mesh".into())
        })
}

fn roadmap_data_mule_config(roadmap: Option<&RoadmapConfig>) -> Result<DataMuleConfig> {
    roadmap
        .ok_or_else(|| {
            ShphError::Config(
                "data-mule transport requested but roadmap transport config missing".into(),
            )
        })?
        .transport
        .as_data_mule()
        .ok_or_else(|| ShphError::Config("roadmap transport is not configured as data-mule".into()))
}

fn load_config(config_path: &Path) -> Result<Config> {
    Config::load(config_path).map_err(|e| ShphError::Config(e.to_string()))
}

fn save_config(config: &Config, config_path: &Path) -> Result<()> {
    config
        .save(config_path)
        .map_err(|e| ShphError::Config(e.to_string()))
}

fn format_endpoint(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn decode_peer_key(value: &str, label: &str) -> Result<[u8; 32]> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(value.as_bytes())
        .map_err(|_| ShphError::Auth(format!("{label} is not valid base64")))?;
    raw.try_into()
        .map_err(|_| ShphError::Auth(format!("{label} must decode to 32 bytes")))
}

fn contact_peer_pin(contact: &Contact) -> Result<PeerPin> {
    let identity_public = decode_peer_key(&contact.pubkey_b64, "configured peer identity")?;
    let signing_public = contact
        .sign_pubkey_b64
        .as_deref()
        .ok_or_else(|| {
            ShphError::Auth(format!(
                "configured contact '{}' has no pinned signing key",
                contact.alias
            ))
        })
        .and_then(|value| decode_peer_key(value, "configured peer signing key"))?;
    Ok(PeerPin::new(identity_public, signing_public))
}

fn outbound_contacts<'a>(keystore: &'a KeyStore, selector: &str) -> Vec<&'a Contact> {
    keystore
        .contacts
        .values()
        .filter(|contact| {
            let configured_endpoint =
                format_endpoint(&contact.endpoint.host, contact.endpoint.port);
            configured_endpoint == selector
                || contact.alias == selector
                || contact.pubkey_b64 == selector
        })
        .collect()
}

fn peer_policy_for_endpoint(
    keystore: &KeyStore,
    selector: &str,
    outbound: bool,
) -> Result<PeerPolicy> {
    let contacts: Vec<&Contact> = if outbound {
        outbound_contacts(keystore, selector)
    } else {
        keystore.contacts.values().collect()
    };

    let pins = contacts
        .into_iter()
        .map(contact_peer_pin)
        .collect::<Result<Vec<_>>>()?;
    PeerPolicy::new(pins)
}

fn enforce_peer_policy(
    keystore_path: &Path,
    selector: &str,
    state: &HandshakeState,
    outbound: bool,
) -> Result<()> {
    let keystore = KeyStore::load(keystore_path, None)?;
    let peers = if outbound {
        let matching = outbound_contacts(&keystore, selector);
        if matching.is_empty() {
            return Err(ShphError::Auth(format!(
                "peer selector is not configured: {selector}"
            )));
        }
        matching
    } else if keystore.contacts.is_empty() {
        return Err(ShphError::Auth(
            "no peers are pinned; add the expected peer before starting a session".into(),
        ));
    } else {
        keystore.contacts.values().collect()
    };

    if peers.iter().any(|peer| {
        let signing_key_matches = peer
            .sign_pubkey_b64
            .as_deref()
            .and_then(|expected| {
                let expected = base64::engine::general_purpose::STANDARD
                    .decode(expected.as_bytes())
                    .ok()?;
                let actual = base64::engine::general_purpose::STANDARD
                    .decode(state.peer_signing_pubkey_b64.as_bytes())
                    .ok()?;
                Some(expected.len() == 32 && expected == actual)
            })
            .unwrap_or(false);
        base64::engine::general_purpose::STANDARD
            .decode(peer.pubkey_b64.as_bytes())
            .ok()
            .filter(|raw| raw.len() == 32)
            .map(|raw| {
                compute_fingerprint_hex(&raw) == state.peer_fingerprint_hex && signing_key_matches
            })
            .unwrap_or(false)
    }) {
        Ok(())
    } else {
        Err(ShphError::Auth(format!(
            "peer identity {} is not pinned in configuration",
            state.peer_fingerprint_hex
        )))
    }
}

fn print_handshake_state(role: &str, endpoint: &str, state: &HandshakeState) {
    println!("SHPH handshake {role} ok");
    println!("  Endpoint: {endpoint}");
    println!("  Peer fingerprint: {}", state.peer_fingerprint_hex);
    println!("  Transcript hash: {}", state.transcript_hash_hex);
}

fn print_control_plane_status(config: &Config) {
    if let Some(control) = &config.control_plane {
        let dry_run = control.dry_run.unwrap_or(true);
        let routes = control.route_cidrs.as_ref().map_or(0, |v| v.len());
        let dns = control.dns_servers.as_ref().map_or(0, |v| v.len());
        let apply_routes = control.apply_routes.unwrap_or(false);
        let apply_dns = control.apply_dns.unwrap_or(false);
        println!(
            "  Control plane: routes={}({}), dns={}({}), dry_run={}",
            apply_routes, routes, apply_dns, dns, dry_run
        );
    }
}

fn apply_control_plane(config: &Config, interface_name: &str) -> Result<ControlPlaneGuard> {
    let Some(control) = &config.control_plane else {
        return Ok(ControlPlaneGuard::default());
    };
    let dry_run = control.dry_run.unwrap_or(true);

    // Phase A.2: preflight validation. Validate every route and DNS entry up
    // front so a live apply is all-or-nothing rather than leaving the host in a
    // half-applied state. Invalid inputs are rejected before any mutation.
    let plan = build_control_plane_plan(control, interface_name)?;

    let mut guard = ControlPlaneGuard {
        dry_run,
        ..ControlPlaneGuard::default()
    };

    let apply_result = (|| -> Result<()> {
        for route in &plan.routes {
            if dry_run {
                println!("  [dry-run] route add {route}");
            } else {
                add_route(route, interface_name)?;
                guard
                    .added_routes
                    .push((route.clone(), interface_name.to_string()));
                println!("  route add {route}");
            }
        }

        if plan.apply_dns {
            if dry_run {
                for server in &plan.dns_servers {
                    println!("  [dry-run] dns add {server}");
                }
            } else {
                guard.applied_dns_servers = plan.dns_servers.clone();
                guard.dns_interface_name = Some(interface_name.to_string());
                apply_dns_servers(&plan.dns_servers, interface_name)?;
                for server in &plan.dns_servers {
                    println!("  dns add {server}");
                }
            }
        }
        Ok(())
    })();

    if let Err(err) = apply_result {
        // Roll back everything already applied, preserving the original error
        // while still surfacing any rollback failure for diagnostics.
        let cleanup_result = guard.cleanup();
        if let Err(clean_err) = cleanup_result {
            return Err(ShphError::Internal(format!(
                "control-plane apply error: {err}; rollback error: {clean_err}"
            )));
        }
        return Err(err);
    }

    Ok(guard)
}

fn configure_native_tun_mtu(interface_name: &str, mtu: usize) -> Result<()> {
    let commands = build_tun_mtu_commands(interface_name, mtu)?;
    for command in &commands {
        run_shell_command(command)?;
    }
    println!("  native TUN MTU: {mtu}");
    Ok(())
}

const MAX_KILLSWITCH_PEERS: usize = 64;

#[derive(Default)]
struct FirewallGuard {
    dry_run: bool,
    cleanup_commands: Vec<Vec<String>>,
    #[cfg(target_os = "windows")]
    windows: Option<WindowsKillswitchGuard>,
}

impl FirewallGuard {
    fn cleanup(&mut self) -> Result<()> {
        let mut first_error = None;

        #[cfg(target_os = "windows")]
        if let Some(mut guard) = self.windows.take() {
            if let Err(error) = guard.cleanup() {
                first_error = Some(error);
            }
        }

        let dry_run = self.dry_run;
        for command in self.cleanup_commands.drain(..) {
            if !dry_run {
                if let Err(error) = run_shell_command(&command) {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }

        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn allow_interface(&mut self, interface_name: &str) -> Result<()> {
        #[cfg(target_os = "windows")]
        if let Some(guard) = self.windows.as_mut() {
            guard.allow_interface(interface_name)?;
        }

        #[cfg(not(target_os = "windows"))]
        let _ = interface_name;

        Ok(())
    }
}

impl Drop for FirewallGuard {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[derive(Default)]
struct NatGuard {
    dry_run: bool,
    cleanup_commands: Vec<Vec<String>>,
    previous_forwarding: Option<String>,
}

impl NatGuard {
    fn cleanup(&mut self) -> Result<()> {
        let mut first_error = None;
        for command in self.cleanup_commands.drain(..) {
            if !self.dry_run {
                if let Err(error) = run_shell_command(&command) {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }

        if !self.dry_run {
            if let Some(previous) = self.previous_forwarding.take() {
                if let Err(error) = run_shell_command(&[
                    "sysctl".into(),
                    "-w".into(),
                    format!("net.ipv4.ip_forward={previous}"),
                ]) {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        } else {
            self.previous_forwarding = None;
        }

        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl Drop for NatGuard {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[cfg(all(not(test), target_os = "linux"))]
fn read_ipv4_forwarding() -> Result<String> {
    let output = Command::new("sysctl")
        .args(["-n", "net.ipv4.ip_forward"])
        .output()
        .map_err(ShphError::Io)?;
    if !output.status.success() {
        return Err(ShphError::Internal(
            "unable to read net.ipv4.ip_forward".into(),
        ));
    }
    let value = String::from_utf8(output.stdout)
        .map_err(|_| ShphError::Internal("sysctl returned non-UTF-8 output".into()))?;
    let value = value.trim();
    if value != "0" && value != "1" {
        return Err(ShphError::Internal(
            "net.ipv4.ip_forward returned an unexpected value".into(),
        ));
    }
    Ok(value.into())
}

#[cfg(all(test, target_os = "linux"))]
fn read_ipv4_forwarding() -> Result<String> {
    Ok("0".into())
}

fn apply_nat(interface_name: &str, dry_run: bool) -> Result<NatGuard> {
    #[cfg(target_os = "linux")]
    {
        let commands = build_linux_nat_commands(interface_name)?;
        let cleanup_commands = build_linux_nat_cleanup_commands();
        let mut guard = NatGuard {
            dry_run,
            cleanup_commands,
            previous_forwarding: None,
        };
        if dry_run {
            println!("  [dry-run] NAT:");
            for command in &commands {
                println!("    {command:?}");
            }
            println!("    [dry-run] sysctl net.ipv4.ip_forward=1");
            Ok(guard)
        } else {
            let previous = read_ipv4_forwarding()?;
            run_shell_command(&["sysctl".into(), "-w".into(), "net.ipv4.ip_forward=1".into()])?;
            guard.previous_forwarding = Some(previous);
            for command in &commands {
                if let Err(error) = run_shell_command(command) {
                    let _ = guard.cleanup();
                    return Err(error);
                }
            }
            println!("  NAT: Linux forwarding and masquerade active ({NAT_TABLE_NAME})");
            Ok(guard)
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (interface_name, dry_run);
        println!("  NAT: unavailable on this platform; continuing without host NAT");
        Ok(NatGuard::default())
    }
}

fn apply_killswitch(
    config: &Config,
    transport: TransportMode,
    dry_run: bool,
) -> Result<FirewallGuard> {
    let firewall_transport = match transport {
        TransportMode::Tcp => FirewallTransport::Tcp,
        TransportMode::Quic | TransportMode::QuicStandard => FirewallTransport::Udp,
        TransportMode::OfflineMesh | TransportMode::DataMule => {
            return Err(ShphError::Unsupported(
                "the host killswitch only supports TCP and UDP transports".into(),
            ))
        }
    };
    let peers = resolve_killswitch_peers(config)?;

    #[cfg(target_os = "linux")]
    {
        let commands =
            build_linux_killswitch_commands(&config.interface_name, &peers, firewall_transport)?;
        apply_linux_firewall_plan(
            "killswitch",
            commands,
            build_linux_killswitch_cleanup_commands(),
            dry_run,
        )
    }

    #[cfg(target_os = "windows")]
    {
        let windows_transport = match firewall_transport {
            FirewallTransport::Tcp => WindowsFirewallTransport::Tcp,
            FirewallTransport::Udp => WindowsFirewallTransport::Udp,
        };
        let mut guard = FirewallGuard {
            dry_run,
            cleanup_commands: Vec::new(),
            windows: None,
        };
        if dry_run {
            println!(
                "  [dry-run] Windows WFP killswitch: {:?} transport, {} literal peer(s)",
                windows_transport,
                peers.len()
            );
        } else {
            guard.windows = Some(WindowsKillswitchGuard::apply(&peers, windows_transport)?);
            println!("  killswitch: persistent Windows WFP policy active");
        }
        Ok(guard)
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = (config, firewall_transport, dry_run, peers);
        Err(ShphError::Unsupported(
            "host killswitch unsupported on this platform".into(),
        ))
    }
}

#[cfg(target_os = "linux")]
fn apply_linux_firewall_plan(
    label: &str,
    commands: Vec<Vec<String>>,
    cleanup_commands: Vec<Vec<String>>,
    dry_run: bool,
) -> Result<FirewallGuard> {
    let mut guard = FirewallGuard {
        dry_run,
        cleanup_commands,
    };
    if dry_run {
        println!("  [dry-run] {label}:");
        for command in &commands {
            println!("    {command:?}");
        }
        Ok(guard)
    } else {
        // Remove a stale SHPH-owned table before applying the new plan. The
        // cleanup is intentionally best-effort here; the install path below is
        // authoritative and every successful mutation remains rollback-tracked.
        let stale_cleanup = guard.cleanup_commands.clone();
        for command in &stale_cleanup {
            let _ = run_shell_command(command);
        }

        for command in &commands {
            if let Err(error) = run_shell_command(command) {
                let cleanup_error = guard.cleanup().err();
                return match cleanup_error {
                    Some(cleanup_error) => Err(ShphError::Internal(format!(
                        "{label} apply error: {error}; rollback error: {cleanup_error}"
                    ))),
                    None => Err(error),
                };
            }
        }
        println!("  {label}: active");
        Ok(guard)
    }
}

fn apply_mss_clamp(interface_name: &str, dry_run: bool) -> Result<FirewallGuard> {
    #[cfg(target_os = "linux")]
    {
        let commands = build_linux_mss_clamp_commands(interface_name, DEFAULT_TUN_MTU_BYTES)?;
        apply_linux_firewall_plan(
            "MSS clamp",
            commands,
            build_linux_mss_clamp_cleanup_commands(),
            dry_run,
        )
    }

    #[cfg(target_os = "windows")]
    {
        let _ = (interface_name, dry_run);
        Err(ShphError::Unsupported(
            "MSS clamping is currently implemented with Linux nftables only; Windows WFP packet rewriting is not available in this build".into(),
        ))
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = (interface_name, dry_run);
        Err(ShphError::Unsupported(
            "MSS clamping unsupported on this platform".into(),
        ))
    }
}

fn resolve_killswitch_peers(config: &Config) -> Result<Vec<SocketAddr>> {
    let endpoint_values = match config.session.as_ref() {
        Some(session) if session.role == SessionRole::Connect => {
            let selector = session.peer.as_deref().ok_or_else(|| {
                ShphError::Config(
                    "killswitch connect mode requires session.peer to select a peer".into(),
                )
            })?;
            if let Some(peer) = config.peers.iter().find(|peer| {
                peer.alias == selector || peer.endpoint == selector || peer.pubkey == selector
            }) {
                vec![peer.endpoint.clone()]
            } else {
                vec![selector.to_string()]
            }
        }
        _ => config
            .peers
            .iter()
            .map(|peer| peer.endpoint.clone())
            .collect(),
    };

    if endpoint_values.is_empty() {
        return Err(ShphError::Config(
            "killswitch requires at least one configured peer endpoint".into(),
        ));
    }
    if endpoint_values.len() > MAX_KILLSWITCH_PEERS {
        return Err(ShphError::Config(format!(
            "killswitch supports at most {MAX_KILLSWITCH_PEERS} peer endpoints"
        )));
    }

    let mut peers = Vec::with_capacity(endpoint_values.len());
    for endpoint_value in endpoint_values {
        let endpoint = Endpoint::parse(&endpoint_value).map_err(|error| {
            ShphError::Config(format!(
                "invalid killswitch peer endpoint {endpoint_value:?}: {error}"
            ))
        })?;
        let address = endpoint.host.parse::<IpAddr>().map_err(|_| {
            ShphError::Config(format!(
                "killswitch requires literal IP peer endpoints; refusing hostname {:?}",
                endpoint.host
            ))
        })?;
        let socket = SocketAddr::new(address, endpoint.port);
        if !peers.contains(&socket) {
            peers.push(socket);
        }
    }

    if peers.is_empty() {
        return Err(ShphError::Config(
            "killswitch peer allowlist is empty after normalization".into(),
        ));
    }
    Ok(peers)
}

fn cleanup_firewall_state() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        cleanup_nft_table(KILLSWITCH_TABLE_NAME)?;
        cleanup_nft_table(MSS_CLAMP_TABLE_NAME)?;
        Ok(())
    }

    #[cfg(target_os = "windows")]
    {
        WindowsKillswitchGuard::clear_stale()
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn cleanup_nft_table(table_name: &str) -> Result<()> {
    let probe = vec![
        "nft".to_string(),
        "list".to_string(),
        "table".to_string(),
        "inet".to_string(),
        table_name.to_string(),
    ];
    match run_shell_command(&probe) {
        Ok(()) => run_shell_command(&[
            "nft".to_string(),
            "delete".to_string(),
            "table".to_string(),
            "inet".to_string(),
            table_name.to_string(),
        ]),
        // A missing SHPH-owned table is already clean. Other command
        // failures remain visible so permission/tooling problems are not
        // mistaken for successful recovery.
        Err(ShphError::Internal(_)) => Ok(()),
        Err(error) => Err(error),
    }
}

fn build_tun_mtu_commands(interface_name: &str, mtu: usize) -> Result<Vec<Vec<String>>> {
    validate_tun_name(interface_name)?;
    validate_tun_mtu(mtu)?;

    if cfg!(target_os = "linux") {
        return Ok(vec![vec![
            "ip".to_string(),
            "link".to_string(),
            "set".to_string(),
            "dev".to_string(),
            interface_name.to_string(),
            "mtu".to_string(),
            mtu.to_string(),
        ]]);
    }

    if cfg!(target_os = "windows") {
        return Ok(vec![
            vec![
                "netsh".to_string(),
                "interface".to_string(),
                "ipv4".to_string(),
                "set".to_string(),
                "subinterface".to_string(),
                format!("name={interface_name}"),
                format!("mtu={mtu}"),
                "store=active".to_string(),
            ],
            vec![
                "netsh".to_string(),
                "interface".to_string(),
                "ipv6".to_string(),
                "set".to_string(),
                "subinterface".to_string(),
                format!("name={interface_name}"),
                format!("mtu={mtu}"),
                "store=active".to_string(),
            ],
        ]);
    }

    Err(ShphError::Unsupported(
        "native TUN MTU configuration unsupported on this platform".into(),
    ))
}

/// Fully-validated, normalized description of what the control plane would do.
/// Built by preflight validation before any host mutation.
#[derive(Debug, Clone, Default)]
struct ControlPlanePlan {
    routes: Vec<String>,
    apply_dns: bool,
    dns_servers: Vec<String>,
}

fn build_control_plane_plan(
    control: &ControlPlaneConfig,
    interface_name: &str,
) -> Result<ControlPlanePlan> {
    validate_tun_name(interface_name)?;

    let mut plan = ControlPlanePlan::default();

    if control.apply_routes.unwrap_or(false) {
        for route in control.route_cidrs.as_deref().unwrap_or(&[]) {
            validate_cidr(route)?;
            plan.routes.push(route.to_string());
        }
    }

    if control.apply_dns.unwrap_or(false) {
        for server in control.dns_servers.as_deref().unwrap_or(&[]) {
            server
                .parse::<IpAddr>()
                .map_err(|_| ShphError::Config(format!("invalid DNS server IP: {server}")))?;
            plan.dns_servers.push(server.to_string());
        }
        plan.apply_dns = !plan.dns_servers.is_empty();
    }

    Ok(plan)
}

fn validate_cidr(cidr: &str) -> Result<()> {
    parse_cidr(cidr)?;
    Ok(())
}

fn parse_cidr(cidr: &str) -> Result<(IpAddr, u8)> {
    let (ip, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| ShphError::Config(format!("invalid CIDR: {cidr}")))?;
    let ip_addr = ip
        .parse::<IpAddr>()
        .map_err(|_| ShphError::Config(format!("invalid CIDR IP: {cidr}")))?;
    let bits: u8 = prefix
        .parse::<u8>()
        .map_err(|_| ShphError::Config(format!("invalid CIDR prefix: {cidr}")))?;
    let max_bits = match ip_addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if bits > max_bits {
        return Err(ShphError::Config(format!(
            "CIDR prefix out of range: {cidr}"
        )));
    }
    Ok((ip_addr, bits))
}

/// Tracks control-plane mutations so they can be rolled back on shutdown or
/// apply failure. `dry_run` is recorded for diagnostics only.
#[derive(Default)]
struct ControlPlaneGuard {
    added_routes: Vec<(String, String)>,
    applied_dns_servers: Vec<String>,
    dns_interface_name: Option<String>,
    /// Recorded for diagnostics/tests; not used by the live apply path.
    #[allow(dead_code)]
    dry_run: bool,
}

impl ControlPlaneGuard {
    fn cleanup(&mut self) -> Result<()> {
        let mut rollback_errors: Vec<ShphError> = Vec::new();

        // Roll back DNS first, then routes. Each step is best-effort: collect
        // all errors rather than aborting, so partial rollback still removes as
        // much applied state as possible.
        if !self.applied_dns_servers.is_empty() {
            if let Err(err) = restore_dns(self.dns_interface_name.as_deref()) {
                rollback_errors.push(err);
            } else {
                println!("  dns restore");
            }
            self.applied_dns_servers.clear();
            self.dns_interface_name = None;
        }

        while let Some((route, interface_name)) = self.added_routes.pop() {
            if let Err(err) = delete_route(&route, &interface_name) {
                rollback_errors.push(err);
            } else {
                println!("  route del {route}");
            }
        }

        if let Some(err) = rollback_errors.into_iter().next() {
            return Err(err);
        }
        Ok(())
    }
}

fn add_route(cidr: &str, interface_name: &str) -> Result<()> {
    let command = build_route_add_command(cidr, interface_name)?;
    run_shell_command(&command)
}

fn delete_route(cidr: &str, interface_name: &str) -> Result<()> {
    let command = build_route_delete_command(cidr, interface_name)?;
    run_shell_command(&command)
}

fn apply_dns_servers(servers: &[String], interface_name: &str) -> Result<()> {
    if servers.is_empty() {
        return Ok(());
    }
    let commands = build_dns_apply_commands(servers, interface_name)?;
    for command in commands {
        run_shell_command(&command)?;
    }
    Ok(())
}

fn build_dns_apply_commands(servers: &[String], interface_name: &str) -> Result<Vec<Vec<String>>> {
    if servers.is_empty() {
        return Ok(Vec::new());
    }
    validate_tun_name(interface_name)?;
    for server in servers {
        server
            .parse::<IpAddr>()
            .map_err(|_| ShphError::Config(format!("invalid DNS server IP: {server}")))?;
    }

    if cfg!(target_os = "linux") {
        return Ok(vec![{
            let mut command = vec![
                "resolvectl".to_string(),
                "dns".to_string(),
                interface_name.to_string(),
            ];
            command.extend(servers.iter().cloned());
            command
        }]);
    }

    if cfg!(target_os = "windows") {
        let mut commands = Vec::with_capacity(servers.len());
        for family in ["ipv4", "ipv6"] {
            let family_servers: Vec<&String> = servers
                .iter()
                .filter(|server| {
                    (server.contains(':') && family == "ipv6")
                        || (!server.contains(':') && family == "ipv4")
                })
                .collect();
            for (index, server) in family_servers.iter().enumerate() {
                if index == 0 {
                    commands.push(vec![
                        "netsh".to_string(),
                        "interface".to_string(),
                        family.to_string(),
                        "set".to_string(),
                        "dns".to_string(),
                        format!("name={interface_name}"),
                        "static".to_string(),
                        (*server).clone(),
                    ]);
                } else {
                    commands.push(vec![
                        "netsh".to_string(),
                        "interface".to_string(),
                        family.to_string(),
                        "add".to_string(),
                        "dnsserver".to_string(),
                        format!("name={interface_name}"),
                        format!("address={}", server),
                        format!("index={}", index + 1),
                    ]);
                }
            }
        }
        return Ok(commands);
    }

    Err(ShphError::Unsupported(
        "DNS apply unsupported on this platform".into(),
    ))
}

#[cfg(test)]
fn build_dns_apply_command(server: &str, interface_name: &str) -> Result<Vec<String>> {
    build_dns_apply_commands(&[server.to_string()], interface_name)?
        .into_iter()
        .next()
        .ok_or_else(|| ShphError::Internal("DNS command builder returned no command".into()))
}

fn restore_dns(interface_name: Option<&str>) -> Result<()> {
    let interface_name = interface_name
        .filter(|name| !name.trim().is_empty())
        .ok_or_else(|| {
            ShphError::InvalidArgument("interface name required for dns restore".into())
        })?;

    // Attempt both families, preserving each real root-cause error rather than
    // collapsing to a generic message. Both are tried even if the first fails,
    // so a single broken family does not block restoring the other.
    let mut errors: Vec<ShphError> = Vec::new();
    for family in ["ipv4", "ipv6"] {
        if let Err(err) = restore_dns_family(interface_name, family) {
            errors.push(err);
        }
    }
    match errors.into_iter().next() {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

fn restore_dns_family(interface_name: &str, family: &str) -> Result<()> {
    let cmd = build_dns_restore_command(interface_name, family)?;
    run_shell_command(&cmd).map_err(|err| {
        ShphError::Internal(format!(
            "dns {family} restore failed for {interface_name}: {err}"
        ))
    })
}

fn build_route_add_command(cidr: &str, interface_name: &str) -> Result<Vec<String>> {
    validate_cidr(cidr)?;
    validate_tun_name(interface_name)?;
    if cfg!(target_os = "linux") {
        Ok(vec![
            "ip".to_string(),
            "route".to_string(),
            "add".to_string(),
            cidr.to_string(),
            "dev".to_string(),
            interface_name.to_string(),
        ])
    } else if cfg!(target_os = "windows") {
        let (ip_addr, _prefix) = parse_cidr(cidr)?;
        let family = if ip_addr.is_ipv6() { "ipv6" } else { "ipv4" };
        let nexthop = if ip_addr.is_ipv6() { "::" } else { "0.0.0.0" };
        Ok(vec![
            "netsh".to_string(),
            "interface".to_string(),
            family.to_string(),
            "add".to_string(),
            "route".to_string(),
            format!("prefix={cidr}"),
            format!("interface={interface_name}"),
            format!("nexthop={nexthop}"),
            "store=active".to_string(),
        ])
    } else {
        Err(ShphError::Unsupported(
            "route apply unsupported on this platform".into(),
        ))
    }
}

fn build_route_delete_command(cidr: &str, interface_name: &str) -> Result<Vec<String>> {
    validate_cidr(cidr)?;
    validate_tun_name(interface_name)?;
    if cfg!(target_os = "linux") {
        Ok(vec![
            "ip".to_string(),
            "route".to_string(),
            "del".to_string(),
            cidr.to_string(),
            "dev".to_string(),
            interface_name.to_string(),
        ])
    } else if cfg!(target_os = "windows") {
        let (ip_addr, _) = parse_cidr(cidr)?;
        let family = if ip_addr.is_ipv6() { "ipv6" } else { "ipv4" };
        Ok(vec![
            "netsh".to_string(),
            "interface".to_string(),
            family.to_string(),
            "delete".to_string(),
            "route".to_string(),
            format!("prefix={cidr}"),
            format!("interface={interface_name}"),
            "store=active".to_string(),
        ])
    } else {
        Err(ShphError::Unsupported(
            "route delete unsupported on this platform".into(),
        ))
    }
}

fn build_dns_restore_command(interface_name: &str, family: &str) -> Result<Vec<String>> {
    validate_tun_name(interface_name)?;
    let family = match family {
        "ipv4" | "ipv6" => family,
        _ => {
            return Err(ShphError::InvalidArgument(
                "dns restore family must be ipv4 or ipv6".into(),
            ))
        }
    };

    if cfg!(target_os = "linux") {
        Ok(vec![
            "resolvectl".to_string(),
            "revert".to_string(),
            interface_name.to_string(),
        ])
    } else if cfg!(target_os = "windows") {
        Ok(vec![
            "netsh".to_string(),
            "interface".to_string(),
            family.to_string(),
            "set".to_string(),
            "dns".to_string(),
            format!("name={interface_name}"),
            "source=dhcp".to_string(),
        ])
    } else {
        Err(ShphError::Unsupported(
            "DNS restore unsupported on this platform".into(),
        ))
    }
}

#[cfg(not(test))]
fn run_shell_command(command: &[String]) -> Result<()> {
    if command.is_empty() {
        return Err(ShphError::InvalidArgument("empty command".into()));
    }
    let status = Command::new(&command[0]).args(&command[1..]).status();
    let status = match status {
        Ok(status) => status,
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
            return Err(ShphError::PermissionDenied(format!(
                "failed to run {:?}: {}",
                command, err
            )));
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Err(ShphError::Unsupported(format!(
                "required command not found: {}",
                command[0]
            )));
        }
        Err(err) => return Err(ShphError::Io(err)),
    };
    if !status.success() {
        return Err(ShphError::Internal(format!(
            "command failed with status {}: {:?}",
            status, command
        )));
    }
    Ok(())
}

#[cfg(test)]
fn run_shell_command(_command: &[String]) -> Result<()> {
    Ok(())
}

fn reconnect_delay_with_jitter(base_delay_ms: u64) -> u64 {
    let base_delay_ms = base_delay_ms.max(1);
    let lower_bound = base_delay_ms.div_ceil(2);
    rand::thread_rng().gen_range(lower_bound..=base_delay_ms)
}

fn run_with_reconnect<F>(
    enabled: bool,
    max_attempts: u32,
    initial_delay_ms: u64,
    max_delay_ms: u64,
    mut run_once: F,
) -> Result<()>
where
    F: FnMut() -> Result<()>,
{
    if !enabled {
        return run_once();
    }

    let mut attempts: u32 = 0;
    let mut delay_ms = initial_delay_ms.max(1);
    loop {
        attempts += 1;
        match run_once() {
            Ok(()) => return Ok(()),
            Err(err @ ShphError::Config(_))
            | Err(err @ ShphError::InvalidArgument(_))
            | Err(err @ ShphError::Unsupported(_))
            | Err(err @ ShphError::PermissionDenied(_)) => return Err(err),
            Err(err) => {
                if attempts >= max_attempts {
                    return Err(err);
                }
                let sleep_ms = reconnect_delay_with_jitter(delay_ms);
                println!(
                    "  Reconnect: attempt {}/{} failed ({:?}), retrying in {}ms",
                    attempts, max_attempts, err, sleep_ms
                );
                thread::sleep(Duration::from_millis(sleep_ms));
                delay_ms = delay_ms
                    .saturating_mul(2)
                    .min(max_delay_ms.max(initial_delay_ms));
            }
        }
    }
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn run_standards_quic_listen_loop(
    keystore_path: &Path,
    keystore: &KeyStore,
    tun: &TunDevice,
    bind: &str,
    timeout_secs: u64,
    profile: HandshakeProfile,
    roadmap: Option<&RoadmapConfig>,
    quic_cert_path: Option<&Path>,
    start_ms: u64,
) -> Result<()> {
    let cert_path = quic_cert_path.ok_or_else(|| {
        ShphError::Config(
            "--quic-cert is required with --transport quic-standard on up listen".into(),
        )
    })?;
    let bind_addr = parse_socket_addr(bind)?;
    let timeout_duration = bounded_cli_timeout(timeout_secs);
    let policy = peer_policy_for_endpoint(keystore, bind, false)?;
    run_async(async {
        let server = standards_quic::server_endpoint(
            bind_addr,
            standards_quic::StandardsQuicConfig::default(),
        )?;
        write_quic_certificate(cert_path, &server.certificate_der)?;
        println!("  Standards QUIC certificate: {}", cert_path.display());
        loop {
            let connection = tokio::select! {
                result = standards_quic::accept(
                    &server,
                    &keystore.identity,
                    &policy,
                    profile,
                    timeout_duration,
                ) => match result {
                    Ok(connection) => connection,
                    Err(ShphError::Timeout) => continue,
                    Err(error) => return Err(error),
                },
                _ = wait_for_native_shutdown() => {
                    server.endpoint.close(0u32.into(), b"bridge closed");
                    server.endpoint.wait_idle().await;
                    return Ok(());
                }
            };
            let state = connection.handshake.clone();
            enforce_peer_policy(keystore_path, bind, &state, false)?;
            append_handshake_audit(
                roadmap,
                &keystore.identity,
                bind,
                &state,
                "listen-loop",
                TransportMode::QuicStandard,
            )?;
            print_handshake_state("listen-loop", bind, &state);
            let tun_to_quic: AsyncTunDevice = tun.try_clone()?.into_async()?;
            let quic_to_tun: AsyncTunDevice = tun.try_clone()?.into_async()?;
            let bridge = standards_tun::run(
                connection,
                tun_to_quic,
                quic_to_tun,
                standards_tun::StandardsTunBridgeConfig::default(),
            );
            match tokio::select! {
                result = bridge => result,
                _ = wait_for_native_shutdown() => {
                    Ok(standards_tun::StandardsTunBridgeStats::default())
                }
            } {
                Ok(stats) => {
                    print_standards_tun_stats(start_ms, &stats);
                    if shutdown::shutdown_requested() {
                        server.endpoint.close(0u32.into(), b"bridge closed");
                        server.endpoint.wait_idle().await;
                        return Ok(());
                    }
                }
                Err(ShphError::ConnectionClosed) if !shutdown::shutdown_requested() => {
                    println!("  Standards QUIC peer disconnected; awaiting reconnect");
                }
                Err(error) => {
                    server.endpoint.close(0u32.into(), b"bridge closed");
                    server.endpoint.wait_idle().await;
                    return Err(error);
                }
            }
        }
    })?;
    Ok(())
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn run_standards_quic_connect_loop(
    keystore_path: &Path,
    keystore: &KeyStore,
    tun: &TunDevice,
    peer: &str,
    timeout_secs: u64,
    profile: HandshakeProfile,
    roadmap: Option<&RoadmapConfig>,
    quic_cert_path: Option<&Path>,
    start_ms: u64,
) -> Result<()> {
    let cert_path = quic_cert_path.ok_or_else(|| {
        ShphError::Config(
            "--quic-cert is required with --transport quic-standard on up connect".into(),
        )
    })?;
    let peer_addr = parse_socket_addr(peer)?;
    let tun_tx = tun.try_clone()?;
    let tun_rx = tun.try_clone()?;
    let timeout_duration = bounded_cli_timeout(timeout_secs);
    let certificate = read_quic_certificate(cert_path)?;
    let policy = peer_policy_for_endpoint(keystore, peer, true)?;
    let (state, stats) = run_async(async {
        let endpoint = standards_quic::client_endpoint(
            "0.0.0.0:0"
                .parse()
                .map_err(|_| ShphError::Internal("invalid ephemeral endpoint".into()))?,
            &certificate,
            standards_quic::StandardsQuicConfig::default(),
        )?;
        let connection = standards_quic::connect(
            &endpoint,
            peer_addr,
            "localhost",
            &keystore.identity,
            &policy,
            profile,
            timeout_duration,
        )
        .await?;
        let state = connection.handshake.clone();
        enforce_peer_policy(keystore_path, peer, &state, true)?;
        append_handshake_audit(
            roadmap,
            &keystore.identity,
            peer,
            &state,
            "connect-loop",
            TransportMode::QuicStandard,
        )?;
        print_handshake_state("connect-loop", peer, &state);
        let tun_to_quic: AsyncTunDevice = tun_tx.into_async()?;
        let quic_to_tun: AsyncTunDevice = tun_rx.into_async()?;
        let bridge = standards_tun::run(
            connection,
            tun_to_quic,
            quic_to_tun,
            standards_tun::StandardsTunBridgeConfig::default(),
        );
        let bridge_result = tokio::select! {
            result = bridge => result,
            _ = wait_for_native_shutdown() => {
                Ok(standards_tun::StandardsTunBridgeStats::default())
            }
        };
        endpoint.close(0u32.into(), b"bridge closed");
        endpoint.wait_idle().await;
        let stats = bridge_result?;
        Ok((state, stats))
    })?;
    print_standards_tun_stats(start_ms, &stats);
    let _ = state;
    Ok(())
}

#[cfg(target_os = "linux")]
fn print_standards_tun_stats(start_ms: u64, stats: &standards_tun::StandardsTunBridgeStats) {
    println!("  Transport loop: closed");
    println!("  Session start: {start_ms}ms");
    println!(
        "  Standards QUIC TUN stats: tx_packets={}, tx_bytes={}, rx_packets={}, rx_bytes={}, oversized_drops={}, invalid_drops={}",
        stats.tun_to_quic_packets,
        stats.tun_to_quic_bytes,
        stats.quic_to_tun_packets,
        stats.quic_to_tun_bytes,
        stats.dropped_oversized_packets,
        stats.dropped_invalid_datagrams,
    );
}

#[allow(clippy::too_many_arguments)]
fn run_listen_loop(
    keystore_path: &Path,
    config_path: &Path,
    tun: &TunDevice,
    bind: &str,
    timeout_secs: u64,
    mode: TransportMode,
    profile: HandshakeProfile,
    roadmap: Option<&RoadmapConfig>,
    quic_cert_path: Option<&Path>,
    host_bootstrap: bool,
) -> Result<()> {
    let start_ms = phase_a1_now_ms()?;
    let keystore = KeyStore::load(keystore_path, None)?;
    let lab = quic_lab_config()?;
    let bootstrap_unpinned = host_bootstrap && keystore.contacts.is_empty();
    let policy = if bootstrap_unpinned {
        PeerPolicy::allow_any()
    } else {
        peer_policy_for_endpoint(&keystore, bind, false)?
    };
    announce_handshake_profile(profile);
    if mode == TransportMode::QuicStandard {
        #[cfg(target_os = "linux")]
        {
            return run_standards_quic_listen_loop(
                keystore_path,
                &keystore,
                tun,
                bind,
                timeout_secs,
                profile,
                roadmap,
                quic_cert_path,
                start_ms,
            );
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (
                keystore_path,
                tun,
                bind,
                timeout_secs,
                profile,
                roadmap,
                quic_cert_path,
                start_ms,
            );
            return Err(ShphError::Unsupported(
                "standards-QUIC native-TUN bridge currently requires Linux".into(),
            ));
        }
    }
    let handshake_started = std::time::Instant::now();
    let (mut session, state) = match mode {
        TransportMode::Tcp | TransportMode::Quic => accept_secure_session_lab_with_profile(
            bind,
            &keystore.identity,
            &policy,
            timeout_secs,
            mode,
            lab,
            profile,
        )?,
        TransportMode::OfflineMesh => {
            let cfg = roadmap_offline_mesh_config(roadmap)?;
            offline_mesh_accept_secure_session_with_profile(
                &cfg,
                &keystore.identity,
                &policy,
                timeout_secs,
                profile,
            )?
        }
        TransportMode::DataMule => {
            let cfg = roadmap_data_mule_config(roadmap)?;
            data_mule_accept_secure_session_with_profile(
                &cfg,
                &keystore.identity,
                &policy,
                timeout_secs,
                profile,
            )?
        }
        TransportMode::QuicStandard => {
            return Err(ShphError::Unsupported(
                "quic-standard uses the async standards_quic API".into(),
            ))
        }
    };
    let handshake_ms = handshake_started.elapsed().as_millis();
    if bootstrap_unpinned {
        enroll_inbound_peer(config_path, keystore_path, bind, &state)?;
    } else {
        enforce_peer_policy(keystore_path, bind, &state, false)?;
    }
    append_handshake_audit(
        roadmap,
        &keystore.identity,
        bind,
        &state,
        "listen-loop",
        mode,
    )?;
    print_handshake_state("listen-loop", bind, &state);
    let session_id = format!("listen-{bind}-{start_ms}");
    let metrics = MetricsCollector::new();
    let _status_bar = LiveStatusBar::start(bind, tun.name(), profile, handshake_ms, &metrics);
    println!("  Session id: {session_id}");
    println!("  Session start: {start_ms}ms");
    println!("  Initial metrics: {:?}", metrics.snapshot());
    if tun.is_native() {
        println!("  Transport loop: active (bidirectional TUN <-> transport)");
        run_bidirectional_native_loop(session, tun, metrics.clone())?;
        println!("  Transport loop: closed");
        println!("  Session id: {session_id}");
        println!("  Session end: {}ms", phase_a1_now_ms()?);
        println!("  Final metrics: {:?}", metrics.snapshot());
        return Ok(());
    }

    println!("  Transport loop: active (recv -> stdout)");

    loop {
        if shutdown::shutdown_requested() {
            println!("  Shutdown requested, closing transport loop");
            break;
        }
        match session.recv_frame() {
            Ok(payload) => {
                metrics.inc_bytes_recv(payload.len());
                if !io::stderr().is_terminal() {
                    let rendered = String::from_utf8_lossy(&payload);
                    println!("  RX: {rendered}");
                }
            }
            Err(ShphError::ConnectionClosed) | Err(ShphError::Timeout) => break,
            Err(err) => {
                metrics.inc_error();
                return Err(err);
            }
        }
    }

    println!("  Transport loop: closed");
    println!("  Session id: {session_id}");
    println!("  Session end: {}ms", phase_a1_now_ms()?);
    println!("  Final metrics: {:?}", metrics.snapshot());
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_connect_loop(
    keystore_path: &Path,
    tun: &TunDevice,
    peer: &str,
    timeout_secs: u64,
    mode: TransportMode,
    profile: HandshakeProfile,
    roadmap: Option<&RoadmapConfig>,
    quic_cert_path: Option<&Path>,
) -> Result<()> {
    let start_ms = phase_a1_now_ms()?;
    let keystore = KeyStore::load(keystore_path, None)?;
    let lab = quic_lab_config()?;
    let policy = peer_policy_for_endpoint(&keystore, peer, true)?;
    announce_handshake_profile(profile);
    if mode == TransportMode::QuicStandard {
        #[cfg(target_os = "linux")]
        {
            return run_standards_quic_connect_loop(
                keystore_path,
                &keystore,
                tun,
                peer,
                timeout_secs,
                profile,
                roadmap,
                quic_cert_path,
                start_ms,
            );
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (
                keystore_path,
                tun,
                peer,
                timeout_secs,
                profile,
                roadmap,
                quic_cert_path,
                start_ms,
            );
            return Err(ShphError::Unsupported(
                "standards-QUIC native-TUN bridge currently requires Linux".into(),
            ));
        }
    }
    let handshake_started = std::time::Instant::now();
    let (mut session, state) = match mode {
        TransportMode::Tcp | TransportMode::Quic => connect_secure_session_lab_with_profile(
            peer,
            &keystore.identity,
            &policy,
            timeout_secs,
            mode,
            lab,
            profile,
        )?,
        TransportMode::OfflineMesh => {
            let cfg = roadmap_offline_mesh_config(roadmap)?;
            offline_mesh_connect_secure_session_with_profile(
                &cfg,
                &keystore.identity,
                &policy,
                timeout_secs,
                profile,
            )?
        }
        TransportMode::DataMule => {
            let cfg = roadmap_data_mule_config(roadmap)?;
            data_mule_connect_secure_session_with_profile(
                &cfg,
                &keystore.identity,
                peer,
                &policy,
                timeout_secs,
                profile,
            )?
        }
        TransportMode::QuicStandard => {
            return Err(ShphError::Unsupported(
                "quic-standard uses the async standards_quic API".into(),
            ))
        }
    };
    let handshake_ms = handshake_started.elapsed().as_millis();
    enforce_peer_policy(keystore_path, peer, &state, true)?;
    append_handshake_audit(
        roadmap,
        &keystore.identity,
        peer,
        &state,
        "connect-loop",
        mode,
    )?;
    print_handshake_state("connect-loop", peer, &state);
    let session_id = format!("connect-{peer}-{start_ms}");
    let metrics = MetricsCollector::new();
    let _status_bar = LiveStatusBar::start(peer, tun.name(), profile, handshake_ms, &metrics);
    println!("  Session id: {session_id}");
    println!("  Session start: {start_ms}ms");
    println!("  Initial metrics: {:?}", metrics.snapshot());
    if tun.is_native() {
        println!("  Transport loop: active (bidirectional TUN <-> transport)");
        run_bidirectional_native_loop(session, tun, metrics.clone())?;
        println!("  Transport loop: closed");
        println!("  Session id: {session_id}");
        println!("  Session end: {}ms", phase_a1_now_ms()?);
        println!("  Final metrics: {:?}", metrics.snapshot());
        return Ok(());
    }

    println!("  Transport loop: active (stdin -> encrypted frames)");
    println!("  Enter plaintext lines; EOF to close.");
    stream_stdin_lines(&mut session, &metrics)?;
    println!("  Transport loop: closed");
    println!("  Session id: {session_id}");
    println!("  Session end: {}ms", phase_a1_now_ms()?);
    println!("  Final metrics: {:?}", metrics.snapshot());
    Ok(())
}

fn stream_stdin_lines(session: &mut SecureSession, metrics: &MetricsCollector) -> Result<()> {
    // The connect loop blocks on stdin. We use a poll-based read (on unix) so
    // that the process-wide shutdown flag (set by the SIGINT/SIGTERM handler)
    // is honored promptly for clean teardown. std's `read_line` retries EINTR
    // internally and would not return on a signal, so we cannot rely on it.
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let mut line = String::new();
    let mut pending = Vec::new();
    loop {
        if shutdown::shutdown_requested() {
            break;
        }
        line.clear();
        let got_line = read_stdin_line(&mut reader, &mut line, &mut pending)?;
        if !got_line {
            break;
        }
        let payload = line.trim_end_matches(&['\r', '\n'][..]).as_bytes().to_vec();
        metrics.inc_bytes_sent(payload.len());
        session.send_frame(&payload)?;
    }
    Ok(())
}

/// Reads one line from the locked stdin handle, honoring the process-wide
/// shutdown flag. Returns `Ok(true)` if a line was read, or `Ok(false)` on a
/// shutdown request or EOF. On unix the underlying read is poll-driven with a
/// short timeout so signals are observed without busy-waiting.
#[cfg(unix)]
fn read_stdin_line(
    reader: &mut io::StdinLock<'_>,
    line: &mut String,
    pending: &mut Vec<u8>,
) -> Result<bool> {
    read_stdin_line_unix(reader, line, pending)
}

#[cfg(not(unix))]
fn read_stdin_line(
    reader: &mut io::StdinLock<'_>,
    line: &mut String,
    _pending: &mut Vec<u8>,
) -> Result<bool> {
    use std::io::BufRead;
    let n = reader.read_line(line).map_err(ShphError::Io)?;
    if line.len() > MAX_STDIN_LINE_BYTES {
        return Err(ShphError::Protocol(
            "stdin line exceeds the 64 KiB safety limit".into(),
        ));
    }
    Ok(n > 0)
}

#[cfg(unix)]
fn read_stdin_line_unix(
    reader: &mut io::StdinLock<'_>,
    line: &mut String,
    pending: &mut Vec<u8>,
) -> Result<bool> {
    use std::os::fd::AsRawFd;
    let fd = reader.as_raw_fd();
    loop {
        if shutdown::shutdown_requested() {
            return Ok(false);
        }
        if let Some(newline) = pending.iter().position(|&byte| byte == b'\n') {
            let mut bytes: Vec<u8> = pending.drain(..=newline).collect();
            while matches!(bytes.last(), Some(b'\n' | b'\r')) {
                bytes.pop();
            }
            *line = String::from_utf8(bytes)
                .map_err(|_| ShphError::InvalidArgument("stdin line is not valid UTF-8".into()))?;
            return Ok(true);
        }
        if pending.len() > MAX_STDIN_LINE_BYTES {
            return Err(ShphError::Protocol(
                "stdin line exceeds the 64 KiB safety limit".into(),
            ));
        }
        // Poll stdin for up to 200ms, then re-check the shutdown flag.
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut pfd as *mut _, 1, 200) };
        if ready == 0 {
            continue;
        }
        if ready < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                if shutdown::shutdown_requested() {
                    return Ok(false);
                }
                continue;
            }
            return Err(ShphError::Io(err));
        }
        if (pfd.revents & libc::POLLIN) != 0 {
            let mut buf = [0u8; 4096];
            let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) };
            if n == 0 {
                return Ok(false);
            }
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    if shutdown::shutdown_requested() {
                        return Ok(false);
                    }
                    continue;
                }
                return Err(ShphError::Io(err));
            }
            let data = &buf[..n as usize];
            if pending.len().saturating_add(data.len()) > MAX_STDIN_LINE_BYTES {
                return Err(ShphError::Protocol(
                    "stdin line exceeds the 64 KiB safety limit".into(),
                ));
            }
            pending.extend_from_slice(data);
            continue;
        }
        if (pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL)) != 0 {
            if pending.is_empty() {
                return Ok(false);
            }
            let mut bytes = std::mem::take(pending);
            while matches!(bytes.last(), Some(b'\n' | b'\r')) {
                bytes.pop();
            }
            *line = String::from_utf8(bytes)
                .map_err(|_| ShphError::InvalidArgument("stdin line is not valid UTF-8".into()))?;
            return Ok(true);
        }
    }
}

fn run_bidirectional_native_loop(
    session: SecureSession,
    tun: &TunDevice,
    metrics: MetricsCollector,
) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let tun_tx = tun.try_clone()?;
        let tun_rx = tun.try_clone()?;
        run_async(run_bidirectional_native_async(
            session, tun_tx, tun_rx, metrics,
        ))
    }

    #[cfg(not(target_os = "linux"))]
    {
        #[cfg(target_os = "windows")]
        {
            let tun_tx = tun.try_clone()?;
            let tun_rx = tun.try_clone()?;
            run_bidirectional_native_sync(session, tun_tx, tun_rx, metrics)
        }

        #[cfg(not(target_os = "windows"))]
        {
            let _ = (session, tun, metrics);
            Err(ShphError::Unsupported(
                "the native TUN bridge is not implemented on this platform".into(),
            ))
        }
    }
}

#[cfg(target_os = "linux")]
type NativePacket = zeroize::Zeroizing<Vec<u8>>;

#[cfg(target_os = "linux")]
async fn run_bidirectional_native_async(
    session: SecureSession,
    tun_tx: TunDevice,
    tun_rx: TunDevice,
    metrics: MetricsCollector,
) -> Result<()> {
    const BRIDGE_QUEUE_CAPACITY: usize = 32;

    let tun_tx = tun_tx.into_async()?;
    let tun_rx = tun_rx.into_async()?;
    let (sender, mut receiver) = session.into_split()?;
    receiver.set_poll_timeout(Duration::from_millis(100))?;
    let (to_transport_tx, to_transport_rx) =
        tokio::sync::mpsc::channel::<NativePacket>(BRIDGE_QUEUE_CAPACITY);
    let (to_tun_tx, to_tun_rx) = tokio::sync::mpsc::channel::<NativePacket>(BRIDGE_QUEUE_CAPACITY);
    let shutdown = Arc::new(AtomicBool::new(false));
    let (task_done_tx, mut task_done_rx) = tokio::sync::mpsc::unbounded_channel::<&'static str>();

    let sender_metrics = metrics.clone();
    let sender_done_tx = task_done_tx.clone();
    let sender_task = tokio::task::spawn_blocking(move || {
        let result = native_transport_sender_loop(to_transport_rx, sender, sender_metrics);
        let _ = sender_done_tx.send("transport sender");
        result
    });
    let receiver_metrics = metrics.clone();
    let receiver_shutdown = Arc::clone(&shutdown);
    let receiver_done_tx = task_done_tx;
    let receiver_task = tokio::task::spawn_blocking(move || {
        let result = native_transport_receiver_loop(
            to_tun_tx,
            receiver,
            receiver_shutdown,
            receiver_metrics,
        );
        let _ = receiver_done_tx.send("transport receiver");
        result
    });

    let tx_shutdown = Arc::clone(&shutdown);
    let tx_metrics = metrics.clone();
    let mut tun_reader = Box::pin(async move {
        native_async_tun_to_transport_loop(tun_tx, to_transport_tx, tx_shutdown, tx_metrics).await
    });
    let rx_shutdown = Arc::clone(&shutdown);
    let rx_metrics = metrics.clone();
    let mut tun_writer = Box::pin(native_async_transport_to_tun_loop(
        tun_rx,
        to_tun_rx,
        rx_shutdown,
        rx_metrics,
    ));

    let (first_result, local_shutdown) = tokio::select! {
        result = &mut tun_reader => (Some(result), false),
        result = &mut tun_writer => (Some(result), false),
        Some(task_name) = task_done_rx.recv() => {
            tracing::debug!(task = task_name, "native TUN transport worker completed");
            (None, false)
        }
        _ = wait_for_native_shutdown() => (None, true),
    };
    shutdown.store(true, Ordering::Relaxed);
    drop(tun_reader);
    drop(tun_writer);

    let mut remote_connection_closed = false;
    if let Some(Err(error)) = first_result {
        if matches!(error, ShphError::ConnectionClosed) {
            remote_connection_closed = true;
        } else {
            return Err(error);
        }
    }
    for result in [sender_task.await, receiver_task.await] {
        let result = result
            .map_err(|err| ShphError::Internal(format!("native TUN worker task failed: {err}")))?;
        if let Err(error) = result {
            if matches!(error, ShphError::ConnectionClosed) {
                remote_connection_closed = true;
            } else {
                return Err(error);
            }
        }
    }
    if remote_connection_closed && !local_shutdown {
        return Err(ShphError::ConnectionClosed);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn wait_for_native_shutdown() {
    while !shutdown::shutdown_requested() {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[cfg(target_os = "windows")]
fn run_bidirectional_native_sync(
    session: SecureSession,
    tun_tx: TunDevice,
    tun_rx: TunDevice,
    metrics: MetricsCollector,
) -> Result<()> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let (sender, mut receiver) = session.into_split()?;
    receiver.set_poll_timeout(Duration::from_millis(100))?;

    let tx_shutdown = Arc::clone(&shutdown);
    let tx_metrics = metrics.clone();
    let tx_handle = thread::spawn(move || {
        windows_tun_to_transport_loop(tun_tx, sender, tx_shutdown, tx_metrics)
    });

    let rx_shutdown = Arc::clone(&shutdown);
    let rx_metrics = metrics.clone();
    let rx_handle = thread::spawn(move || {
        windows_transport_to_tun_loop(receiver, tun_rx, rx_shutdown, rx_metrics)
    });

    let tx_result = tx_handle
        .join()
        .map_err(|_| ShphError::Internal("Windows TUN sender thread panicked".into()))?;
    let rx_result = rx_handle
        .join()
        .map_err(|_| ShphError::Internal("Windows TUN receiver thread panicked".into()))?;

    match (tx_result, rx_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(ShphError::ConnectionClosed), Ok(()))
        | (Ok(()), Err(ShphError::ConnectionClosed))
        | (Err(ShphError::ConnectionClosed), Err(ShphError::ConnectionClosed)) => {
            if shutdown::shutdown_requested() {
                Ok(())
            } else {
                Err(ShphError::ConnectionClosed)
            }
        }
        (Err(left), Ok(())) => Err(left),
        (Ok(()), Err(right)) => Err(right),
        (Err(left), Err(_right)) => Err(left),
    }
}

#[cfg(target_os = "windows")]
fn windows_tun_to_transport_loop(
    mut tun: TunDevice,
    mut sender: SecureSender,
    shutdown: Arc<AtomicBool>,
    metrics: MetricsCollector,
) -> Result<()> {
    let mut packet = zeroize::Zeroizing::new(vec![0u8; TUN_READ_BUFFER_BYTES]);
    while !shutdown.load(Ordering::Relaxed) && !shutdown::shutdown_requested() {
        match tun.recv_packet(&mut packet) {
            Ok(n) => {
                sender.send_frame(&packet[..n])?;
                metrics.inc_bytes_sent(n);
                packet[..n].zeroize();
            }
            Err(ShphError::Timeout) => metrics.inc_timeout(),
            Err(ShphError::ConnectionClosed) | Err(ShphError::Unsupported(_)) => break,
            Err(ShphError::Tun(message)) => {
                if message.contains("exceeds") {
                    metrics.inc_oversized_packet();
                } else {
                    metrics.inc_malformed_packet();
                }
            }
            Err(error) => {
                record_data_plane_error(&metrics, &error);
                shutdown.store(true, Ordering::Relaxed);
                return Err(error);
            }
        }
    }
    shutdown.store(true, Ordering::Relaxed);
    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_transport_to_tun_loop(
    mut receiver: SecureReceiver,
    mut tun: TunDevice,
    shutdown: Arc<AtomicBool>,
    metrics: MetricsCollector,
) -> Result<()> {
    while !shutdown.load(Ordering::Relaxed) && !shutdown::shutdown_requested() {
        match receiver.recv_frame() {
            Ok(payload) => {
                let payload = zeroize::Zeroizing::new(payload);
                if payload.is_empty() {
                    continue;
                }
                match tun.send_packet(&payload) {
                    Ok(()) => metrics.inc_bytes_recv(payload.len()),
                    Err(ShphError::Timeout) => metrics.inc_timeout(),
                    Err(ShphError::ConnectionClosed) | Err(ShphError::Unsupported(_)) => break,
                    Err(ShphError::Tun(message)) => {
                        if message.contains("exceeds") {
                            metrics.inc_oversized_packet();
                        } else {
                            metrics.inc_malformed_packet();
                        }
                    }
                    Err(error) => {
                        record_data_plane_error(&metrics, &error);
                        shutdown.store(true, Ordering::Relaxed);
                        return Err(error);
                    }
                }
            }
            Err(ShphError::Timeout) => metrics.inc_timeout(),
            Err(ShphError::ConnectionClosed) => {
                shutdown.store(true, Ordering::Relaxed);
                return Err(ShphError::ConnectionClosed);
            }
            Err(error) => {
                record_data_plane_error(&metrics, &error);
                shutdown.store(true, Ordering::Relaxed);
                return Err(error);
            }
        }
    }
    shutdown.store(true, Ordering::Relaxed);
    Ok(())
}

#[cfg(target_os = "linux")]
fn native_transport_sender_loop(
    mut payloads: tokio::sync::mpsc::Receiver<NativePacket>,
    mut sender: SecureSender,
    metrics: MetricsCollector,
) -> Result<()> {
    while let Some(payload) = payloads.blocking_recv() {
        let payload = zeroize::Zeroizing::new(payload);
        sender.send_frame(&payload)?;
        metrics.inc_bytes_sent(payload.len());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn native_transport_receiver_loop(
    payloads: tokio::sync::mpsc::Sender<NativePacket>,
    mut receiver: SecureReceiver,
    shutdown: Arc<AtomicBool>,
    metrics: MetricsCollector,
) -> Result<()> {
    while !shutdown.load(Ordering::Relaxed) && !shutdown::shutdown_requested() {
        match receiver.recv_frame() {
            Ok(payload) => {
                let payload = zeroize::Zeroizing::new(payload);
                if payload.is_empty() {
                    continue;
                }
                let mut payload = payload;
                loop {
                    match payloads.try_send(payload) {
                        Ok(()) => break,
                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return Ok(()),
                        Err(tokio::sync::mpsc::error::TrySendError::Full(returned)) => {
                            if shutdown.load(Ordering::Relaxed) || shutdown::shutdown_requested() {
                                return Ok(());
                            }
                            payload = returned;
                            thread::sleep(Duration::from_millis(5));
                        }
                    }
                }
            }
            Err(ShphError::Timeout) => {
                metrics.inc_timeout();
                if shutdown.load(Ordering::Relaxed) || shutdown::shutdown_requested() {
                    return Ok(());
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn native_async_tun_to_transport_loop(
    mut tun: AsyncTunDevice,
    payloads: tokio::sync::mpsc::Sender<NativePacket>,
    shutdown: Arc<AtomicBool>,
    metrics: MetricsCollector,
) -> Result<()> {
    let mut packet = zeroize::Zeroizing::new(vec![0u8; TUN_READ_BUFFER_BYTES]);
    while !shutdown.load(Ordering::Relaxed) && !shutdown::shutdown_requested() {
        match tun.recv_packet(&mut packet).await {
            Ok(0) => return Err(ShphError::ConnectionClosed),
            Ok(length) => {
                let payload = zeroize::Zeroizing::new(packet[..length].to_vec());
                payloads
                    .send(payload)
                    .await
                    .map_err(|_| ShphError::ConnectionClosed)?;
                packet[..length].zeroize();
            }
            Err(ShphError::Tun(message)) => {
                if message.contains("exceeds") {
                    metrics.inc_oversized_packet();
                } else {
                    metrics.inc_malformed_packet();
                }
            }
            Err(ShphError::ConnectionClosed) => return Ok(()),
            Err(error) => {
                record_data_plane_error(&metrics, &error);
                return Err(error);
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn native_async_transport_to_tun_loop(
    mut tun: AsyncTunDevice,
    mut payloads: tokio::sync::mpsc::Receiver<NativePacket>,
    shutdown: Arc<AtomicBool>,
    metrics: MetricsCollector,
) -> Result<()> {
    while !shutdown.load(Ordering::Relaxed) && !shutdown::shutdown_requested() {
        let Some(payload) = payloads.recv().await else {
            return Ok(());
        };
        let payload = zeroize::Zeroizing::new(payload);
        if payload.is_empty() {
            continue;
        }
        match tun.send_packet(&payload).await {
            Ok(()) => metrics.inc_bytes_recv(payload.len()),
            Err(ShphError::Tun(message)) => {
                if message.contains("exceeds") {
                    metrics.inc_oversized_packet();
                } else if message.contains("short TUN packet write") {
                    record_data_plane_error(&metrics, &ShphError::Tun(message.clone()));
                    return Err(ShphError::Tun(message));
                } else {
                    metrics.inc_malformed_packet();
                }
            }
            Err(error) => {
                record_data_plane_error(&metrics, &error);
                return Err(error);
            }
        }
    }
    Ok(())
}

fn record_data_plane_error(metrics: &MetricsCollector, error: &ShphError) {
    match error {
        ShphError::Timeout => metrics.inc_timeout(),
        ShphError::Tun(message) if message.contains("exceeds") => metrics.inc_oversized_packet(),
        ShphError::Tun(_) => metrics.inc_malformed_packet(),
        ShphError::Protocol(message) | ShphError::Crypto(message)
            if message.contains("replay") || message.contains("stale nonce") =>
        {
            metrics.inc_replay_drop()
        }
        ShphError::Protocol(_) => metrics.inc_malformed_packet(),
        _ => metrics.inc_error(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        advertised_endpoint, apply_control_plane, build_control_plane_plan,
        build_dns_apply_command, build_dns_apply_commands, build_dns_restore_command,
        build_route_add_command, build_route_delete_command, build_tun_mtu_commands, cli_exit_code,
        control_plane_state_path, enforce_peer_policy, handle_up, load_control_plane_state,
        parse_shroud_profile_name, phase_a1_now_ms, reconnect_delay_with_jitter,
        render_config_for_display, resolve_killswitch_peers, resolve_shroud_profile,
        run_with_reconnect, save_control_plane_state, transport_mode_to_str, validate_cidr,
        CliErrorOutput, ControlPlaneGuard, ControlPlanePlan, HandshakeState, KeyStore,
        KeyStoreConfig, PersistedControlPlaneState, TransportMode, UpOptions,
        DEFAULT_TUN_MTU_BYTES, EXIT_CONFIG, EXIT_PERMISSION, EXIT_TEMPORARY, EXIT_USAGE,
        MAX_CONTROL_PLANE_STATE_BYTES,
    };
    use shph_config::RoadmapConfig;
    use shph_config::{
        Config, ControlPlaneConfig, PeerConfig, ReconnectConfig, SessionConfig, SessionRole,
    };
    use shph_core::roadmap::{IdentityProviderConfig, TransportAdapterConfig};
    use shph_core::{Result, ShphError};
    use std::io;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[test]
    fn show_config_redacts_all_known_credential_fields_by_default() {
        let config = Config {
            interface_name: "shph0".into(),
            local_endpoint: "127.0.0.1:51820".into(),
            peers: Vec::new(),
            obfuscation: Some(shph_config::ObfuscationConfig {
                mode: shph_config::ObfuscationMode::Shadowsocks,
                shadowsocks: Some(shph_config::ShadowsocksConfig {
                    server: "127.0.0.1:8388".into(),
                    method: "2022-blake3-aes-256-gcm".into(),
                    password: "ss-secret".into(),
                }),
                tls: None,
            }),
            stealth: None,
            roadmap: Some(RoadmapConfig {
                identity: IdentityProviderConfig::YubikeyPiv {
                    slot: "9a".into(),
                    pin: Some("123456".into()),
                },
                ..RoadmapConfig::default()
            }),
            control_plane: None,
            session: None,
        };

        let redacted = render_config_for_display(&config, false).expect("render redacted config");
        assert!(redacted.contains("password = \"<redacted>\""));
        assert!(redacted.contains("pin = \"<redacted>\""));
        assert!(!redacted.contains("ss-secret"));
        assert!(!redacted.contains("123456"));

        let visible = render_config_for_display(&config, true).expect("render full config");
        assert!(visible.contains("ss-secret"));
        assert!(visible.contains("123456"));
    }

    #[test]
    fn reconnect_retries_then_succeeds() {
        let calls = Arc::new(AtomicU32::new(0));
        let calls_clone = Arc::clone(&calls);
        let out = run_with_reconnect(true, 4, 1, 2, move || -> Result<()> {
            let current = calls_clone.fetch_add(1, Ordering::SeqCst);
            if current < 2 {
                Err(ShphError::Transport("temporary".into()))
            } else {
                Ok(())
            }
        });
        assert!(out.is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn reconnect_retries_after_connection_closed() {
        let calls = Arc::new(AtomicU32::new(0));
        let calls_clone = Arc::clone(&calls);
        let out = run_with_reconnect(true, 3, 1, 1, move || -> Result<()> {
            if calls_clone.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(ShphError::ConnectionClosed)
            } else {
                Ok(())
            }
        });
        assert!(out.is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn reconnect_jitter_stays_within_equal_jitter_bounds() {
        for base in [1, 2, 5, 100, u64::MAX] {
            let delay = reconnect_delay_with_jitter(base);
            let base = base.max(1);
            assert!(delay >= base.div_ceil(2));
            assert!(delay <= base);
        }
    }

    #[test]
    fn cli_exit_codes_distinguish_automation_failures() {
        assert_eq!(
            cli_exit_code(&ShphError::InvalidArgument("bad".into())),
            EXIT_USAGE
        );
        assert_eq!(
            cli_exit_code(&ShphError::Config("bad config".into())),
            EXIT_CONFIG
        );
        assert_eq!(
            cli_exit_code(&ShphError::PermissionDenied("no".into())),
            EXIT_PERMISSION
        );
        assert_eq!(cli_exit_code(&ShphError::Timeout), EXIT_TEMPORARY);
        assert_eq!(
            cli_exit_code(&ShphError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                "missing"
            ))),
            66
        );
    }

    #[test]
    fn cli_json_error_schema_is_stable() {
        let output = CliErrorOutput {
            ok: false,
            error: "bad config".into(),
            code: EXIT_CONFIG,
            hint: Some("run doctor"),
        };
        let value = serde_json::to_value(output).expect("serialize JSON error");
        assert_eq!(value["ok"], false);
        assert_eq!(value["error"], "bad config");
        assert_eq!(value["code"], EXIT_CONFIG);
        assert_eq!(value["hint"], "run doctor");
    }

    #[test]
    fn killswitch_peer_resolution_requires_literal_endpoints_and_deduplicates() {
        let config = Config {
            peers: vec![
                PeerConfig {
                    alias: "primary".into(),
                    endpoint: "198.51.100.10:443".into(),
                    pubkey: "peer-key".into(),
                    sign_pubkey: None,
                },
                PeerConfig {
                    alias: "duplicate".into(),
                    endpoint: "198.51.100.10:443".into(),
                    pubkey: "peer-key-2".into(),
                    sign_pubkey: None,
                },
            ],
            ..Config::default()
        };
        let peers = resolve_killswitch_peers(&config).expect("literal peers");
        assert_eq!(peers, vec!["198.51.100.10:443".parse().unwrap()]);

        let hostname_config = Config {
            peers: vec![PeerConfig {
                alias: "hostname".into(),
                endpoint: "vpn.example.test:443".into(),
                pubkey: "peer-key".into(),
                sign_pubkey: None,
            }],
            ..Config::default()
        };
        assert!(matches!(
            resolve_killswitch_peers(&hostname_config),
            Err(ShphError::Config(message)) if message.contains("literal IP")
        ));
    }

    #[test]
    fn killswitch_connect_selector_uses_selected_configured_peer() {
        let config = Config {
            peers: vec![
                PeerConfig {
                    alias: "first".into(),
                    endpoint: "198.51.100.10:443".into(),
                    pubkey: "peer-a".into(),
                    sign_pubkey: None,
                },
                PeerConfig {
                    alias: "second".into(),
                    endpoint: "203.0.113.20:8443".into(),
                    pubkey: "peer-b".into(),
                    sign_pubkey: None,
                },
            ],
            session: Some(SessionConfig {
                role: SessionRole::Connect,
                bind: None,
                peer: Some("second".into()),
                timeout_secs: None,
                handshake_profile: None,
                reconnect: None,
                startup_payload: None,
            }),
            ..Config::default()
        };
        let peers = resolve_killswitch_peers(&config).expect("selected peer");
        assert_eq!(peers, vec!["203.0.113.20:8443".parse().unwrap()]);
    }

    #[test]
    fn killswitch_dry_run_does_not_require_native_tun() {
        let config = Config {
            peers: vec![PeerConfig {
                alias: "preview".into(),
                endpoint: "198.51.100.10:443".into(),
                pubkey: "peer-key".into(),
                sign_pubkey: None,
            }],
            ..Config::default()
        };
        handle_up(
            std::path::Path::new("/tmp/shph-config.toml"),
            std::path::Path::new("/tmp/shph-keystore.json"),
            &config,
            UpOptions {
                transport: TransportMode::Tcp,
                profile: shph_core::HandshakeProfile::SecureDefault,
                shroud_profile: "medium".into(),
                quic_cert_path: None,
                killswitch: true,
                killswitch_dry_run: true,
                mss_clamp: false,
                tun: false,
                host_bootstrap: false,
                nat: false,
            },
        )
        .expect("killswitch dry-run should preview without native TUN");
    }

    #[test]
    fn up_refuses_to_overwrite_persisted_control_plane_state() {
        let dir = std::env::temp_dir().join(format!(
            "shph-cli-stale-state-{}-{}",
            std::process::id(),
            phase_a1_now_ms().unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("config.toml");
        let state = PersistedControlPlaneState {
            interface_name: "shph0".into(),
            routes: vec!["10.20.0.0/16".into()],
            dns_servers: Vec::new(),
        };
        save_control_plane_state(&config_path, &state).expect("save stale state");

        let error = handle_up(
            &config_path,
            &dir.join("keystore.json"),
            &Config::default(),
            UpOptions {
                transport: TransportMode::Tcp,
                profile: shph_core::HandshakeProfile::SecureDefault,
                shroud_profile: "medium".into(),
                quic_cert_path: None,
                killswitch: false,
                killswitch_dry_run: false,
                mss_clamp: false,
                tun: false,
                host_bootstrap: false,
                nat: false,
            },
        )
        .expect_err("stale control-plane state must block up");
        assert!(matches!(error, ShphError::Config(message) if message.contains("reconcile")));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn quic_standard_up_rejects_reconnect_before_opening_tun() {
        let config = Config {
            session: Some(SessionConfig {
                role: SessionRole::Connect,
                bind: None,
                peer: Some("127.0.0.1:7231".into()),
                timeout_secs: Some(5),
                startup_payload: None,
                handshake_profile: None,
                reconnect: Some(ReconnectConfig {
                    enabled: Some(true),
                    max_attempts: Some(2),
                    initial_delay_ms: Some(1),
                    max_delay_ms: Some(1),
                }),
            }),
            ..Config::default()
        };
        let error = handle_up(
            std::path::Path::new("/tmp/shph-config.toml"),
            std::path::Path::new("/tmp/shph-keystore.json"),
            &config,
            UpOptions {
                transport: TransportMode::QuicStandard,
                profile: shph_core::HandshakeProfile::SecureDefault,
                shroud_profile: "medium".into(),
                quic_cert_path: Some(std::path::Path::new("/tmp/server.der")),
                killswitch: false,
                killswitch_dry_run: false,
                mss_clamp: false,
                tun: false,
                host_bootstrap: false,
                nat: false,
            },
        )
        .expect_err("standards QUIC reconnect must fail before native TUN setup");
        assert!(matches!(error, ShphError::Config(message) if message.contains("reconnect")));
    }

    #[test]
    fn shroud_profile_resolver_accepts_all_lab_profiles() {
        for profile in shph_core::profiles() {
            assert_eq!(
                parse_shroud_profile_name(profile.name).unwrap(),
                Some(*profile)
            );
        }
    }

    #[test]
    fn shroud_profile_resolver_rejects_unknown_profiles() {
        let result = parse_shroud_profile_name("production-stealth");
        assert!(
            matches!(result, Err(ShphError::Config(message)) if message.contains("unknown SHPH_SHROUD_PROFILE"))
        );
    }

    #[test]
    fn shroud_profile_resolver_supports_disabled_and_intensity_aliases() {
        assert_eq!(parse_shroud_profile_name("off").unwrap(), None);
        assert_eq!(
            parse_shroud_profile_name("low").unwrap(),
            Some(shph_core::LOW_LATENCY)
        );
        assert_eq!(
            parse_shroud_profile_name("medium").unwrap(),
            Some(shph_core::BALANCED)
        );
        assert_eq!(
            parse_shroud_profile_name("high").unwrap(),
            Some(shph_core::BULK)
        );
        assert_eq!(
            parse_shroud_profile_name("extreme-lab").unwrap(),
            Some(shph_core::EXTREME_LAB)
        );
    }

    #[test]
    fn shroud_profiles_are_explicitly_lab_only() {
        assert!(shph_core::profiles()
            .iter()
            .all(|profile| profile.is_valid()));
        assert!(shph_core::shroud_profile_by_name("randomized-lab")
            .expect("randomized profile")
            .name
            .ends_with("-lab"));
    }

    #[test]
    fn smart_defaults_resolve_to_medium_and_canonical_aliases() {
        assert_eq!(
            resolve_shroud_profile(None, None).expect("default profile"),
            "medium"
        );
        assert_eq!(
            resolve_shroud_profile(Some("low-latency"), None).expect("low alias"),
            "low"
        );
        assert_eq!(
            resolve_shroud_profile(None, Some("bulk")).expect("bulk alias"),
            "high"
        );
        assert_eq!(
            resolve_shroud_profile(Some("disabled"), None).expect("disabled alias"),
            "off"
        );
    }

    #[test]
    fn advertised_endpoint_rejects_malformed_values() {
        assert!(advertised_endpoint(Some("example.invalid:not-a-port"), 443).is_err());
        assert!(advertised_endpoint(Some("example.invalid bad"), 443).is_err());
        assert_eq!(
            advertised_endpoint(Some("[::1]"), 443).expect("IPv6 host"),
            "[::1]:443"
        );
    }

    #[test]
    fn reconnect_stops_on_non_retryable_error() {
        let calls = Arc::new(AtomicU32::new(0));
        let calls_clone = Arc::clone(&calls);
        let out = run_with_reconnect(true, 4, 1, 2, move || -> Result<()> {
            calls_clone.fetch_add(1, Ordering::SeqCst);
            Err(ShphError::InvalidArgument("bad input".into()))
        });
        assert!(matches!(out, Err(ShphError::InvalidArgument(_))));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn empty_peer_store_fails_closed() {
        let dir = std::env::temp_dir().join(format!(
            "shph-cli-pin-{}-{}",
            std::process::id(),
            phase_a1_now_ms().unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keystore.json");
        KeyStore::new(KeyStoreConfig::default())
            .unwrap()
            .save(&path)
            .unwrap();
        let state = HandshakeState {
            peer_fingerprint_hex: "00".repeat(32),
            peer_identity_pubkey_b64: String::new(),
            peer_signing_pubkey_b64: String::new(),
            session_keys: shph_core::SessionKeys {
                send_nonce: 0,
                recv_nonce: 0,
                send_key: [0; 32],
                recv_key: [0; 32],
            },
            transcript_hash_hex: String::new(),
        };

        let result = enforce_peer_policy(&path, "127.0.0.1:7000", &state, false);
        assert!(
            matches!(result, Err(ShphError::Auth(message)) if message.contains("no peers are pinned"))
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn peer_policy_requires_pinned_signing_key() {
        let dir = std::env::temp_dir().join(format!(
            "shph-cli-sign-pin-{}-{}",
            std::process::id(),
            phase_a1_now_ms().unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keystore.json");
        let mut keystore = KeyStore::new(KeyStoreConfig::default()).unwrap();
        let peer = KeyStore::new(KeyStoreConfig::default()).unwrap();
        keystore.add_contact(shph_core::Contact {
            alias: "peer".into(),
            endpoint: shph_core::Endpoint {
                host: "127.0.0.1".into(),
                port: 7000,
            },
            pubkey_b64: peer.public_key_b64(),
            sign_pubkey_b64: None,
        });
        keystore.save(&path).unwrap();
        let state = HandshakeState {
            peer_fingerprint_hex: peer.fingerprint_hex(),
            peer_identity_pubkey_b64: peer.public_key_b64(),
            peer_signing_pubkey_b64: peer.identity.signing_public_b64(),
            session_keys: shph_core::SessionKeys {
                send_nonce: 0,
                recv_nonce: 0,
                send_key: [0; 32],
                recv_key: [0; 32],
            },
            transcript_hash_hex: String::new(),
        };

        assert!(matches!(
            enforce_peer_policy(&path, "127.0.0.1:7000", &state, true),
            Err(ShphError::Auth(_))
        ));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn peer_policy_accepts_alias_and_public_key_selectors() {
        let dir = std::env::temp_dir().join(format!(
            "shph-cli-selector-{}-{}",
            std::process::id(),
            phase_a1_now_ms().unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keystore.json");
        let mut keystore = KeyStore::new(KeyStoreConfig::default()).unwrap();
        let peer = KeyStore::new(KeyStoreConfig::default()).unwrap();
        let peer_pubkey = peer.public_key_b64();
        keystore.add_contact(shph_core::Contact {
            alias: "peer".into(),
            endpoint: shph_core::Endpoint {
                host: "127.0.0.1".into(),
                port: 7000,
            },
            pubkey_b64: peer_pubkey.clone(),
            sign_pubkey_b64: Some(peer.identity.signing_public_b64()),
        });
        keystore.save(&path).unwrap();
        let state = HandshakeState {
            peer_fingerprint_hex: peer.fingerprint_hex(),
            peer_identity_pubkey_b64: peer_pubkey.clone(),
            peer_signing_pubkey_b64: peer.identity.signing_public_b64(),
            session_keys: shph_core::SessionKeys {
                send_nonce: 0,
                recv_nonce: 0,
                send_key: [0; 32],
                recv_key: [0; 32],
            },
            transcript_hash_hex: String::new(),
        };

        assert!(enforce_peer_policy(&path, "peer", &state, true).is_ok());
        assert!(enforce_peer_policy(&path, &peer_pubkey, &state, true).is_ok());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn cidr_validation_checks_prefix() {
        assert!(validate_cidr("10.0.0.0/24").is_ok());
        assert!(validate_cidr("2001:db8::/64").is_ok());
        assert!(validate_cidr("10.0.0.0/33").is_err());
        assert!(validate_cidr("not-a-cidr").is_err());
    }

    #[test]
    fn route_command_builders_validate_and_emit_commands() {
        let add_cmd = build_route_add_command("10.12.0.0/16", "shph0").expect("route add command");
        assert!(!add_cmd.is_empty());
        if cfg!(target_os = "linux") {
            assert_eq!(add_cmd[2], "add");
        }
        let del_cmd =
            build_route_delete_command("10.12.0.0/16", "shph0").expect("route del command");
        assert!(!del_cmd.is_empty());
        if cfg!(target_os = "windows") {
            assert!(del_cmd.contains(&"interface=shph0".to_string()));
        } else if cfg!(target_os = "linux") {
            assert!(del_cmd.ends_with(&["dev".to_string(), "shph0".to_string()]));
        }
        assert!(build_route_add_command("10.12.0.0/64", "shph0").is_err());
    }

    #[test]
    fn tun_mtu_command_builder_is_bounded() {
        let commands =
            build_tun_mtu_commands("shph0", DEFAULT_TUN_MTU_BYTES).expect("MTU commands");
        assert!(!commands.is_empty());
        assert!(commands.iter().all(|command| command
            .iter()
            .any(|part| part.contains(&DEFAULT_TUN_MTU_BYTES.to_string()))));
        assert!(build_tun_mtu_commands("", DEFAULT_TUN_MTU_BYTES).is_err());
        assert!(build_tun_mtu_commands("shph0", 575).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn control_plane_state_loader_rejects_final_component_symlink() {
        use std::os::unix::fs::symlink;

        let dir = std::env::temp_dir().join(format!(
            "shph-cli-state-symlink-{}-{}",
            std::process::id(),
            phase_a1_now_ms().unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("config.toml");
        let state = control_plane_state_path(&config);
        let target = dir.join("target.json");
        std::fs::write(
            &target,
            r#"{"interface_name":"shph0","routes":[],"dns_servers":[]}"#,
        )
        .unwrap();
        symlink(&target, &state).unwrap();

        assert!(load_control_plane_state(&config).is_err());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn control_plane_state_loader_rejects_oversized_state() {
        let dir = std::env::temp_dir().join(format!(
            "shph-cli-state-large-{}-{}",
            std::process::id(),
            phase_a1_now_ms().unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("config.toml");
        let state = control_plane_state_path(&config);
        std::fs::write(
            &state,
            vec![b'x'; (MAX_CONTROL_PLANE_STATE_BYTES + 1) as usize],
        )
        .unwrap();

        assert!(load_control_plane_state(&config).is_err());
        std::fs::remove_dir_all(dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn control_plane_state_loader_requires_owner_only_permissions() {
        use std::fs::Permissions;
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "shph-cli-state-permissions-{}-{}",
            std::process::id(),
            phase_a1_now_ms().unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("config.toml");
        let state = control_plane_state_path(&config);
        std::fs::write(
            &state,
            r#"{"interface_name":"shph0","routes":[],"dns_servers":[]}"#,
        )
        .unwrap();

        std::fs::set_permissions(&state, Permissions::from_mode(0o644)).unwrap();
        assert!(load_control_plane_state(&config).is_err());
        std::fs::set_permissions(&state, Permissions::from_mode(0o600)).unwrap();
        assert!(load_control_plane_state(&config).is_ok());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn dns_command_builders_validate_inputs() {
        let apply_cmd = build_dns_apply_command("1.1.1.1", "shph0").expect("dns apply command");
        assert!(!apply_cmd.is_empty());
        let restore_cmd = build_dns_restore_command("shph0", "ipv4").expect("dns restore command");
        assert!(!restore_cmd.is_empty());
        assert!(build_dns_apply_command("bad_ip", "shph0").is_err());
    }

    #[test]
    fn dns_command_builder_preserves_multiple_servers() {
        let commands =
            build_dns_apply_commands(&["1.1.1.1".to_string(), "9.9.9.9".to_string()], "shph0")
                .expect("dns commands");
        if cfg!(target_os = "linux") {
            assert_eq!(commands.len(), 1);
            assert_eq!(
                commands[0],
                vec!["resolvectl", "dns", "shph0", "1.1.1.1", "9.9.9.9"]
            );
        } else if cfg!(target_os = "windows") {
            assert_eq!(commands.len(), 2);
            assert_eq!(
                commands[0],
                vec![
                    "netsh",
                    "interface",
                    "ipv4",
                    "set",
                    "dns",
                    "name=shph0",
                    "static",
                    "1.1.1.1"
                ]
            );
            assert_eq!(
                commands[1],
                vec![
                    "netsh",
                    "interface",
                    "ipv4",
                    "add",
                    "dnsserver",
                    "name=shph0",
                    "address=9.9.9.9",
                    "index=2"
                ]
            );
        } else {
            assert!(commands.is_empty());
        }
    }

    #[test]
    fn guard_cleanup_is_idempotent_for_empty_state() {
        let mut guard = ControlPlaneGuard::default();
        assert!(guard.cleanup().is_ok());
        assert!(guard.cleanup().is_ok());
    }

    #[test]
    fn apply_control_plane_dry_run_accepts_valid_inputs() {
        let cfg = Config {
            control_plane: Some(ControlPlaneConfig {
                apply_routes: Some(true),
                route_cidrs: Some(vec!["10.20.0.0/16".to_string()]),
                apply_dns: Some(true),
                dns_servers: Some(vec!["1.1.1.1".to_string()]),
                dry_run: Some(true),
            }),
            ..Config::default()
        };
        let guard = apply_control_plane(&cfg, "shph0").expect("apply control plane");
        assert!(guard.added_routes.is_empty());
        assert!(guard.applied_dns_servers.is_empty());
    }

    #[test]
    fn apply_control_plane_rejects_bad_dns() {
        let cfg = Config {
            control_plane: Some(ControlPlaneConfig {
                apply_routes: Some(false),
                route_cidrs: None,
                apply_dns: Some(true),
                dns_servers: Some(vec!["bad_dns".to_string()]),
                dry_run: Some(true),
            }),
            ..Config::default()
        };
        assert!(apply_control_plane(&cfg, "shph0").is_err());
    }

    #[test]
    fn control_plane_plan_preflight_validates_all_before_apply() {
        // A bad CIDR alongside a good one must be rejected up front (atomicity).
        let control = ControlPlaneConfig {
            apply_routes: Some(true),
            route_cidrs: Some(vec!["10.20.0.0/16".to_string(), "10.30.0.0/40".to_string()]),
            apply_dns: Some(true),
            dns_servers: Some(vec!["1.1.1.1".to_string()]),
            dry_run: Some(false),
        };
        assert!(build_control_plane_plan(&control, "shph0").is_err());
    }

    #[test]
    fn control_plane_plan_normalizes_dns_and_routes() {
        let control = ControlPlaneConfig {
            apply_routes: Some(true),
            route_cidrs: Some(vec![
                "10.20.0.0/16".to_string(),
                "2001:db8::/32".to_string(),
            ]),
            apply_dns: Some(true),
            dns_servers: Some(vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()]),
            dry_run: Some(true),
        };
        let plan = build_control_plane_plan(&control, "shph0").expect("plan");
        assert_eq!(plan.routes, vec!["10.20.0.0/16", "2001:db8::/32"]);
        assert!(plan.apply_dns);
        assert_eq!(plan.dns_servers, vec!["1.1.1.1", "8.8.8.8"]);
    }

    #[test]
    fn control_plane_plan_requires_interface_name() {
        let control = ControlPlaneConfig {
            apply_routes: Some(true),
            route_cidrs: Some(vec!["10.20.0.0/16".to_string()]),
            apply_dns: None,
            dns_servers: None,
            dry_run: Some(true),
        };
        assert!(build_control_plane_plan(&control, "").is_err());
        assert!(build_control_plane_plan(&control, "   ").is_err());
    }

    #[test]
    fn control_plane_plan_skips_dns_when_no_servers() {
        let control = ControlPlaneConfig {
            apply_routes: Some(false),
            route_cidrs: None,
            apply_dns: Some(true),
            dns_servers: Some(vec![]),
            dry_run: Some(true),
        };
        let plan = build_control_plane_plan(&control, "shph0").expect("plan");
        assert!(!plan.apply_dns);
        assert!(plan.dns_servers.is_empty());
    }

    #[test]
    fn apply_control_plane_records_dry_run_flag() {
        let cfg = Config {
            control_plane: Some(ControlPlaneConfig {
                apply_routes: Some(true),
                route_cidrs: Some(vec!["10.20.0.0/16".to_string()]),
                apply_dns: Some(false),
                dns_servers: None,
                dry_run: Some(true),
            }),
            ..Config::default()
        };
        let guard = apply_control_plane(&cfg, "shph0").expect("apply");
        assert!(guard.dry_run);
        assert!(guard.added_routes.is_empty());
    }

    #[test]
    fn control_plane_plan_default_is_empty() {
        let plan = ControlPlanePlan::default();
        assert!(plan.routes.is_empty());
        assert!(!plan.apply_dns);
        assert!(plan.dns_servers.is_empty());
    }

    #[test]
    fn transport_mode_parse_supports_tcp_and_quic() {
        assert!(TransportMode::parse("tcp").is_ok());
        assert!(TransportMode::parse("quic").is_ok());
        assert_eq!(
            TransportMode::parse("quic-standard").unwrap(),
            TransportMode::QuicStandard
        );
        assert_eq!(
            TransportMode::parse("quic-rfc").unwrap(),
            TransportMode::QuicStandard
        );
        assert!(TransportMode::parse("offline-mesh").is_ok());
        assert!(TransportMode::parse("data-mule").is_ok());
        assert!(TransportMode::parse("bad").is_err());
        assert_eq!(transport_mode_to_str(TransportMode::Tcp), "tcp");
        assert_eq!(transport_mode_to_str(TransportMode::Quic), "quic");
        assert_eq!(
            transport_mode_to_str(TransportMode::QuicStandard),
            "quic-standard"
        );
    }

    #[cfg(unix)]
    #[test]
    fn quic_certificate_writer_rejects_symlink_destination() {
        use std::os::unix::fs::symlink;

        let dir = std::env::temp_dir().join(format!(
            "shph-cli-quic-cert-symlink-{}-{}",
            std::process::id(),
            phase_a1_now_ms().unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("target.der");
        let cert = dir.join("server.der");
        std::fs::write(&target, b"existing").unwrap();
        symlink(&target, &cert).unwrap();

        let result = super::write_quic_certificate(&cert, b"replacement");
        assert!(matches!(
            result,
            Err(ShphError::InvalidArgument(message))
                if message.contains("symlinked QUIC certificate")
        ));
        assert_eq!(std::fs::read(&target).unwrap(), b"existing");
        std::fs::remove_dir_all(dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn shamir_share_writer_rejects_symlinked_output_directory() {
        use std::os::unix::fs::symlink;

        let dir = std::env::temp_dir().join(format!(
            "shph-cli-shamir-symlink-{}-{}",
            std::process::id(),
            phase_a1_now_ms().unwrap()
        ));
        let real = dir.join("real");
        let link = dir.join("link");
        std::fs::create_dir_all(&real).unwrap();
        symlink(&real, &link).unwrap();
        let shares = vec![shph_core::ShamirShare {
            index: 1,
            payload_b64: "AA==".into(),
        }];

        assert!(super::write_shamir_shares(&link, &shares).is_err());
        assert!(!real.join("share-001.json").exists());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn transport_mode_from_roadmap_defaults_to_tcp() {
        let roadmap = RoadmapConfig::default();
        let mode = super::resolve_transport_mode(None, Some(&roadmap))
            .expect("resolve tcp from default roadmap");
        assert_eq!(transport_mode_to_str(mode), "tcp");
    }

    #[test]
    fn transport_mode_resolves_offline_mesh_and_data_mule_from_roadmap() {
        let offline = RoadmapConfig {
            transport: TransportAdapterConfig::OfflineMesh {
                node_id: "node-a".to_string(),
                peer_id: "node-b".to_string(),
                spool_dir: ".shph/offline".to_string(),
                poll_interval_ms: 250,
                max_idle_entries: 1024,
            },
            ..RoadmapConfig::default()
        };
        let data_mule = RoadmapConfig {
            transport: TransportAdapterConfig::DataMule {
                inbox_dir: ".shph/inbox".to_string(),
                outbox_dir: ".shph/outbox".to_string(),
                poll_interval_ms: 250,
                max_file_bytes: 1024,
                max_total_bytes: 8 * 1024 * 1024,
                max_age_ms: 24 * 60 * 60 * 1_000,
            },
            ..RoadmapConfig::default()
        };

        let offline_mode = super::resolve_transport_mode(None, Some(&offline))
            .expect("resolve offline-mesh mode from roadmap");
        let data_mule_mode = super::resolve_transport_mode(None, Some(&data_mule))
            .expect("resolve data-mule mode from roadmap");
        assert_eq!(transport_mode_to_str(offline_mode), "offline-mesh");
        assert_eq!(transport_mode_to_str(data_mule_mode), "data-mule");
    }

    #[test]
    fn transport_mode_override_trumps_roadmap() {
        let roadmap = RoadmapConfig {
            transport: TransportAdapterConfig::DataMule {
                inbox_dir: ".shph/inbox".to_string(),
                outbox_dir: ".shph/outbox".to_string(),
                poll_interval_ms: 250,
                max_file_bytes: 1024,
                max_total_bytes: 8 * 1024 * 1024,
                max_age_ms: 24 * 60 * 60 * 1_000,
            },
            ..RoadmapConfig::default()
        };
        let mode = super::resolve_transport_mode(Some("offline-mesh"), Some(&roadmap))
            .expect("explicit transport override");
        assert_eq!(transport_mode_to_str(mode), "offline-mesh");
    }
}
