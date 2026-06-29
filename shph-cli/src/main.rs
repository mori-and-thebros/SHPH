//! SHPH CLI - Command-line interface for Shroud-Phantom VPN.

mod shutdown;

use base64::Engine as _;
use clap::{Parser, Subcommand};
use serde::Serialize;
use shph_config::{Config, ControlPlaneConfig, PeerConfig, SessionRole};
use shph_core::{
    build_hello,
    roadmap::{DataMuleConfig, OfflineMeshConfig, RoadmapConfig},
    verify_and_derive, Contact, Endpoint, HandshakeState, KeyStore, KeyStoreConfig,
    MetricsCollector, Result, ShphError,
};
use shph_transport::{
    accept_secure_session, connect_secure_session, data_mule_accept_and_handshake,
    data_mule_accept_secure_session, data_mule_connect_and_handshake,
    data_mule_connect_secure_session, offline_mesh_accept_and_handshake,
    offline_mesh_accept_secure_session, offline_mesh_connect_and_handshake,
    offline_mesh_connect_secure_session, quic_handshake_client, quic_handshake_server,
    tcp_handshake_client, tcp_handshake_server, SecureReceiver, SecureSender, SecureSession,
    TransportMode,
};
use shph_tun::TunDevice;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
#[cfg(not(test))]
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

fn phase_a1_now_ms() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ShphError::Internal("system clock before unix epoch".into()))?
        .as_millis() as u64)
}

#[derive(Parser, Debug)]
#[command(name = "shph")]
#[command(
    about = "SHPH (Shroud-Phantom): Layer 3 VPN with stealth/shroud features",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Config file path
    #[arg(short, long)]
    config: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialize a new identity and configuration
    Init {
        /// Force overwrite existing identity/config
        #[arg(long)]
        new: bool,
    },
    /// Bring up the VPN tunnel
    Up {
        /// Config file to use
        #[arg(long)]
        config: Option<PathBuf>,
        /// Optional transport override (tcp|quic|offline-mesh|data-mule)
        #[arg(long)]
        transport: Option<String>,
    },
    /// Bring down the VPN tunnel
    Down,
    /// Show VPN status
    Status,
    /// Show peer fingerprint
    ShowFingerprint,
    /// List configured peers
    ListPeers,
    /// Add a new peer
    AddPeer {
        alias: String,
        host: String,
        port: u16,
        pubkey: String,
    },
    /// Show configuration
    ShowConfig,
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
        /// Optional transport override (tcp|quic|offline-mesh|data-mule)
        #[arg(long)]
        transport: Option<String>,
    },
    /// Connect to a peer and perform one TCP handshake
    Connect {
        #[arg(long)]
        peer: String,
        #[arg(long, default_value_t = 5)]
        timeout_secs: u64,
        /// Optional transport override (tcp|quic|offline-mesh|data-mule)
        #[arg(long)]
        transport: Option<String>,
    },
    /// Send one encrypted payload over a freshly established TCP session
    SendOnce {
        #[arg(long)]
        peer: String,
        #[arg(long)]
        text: String,
        #[arg(long, default_value_t = 5)]
        timeout_secs: u64,
        /// Optional transport override (tcp|quic|offline-mesh|data-mule)
        #[arg(long)]
        transport: Option<String>,
    },
    /// Receive one encrypted payload after TCP handshake
    RecvOnce {
        #[arg(long, default_value = "0.0.0.0:7000")]
        bind: String,
        #[arg(long, default_value_t = 5)]
        timeout_secs: u64,
        /// Optional transport override (tcp|quic|offline-mesh|data-mule)
        #[arg(long)]
        transport: Option<String>,
    },
}

#[derive(Debug, Serialize)]
struct HandshakeSimOut {
    peer_fingerprint_hex: String,
    transcript_hash_hex: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt::init();
    shutdown::install_signal_handlers();

    let config_path = cli.config.unwrap_or_else(Config::default_config_path);
    let keystore_path = keystore_path_from_config(&config_path);

    match cli.command {
        Commands::Init { new } => handle_init(&config_path, &keystore_path, new)?,
        Commands::Up { config, transport } => {
            let path = config.unwrap_or(config_path);
            let config = load_config(&path)?;
            let mode = resolve_transport_mode(transport.as_deref(), config.roadmap.as_ref())?;
            handle_up(
                &path,
                &keystore_path,
                &config,
                mode,
                config.roadmap.as_ref(),
            )?
        }
        Commands::Down => handle_down()?,
        Commands::Status => handle_status(&config_path, &keystore_path)?,
        Commands::ShowFingerprint => handle_show_fingerprint(&keystore_path)?,
        Commands::ListPeers => handle_list_peers(&config_path)?,
        Commands::AddPeer {
            alias,
            host,
            port,
            pubkey,
        } => handle_add_peer(&config_path, &keystore_path, alias, host, port, pubkey)?,
        Commands::ShowConfig => handle_show_config(&config_path)?,
        Commands::HandshakeSim { peer_pubkey_b64 } => {
            handle_handshake_sim(&keystore_path, &peer_pubkey_b64)?
        }
        Commands::Listen {
            bind,
            timeout_secs,
            transport,
        } => {
            let config = load_config(&config_path)?;
            handle_listen(
                &keystore_path,
                &bind,
                timeout_secs,
                transport,
                config.roadmap.as_ref(),
            )?
        }
        Commands::Connect {
            peer,
            timeout_secs,
            transport,
        } => {
            let config = load_config(&config_path)?;
            handle_connect(
                &keystore_path,
                &peer,
                timeout_secs,
                transport,
                config.roadmap.as_ref(),
            )?
        }
        Commands::SendOnce {
            peer,
            text,
            timeout_secs,
            transport,
        } => {
            let config = load_config(&config_path)?;
            handle_send_once(
                &keystore_path,
                &peer,
                &text,
                timeout_secs,
                transport,
                config.roadmap.as_ref(),
            )?
        }
        Commands::RecvOnce {
            bind,
            timeout_secs,
            transport,
        } => {
            let config = load_config(&config_path)?;
            handle_recv_once(
                &keystore_path,
                &bind,
                timeout_secs,
                transport,
                config.roadmap.as_ref(),
            )?
        }
    }

    Ok(())
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

fn handle_up(
    _config_path: &Path,
    keystore_path: &Path,
    config: &Config,
    transport: TransportMode,
    _roadmap: Option<&RoadmapConfig>,
) -> Result<()> {
    let tun = TunDevice::open(&config.interface_name)?;
    println!("SHPH up");
    println!("  Interface: {}", tun.name());
    println!("  Local endpoint: {}", config.local_endpoint);
    println!("  Peer count: {}", config.peers.len());
    print_control_plane_status(config);
    let mut control_guard = apply_control_plane(config, tun.name())?;
    let interface_name = tun.name().to_string();
    let session_result = if let Some(session) = &config.session {
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
                                &interface_name,
                                bind,
                                timeout_secs,
                                transport,
                                config.roadmap.as_ref(),
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
                                &interface_name,
                                peer,
                                timeout_secs,
                                transport,
                                config.roadmap.as_ref(),
                            )
                        },
                    )?;
                }
            }
        }
        Ok(())
    } else {
        Ok(())
    };
    match session_result {
        Ok(()) => {
            control_guard.cleanup()?;
            Ok(())
        }
        Err(err) => {
            let cleanup_result = control_guard.cleanup();
            if let Err(clean_err) = cleanup_result {
                return Err(ShphError::Internal(format!(
                    "session error: {err}; control-plane cleanup error: {clean_err}"
                )));
            }
            Err(err)
        }
    }
}

fn handle_down() -> Result<()> {
    println!("SHPH down");
    Ok(())
}

fn handle_status(config_path: &Path, keystore_path: &Path) -> Result<()> {
    let config_exists = config_path.exists();
    let keystore_exists = keystore_path.exists();
    let peer_count = if config_exists {
        load_config(config_path).map(|c| c.peers.len()).unwrap_or(0)
    } else {
        0
    };
    println!("SHPH Status");
    println!(
        "  Config: {}",
        if config_exists { "present" } else { "missing" }
    );
    println!(
        "  Identity: {}",
        if keystore_exists {
            "present"
        } else {
            "missing"
        }
    );
    println!("  Tunnel: inactive");
    println!("  Peers: {peer_count}");
    Ok(())
}

fn handle_show_fingerprint(keystore_path: &Path) -> Result<()> {
    let keystore = KeyStore::load(keystore_path, None)?;
    println!("{}", keystore.fingerprint_hex());
    Ok(())
}

fn handle_list_peers(config_path: &Path) -> Result<()> {
    let config = load_config(config_path)?;
    if config.peers.is_empty() {
        println!("No peers configured");
        return Ok(());
    }
    for peer in config.peers {
        println!("{} {} {}", peer.alias, peer.endpoint, peer.pubkey);
    }
    Ok(())
}

fn handle_add_peer(
    config_path: &Path,
    keystore_path: &Path,
    alias: String,
    host: String,
    port: u16,
    pubkey_b64: String,
) -> Result<()> {
    if alias.trim().is_empty() {
        return Err(ShphError::InvalidArgument("alias cannot be empty".into()));
    }
    if port == 0 {
        return Err(ShphError::InvalidArgument("port must be > 0".into()));
    }
    validate_pubkey_b64(&pubkey_b64)?;

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

    let endpoint = format!("{host}:{port}");
    config.peers.push(PeerConfig {
        alias: alias.clone(),
        endpoint: endpoint.clone(),
        pubkey: pubkey_b64.clone(),
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
    });
    keystore.save(keystore_path)?;

    println!("Peer added: {alias} ({endpoint})");
    Ok(())
}

fn handle_show_config(config_path: &Path) -> Result<()> {
    let config = load_config(config_path)?;
    let rendered = toml::to_string_pretty(&config).map_err(|e| ShphError::Config(e.to_string()))?;
    println!("{rendered}");
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
    let state: HandshakeState = verify_and_derive(
        &keystore.identity,
        &material,
        &peer_material.local_hello,
        true,
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
    roadmap: Option<&RoadmapConfig>,
) -> Result<()> {
    let mode = resolve_transport_mode(transport.as_deref(), roadmap)?;
    let keystore = KeyStore::load(keystore_path, None)?;
    let state = match mode {
        TransportMode::Tcp => tcp_handshake_server(bind, &keystore.identity, timeout_secs)?,
        TransportMode::Quic => {
            let (_socket, _peer, state) =
                quic_handshake_server(bind, &keystore.identity, timeout_secs)?;
            state
        }
        TransportMode::OfflineMesh => {
            let cfg = roadmap_offline_mesh_config(roadmap)?;
            offline_mesh_accept_and_handshake(&cfg, &keystore.identity, timeout_secs)?
        }
        TransportMode::DataMule => {
            let cfg = roadmap_data_mule_config(roadmap)?;
            data_mule_accept_and_handshake(&cfg, &keystore.identity, timeout_secs)?
        }
    };
    print_handshake_state("listen", bind, &state);
    Ok(())
}

fn handle_connect(
    keystore_path: &Path,
    peer: &str,
    timeout_secs: u64,
    transport: Option<String>,
    roadmap: Option<&RoadmapConfig>,
) -> Result<()> {
    let mode = resolve_transport_mode(transport.as_deref(), roadmap)?;
    let keystore = KeyStore::load(keystore_path, None)?;
    let state = match mode {
        TransportMode::Tcp => tcp_handshake_client(peer, &keystore.identity, timeout_secs)?,
        TransportMode::Quic => {
            let (_socket, _peer_addr, state) =
                quic_handshake_client(peer, &keystore.identity, timeout_secs)?;
            state
        }
        TransportMode::OfflineMesh => {
            let cfg = roadmap_offline_mesh_config(roadmap)?;
            offline_mesh_connect_and_handshake(&cfg, &keystore.identity, timeout_secs)?
        }
        TransportMode::DataMule => {
            let cfg = roadmap_data_mule_config(roadmap)?;
            data_mule_connect_and_handshake(&cfg, &keystore.identity, peer, timeout_secs)?
        }
    };
    print_handshake_state("connect", peer, &state);
    Ok(())
}

fn handle_send_once(
    keystore_path: &Path,
    peer: &str,
    text: &str,
    timeout_secs: u64,
    transport: Option<String>,
    roadmap: Option<&RoadmapConfig>,
) -> Result<()> {
    let start_ms = phase_a1_now_ms()?;
    let session_id = format!("send-once-{peer}-{start_ms}");
    let metrics = MetricsCollector::new();
    println!("  Session id: {session_id}");
    println!("  Session start: {start_ms}ms");
    println!("  Initial metrics: {:?}", metrics.snapshot());
    let mode = resolve_transport_mode(transport.as_deref(), roadmap)?;
    let (mut session, state) = match mode {
        TransportMode::Tcp => {
            let keystore = KeyStore::load(keystore_path, None)?;
            connect_secure_session(peer, &keystore.identity, timeout_secs, mode)?
        }
        TransportMode::Quic => {
            let keystore = KeyStore::load(keystore_path, None)?;
            connect_secure_session(peer, &keystore.identity, timeout_secs, mode)?
        }
        TransportMode::OfflineMesh => {
            let keystore = KeyStore::load(keystore_path, None)?;
            let cfg = roadmap_offline_mesh_config(roadmap)?;
            offline_mesh_connect_secure_session(&cfg, &keystore.identity, timeout_secs)?
        }
        TransportMode::DataMule => {
            let keystore = KeyStore::load(keystore_path, None)?;
            let cfg = roadmap_data_mule_config(roadmap)?;
            data_mule_connect_secure_session(&cfg, &keystore.identity, peer, timeout_secs)?
        }
    };
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
    roadmap: Option<&RoadmapConfig>,
) -> Result<()> {
    let start_ms = phase_a1_now_ms()?;
    let session_id = format!("recv-once-{bind}-{start_ms}");
    let metrics = MetricsCollector::new();
    println!("  Session id: {session_id}");
    println!("  Session start: {start_ms}ms");
    println!("  Initial metrics: {:?}", metrics.snapshot());
    let mode = resolve_transport_mode(transport.as_deref(), roadmap)?;
    let (mut session, state) = match mode {
        TransportMode::Tcp => {
            let keystore = KeyStore::load(keystore_path, None)?;
            accept_secure_session(bind, &keystore.identity, timeout_secs, mode)?
        }
        TransportMode::Quic => {
            let keystore = KeyStore::load(keystore_path, None)?;
            accept_secure_session(bind, &keystore.identity, timeout_secs, mode)?
        }
        TransportMode::OfflineMesh => {
            let keystore = KeyStore::load(keystore_path, None)?;
            let cfg = roadmap_offline_mesh_config(roadmap)?;
            offline_mesh_accept_secure_session(&cfg, &keystore.identity, timeout_secs)?
        }
        TransportMode::DataMule => {
            let keystore = KeyStore::load(keystore_path, None)?;
            let cfg = roadmap_data_mule_config(roadmap)?;
            data_mule_accept_secure_session(&cfg, &keystore.identity, timeout_secs)?
        }
    };
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
    let raw = base64::engine::general_purpose::STANDARD
        .decode(input.as_bytes())
        .map_err(|_| ShphError::InvalidArgument("pubkey must be base64".into()))?;
    if raw.len() != 32 {
        return Err(ShphError::InvalidArgument(
            "pubkey must decode to 32 bytes".into(),
        ));
    }
    Ok(())
}

fn transport_mode_to_str(mode: TransportMode) -> &'static str {
    match mode {
        TransportMode::Tcp => "tcp",
        TransportMode::Quic => "quic",
        TransportMode::OfflineMesh => "offline-mesh",
        TransportMode::DataMule => "data-mule",
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
                guard.added_routes.push(route.clone());
                println!("  route add {route}");
            }
        }

        if plan.apply_dns {
            for server in &plan.dns_servers {
                if dry_run {
                    println!("  [dry-run] dns add {server}");
                } else {
                    apply_dns_server(server, interface_name)?;
                    guard.applied_dns_servers.push(server.clone());
                    guard.dns_interface_name = Some(interface_name.to_string());
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
    if interface_name.trim().is_empty() {
        return Err(ShphError::InvalidArgument(
            "interface name required for control-plane apply".into(),
        ));
    }

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
    added_routes: Vec<String>,
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

        while let Some(route) = self.added_routes.pop() {
            if let Err(err) = delete_route(&route) {
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

fn delete_route(cidr: &str) -> Result<()> {
    let command = build_route_delete_command(cidr)?;
    run_shell_command(&command)
}

fn apply_dns_server(server: &str, interface_name: &str) -> Result<()> {
    let command = build_dns_apply_command(server, interface_name)?;
    run_shell_command(&command)
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
    if cfg!(target_os = "linux") {
        Ok(vec![
            "ip".to_string(),
            "route".to_string(),
            "replace".to_string(),
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

fn build_route_delete_command(cidr: &str) -> Result<Vec<String>> {
    validate_cidr(cidr)?;
    if cfg!(target_os = "linux") {
        Ok(vec![
            "ip".to_string(),
            "route".to_string(),
            "del".to_string(),
            cidr.to_string(),
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
            "store=active".to_string(),
        ])
    } else {
        Err(ShphError::Unsupported(
            "route delete unsupported on this platform".into(),
        ))
    }
}

fn build_dns_apply_command(server: &str, interface_name: &str) -> Result<Vec<String>> {
    let _addr = server
        .parse::<IpAddr>()
        .map_err(|_| ShphError::Config(format!("invalid DNS server IP: {server}")))?;
    if cfg!(target_os = "linux") {
        Ok(vec![
            "resolvectl".to_string(),
            "dns".to_string(),
            interface_name.to_string(),
            server.to_string(),
        ])
    } else if cfg!(target_os = "windows") {
        let family = if server.contains(':') { "ipv6" } else { "ipv4" };
        Ok(vec![
            "netsh".to_string(),
            "interface".to_string(),
            family.to_string(),
            "set".to_string(),
            "dns".to_string(),
            format!("name={interface_name}"),
            "static".to_string(),
            server.to_string(),
        ])
    } else {
        Err(ShphError::Unsupported(
            "DNS apply unsupported on this platform".into(),
        ))
    }
}

fn build_dns_restore_command(interface_name: &str, family: &str) -> Result<Vec<String>> {
    if interface_name.trim().is_empty() {
        return Err(ShphError::InvalidArgument(
            "interface name required for dns restore".into(),
        ));
    }
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
                println!(
                    "  Reconnect: attempt {}/{} failed ({:?}), retrying in {}ms",
                    attempts, max_attempts, err, delay_ms
                );
                thread::sleep(Duration::from_millis(delay_ms));
                delay_ms = delay_ms
                    .saturating_mul(2)
                    .min(max_delay_ms.max(initial_delay_ms));
            }
        }
    }
}

fn run_listen_loop(
    keystore_path: &Path,
    interface_name: &str,
    bind: &str,
    timeout_secs: u64,
    mode: TransportMode,
    roadmap: Option<&RoadmapConfig>,
) -> Result<()> {
    let start_ms = phase_a1_now_ms()?;
    let keystore = KeyStore::load(keystore_path, None)?;
    let (mut session, state) = match mode {
        TransportMode::Tcp | TransportMode::Quic => {
            accept_secure_session(bind, &keystore.identity, timeout_secs, mode)?
        }
        TransportMode::OfflineMesh => {
            let cfg = roadmap_offline_mesh_config(roadmap)?;
            offline_mesh_accept_secure_session(&cfg, &keystore.identity, timeout_secs)?
        }
        TransportMode::DataMule => {
            let cfg = roadmap_data_mule_config(roadmap)?;
            data_mule_accept_secure_session(&cfg, &keystore.identity, timeout_secs)?
        }
    };
    print_handshake_state("listen-loop", bind, &state);
    let session_id = format!("listen-{bind}-{start_ms}");
    let metrics = MetricsCollector::new();
    println!("  Session id: {session_id}");
    println!("  Session start: {start_ms}ms");
    println!("  Initial metrics: {:?}", metrics.snapshot());
    let tun = TunDevice::open(interface_name)?;

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
                let rendered = String::from_utf8_lossy(&payload);
                println!("  RX: {rendered}");
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

fn run_connect_loop(
    keystore_path: &Path,
    interface_name: &str,
    peer: &str,
    timeout_secs: u64,
    mode: TransportMode,
    roadmap: Option<&RoadmapConfig>,
) -> Result<()> {
    let start_ms = phase_a1_now_ms()?;
    let keystore = KeyStore::load(keystore_path, None)?;
    let (mut session, state) = match mode {
        TransportMode::Tcp | TransportMode::Quic => {
            connect_secure_session(peer, &keystore.identity, timeout_secs, mode)?
        }
        TransportMode::OfflineMesh => {
            let cfg = roadmap_offline_mesh_config(roadmap)?;
            offline_mesh_connect_secure_session(&cfg, &keystore.identity, timeout_secs)?
        }
        TransportMode::DataMule => {
            let cfg = roadmap_data_mule_config(roadmap)?;
            data_mule_connect_secure_session(&cfg, &keystore.identity, peer, timeout_secs)?
        }
    };
    print_handshake_state("connect-loop", peer, &state);
    let session_id = format!("connect-{peer}-{start_ms}");
    let metrics = MetricsCollector::new();
    println!("  Session id: {session_id}");
    println!("  Session start: {start_ms}ms");
    println!("  Initial metrics: {:?}", metrics.snapshot());
    let tun = TunDevice::open(interface_name)?;

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
    loop {
        if shutdown::shutdown_requested() {
            break;
        }
        line.clear();
        let got_line = read_stdin_line(&mut reader, &mut line)?;
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
fn read_stdin_line(reader: &mut io::StdinLock<'_>, line: &mut String) -> Result<bool> {
    read_stdin_line_unix(reader, line)
}

#[cfg(not(unix))]
fn read_stdin_line(reader: &mut io::StdinLock<'_>, line: &mut String) -> Result<bool> {
    use std::io::BufRead;
    let n = reader.read_line(line).map_err(ShphError::Io)?;
    Ok(n > 0)
}

#[cfg(unix)]
fn read_stdin_line_unix(reader: &mut io::StdinLock<'_>, line: &mut String) -> Result<bool> {
    use std::os::fd::AsRawFd;
    let fd = reader.as_raw_fd();
    loop {
        if shutdown::shutdown_requested() {
            return Ok(false);
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
            if let Some(nl) = data.iter().position(|&b| b == b'\n') {
                line.push_str(std::str::from_utf8(&data[..nl]).unwrap_or(""));
                return Ok(true);
            } else {
                line.push_str(std::str::from_utf8(data).unwrap_or(""));
                continue;
            }
        }
        if (pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL)) != 0 {
            return Ok(false);
        }
    }
}

fn run_bidirectional_native_loop(
    session: SecureSession,
    tun: TunDevice,
    metrics: MetricsCollector,
) -> Result<()> {
    let shutdown = Arc::new(AtomicBool::new(false));

    let tun_tx = tun.try_clone()?;
    let tun_rx = tun;
    let (sender, receiver) = session.into_split()?;

    let tx_shutdown = Arc::clone(&shutdown);
    let tx_metrics = metrics.clone();
    let tx_handle =
        thread::spawn(move || tun_to_transport_loop(tun_tx, sender, tx_shutdown, tx_metrics));

    let rx_shutdown = Arc::clone(&shutdown);
    let rx_metrics = metrics.clone();
    let rx_handle =
        thread::spawn(move || transport_to_tun_loop(receiver, tun_rx, rx_shutdown, rx_metrics));

    let tx_result = tx_handle
        .join()
        .map_err(|_| ShphError::Internal("tun_to_transport thread panicked".into()))?;
    let rx_result = rx_handle
        .join()
        .map_err(|_| ShphError::Internal("transport_to_tun thread panicked".into()))?;

    match (tx_result, rx_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(ShphError::ConnectionClosed), Ok(()))
        | (Ok(()), Err(ShphError::ConnectionClosed))
        | (Err(ShphError::ConnectionClosed), Err(ShphError::ConnectionClosed)) => Ok(()),
        (Err(left), Ok(())) => Err(left),
        (Ok(()), Err(right)) => Err(right),
        (Err(left), Err(_right)) => Err(left),
    }
}

fn tun_to_transport_loop(
    mut tun: TunDevice,
    mut sender: SecureSender,
    shutdown: Arc<AtomicBool>,
    metrics: MetricsCollector,
) -> Result<()> {
    let mut packet = vec![0u8; 65535];
    while !shutdown.load(Ordering::Relaxed) && !shutdown::shutdown_requested() {
        match tun.recv_packet(&mut packet) {
            Ok(0) => thread::sleep(Duration::from_millis(5)),
            Ok(n) => {
                sender.send_frame(&packet[..n])?;
                metrics.inc_bytes_sent(n);
            }
            Err(ShphError::Timeout) => thread::sleep(Duration::from_millis(5)),
            Err(ShphError::Unsupported(_)) => break,
            Err(ShphError::ConnectionClosed) => break,
            Err(err) => {
                shutdown.store(true, Ordering::Relaxed);
                metrics.inc_error();
                return Err(err);
            }
        }
    }
    shutdown.store(true, Ordering::Relaxed);
    Ok(())
}

fn transport_to_tun_loop(
    mut receiver: SecureReceiver,
    mut tun: TunDevice,
    shutdown: Arc<AtomicBool>,
    metrics: MetricsCollector,
) -> Result<()> {
    while !shutdown.load(Ordering::Relaxed) && !shutdown::shutdown_requested() {
        match receiver.recv_frame() {
            Ok(payload) => {
                if payload.is_empty() {
                    continue;
                }
                match tun.send_packet(&payload) {
                    Ok(()) => {}
                    Err(ShphError::Timeout) => thread::sleep(Duration::from_millis(5)),
                    Err(ShphError::Unsupported(_)) => break,
                    Err(err) => {
                        shutdown.store(true, Ordering::Relaxed);
                        metrics.inc_error();
                        return Err(err);
                    }
                }
                metrics.inc_bytes_recv(payload.len());
            }
            Err(ShphError::Timeout) => thread::sleep(Duration::from_millis(5)),
            Err(ShphError::ConnectionClosed) => {
                shutdown.store(true, Ordering::Relaxed);
                return Err(ShphError::ConnectionClosed);
            }
            Err(err) => {
                shutdown.store(true, Ordering::Relaxed);
                metrics.inc_error();
                return Err(err);
            }
        }
    }
    shutdown.store(true, Ordering::Relaxed);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        apply_control_plane, build_control_plane_plan, build_dns_apply_command,
        build_dns_restore_command, build_route_add_command, build_route_delete_command,
        run_with_reconnect, transport_mode_to_str, validate_cidr, ControlPlaneGuard,
        ControlPlanePlan, TransportMode,
    };
    use shph_config::RoadmapConfig;
    use shph_config::{Config, ControlPlaneConfig};
    use shph_core::roadmap::TransportAdapterConfig;
    use shph_core::{Result, ShphError};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

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
        let del_cmd = build_route_delete_command("10.12.0.0/16").expect("route del command");
        assert!(!del_cmd.is_empty());
        assert!(build_route_add_command("10.12.0.0/64", "shph0").is_err());
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
        assert!(TransportMode::parse("offline-mesh").is_ok());
        assert!(TransportMode::parse("data-mule").is_ok());
        assert!(TransportMode::parse("bad").is_err());
        assert_eq!(transport_mode_to_str(TransportMode::Tcp), "tcp");
        assert_eq!(transport_mode_to_str(TransportMode::Quic), "quic");
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
            },
            ..RoadmapConfig::default()
        };
        let mode = super::resolve_transport_mode(Some("offline-mesh"), Some(&roadmap))
            .expect("explicit transport override");
        assert_eq!(transport_mode_to_str(mode), "offline-mesh");
    }
}
