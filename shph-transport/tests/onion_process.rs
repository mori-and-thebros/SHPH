use rcgen::generate_simple_self_signed;
use shph_core::{HandshakeProfile, IdentityKeyPair, PeerPin, PeerPolicy};
use shph_transport::onion::{OnionPath, RelayHop};
use shph_transport::{
    accept_secure_session_lab_with_profile, connect_secure_session_onion, QuicLabConfig,
    TransportMode,
};
use std::fs;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct ScratchDirectory(PathBuf);

impl ScratchDirectory {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("shph-onion-process-{nonce}"));
        fs::create_dir_all(&path).expect("create scratch directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct ChildProcesses(Vec<Child>);

impl ChildProcesses {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn push(&mut self, child: Child) {
        self.0.push(child);
    }
}

impl Drop for ChildProcesses {
    fn drop(&mut self) {
        for child in &mut self.0 {
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
    }
}

fn reserve_loopback() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve loopback port");
    listener.local_addr().expect("read reserved address")
}

fn write_relay_material(
    root: &Path,
    name: &str,
    token: &[u8; 32],
) -> (PathBuf, PathBuf, PathBuf, Vec<u8>) {
    let generated = generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("generate relay certificate");
    let certificate = generated.cert.der().to_vec();
    let certificate_path = root.join(format!("{name}.cert.der"));
    let key_path = root.join(format!("{name}.key.der"));
    let token_path = root.join(format!("{name}.token"));
    fs::write(&certificate_path, &certificate).expect("write relay certificate");
    fs::write(&key_path, generated.key_pair.serialize_der()).expect("write relay key");
    fs::write(&token_path, token).expect("write relay token");
    (certificate_path, key_path, token_path, certificate)
}

fn start_relay_process(
    bind: SocketAddr,
    target: SocketAddr,
    certificate: &Path,
    key: &Path,
    token: &Path,
) -> Child {
    Command::new(env!("CARGO_BIN_EXE_shph-onion-relay"))
        .arg("--bind")
        .arg(bind.to_string())
        .arg("--cert-der")
        .arg(certificate)
        .arg("--key-pkcs8-der")
        .arg(key)
        .arg("--token-file")
        .arg(token)
        .arg("--allow-target")
        .arg(target.to_string())
        .arg("--max-circuits")
        .arg("4")
        .arg("--setup-timeout-secs")
        .arg("3")
        .arg("--max-lifetime-secs")
        .arg("30")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start relay process")
}

fn wait_until_listening(address: SocketAddr, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            panic!("relay process exited before listening: {status}");
        }
        if TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok() {
            return;
        }
        assert!(Instant::now() < deadline, "relay process did not listen");
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn three_relay_processes_carry_an_authenticated_shph_session_without_direct_fallback() {
    let scratch = ScratchDirectory::new();
    let destination_address = reserve_loopback();
    let relay_addresses = [reserve_loopback(), reserve_loopback(), reserve_loopback()];
    let tokens = [[31u8; 32], [32u8; 32], [33u8; 32]];
    let material = [
        write_relay_material(scratch.path(), "entry", &tokens[0]),
        write_relay_material(scratch.path(), "middle", &tokens[1]),
        write_relay_material(scratch.path(), "exit", &tokens[2]),
    ];

    let server_identity = IdentityKeyPair::generate().expect("destination identity");
    let client_identity = IdentityKeyPair::generate().expect("client identity");
    let server_policy = PeerPolicy::single(PeerPin::for_identity(&client_identity));
    let client_policy = PeerPolicy::single(PeerPin::for_identity(&server_identity));
    let server_identity_for_thread = server_identity.clone();
    let server = thread::spawn(move || {
        let (mut session, _) = accept_secure_session_lab_with_profile(
            &destination_address.to_string(),
            &server_identity_for_thread,
            &server_policy,
            8,
            TransportMode::Tcp,
            QuicLabConfig::default(),
            HandshakeProfile::SecureDefault,
        )?;
        session.activate()?;
        session.recv_frame()
    });

    let mut processes = ChildProcesses::new();
    let exit = start_relay_process(
        relay_addresses[2],
        destination_address,
        &material[2].0,
        &material[2].1,
        &material[2].2,
    );
    processes.push(exit);
    let middle = start_relay_process(
        relay_addresses[1],
        relay_addresses[2],
        &material[1].0,
        &material[1].1,
        &material[1].2,
    );
    processes.push(middle);
    let entry = start_relay_process(
        relay_addresses[0],
        relay_addresses[1],
        &material[0].0,
        &material[0].1,
        &material[0].2,
    );
    processes.push(entry);
    for (index, address) in relay_addresses.iter().enumerate() {
        wait_until_listening(*address, &mut processes.0[index]);
    }

    let relays = material
        .iter()
        .zip(relay_addresses)
        .zip(tokens)
        .map(|((item, endpoint), token)| {
            RelayHop::new(endpoint, "localhost", item.3.clone(), token).expect("relay pin")
        })
        .collect();
    let path = OnionPath::new(relays, destination_address).expect("three relay path");
    let (mut session, state) = connect_secure_session_onion(
        path,
        &client_identity,
        &client_policy,
        Duration::from_secs(8),
        QuicLabConfig::default(),
        HandshakeProfile::SecureDefault,
    )
    .expect("authenticated SHPH connection through child relays");
    assert_eq!(
        state.peer_fingerprint_hex,
        server_identity.fingerprint_hex()
    );
    session.activate().expect("activate SHPH session");
    session
        .send_frame(b"process-level three-relay payload")
        .expect("send through onion tunnel");
    drop(session);
    assert_eq!(
        server
            .join()
            .expect("SHPH server thread")
            .expect("receive authenticated payload"),
        b"process-level three-relay payload".to_vec()
    );
}
