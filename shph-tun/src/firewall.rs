//! Bounded, platform-neutral firewall and MSS-clamp planning helpers.
//!
//! The helpers only construct validated argument vectors. Privileged mutation
//! remains an explicit caller decision so ordinary developer-mode TUN tests do
//! not rewrite host firewall policy.

use std::net::{IpAddr, SocketAddr};

use shph_core::{Result, ShphError};

use crate::{validate_tun_mtu, DEFAULT_TUN_MTU_BYTES};

pub const KILLSWITCH_TABLE_NAME: &str = "shph_killswitch";
pub const MSS_CLAMP_TABLE_NAME: &str = "shph_mss_clamp";
pub const NAT_TABLE_NAME: &str = "shph_nat";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallTransport {
    Tcp,
    Udp,
}

impl FirewallTransport {
    fn protocol_name(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

pub fn validate_firewall_interface(interface_name: &str) -> Result<()> {
    if interface_name.trim().is_empty()
        || interface_name
            .chars()
            .any(|character| character.is_control())
    {
        return Err(ShphError::InvalidArgument(
            "firewall interface name is invalid".into(),
        ));
    }
    Ok(())
}

pub fn validate_peer_allowlist(peers: &[SocketAddr]) -> Result<()> {
    if peers.is_empty() {
        return Err(ShphError::Config(
            "killswitch requires at least one literal peer endpoint".into(),
        ));
    }
    if peers.iter().any(|peer| peer.port() == 0) {
        return Err(ShphError::Config(
            "killswitch peer endpoints must use non-zero ports".into(),
        ));
    }
    Ok(())
}

/// Construct an nftables output policy that drops all traffic except loopback,
/// the named TUN interface, and the configured encrypted transport peers.
///
/// The first delete command is intentionally omitted. Callers may remove a
/// stale table best-effort before applying this plan, but a failed delete must
/// never be mistaken for a successful install.
pub fn build_linux_killswitch_commands(
    interface_name: &str,
    peers: &[SocketAddr],
    transport: FirewallTransport,
) -> Result<Vec<Vec<String>>> {
    validate_firewall_interface(interface_name)?;
    validate_peer_allowlist(peers)?;

    let mut commands = vec![
        vec![
            "nft".into(),
            "add".into(),
            "table".into(),
            "inet".into(),
            KILLSWITCH_TABLE_NAME.into(),
        ],
        vec![
            "nft".into(),
            "add".into(),
            "chain".into(),
            "inet".into(),
            KILLSWITCH_TABLE_NAME.into(),
            "output".into(),
            "{".into(),
            "type".into(),
            "filter".into(),
            "hook".into(),
            "output".into(),
            "priority".into(),
            "0".into(),
            ";".into(),
            "policy".into(),
            "drop".into(),
            ";".into(),
            "}".into(),
        ],
        vec![
            "nft".into(),
            "add".into(),
            "rule".into(),
            "inet".into(),
            KILLSWITCH_TABLE_NAME.into(),
            "output".into(),
            "oifname".into(),
            "lo".into(),
            "accept".into(),
        ],
        vec![
            "nft".into(),
            "add".into(),
            "rule".into(),
            "inet".into(),
            KILLSWITCH_TABLE_NAME.into(),
            "output".into(),
            "oifname".into(),
            interface_name.into(),
            "accept".into(),
        ],
    ];

    for peer in peers {
        let (family, address) = match peer.ip() {
            IpAddr::V4(address) => ("ip", address.to_string()),
            IpAddr::V6(address) => ("ip6", address.to_string()),
        };
        commands.push(vec![
            "nft".into(),
            "add".into(),
            "rule".into(),
            "inet".into(),
            KILLSWITCH_TABLE_NAME.into(),
            "output".into(),
            family.into(),
            "daddr".into(),
            address,
            transport.protocol_name().into(),
            "dport".into(),
            peer.port().to_string(),
            "accept".into(),
        ]);
    }

    Ok(commands)
}

pub fn build_linux_killswitch_cleanup_commands() -> Vec<Vec<String>> {
    vec![vec![
        "nft".into(),
        "delete".into(),
        "table".into(),
        "inet".into(),
        KILLSWITCH_TABLE_NAME.into(),
    ]]
}

/// Construct bidirectional TCP SYN MSS clamping rules for the named TUN
/// interface. The rules live in their own table so cleanup cannot touch an
/// operator's unrelated nftables policy.
pub fn build_linux_mss_clamp_commands(
    interface_name: &str,
    mtu: usize,
) -> Result<Vec<Vec<String>>> {
    validate_firewall_interface(interface_name)?;
    validate_tun_mtu(mtu)?;

    let mut commands = vec![
        vec![
            "nft".into(),
            "add".into(),
            "table".into(),
            "inet".into(),
            MSS_CLAMP_TABLE_NAME.into(),
        ],
        vec![
            "nft".into(),
            "add".into(),
            "chain".into(),
            "inet".into(),
            MSS_CLAMP_TABLE_NAME.into(),
            "forward".into(),
            "{".into(),
            "type".into(),
            "filter".into(),
            "hook".into(),
            "forward".into(),
            "priority".into(),
            "-150".into(),
            ";".into(),
            "policy".into(),
            "accept".into(),
            ";".into(),
            "}".into(),
        ],
    ];

    for direction in ["oifname", "iifname"] {
        commands.push(vec![
            "nft".into(),
            "add".into(),
            "rule".into(),
            "inet".into(),
            MSS_CLAMP_TABLE_NAME.into(),
            "forward".into(),
            direction.into(),
            interface_name.into(),
            "tcp".into(),
            "flags".into(),
            "syn".into(),
            "tcp".into(),
            "option".into(),
            "maxseg".into(),
            "size".into(),
            "set".into(),
            "rt".into(),
            "mtu".into(),
        ]);
    }

    Ok(commands)
}

pub fn build_linux_mss_clamp_cleanup_commands() -> Vec<Vec<String>> {
    vec![vec![
        "nft".into(),
        "delete".into(),
        "table".into(),
        "inet".into(),
        MSS_CLAMP_TABLE_NAME.into(),
    ]]
}

/// Construct SHPH-owned Linux forwarding and masquerade rules for a host
/// gateway. The rules are scoped to traffic entering through the named TUN
/// interface and can be removed without touching unrelated firewall state.
pub fn build_linux_nat_commands(interface_name: &str) -> Result<Vec<Vec<String>>> {
    validate_firewall_interface(interface_name)?;
    Ok(vec![
        vec![
            "nft".into(),
            "add".into(),
            "table".into(),
            "inet".into(),
            NAT_TABLE_NAME.into(),
        ],
        vec![
            "nft".into(),
            "add".into(),
            "chain".into(),
            "inet".into(),
            NAT_TABLE_NAME.into(),
            "forward".into(),
            "{".into(),
            "type".into(),
            "filter".into(),
            "hook".into(),
            "forward".into(),
            "priority".into(),
            "0".into(),
            ";".into(),
            "policy".into(),
            "accept".into(),
            ";".into(),
            "}".into(),
        ],
        vec![
            "nft".into(),
            "add".into(),
            "table".into(),
            "ip".into(),
            NAT_TABLE_NAME.into(),
        ],
        vec![
            "nft".into(),
            "add".into(),
            "chain".into(),
            "ip".into(),
            NAT_TABLE_NAME.into(),
            "postrouting".into(),
            "{".into(),
            "type".into(),
            "nat".into(),
            "hook".into(),
            "postrouting".into(),
            "priority".into(),
            "100".into(),
            ";".into(),
            "policy".into(),
            "accept".into(),
            ";".into(),
            "}".into(),
        ],
        vec![
            "nft".into(),
            "add".into(),
            "rule".into(),
            "ip".into(),
            NAT_TABLE_NAME.into(),
            "postrouting".into(),
            "iifname".into(),
            interface_name.into(),
            "masquerade".into(),
        ],
    ])
}

pub fn build_linux_nat_cleanup_commands() -> Vec<Vec<String>> {
    vec![
        vec![
            "nft".into(),
            "delete".into(),
            "table".into(),
            "ip".into(),
            NAT_TABLE_NAME.into(),
        ],
        vec![
            "nft".into(),
            "delete".into(),
            "table".into(),
            "inet".into(),
            NAT_TABLE_NAME.into(),
        ],
    ]
}

pub const fn default_mtu_for_mss_clamp() -> usize {
    DEFAULT_TUN_MTU_BYTES
}

#[cfg(test)]
mod tests {
    use super::{
        build_linux_killswitch_cleanup_commands, build_linux_killswitch_commands,
        build_linux_mss_clamp_cleanup_commands, build_linux_mss_clamp_commands,
        build_linux_nat_cleanup_commands, build_linux_nat_commands, default_mtu_for_mss_clamp,
        FirewallTransport, KILLSWITCH_TABLE_NAME, MSS_CLAMP_TABLE_NAME, NAT_TABLE_NAME,
    };
    use std::net::SocketAddr;

    #[test]
    fn killswitch_commands_are_argument_bounded() {
        let peers = vec![
            "198.51.100.10:443".parse::<SocketAddr>().unwrap(),
            "[2001:db8::10]:443".parse::<SocketAddr>().unwrap(),
        ];
        let commands = build_linux_killswitch_commands("shph0", &peers, FirewallTransport::Tcp)
            .expect("killswitch plan");
        assert!(commands
            .iter()
            .all(|command| command.first() == Some(&"nft".into())));
        assert!(commands
            .iter()
            .any(|command| command.iter().any(|part| part == KILLSWITCH_TABLE_NAME)));
        assert!(commands
            .iter()
            .any(|command| command.iter().any(|part| part == "198.51.100.10")));
        assert!(commands
            .iter()
            .any(|command| command.iter().any(|part| part == "2001:db8::10")));
    }

    #[test]
    fn killswitch_requires_literal_peer_allowlist() {
        assert!(build_linux_killswitch_commands("shph0", &[], FirewallTransport::Udp).is_err());
        assert!(build_linux_killswitch_commands(
            "shph0\nnft delete table inet filter",
            &["198.51.100.10:443".parse().unwrap()],
            FirewallTransport::Tcp
        )
        .is_err());
    }

    #[test]
    fn mss_clamp_commands_are_separate_and_bounded() {
        let commands =
            build_linux_mss_clamp_commands("shph0", default_mtu_for_mss_clamp()).expect("MSS plan");
        assert!(commands
            .iter()
            .all(|command| command.iter().any(|part| part == MSS_CLAMP_TABLE_NAME)));
        assert!(build_linux_mss_clamp_commands("shph0", 575).is_err());
        assert_eq!(
            build_linux_mss_clamp_cleanup_commands()[0],
            vec![
                "nft".to_string(),
                "delete".to_string(),
                "table".to_string(),
                "inet".to_string(),
                MSS_CLAMP_TABLE_NAME.to_string()
            ]
        );
        assert_eq!(
            build_linux_killswitch_cleanup_commands()[0][4],
            KILLSWITCH_TABLE_NAME
        );
    }

    #[test]
    fn nat_commands_are_scoped_to_the_tun_interface() {
        let commands = build_linux_nat_commands("shph0").expect("NAT plan");
        assert!(commands
            .iter()
            .all(|command| command.iter().any(|part| part == NAT_TABLE_NAME)));
        assert!(commands
            .iter()
            .any(|command| command.iter().any(|part| part == "shph0")));
        assert_eq!(build_linux_nat_cleanup_commands().len(), 2);
    }
}
