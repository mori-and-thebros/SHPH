//! Windows Filtering Platform fail-closed policy.
//!
//! Filters are persistent on purpose: if SHPH is terminated with SIGKILL or
//! the process crashes, the block policy remains until the next explicit
//! cleanup. The policy is installed only when the caller opts into the
//! killswitch and requires an elevated process. The policy uses WFP's
//! outbound ALE authorization layers so TCP, UDP, and first-packet ICMP
//! connection attempts are evaluated with remote-address/port allowlists.

#![cfg(target_os = "windows")]

use sha2::{Digest, Sha256};
use shph_core::{Result, ShphError};
use std::net::{IpAddr, SocketAddr};
use std::ptr::{null, null_mut};
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, FWP_E_FILTER_NOT_FOUND, HANDLE,
};
use windows_sys::Win32::NetworkManagement::IpHelper::ConvertInterfaceAliasToLuid;
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteByKey0,
    FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0, FWPM_ACTION0,
    FWPM_CONDITION_IP_LOCAL_INTERFACE, FWPM_CONDITION_IP_PROTOCOL,
    FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT, FWPM_FILTER0,
    FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_PERSISTENT, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_SUBLAYER_UNIVERSAL, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT,
    FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_UINT16, FWP_UINT8, FWP_V4_ADDR_AND_MASK,
    FWP_V4_ADDR_MASK, FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK, FWP_VALUE0, FWP_VALUE0_0,
};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_TYPE, FWP_UINT64,
};
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use windows_sys::Win32::System::Threading::CreateMutexW;

const MAX_PEER_SLOTS: usize = 64;
const FILTER_WEIGHT_BLOCK: u64 = 10;
const FILTER_WEIGHT_ALLOW: u64 = 100;
const WFP_MUTEX_NAME: &str = "Global\\SHPH-WFP-KILLSWITCH";
const WFP_AUTHN_SERVICE: u32 = RPC_C_AUTHN_WINNT;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallTransport {
    Tcp,
    Udp,
}

impl FirewallTransport {
    fn protocol_number(self) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
        }
    }
}

pub struct WindowsKillswitchGuard {
    engine: HANDLE,
    mutex: HANDLE,
    keys: Vec<GUID>,
}

impl std::fmt::Debug for WindowsKillswitchGuard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WindowsKillswitchGuard")
            .field("engine_open", &(!self.engine.is_null()))
            .field("mutex_held", &(!self.mutex.is_null()))
            .field("filter_count", &self.keys.len())
            .finish()
    }
}

impl WindowsKillswitchGuard {
    pub fn apply(peers: &[SocketAddr], transport: FirewallTransport) -> Result<Self> {
        if peers.is_empty() {
            return Err(ShphError::Config(
                "Windows killswitch requires at least one peer endpoint".into(),
            ));
        }
        if peers.len() > MAX_PEER_SLOTS {
            return Err(ShphError::Config(format!(
                "Windows killswitch supports at most {MAX_PEER_SLOTS} peer endpoints"
            )));
        }

        let mutex = acquire_wfp_mutex()?;
        let mut engine = null_mut();
        let status =
            unsafe { FwpmEngineOpen0(null(), WFP_AUTHN_SERVICE, null(), null(), &mut engine) };
        if status != 0 || engine.is_null() {
            unsafe {
                CloseHandle(mutex);
            }
            return Err(wfp_error("FwpmEngineOpen0", status));
        }

        let mut guard = Self {
            engine,
            mutex,
            keys: Vec::new(),
        };
        guard.with_transaction(|guard| {
            guard.remove_stale_filters()?;
            guard.add_filter(
                filter_key("block-v4", 0),
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                Vec::new(),
                FWP_ACTION_BLOCK,
                FILTER_WEIGHT_BLOCK,
                "SHPH killswitch block IPv4 connections",
            )?;
            guard.add_filter(
                filter_key("block-v6", 0),
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                Vec::new(),
                FWP_ACTION_BLOCK,
                FILTER_WEIGHT_BLOCK,
                "SHPH killswitch block IPv6 connections",
            )?;
            guard.add_loopback(IpAddr::V4([127, 0, 0, 0].into()), 0)?;
            guard.add_loopback(IpAddr::V6("::1".parse().expect("static IPv6")), 0)?;

            for (index, peer) in peers.iter().enumerate() {
                guard.add_peer(index, *peer, transport)?;
            }
            Ok(())
        })?;
        Ok(guard)
    }

    pub fn allow_interface(&mut self, interface_name: &str) -> Result<()> {
        let luid = interface_luid(interface_name)?;
        self.with_transaction(|guard| {
            let v4_key = filter_key("interface-v4", 0);
            let v6_key = filter_key("interface-v6", 0);
            guard.remove_key(&v4_key)?;
            guard.keys.retain(|key| !same_guid(key, &v4_key));
            guard.remove_key(&v6_key)?;
            guard.keys.retain(|key| !same_guid(key, &v6_key));
            guard.add_interface(luid, FWPM_LAYER_ALE_AUTH_CONNECT_V4, "v4")?;
            guard.add_interface(luid, FWPM_LAYER_ALE_AUTH_CONNECT_V6, "v6")?;
            Ok(())
        })
    }

    pub fn cleanup(&mut self) -> Result<()> {
        if self.engine.is_null() && self.mutex.is_null() {
            return Ok(());
        }
        let mut first_error = None;
        if !self.engine.is_null() {
            let pending_keys = self.keys.clone();
            if !pending_keys.is_empty() {
                self.with_transaction(|guard| {
                    for key in &pending_keys {
                        guard.remove_key(key)?;
                    }
                    Ok(())
                })?;
                self.keys.clear();
            }
            if self.keys.is_empty() {
                let status = unsafe { FwpmEngineClose0(self.engine) };
                if status == 0 {
                    self.engine = null_mut();
                } else if first_error.is_none() {
                    first_error = Some(wfp_error("FwpmEngineClose0", status));
                }
            }
        }
        if self.engine.is_null() && !self.mutex.is_null() {
            let closed = unsafe { CloseHandle(self.mutex) };
            if closed != 0 {
                self.mutex = null_mut();
            } else if first_error.is_none() {
                first_error = Some(wfp_error("CloseHandle(WFP mutex)", unsafe {
                    GetLastError()
                }));
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    pub fn clear_stale() -> Result<()> {
        let mutex = acquire_wfp_mutex()?;
        let mut engine = null_mut();
        let status =
            unsafe { FwpmEngineOpen0(null(), WFP_AUTHN_SERVICE, null(), null(), &mut engine) };
        if status != 0 || engine.is_null() {
            unsafe {
                CloseHandle(mutex);
            }
            return Err(wfp_error("FwpmEngineOpen0", status));
        }
        let mut guard = Self {
            engine,
            mutex,
            keys: Vec::new(),
        };
        guard.with_transaction(|guard| guard.remove_stale_filters())?;
        guard.cleanup()
    }

    fn remove_stale_filters(&self) -> Result<()> {
        let mut keys = vec![
            filter_key("block-v4", 0),
            filter_key("block-v6", 0),
            filter_key("loopback-v4", 0),
            filter_key("loopback-v6", 0),
            filter_key("interface-v4", 0),
            filter_key("interface-v6", 0),
        ];
        for index in 0..MAX_PEER_SLOTS {
            keys.push(filter_key("peer", index as u32));
        }
        let mut first_error = None;
        for key in keys.drain(..) {
            if let Err(error) = self.remove_key(&key) {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    fn remove_key(&self, key: &GUID) -> Result<()> {
        let status = unsafe { FwpmFilterDeleteByKey0(self.engine, key) };
        if status == 0 || is_filter_absent_status(status) {
            Ok(())
        } else {
            Err(wfp_error("FwpmFilterDeleteByKey0", status))
        }
    }

    fn add_loopback(&mut self, address: IpAddr, index: u32) -> Result<()> {
        match address {
            IpAddr::V4(address) => {
                let mut mask = FWP_V4_ADDR_AND_MASK {
                    addr: u32::from_be_bytes(address.octets()),
                    mask: u32::from_be_bytes([255, 0, 0, 0]),
                };
                let condition = FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    matchType: 0,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_V4_ADDR_MASK,
                        Anonymous: FWP_CONDITION_VALUE0_0 {
                            v4AddrMask: &mut mask,
                        },
                    },
                };
                self.add_filter(
                    filter_key("loopback-v4", index),
                    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                    vec![condition],
                    FWP_ACTION_PERMIT,
                    FILTER_WEIGHT_ALLOW,
                    "SHPH killswitch loopback",
                )
            }
            IpAddr::V6(address) => {
                let mut mask = FWP_V6_ADDR_AND_MASK {
                    addr: address.octets(),
                    prefixLength: 128,
                };
                let condition = FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    matchType: 0,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_V6_ADDR_MASK,
                        Anonymous: FWP_CONDITION_VALUE0_0 {
                            v6AddrMask: &mut mask,
                        },
                    },
                };
                self.add_filter(
                    filter_key("loopback-v6", index),
                    FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                    vec![condition],
                    FWP_ACTION_PERMIT,
                    FILTER_WEIGHT_ALLOW,
                    "SHPH killswitch loopback",
                )
            }
        }
    }

    fn with_transaction<T>(&mut self, operation: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let status = unsafe { FwpmTransactionBegin0(self.engine, 0) };
        if status != 0 {
            return Err(wfp_error("FwpmTransactionBegin0", status));
        }

        let original_keys = self.keys.clone();
        match operation(self) {
            Ok(value) => {
                let status = unsafe { FwpmTransactionCommit0(self.engine) };
                if status == 0 {
                    return Ok(value);
                }

                self.keys = original_keys;
                let abort_status = unsafe { FwpmTransactionAbort0(self.engine) };
                if abort_status == 0 {
                    Err(wfp_error("FwpmTransactionCommit0", status))
                } else {
                    Err(ShphError::PermissionDenied(format!(
                        "FwpmTransactionCommit0 failed with status 0x{status:08x}; abort failed with status 0x{abort_status:08x}; administrator elevation is required"
                    )))
                }
            }
            Err(error) => {
                self.keys = original_keys;
                let abort_status = unsafe { FwpmTransactionAbort0(self.engine) };
                if abort_status == 0 {
                    Err(error)
                } else {
                    Err(ShphError::PermissionDenied(format!(
                        "{error}; WFP transaction abort failed with status 0x{abort_status:08x}; administrator elevation is required"
                    )))
                }
            }
        }
    }

    fn add_peer(
        &mut self,
        index: usize,
        peer: SocketAddr,
        transport: FirewallTransport,
    ) -> Result<()> {
        match peer.ip() {
            IpAddr::V4(address) => {
                let mut mask = FWP_V4_ADDR_AND_MASK {
                    addr: u32::from_be_bytes(address.octets()),
                    mask: u32::MAX,
                };
                let address_condition = FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    matchType: 0,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_V4_ADDR_MASK,
                        Anonymous: FWP_CONDITION_VALUE0_0 {
                            v4AddrMask: &mut mask,
                        },
                    },
                };
                self.add_peer_filter(
                    index,
                    peer,
                    transport,
                    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                    address_condition,
                )
            }
            IpAddr::V6(address) => {
                let mut mask = FWP_V6_ADDR_AND_MASK {
                    addr: address.octets(),
                    prefixLength: 128,
                };
                let address_condition = FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    matchType: 0,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_V6_ADDR_MASK,
                        Anonymous: FWP_CONDITION_VALUE0_0 {
                            v6AddrMask: &mut mask,
                        },
                    },
                };
                self.add_peer_filter(
                    index,
                    peer,
                    transport,
                    FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                    address_condition,
                )
            }
        }
    }

    fn add_peer_filter(
        &mut self,
        index: usize,
        peer: SocketAddr,
        transport: FirewallTransport,
        layer: GUID,
        address_condition: FWPM_FILTER_CONDITION0,
    ) -> Result<()> {
        let conditions = vec![
            address_condition,
            FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_PROTOCOL,
                matchType: 0,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT8,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        uint8: transport.protocol_number(),
                    },
                },
            },
            FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
                matchType: 0,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        uint16: peer.port(),
                    },
                },
            },
        ];
        self.add_filter(
            filter_key("peer", index as u32),
            layer,
            conditions,
            FWP_ACTION_PERMIT,
            FILTER_WEIGHT_ALLOW,
            "SHPH killswitch peer allow",
        )
    }

    fn add_interface(&mut self, interface_luid: u64, layer: GUID, family: &str) -> Result<()> {
        let mut interface_luid = interface_luid;
        let condition = FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_LOCAL_INTERFACE,
            matchType: 0,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT64,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    uint64: &mut interface_luid,
                },
            },
        };
        self.add_filter(
            filter_key(&format!("interface-{family}"), 0),
            layer,
            vec![condition],
            FWP_ACTION_PERMIT,
            FILTER_WEIGHT_ALLOW,
            "SHPH killswitch TUN allow",
        )
    }

    fn add_filter(
        &mut self,
        key: GUID,
        layer: GUID,
        mut conditions: Vec<FWPM_FILTER_CONDITION0>,
        action_type: FWP_ACTION_TYPE,
        weight: u64,
        name: &str,
    ) -> Result<()> {
        let mut name_wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let mut weight = weight;
        let filter = FWPM_FILTER0 {
            filterKey: key,
            displayData: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_DISPLAY_DATA0 {
                name: name_wide.as_mut_ptr(),
                description: null_mut(),
            },
            flags: FWPM_FILTER_FLAG_PERSISTENT,
            layerKey: layer,
            subLayerKey: FWPM_SUBLAYER_UNIVERSAL,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT64,
                Anonymous: FWP_VALUE0_0 {
                    uint64: &mut weight,
                },
            },
            numFilterConditions: conditions.len() as u32,
            filterCondition: if conditions.is_empty() {
                null_mut()
            } else {
                conditions.as_mut_ptr()
            },
            action: FWPM_ACTION0 {
                r#type: action_type,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut filter_id = 0u64;
        let status = unsafe { FwpmFilterAdd0(self.engine, &filter, null_mut(), &mut filter_id) };
        if status != 0 {
            return Err(wfp_error(name, status));
        }
        self.keys.push(key);
        Ok(())
    }
}

impl Drop for WindowsKillswitchGuard {
    fn drop(&mut self) {
        let _ = self.cleanup();
        if !self.engine.is_null() {
            let _ = unsafe { FwpmEngineClose0(self.engine) };
            self.engine = null_mut();
        }
        if !self.mutex.is_null() {
            let _ = unsafe { CloseHandle(self.mutex) };
            self.mutex = null_mut();
        }
    }
}

fn acquire_wfp_mutex() -> Result<HANDLE> {
    let name: Vec<u16> = WFP_MUTEX_NAME.encode_utf16().chain(Some(0)).collect();
    let mutex = unsafe { CreateMutexW(null(), 0, name.as_ptr()) };
    if mutex.is_null() {
        return Err(wfp_error("CreateMutexW", unsafe { GetLastError() }));
    }
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        unsafe {
            CloseHandle(mutex);
        }
        return Err(ShphError::ResourceExhausted(
            "SHPH Windows killswitch is already active in another process".into(),
        ));
    }
    Ok(mutex)
}

pub fn interface_luid(interface_name: &str) -> Result<u64> {
    if interface_name.is_empty()
        || interface_name.contains('\0')
        || interface_name.chars().any(char::is_control)
    {
        return Err(ShphError::InvalidArgument(
            "Windows interface alias contains invalid characters".into(),
        ));
    }
    let mut wide: Vec<u16> = interface_name.encode_utf16().chain(Some(0)).collect();
    let mut luid = NET_LUID_LH::default();
    let status = unsafe { ConvertInterfaceAliasToLuid(wide.as_mut_ptr(), &mut luid) };
    if status != 0 {
        return Err(wfp_error("ConvertInterfaceAliasToLuid", status));
    }
    Ok(unsafe { luid.Value })
}

fn same_guid(left: &GUID, right: &GUID) -> bool {
    left.data1 == right.data1
        && left.data2 == right.data2
        && left.data3 == right.data3
        && left.data4 == right.data4
}

fn filter_key(kind: &str, index: u32) -> GUID {
    let mut hasher = Sha256::new();
    hasher.update(b"SHPH-WFP-FILTER-V1");
    hasher.update(kind.as_bytes());
    hasher.update(index.to_be_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    GUID::from_u128(u128::from_be_bytes(bytes))
}

fn wfp_error(operation: &str, status: u32) -> ShphError {
    ShphError::PermissionDenied(format!(
        "{operation} failed with Windows Filtering Platform status 0x{status:08x}; administrator elevation is required"
    ))
}

fn is_filter_absent_status(status: u32) -> bool {
    status as i32 == FWP_E_FILTER_NOT_FOUND
}

#[cfg(test)]
mod tests {
    use super::{
        interface_luid, is_filter_absent_status, FWP_E_FILTER_NOT_FOUND, RPC_C_AUTHN_WINNT,
        WFP_AUTHN_SERVICE,
    };

    #[test]
    fn interface_alias_rejects_nul_and_control_characters_before_ffi() {
        for alias in ["", "Ethernet\0suffix", "Ethernet\n"] {
            assert!(interface_luid(alias).is_err());
        }
    }

    #[test]
    fn engine_open_uses_supported_rpc_authentication() {
        assert_eq!(WFP_AUTHN_SERVICE, RPC_C_AUTHN_WINNT);
        assert_ne!(WFP_AUTHN_SERVICE, 0);
    }

    #[test]
    fn filter_cleanup_treats_missing_owned_filter_as_clean() {
        assert!(is_filter_absent_status(FWP_E_FILTER_NOT_FOUND as u32));
        assert!(!is_filter_absent_status(5));
    }
}
