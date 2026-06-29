//! Keystore for identity and contact management.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use crate::crypto::IdentityKeyPair;
use crate::error::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub alias: String,
    pub endpoint: crate::net::Endpoint,
    pub pubkey_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KeyStoreConfig {
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredKeyStore {
    identity_private_b64: String,
    identity_public_b64: String,
    contacts: HashMap<String, Contact>,
    config: KeyStoreConfig,
}

#[derive(Clone)]
pub struct KeyStore {
    pub identity: IdentityKeyPair,
    pub contacts: HashMap<String, Contact>,
    pub config: KeyStoreConfig,
}

impl KeyStore {
    pub fn new(config: KeyStoreConfig) -> Result<Self> {
        Ok(Self {
            identity: IdentityKeyPair::generate()?,
            contacts: HashMap::new(),
            config,
        })
    }

    pub fn fingerprint_hex(&self) -> String {
        self.identity.fingerprint_hex()
    }

    pub fn public_key_b64(&self) -> String {
        self.identity.public_key_b64()
    }

    pub fn add_contact(&mut self, contact: Contact) {
        self.contacts.insert(contact.alias.clone(), contact);
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let stored = StoredKeyStore {
            identity_private_b64: self.identity.private_key_b64(),
            identity_public_b64: self.identity.public_key_b64(),
            contacts: self.contacts.clone(),
            config: self.config.clone(),
        };
        let data = serde_json::to_string_pretty(&stored)?;
        let mut file = File::create(path)?;
        file.write_all(data.as_bytes())?;
        Ok(())
    }

    pub fn load(path: &Path, password: Option<&str>) -> Result<Self> {
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let stored: StoredKeyStore = serde_json::from_str(&contents)?;
        let mut config = stored.config;
        if config.password.is_none() {
            config.password = password.map(ToOwned::to_owned);
        }
        let identity = IdentityKeyPair::from_base64(
            &stored.identity_private_b64,
            Some(&stored.identity_public_b64),
        )?;
        Ok(Self {
            identity,
            contacts: stored.contacts,
            config,
        })
    }
}

pub fn compute_fingerprint_hex(public_key_raw: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"shph-fingerprint-v1");
    hasher.update(public_key_raw);
    hex::encode(hasher.finalize())
}
