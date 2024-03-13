use std::collections::HashMap;

use anyhow::Result;
use rand::seq::SliceRandom;
use serde::Deserialize;

pub const ETH_SCAN_API_URL: &str = "https://api.etherscan.io/api";
pub const BSC_SCAN_API_URL: &str = "https://api.bscscan.com/api";
pub const POLYGON_SCAN_API_URL: &str = "https://api.polygonscan.com/api";
pub const ARBITRUM_SCAN_API_URL: &str = "https://api.arbiscan.io/api";

pub const PHALCON_URL: &str = "https://explorer.phalcon.xyz/tx";
pub const FN_SIGNATURE_URL: &str = "https://api.openchain.xyz/signature-database/v1/lookup";

pub const CALL_STACK_MAX_DEPTH: usize = 30;
pub const HARDHAT_CHEAT_ADDR: &str = "0x000000000000000000636F6e736F6c652e6c6f67";

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Config {
    pub comm: Common,
    pub rpc: Rpc,
    pub scan: Scan,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Common {
    pub db_dir: String,
    pub cache_dir: String,
    pub output_dir: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Rpc {
    pub eth_rpc_url: String,
    pub bsc_rpc_url: String,
    pub polygon_rpc_url: String,
    pub arbitrum_rpc_url: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Scan {
    pub eth_scan_keys: Vec<String>,
    pub bsc_scan_keys: Vec<String>,
    pub polygon_scan_keys: Vec<String>,
    pub arbitrum_scan_keys: Vec<String>,
}

impl Config {
    pub fn new(cfg_path: &str) -> Result<Self> {
        let cfg_str = std::fs::read_to_string(cfg_path)?;
        let cfg: Config = toml::from_str(&cfg_str)?;
        Ok(cfg)
    }

    pub fn rpc_url(&self, chain: &str) -> &str {
        match chain.to_lowercase().as_str() {
            "bsc" => &self.rpc.bsc_rpc_url,
            "eth" => &self.rpc.eth_rpc_url,
            "polygon" => &self.rpc.polygon_rpc_url,
            "arbitrum" => &self.rpc.arbitrum_rpc_url,
            _ => panic!("Unsupported chain: {}", chain),
        }
    }

    pub fn rpc_urls(&self) -> HashMap<String, String> {
        [
            ("bsc", &self.rpc.bsc_rpc_url),
            ("eth", &self.rpc.eth_rpc_url),
            ("polygon", &self.rpc.polygon_rpc_url),
            ("arbitrum", &self.rpc.arbitrum_rpc_url),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
    }

    pub fn scan_key(&self, chain: &str) -> &str {
        let keys = match chain.to_lowercase().as_str() {
            "bsc" => &self.scan.bsc_scan_keys,
            "eth" => &self.scan.eth_scan_keys,
            "polygon" => &self.scan.polygon_scan_keys,
            "arbitrum" => &self.scan.arbitrum_scan_keys,
            _ => panic!("Unsupported chain: {}", chain),
        };

        keys.choose(&mut rand::thread_rng()).unwrap_or(&keys[0])
    }
}

pub fn get_scan_api_url(chain: &str) -> &'static str {
    match chain.to_lowercase().as_str() {
        "bsc" => BSC_SCAN_API_URL,
        "eth" => ETH_SCAN_API_URL,
        "polygon" => POLYGON_SCAN_API_URL,
        "arbitrum" => ARBITRUM_SCAN_API_URL,
        _ => panic!("Unsupported chain: {}", chain),
    }
}
