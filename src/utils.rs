use std::str::FromStr;

use alloy_primitives::{Address, U256};

pub fn hash_to_name(hash: &str) -> String {
    if !hash.starts_with("0x0000") {
        return hash[1..6].to_lowercase();
    }

    let len = hash.len();
    let trimmed = hash.trim_start_matches("0x").trim_start_matches('0');
    let trimmed = if trimmed.len() < 4 { &hash[len - 4..] } else { trimmed };

    format!("x{}", &trimmed[..4].to_lowercase())
}

pub fn checksum(address: &str) -> String {
    match Address::from_str(address) {
        Ok(addr) => addr.to_checksum(None),
        Err(_) => {
            tracing::error!("Invalid address: {}", address);
            address.to_string()
        }
    }
}

pub fn prettify_value(value: &str) -> String {
    let v = U256::from_str(value);
    if v.is_err() {
        return format!("uint256({value})");
    }
    let v = v.unwrap();

    if v > U256::from(10).pow(U256::from(15)) {
        let one_eth = U256::from(10).pow(U256::from(18));
        let integer = v / one_eth;
        let decimal: String = (v % one_eth).to_string().chars().take(4).collect();

        format!("\"{value} ({integer}.{decimal} ether)\"")
    } else {
        format!("uint256({value})")
    }
}

// used to generate `vm.createSelectFork`
pub fn get_vm_fork_rpc(chain: &str) -> String {
    let endpoint = match chain.to_lowercase().as_str() {
        "mainnet" => "https://rpc.ankr.com/eth",
        "eth" => "https://rpc.ankr.com/eth",
        "bsc" => "https://rpc.ankr.com/bsc",
        "polygon" => "https://rpc.ankr.com/polygon",
        "arbitrum" => "https://rpc.ankr.com/arbitrum",
        _ => panic!("Unsupported chain: {}", chain),
    };

    endpoint.to_string()
}

// Only used for generating foundry comment
pub fn get_sender_scan_url(chain: &str, sender: &str) -> String {
    let url = match chain.to_lowercase().as_str() {
        "bsc" => "https://bscscan.com",
        "eth" => "https://etherscan.io",
        "polygon" => "https://polygonscan.com",
        "arbitrum" => "https://arbiscan.io",
        _ => panic!("Unsupported chain: {}", chain),
    };

    format!("{}/address/{}", url, sender)
}
