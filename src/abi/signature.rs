use std::collections::HashMap;

use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use serde_json::Value;
use tracing::debug;

use crate::{
    abi::guesser::{abi_guess, GuessedAbi},
    config::{FN_SIGNATURE_URL, HARDHAT_CHEAT_ADDR},
    http::HTTPC,
};

lazy_static! {
    // map<fn_name, the idx of timestamp arg>
    pub static ref TIMESTAMP_SIG: HashMap<&'static str, usize> = HashMap::from_iter(vec![
        ("addLiquidity", 7),
        ("addLiquidityETH", 5),
        ("removeLiquidity", 6),
        ("removeLiquidityETH", 5),
        ("removeLiquidityWithPermit", 6),
        ("removeLiquidityETHWithPermit", 5),
        ("swapExactTokensForTokens", 4),
        ("swapTokensForExactTokens", 4),
        ("swapExactETHForTokens", 3),
        ("swapTokensForExactETH", 4),
        ("swapExactTokensForETH", 4),
        ("swapETHForExactTokens", 3),
        ("removeLiquidityETHSupportingFeeOnTransferTokens", 5),
        ("removeLiquidityETHWithPermitSupportingFeeOnTransferTokens", 5),
        ("swapExactTokensForTokensSupportingFeeOnTransferTokens", 4),
        ("swapExactETHForTokensSupportingFeeOnTransferTokens", 3),
        ("swapExactTokensForETHSupportingFeeOnTransferTokens", 4),
        ("selfPermit", 2),
        ("selfPermitIfNecessary", 2),
    ]);
}

pub fn get_fn_signature(input: &str, output: &str, target: &str) -> Result<(String, Option<String>)> {
    let ret_sig = guess_ret_signature(output);

    let selector = &input[..10];
    if let Ok(fn_sig) = get_fn_signature_by_selector(selector) {
        return Ok((fn_sig, ret_sig));
    }

    if target.to_lowercase() != HARDHAT_CHEAT_ADDR.to_lowercase() {
        if let Ok(fn_sig) = guess_fn_signature(input) {
            return Ok((fn_sig, ret_sig));
        }
    }

    Err(anyhow!("Function signature not found"))
}

fn get_fn_signature_by_selector(selector: &str) -> Result<String> {
    let url = format!("{}?function={}&filter=true", FN_SIGNATURE_URL, selector);
    debug!("Lookup fn signature from {}", url);

    let resp = HTTPC.get(&url).and_then(|r| Ok(r.json::<Value>()?));
    if resp.is_err() || !resp.as_ref().unwrap()["ok"].as_bool().unwrap_or_default() {
        return Err(anyhow!("Lookup fn signature failed"));
    }
    let resp = resp.unwrap();

    let found = resp["result"]["function"][selector].as_array();
    if found.is_none() {
        return Err(anyhow!("Signature not found"));
    }
    let sig = found
        .unwrap()
        .first()
        .and_then(|v| v["name"].as_str())
        .unwrap_or_default();
    if sig.is_empty() {
        return Err(anyhow!("Signature format error, found: {:?}", found));
    }

    Ok(sig.to_string())
}

fn guess_fn_signature(input: &str) -> Result<String> {
    match abi_guess(input)? {
        GuessedAbi::FnSig(sig) => Ok(sig),
        _ => Err(anyhow!("Function signature not found")),
    }
}

fn guess_ret_signature(output: &str) -> Option<String> {
    match abi_guess(output) {
        Ok(GuessedAbi::ParamSig(sig)) => Some(sig),
        _ => None,
    }
}
