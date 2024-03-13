use std::{fs, path::Path};

use alloy_primitives::U256;
use anyhow::{anyhow, Result};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::debug;

use crate::{
    config::{get_scan_api_url, Config},
    contract::VmState,
    http::HTTPC,
    utils::{self, *},
};

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct ConciseTx {
    pub chain: String,
    pub tx_hash: String,
    pub sender: String,
    pub block_number: U256,
    pub timestamp: U256,

    #[serde(skip)]
    cfg: Config,
    #[serde(skip)]
    txhash_dir: String,
    #[serde(skip)]
    trace_dir: String,
}

impl ConciseTx {
    pub fn new(cfg: Config) -> Result<Self> {
        let tx = Self {
            txhash_dir: format!("{}/txhash", cfg.comm.cache_dir),
            trace_dir: format!("{}/trace", cfg.comm.cache_dir),
            cfg,
            ..Default::default()
        };
        if !Path::new(&tx.txhash_dir).exists() {
            fs::create_dir_all(&tx.txhash_dir)?;
        }
        if !Path::new(&tx.trace_dir).exists() {
            fs::create_dir_all(&tx.trace_dir)?;
        }

        Ok(tx)
    }

    pub fn prev_block_number(&self) -> String {
        (self.block_number - U256::from(1)).to_string()
    }

    pub fn timestamp(&self) -> String {
        self.timestamp.to_string()
    }

    pub fn three_hours_ago(&self) -> String {
        // 3h = 20*60*3 = 3600
        (self.block_number - U256::from(3600)).to_string()
    }

    pub fn get_tx_history(&mut self, txhash: &str) -> Result<Vec<ConciseTx>> {
        let filepath = format!("{}/{}.json", self.txhash_dir, txhash);
        if Path::new(&filepath).exists() {
            debug!("Load txhash history from {}", filepath);
            let content = fs::read_to_string(filepath)?;
            let txs: Vec<ConciseTx> = serde_json::from_str(&content)?;
            self.load_from_cache(txs.last());
            return Ok(txs);
        }

        self.update_tx_info(txhash)?;
        let scan_url = get_scan_api_url(&self.chain);
        let scan_key = self.cfg.scan_key(&self.chain);
        let start_block = self.three_hours_ago();

        let url = format!(
            "{}?module=account&action=txlist&address={}&startblock={}&endblock={}&page=1&offset=100&sort=desc&apikey={}",
            scan_url, self.sender, start_block, self.block_number, scan_key
        );
        debug!("Get tx history from {}", url);
        let mut resp: Value = HTTPC.get(&url)?.json()?;
        let res = resp["result"].take();
        if res.is_null() {
            return Err(anyhow!("Tx history not found"));
        }
        let mut txs = serde_json::from_value::<Vec<ScanTx>>(res)?
            .into_iter()
            .filter(|tx| tx.is_interesting(&self.sender))
            .map(|tx| tx.into_concise_tx(&self.chain))
            .collect::<Vec<_>>();

        let idx = txs.iter().position(|x| x.tx_hash == txhash).unwrap_or_default();
        txs = txs.into_iter().skip(idx).take(10).collect::<Vec<_>>();
        txs.reverse();

        // save to cache
        fs::write(filepath, serde_json::to_string(&txs)?)?;

        Ok(txs)
    }

    pub fn get_tx_trace(&self, txhash: &str) -> Result<Value> {
        let filepath = format!("{}/{}.json", self.trace_dir, txhash);
        if Path::new(&filepath).exists() {
            debug!("Load trace from {}", filepath);
            let content = fs::read_to_string(filepath)?;
            let json: Value = serde_json::from_str(&content)?;

            return Ok(json);
        }

        let url = self.cfg.rpc_url(&self.chain);
        debug!("Get trace from {}", url);
        let body = json!(
            {
                "jsonrpc": "2.0",
                "method": "debug_traceTransaction",
                "params": [txhash, {"tracer": "callTracer"}],
                "id": 1
            }
        );
        let mut resp: Value = HTTPC.post(url, body.to_string())?.json()?;
        let trace = resp["result"].take();
        if trace.is_null() {
            return Err(anyhow!("Trace not found"));
        }

        // save to cache
        fs::write(filepath, trace.to_string())?;

        Ok(trace)
    }

    pub fn generate_vm_state(&self) -> VmState {
        VmState {
            forked_rpc: utils::get_vm_fork_rpc(&self.chain),
            tx_hash: self.tx_hash.clone(),
            block_number: self.prev_block_number(),
            block_timestamp: self.timestamp(),
        }
    }

    fn update_tx_info(&mut self, txhash: &str) -> Result<()> {
        let tx = self
            .cfg
            .rpc_urls()
            .into_par_iter()
            .map(|(chain, url)| self.try_update_tx_info(chain, &url, txhash))
            .find_first(|res| res.is_ok())
            .unwrap_or(Err(anyhow!("Get tx failed")))?;

        self.chain = tx.chain;
        self.block_number = tx.block_number;
        self.sender = tx.sender;

        Ok(())
    }

    fn try_update_tx_info(&self, chain: String, url: &str, txhash: &str) -> Result<ConciseTx> {
        debug!("Get tx from {}", url);
        let body = json!(
            {
                "jsonrpc": "2.0",
                "method": "eth_getTransactionByHash",
                "params": [txhash],
                "id": 1
            }
        );
        let mut resp: Value = HTTPC.post(url, body.to_string())?.json()?;
        let res = resp["result"].take();
        if res.is_null() {
            return Err(anyhow!("Tx not found"));
        }

        let sender = checksum(res["from"].as_str().unwrap_or_default());
        let b = res["blockNumber"].as_str().unwrap_or_default();
        let block_number = string_to_u256(b)?;
        let tx = ConciseTx {
            chain,
            sender,
            block_number,
            ..Default::default()
        };

        Ok(tx)
    }

    fn load_from_cache(&mut self, tx: Option<&ConciseTx>) {
        if let Some(tx) = tx {
            self.chain = tx.chain.clone();
            self.tx_hash = tx.tx_hash.clone();
            self.sender = tx.sender.clone();
            self.block_number = tx.block_number;
            self.timestamp = tx.timestamp;
        }
    }
}

fn string_to_u256(s: &str) -> Result<U256> {
    if s.starts_with("0x") {
        Ok(U256::from_str_radix(s.trim_start_matches("0x"), 16)?)
    } else {
        Ok(U256::from_str_radix(s, 10)?)
    }
}

// Tx from scan
#[derive(Debug, Deserialize)]
struct ScanTx {
    #[serde(rename = "blockNumber")]
    block_number: String,
    #[serde(rename = "timeStamp")]
    timestamp: String,
    #[serde(rename = "hash")]
    tx_hash: String,
    #[serde(rename = "from")]
    sender: String,
    #[serde(rename = "txreceipt_status")]
    status: String,
}

impl ScanTx {
    fn is_interesting(&self, sender: &str) -> bool {
        self.sender.to_lowercase() == sender.to_lowercase() && self.status == "1"
    }

    fn into_concise_tx(self, chain: &str) -> ConciseTx {
        let mut tx = ConciseTx::from(self);
        tx.chain = chain.to_string();
        tx
    }
}

impl From<ScanTx> for ConciseTx {
    fn from(tx: ScanTx) -> Self {
        let block_number = string_to_u256(&tx.block_number).unwrap_or_default();
        let timestamp = string_to_u256(&tx.timestamp).unwrap_or_default();
        Self {
            tx_hash: tx.tx_hash,
            sender: tx.sender,
            block_number,
            timestamp,
            ..Default::default()
        }
    }
}
