//! Back Tester

use std::{
    collections::{HashMap, HashSet},
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time,
};

use anyhow::Result;
use clap::{command, Parser};
use girlfriend::{config::Config, logger, Girlfriend};
use lazy_static::lazy_static;
use regex::Regex;
use tracing::{error, info};

lazy_static! {
    static ref COLOR: Regex = Regex::new(r"\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]").unwrap();
}

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct CmdArgs {
    /// the config file path
    #[arg(short, long, default_value = "config/config.toml")]
    config: String,
    /// the back test txhashes file path
    #[arg(short, long, default_value = "assets/eth_tx.txt")]
    txhashes_path: String,
    /// the result dir
    #[arg(short, long, default_value = "eth_back_test")]
    result_dir: String,
}

fn main() {
    logger::init();
    let args = CmdArgs::parse();
    let cfg = Config::new(&args.config).expect("Failed to load config");

    // clean up
    let _ = fs::remove_dir_all("test");
    let _ = fs::remove_dir_all(&args.result_dir);

    let txhashes = fs::read_to_string(&args.txhashes_path).expect("Failed to read txhashes");
    let testcases = txhashes.lines().collect::<Vec<_>>();

    let mut test_result = TestResult::new();
    for txhash in testcases {
        let now = time::Instant::now();
        match Girlfriend::new(cfg.clone()).unwrap().gen(txhash.to_string()) {
            Ok((output_path, _)) => {
                info!(
                    "🎉 Foundry test file: {}, time elapsed: {:?}",
                    output_path,
                    now.elapsed()
                );
                let result = forge_test(&output_path, &args.result_dir).unwrap();
                test_result.insert(&result, txhash);
            }
            Err(e) => error!("Error: {}", e),
        }
    }

    let summary_path = Path::new(&args.result_dir).join("summary.txt");
    test_result.summary(summary_path);
}

fn forge_test(output_path: &str, result_dir: &str) -> Result<String> {
    let output_path = Path::new(output_path);
    let filename = output_path.file_stem().unwrap().to_str().unwrap();

    info!("forge test -vvvvv ...");
    let mut forge_cmd = Command::new("forge")
        .arg("test")
        .arg("--via-ir")
        .arg("-vvvvv")
        .stdout(Stdio::piped())
        .spawn()?;

    let mut result_dir = PathBuf::from(result_dir);
    let mut result = String::new();
    if let Some(ref mut forge_stdout) = forge_cmd.stdout {
        let mut buf = String::new();
        forge_stdout.read_to_string(&mut buf)?;
        let log = remove_color(&buf);
        result = get_test_result(&log);

        result_dir = result_dir.join(&result);
        // create result dir if not exists
        if !result_dir.exists() {
            fs::create_dir_all(&result_dir)?;
        }

        let html_path = result_dir.join(format!("{}.log", filename));
        let mut output_file = File::create(&html_path)?;
        output_file.write_all(log.as_bytes())?;
        info!("🎉 Foundry test result: {}", html_path.to_str().unwrap());
    }

    forge_cmd.wait()?;

    // move `test/*` to result_dir
    info!("mv {:?} {}", output_path, result_dir.to_str().unwrap());
    Command::new("mv").arg(output_path).arg(result_dir).output()?;

    Ok(result)
}

fn get_test_result(log: &str) -> String {
    let pass = "[PASS] test";
    let fail_start = "[FAIL. Reason: ";
    let fail_end = "] test";

    if log.contains(pass) {
        "success".to_string()
    } else if let Some(reason) = extract_text(log, fail_start, fail_end) {
        reason
    } else {
        "unknown".to_string()
    }
}

fn extract_text(log: &str, start: &str, end: &str) -> Option<String> {
    let start_index = log.find(start)? + start.len();
    let end_index = log.find(end)?;
    let reason = log[start_index..end_index].trim().replace(':', "").replace(' ', "_");
    Some(reason)
}

#[derive(Debug)]
struct TestResult {
    // key: result, value: txhashes
    inner: HashMap<String, HashSet<String>>,
}

impl TestResult {
    pub fn new() -> Self {
        Self { inner: HashMap::new() }
    }

    pub fn insert(&mut self, res_type: &str, txhash: &str) {
        let value = txhash.to_string();
        self.inner.entry(res_type.to_string()).or_default().insert(value);
    }

    pub fn summary(&self, path: impl AsRef<Path>) {
        let mut summary = String::new();
        summary.push_str("=============== Summary ===============\n");
        summary.push_str(&format!("[total] {}\n\n", self.inner.values().flatten().count()));
        for (result, txhashes) in &self.inner {
            summary.push_str(&format!("[{}] {}\n", result, txhashes.len()));
            summary.push_str(&format!(
                "{}\n\n",
                txhashes.iter().cloned().collect::<Vec<_>>().join("\n")
            ));
        }

        let mut output_file = File::create(path).unwrap();
        output_file.write_all(summary.as_bytes()).unwrap();
    }
}

fn remove_color(input: &str) -> String {
    COLOR.replace_all(input, "").to_string()
}
