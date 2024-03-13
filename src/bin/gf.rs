use std::time;

use clap::{command, Parser};
use girlfriend::{config::Config, logger, Girlfriend};
use tracing::{error, info};

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// the config file path
    #[arg(short, long, default_value = "config/config.toml")]
    config: String,
    /// the txhash
    #[arg(short, long)]
    txhash: String,
}

fn main() {
    logger::init();
    let args = Args::parse();
    let cfg = Config::new(&args.config).expect("Failed to load config");
    let mut gf = Girlfriend::new(cfg).expect("Failed to create girlfriend");

    let now = time::Instant::now();
    match gf.gen(args.txhash) {
        Ok((output_path, contract_name)) => {
            info!(
                "🎉 Done ({:?})! Output: {}, Contract: {}",
                now.elapsed(),
                output_path,
                contract_name
            )
        }
        Err(e) => error!("Error: {}", e),
    }
}
