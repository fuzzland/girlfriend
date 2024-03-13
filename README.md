# girlfriend


**G**irl **F**riend <- **G F** <- **G**enerate **F**oundry Fork Test from Attack Transaction

She is truly a great friend.

## Prerequisites

```sh
# Install abi-guesser
git clone git@github.com:fuzzland/abi-guesser-cli.git
cd abi-guesser-cli
npm i -g

# Init submodules
git submodule update --recursive --init
```

## Getting Started

### Config

Before running the commands, you need to rename [config/config.example.toml](config/config.example.toml) to config.toml.
And modify it as follows:

- The RPC URLs should support the debug API (e.g. debug_traceTransaction).
- Add your scan keys. You can get them as follows (take ETH as an example, other chains are similar):
  1. Register an account on [Etherscan](https://etherscan.io/).
  2. [Create API keys](https://docs.etherscan.io/getting-started/viewing-api-usage-statistics).

### Generate A Foundry Test PoC

`gf` is used to generate a Foundry test PoC using a given txhash.

```log
Usage: gf [OPTIONS] --txhash <TXHASH>

Options:
  -c, --config <CONFIG>  the config file path [default: config/config.toml]
  -t, --txhash <TXHASH>  the txhash
  -h, --help             Print help
  -V, --version          Print version
```

- Example

```sh
# The output_dir is configured in the config file [default: ./test]
cargo run --bin gf -- -t 0xeaef2831d4d6bca04e4e9035613be637ae3b0034977673c1c2f10903926f29c0

# If the output_dir is `./test`, you can run it directly
forge test -vvvvv
```

### Backtest

`bt` is used to perform a backtest with a given txhashes file.

```log
Usage: bt [OPTIONS]

Options:
  -c, --config <CONFIG>                the config file path [default: config/config.toml]
  -t, --txhashes-path <TXHASHES_PATH>  the back test txhashes file path [default: assets/eth_tx.txt]
  -r, --result-dir <RESULT_DIR>        the result dir [default: eth_back_test]
  -h, --help                           Print help
  -V, --version                        Print version
```

- Example

```sh
# ETH backtest
cargo run --bin bt
# BSC backtest
cargo run --bin bt -- -t assets/bsc_tx.txt -r bsc_back_test
```

## Progress

We collected 74 historical attacks on ETH and 117 on BSC for backtesting. The commands executed are as mentioned [above](#backtest). The results are as follows:

| Chain | Total | Success | Success Rate |
| ----- | ----- | ------- | ------------ |
| ETH   | 74    | 24      | 32.43%       |
| BSC   | 117   | 46      | 39.32%       |
