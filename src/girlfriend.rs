use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs::{self, File},
    mem,
    path::Path,
    process::Command,
    vec,
};

use alloy_primitives::{hex, U256};
use anyhow::{anyhow, Result};
use handlebars::{handlebars_helper, Handlebars};
use serde::Serialize;
use serde_json::Value;
use tracing::{debug, info};

use crate::{
    abi::{
        signature::get_fn_signature,
        types::{DecodedArg, MemoryVar, StructDef},
        Abi,
    },
    call::Call,
    config::*,
    contract::{Contract, ParsedCall, ParsedCallType, ReturnData, SubContract, UnresolvedFn},
    kv::KV,
    tx::ConciseTx,
    utils::*,
};

const TEMPLATE: &str = include_str!("../assets/template.hbs");
const FN_SIGNATURES: &str = include_str!("../assets/fn_signatures.json");

// A template helper to add two numbers.
handlebars_helper!(add: |x: usize, y: usize| x + y);

#[derive(Debug)]
pub struct Girlfriend {
    // Output directory to store the foundry test files.
    output_dir: String,
    // A KV database to store the data from remote (fn signatures).
    db: KV,
    // ABI decoder.
    abi: Abi,
    // Nonce to generate salt for `CREATE2`.
    nonce: usize,
    // The attack tx
    tx: ConciseTx,
}

#[derive(Debug, Serialize, Default)]
struct TemplateArgs {
    file_name: String,
    receiver_name: String,
    last_txhash: String,
    chain_name: String,
    sender: String,
    sender_scan_url: String,
    // map<struct_signature, struct_def>
    struct_defs: HashMap<String, StructDef>,
    interface: HashSet<String>,
    contracts: Vec<Contract>,
}

#[derive(Debug)]
struct ParsedInput {
    fn_signature: String,
    ret_signature: String,
    fn_name: String,
    args: Vec<DecodedArg>,
}

impl Girlfriend {
    pub fn new(cfg: Config) -> Result<Self> {
        let db = KV::new(&cfg.comm.db_dir);
        let output_dir = String::from(&cfg.comm.output_dir);
        let tx = ConciseTx::new(cfg)?;
        db.load_fn_signatures(FN_SIGNATURES);

        Ok(Self {
            output_dir,
            db,
            abi: Abi::new(),
            nonce: 0,
            tx,
        })
    }

    /// Generate the foundry test file by the given txhash.
    /// Return (output_path, contract_name)
    pub fn gen(&mut self, txhash: String) -> Result<(String, String)> {
        info!("🔥 Start generating: {:?}", txhash);
        // create directories if not exists
        if !Path::new(&self.output_dir).exists() {
            fs::create_dir_all(&self.output_dir)?;
        }

        // get txhash history
        let txs = self.tx.get_tx_history(&txhash)?;

        // get tx traces
        let traces = txs
            .iter()
            .map(|tx| self.tx.get_tx_trace(&tx.tx_hash))
            .collect::<Result<Vec<_>>>()?;

        let args = self.make_template_args(&txs, &traces)?;
        let res = self.render_test_file(&args)?;

        let _ = Command::new("forge").arg("fmt").output();
        Ok(res)
    }

    fn parse_calls(
        &mut self,
        call: &Call,
        sender: &str,
        parent_call: &mut ParsedCall,
        contracts: &mut HashMap<String, Contract>,
        parsed_calls: &mut Vec<ParsedCall>,
    ) -> Vec<ParsedCall> {
        let contract_addrs = contracts.keys().cloned().collect::<Vec<_>>();
        // map<return_value, return_var>, clear return_vars every `CALL_STACK_MAX_DEPTH`
        // calls to avoid `stack too deep`.
        let (mut return_vars, mut return_vars_clear_idx) = (HashMap::new(), CALL_STACK_MAX_DEPTH);
        let mut has_parentheses = false;
        // there might be same return values in different calls, so the var_nonce is not
        // the same as return_vars.len()
        let mut var_nonce = 1;

        // parsed_sub_calls are pushed back, and parsed_calls are pushed front
        // so that the all_parsed are in the same order as the calls in trace
        let mut all_parsed = VecDeque::new();

        for (idx, c) in call.sub_calls.iter().enumerate() {
            if idx == return_vars_clear_idx {
                return_vars.clear();
                return_vars_clear_idx += CALL_STACK_MAX_DEPTH;
                if !has_parentheses {
                    has_parentheses = true;
                    parsed_calls.push(ParsedCall::left_parenthesis());
                } else {
                    parsed_calls.push(ParsedCall::right_parenthesis());
                    parsed_calls.push(ParsedCall::left_parenthesis());
                }
            }

            let target = c.target.clone();
            let target_is_contract = contract_addrs.contains(&target);
            let receiver = contracts.get(&c.caller).map(|c| c.addr.clone()).unwrap_or_default();

            let mut parsed_call = self.parse_call(c, sender, &receiver, target_is_contract, &return_vars);
            if parsed_call.sol_ty == "staticcall" && !parsed_call.ret_signature.is_empty() {
                // handle staticcall returns
                if let Ok(()) = parsed_call.add_returns(&c.output, var_nonce) {
                    var_nonce += parsed_call.return_data.len();
                    return_vars.extend(parsed_call.return_vars.clone());
                }
            } else if [ParsedCallType::Create, ParsedCallType::Create2].contains(&parsed_call.ty) {
                // handle inner create
                if !contracts.contains_key(&target) {
                    let contract = Contract::new(target.clone(), false, true, parsed_call.salt.clone());
                    contracts.insert(target.clone(), contract);
                }
            }

            parsed_calls.push(parsed_call.clone());

            // console2 accepts at most 4 arguments, including the first one `string`.
            #[cfg(debug_assertions)]
            if !parsed_call.return_data.is_empty() && parsed_call.return_data.len() < 4 {
                if let Some(log) = parsed_call.new_log() {
                    parsed_calls.push(log);
                }
            }

            // parse sub calls
            let mut parsed_sub_calls = vec![];
            let all_subs = self.parse_calls(c, sender, &mut parsed_call, contracts, &mut parsed_sub_calls);
            all_parsed.extend(all_subs);
        }
        if has_parentheses {
            parsed_calls.push(ParsedCall::right_parenthesis());
        }

        parent_call.sub_calls = mem::take(parsed_calls);
        all_parsed.push_front(parent_call.clone());
        all_parsed.into()
    }

    fn organize_parsed_calls(
        &self,
        parsed_calls: Vec<ParsedCall>,
        sender: &str,
        contracts: &mut HashMap<String, Contract>,
        struct_defs: &mut HashMap<String, StructDef>,
    ) {
        for parsed_call in parsed_calls {
            let mut named_addresses = HashMap::new();
            for sub_call in &parsed_call.sub_calls {
                if sub_call.ty == ParsedCallType::Parentheses {
                    continue;
                }

                // handle unresolved functions
                if [ParsedCallType::Raw, ParsedCallType::WithSelector].contains(&sub_call.ty) {
                    self.push_fallback(sub_call.clone(), contracts);
                }

                struct_defs.extend(sub_call.struct_defs.clone());
                let target = sub_call.target.clone();
                named_addresses.insert(hash_to_name(&target), target.clone());
                named_addresses.extend(sub_call.named_addresses.clone());
            }

            if let Some(contract) = contracts.get_mut(&parsed_call.target) {
                // build_function will parse the output and may generate named_addresses and
                // struct_defs
                contract.build_function(parsed_call, struct_defs);
                contract.named_addresses.extend(named_addresses);
                contract.named_addresses.remove(&hash_to_name(sender));
            }
        }
    }

    fn push_fallback(&self, parsed_call: ParsedCall, contracts: &mut HashMap<String, Contract>) {
        if let Some(contract) = contracts.get_mut(&parsed_call.target) {
            let fn_selector = parsed_call.raw_input[..10].to_string();
            let fn_signature = parsed_call.fn_signature.clone();
            contract
                .fallback
                .entry(fn_signature.clone())
                .or_insert(UnresolvedFn::new(fn_selector, fn_signature));
        }
    }

    fn parse_call(
        &mut self,
        call: &Call,
        sender: &str,
        receiver: &str,
        target_is_contract: bool,
        // map<return_value, ReturnData>
        return_vars: &HashMap<String, ReturnData>,
    ) -> ParsedCall {
        let parsed_input = self.parse_input(call);
        let parsed_call_type = get_parsed_call_type(call, &parsed_input, target_is_contract);

        // contract variable name
        let mut contract_var = call.target_var.clone();
        if receiver == call.target {
            contract_var = "r".to_string();
        } else if sender == call.target {
            contract_var = "address(tx.origin)".to_string();
        }

        // sender and receiver variable names
        let sender_var = hash_to_name(sender);
        let receiver_var = if receiver.is_empty() {
            "".to_string()
        } else {
            hash_to_name(receiver)
        };

        let ret_signature = parsed_input
            .as_ref()
            .map(|i| i.ret_signature.clone())
            .unwrap_or_default();

        let mut named_addresses = HashMap::new();
        let (fn_sig, fn_call) = match parsed_call_type {
            ParsedCallType::Create | ParsedCallType::Create2 => call_inner_create(call, &contract_var),
            ParsedCallType::SelfDestruct => call_selfdestruct(&contract_var),
            ParsedCallType::WithSelector => call_with_selector(
                call,
                &contract_var,
                &sender_var,
                &receiver_var,
                return_vars,
                &mut named_addresses,
            ),
            _ => {
                if let Ok(input) = parsed_input {
                    let fn_sig = format_fn_sig(&input.fn_signature, &parsed_call_type);
                    let fn_args =
                        format_fn_args(&input.args, &sender_var, &receiver_var, return_vars, &parsed_call_type);
                    let fn_call = format_fn_call(
                        call,
                        &input,
                        &parsed_call_type,
                        target_is_contract,
                        &contract_var,
                        &fn_args,
                    );
                    (fn_sig, fn_call)
                } else if parsed_call_type == ParsedCallType::HardhatCheat {
                    generate_hardhat_comment(call, &sender_var, &receiver_var, return_vars)
                } else {
                    call_with_rawdata(call, &contract_var)
                }
            }
        };
        named_addresses.extend(self.abi.take_addresses());

        let salt = if parsed_call_type == ParsedCallType::Create2 {
            Some(self.generate_salt())
        } else {
            None
        };

        ParsedCall {
            ty: parsed_call_type,
            sol_ty: call.ty.clone(),
            caller: call.caller.clone(),
            target: call.target.clone(),
            fn_signature: fn_sig,
            ret_signature,
            fn_call,
            raw_input: call.input.to_string(),
            raw_output: call.output.to_string(),
            value: call.value,
            target_is_contract,
            memory_vars: self.take_memory_vars(&sender_var, &receiver_var),
            named_addresses,
            struct_defs: self.abi.take_struct_defs(),
            salt,
            ..Default::default()
        }
    }

    // mock a function named `txhash[1..0]()` in the receiver contract.
    // the calls in trace will be parsed into this function.
    fn parse_pre_call(&mut self, tx: &ConciseTx, receiver: &str) -> ParsedCall {
        let fn_sig = format!("{}()", &tx.tx_hash[1..10]);
        let phalcon_link = format!("// {}/{}/{}", PHALCON_URL, tx.chain, tx.tx_hash);

        ParsedCall {
            ty: ParsedCallType::Interface,
            sol_ty: "call".to_string(),
            caller: tx.sender.to_string(),
            target: receiver.to_string(),
            fn_call: format!("{};", fn_sig),
            fn_signature: fn_sig,
            target_is_contract: true,
            comment: Some(phalcon_link),
            vm_state: Some(tx.generate_vm_state()),

            ..Default::default()
        }
    }

    // Root call is always an internal interface call.
    fn parse_root_call(&mut self, tx: &ConciseTx, call: &Call) -> ParsedCall {
        if ["create", "create2"].contains(&call.ty.as_str()) {
            return self.parse_pre_call(tx, &call.target);
        }

        let parsed_input = self.parse_input(call);
        let sender_var = hash_to_name(&call.caller);
        let ty = ParsedCallType::Interface;

        let ret_signature = parsed_input
            .as_ref()
            .map(|i| i.ret_signature.clone())
            .unwrap_or_default();

        let (fn_signature, fn_name, args) = match parsed_input {
            Ok(input) => {
                let return_vars = HashMap::new();
                let fn_args = format_fn_args(&input.args, &sender_var, &call.target_var, &return_vars, &ty);

                (input.fn_signature, input.fn_name, fn_args)
            }
            Err(_) => {
                let fn_signature = format!("{}()", &call.input[1..10]);
                let fn_name = call.input[1..10].to_string();
                let args = "".to_string();
                (fn_signature, fn_name, args)
            }
        };

        let fn_call = if call.value != U256::ZERO {
            format!("this.{}{{value: {}}}({});", fn_name, call.value, args)
        } else {
            format!("{}({});", fn_name, args)
        };

        let phalcon_link = format!("// {}/{}/{}", PHALCON_URL, tx.chain, tx.tx_hash);
        ParsedCall {
            ty,
            sol_ty: call.ty.clone(),
            caller: call.caller.clone(),
            target: call.target.clone(),
            fn_signature,
            ret_signature,
            fn_call,
            target_is_contract: true,
            raw_input: call.input.clone(),
            raw_output: call.output.clone(),
            value: call.value,
            memory_vars: self.take_memory_vars(&sender_var, &call.target_var),
            named_addresses: self.abi.take_addresses(),
            struct_defs: self.abi.take_struct_defs(),
            comment: Some(phalcon_link),
            vm_state: Some(tx.generate_vm_state()),
            ..Default::default()
        }
    }

    fn initialize_contracts(&mut self, receiver: &str) -> HashMap<String, Contract> {
        let recv_contract = Contract::new(receiver.to_string(), true, false, None);
        let mut contracts = HashMap::new();
        contracts.insert(recv_contract.addr.clone(), recv_contract);
        contracts
    }

    fn parse_input(&mut self, call: &Call) -> Result<ParsedInput> {
        if call.input.len() < 10 {
            return Err(anyhow!("Ignore: {}", call.input));
        }

        let selector = &call.input[..10];

        let (fn_sig, ret_sig) = match self.db.get_fn_signature(selector) {
            Some((fn_sig, ret_sig)) => {
                if fn_sig.is_empty() {
                    return Err(anyhow!("Signature not found"));
                } else {
                    debug!("Get fn signature from local: {}; ret_sig: {}", fn_sig, ret_sig);
                    (fn_sig, ret_sig)
                }
            }
            None => {
                if let Ok((fn_sig, ret_sig)) = get_fn_signature(&call.input, &call.output, &call.target) {
                    self.db.set_fn_signature(selector, &fn_sig, ret_sig.clone());
                    (fn_sig, ret_sig.unwrap_or_default())
                } else {
                    self.db.set_fn_signature(selector, "", None);
                    return Err(anyhow!("Signature not found"));
                }
            }
        };

        let fn_name = fn_sig.split('(').next().unwrap_or(selector).to_string();
        let args = self.abi.decode_input(&fn_sig, &call.input)?;

        Ok(ParsedInput {
            fn_signature: fn_sig,
            ret_signature: ret_sig,
            fn_name,
            args,
        })
    }

    fn make_template_args(&mut self, txs: &[ConciseTx], traces: &[Value]) -> Result<TemplateArgs> {
        let chain = self.tx.chain.clone();

        let last_tx = txs.last().unwrap();
        let mut pre_calls = traces.iter().map(Call::from).collect::<Vec<_>>();
        let root_call = pre_calls.pop().unwrap();
        let sender = root_call.caller.clone();
        let receiver = root_call.target.clone();
        let file_name = format!("{}.t.sol", hash_to_name(&last_tx.tx_hash));

        let mut contract_map = self.initialize_contracts(&receiver);
        let mut struct_defs = HashMap::new();

        let mut parsed_root_calls = vec![];
        // parse pre_calls
        for (idx, c) in pre_calls.iter().enumerate() {
            let mut pc = self.parse_pre_call(&txs[idx], &receiver);
            struct_defs.extend(pc.struct_defs.clone());
            parsed_root_calls.push(pc.clone());
            let root_call = Call::mock_parent(&sender, &receiver, c);
            let parsed_calls = self.parse_calls(&root_call, &sender, &mut pc, &mut contract_map, &mut vec![]);
            self.organize_parsed_calls(parsed_calls, &sender, &mut contract_map, &mut struct_defs);
        }

        // parse root_call
        let mut pc = self.parse_root_call(last_tx, &root_call);
        struct_defs.extend(pc.struct_defs.clone());
        parsed_root_calls.push(pc.clone());
        let root_call = if ["create", "create2"].contains(&root_call.ty.as_str()) {
            Call::mock_parent(&sender, &receiver, &root_call)
        } else {
            root_call
        };
        let parsed_calls = self.parse_calls(&root_call, &sender, &mut pc, &mut contract_map, &mut vec![]);
        self.organize_parsed_calls(parsed_calls, &sender, &mut contract_map, &mut struct_defs);

        build_sub_contracts(&mut contract_map);
        // build constructor args for sub contracts
        let mut sub_contracts = contract_map
            .values()
            .map(|c| (c.name.to_lowercase(), c.sub_contracts.clone()))
            .collect::<HashMap<_, _>>();
        for c in contract_map.values_mut() {
            c.build_sub_contracts_constructor_args(&mut sub_contracts);
        }

        // Generate contracts
        let root_fn_sigs = parsed_root_calls
            .iter()
            .map(|prc| prc.fn_signature.as_str())
            .collect::<Vec<_>>();
        let mut interface = HashSet::new();
        for c in contract_map.values_mut() {
            c.generate(
                &sub_contracts,
                &last_tx.tx_hash,
                &root_fn_sigs,
                &mut interface,
                &struct_defs,
            )
        }

        // Builder test1() and test2()
        let mut recv_contract = contract_map.remove(&receiver).unwrap();
        // build `test1()`: setup vm state one time for all calls
        let first_state = parsed_root_calls.first().and_then(|pc| pc.vm_state.clone()).unwrap();
        let last_state = parsed_root_calls.last().and_then(|pc| pc.vm_state.clone()).unwrap();
        recv_contract.setup_test1_vm_state(first_state, last_state);
        for (i, prc) in parsed_root_calls.iter().enumerate() {
            let is_last_call = i == parsed_root_calls.len() - 1;
            recv_contract.push_test1_call(prc.clone(), is_last_call);
        }
        if txs.len() > 1 {
            // build `test2()`: setup vm state for each call
            for (i, prc) in parsed_root_calls.iter().enumerate() {
                let is_first_call = i == 0;
                let is_last_call = i == parsed_root_calls.len() - 1;
                recv_contract.push_test2_call(prc.clone(), is_first_call, is_last_call);
            }
        }

        recv_contract.tidy_named_addresses();

        let receiver_name = recv_contract.name.clone();
        let mut contracts = vec![recv_contract];
        contracts.extend(contract_map.into_values());

        let args = TemplateArgs {
            file_name,
            receiver_name,
            last_txhash: last_tx.tx_hash.clone(),
            sender_scan_url: get_sender_scan_url(&chain, &sender),
            chain_name: chain,
            sender,
            struct_defs,
            interface,
            contracts,
        };

        Ok(args)
    }

    // Return (output_path, contract_name)
    fn render_test_file(&self, args: &TemplateArgs) -> Result<(String, String)> {
        let mut handlebars = Handlebars::new();
        handlebars.register_template_string("foundry_test", TEMPLATE)?;
        handlebars.register_helper("add", Box::new(add));

        let output_path = format!("{}/{}", self.output_dir, args.file_name);
        let output = File::create(&output_path)?;
        handlebars.render_to_write("foundry_test", args, output)?;

        Ok((output_path, args.receiver_name.clone()))
    }

    fn generate_salt(&mut self) -> String {
        self.nonce += 1;
        self.nonce.to_string()
    }

    fn take_memory_vars(&mut self, sender_var: &str, receiver_var: &str) -> Vec<MemoryVar> {
        let mut memory_vars = self.abi.take_memory_vars();
        for v in memory_vars.iter_mut() {
            v.replace_sender(sender_var);
            if !receiver_var.is_empty() {
                v.replace_receiver(receiver_var);
            }
        }

        memory_vars
    }
}

fn get_parsed_call_type(call: &Call, parsed_input: &Result<ParsedInput>, target_is_contract: bool) -> ParsedCallType {
    let input_is_parsed = parsed_input.is_ok();
    let fn_name = parsed_input.as_ref().map(|i| i.fn_name.to_string()).unwrap_or_default();

    let input_len = call.input.len();

    if call.target == HARDHAT_CHEAT_ADDR {
        ParsedCallType::HardhatCheat
    } else if "create" == call.ty {
        ParsedCallType::Create
    } else if "create2" == call.ty {
        ParsedCallType::Create2
    } else if "selfdestruct" == call.ty {
        ParsedCallType::SelfDestruct
    } else if "delegatecall" == call.ty {
        ParsedCallType::DelegateCall
    } else if input_is_parsed {
        if !target_is_contract && fn_name.starts_with("guessed_") {
            ParsedCallType::WithSelector
        } else {
            ParsedCallType::Interface
        }
    } else if input_len < 10 {
        ParsedCallType::SendValue
    } else if input_len >= 74 && (input_len - 10) % 64 == 0 {
        ParsedCallType::WithSelector
    } else {
        ParsedCallType::Raw
    }
}

fn call_inner_create(call: &Call, contract_var: &str) -> (String, String) {
    let contract_name = call.target_var[..1].to_uppercase() + &call.target_var[1..];
    let fn_signature = "constructor()".to_string();
    let fn_call = format!("{} = address(new {}());", contract_var, contract_name);

    (fn_signature, fn_call)
}

fn call_selfdestruct(contract_var: &str) -> (String, String) {
    let fn_signature = String::new();
    let fn_call = format!("selfdestruct(payable({}));", contract_var);

    (fn_signature, fn_call)
}

fn call_with_rawdata(call: &Call, contract_var: &str) -> (String, String) {
    let fn_signature = if call.input.len() < 10 {
        format!("{}()", call.ty)
    } else {
        format!("{}()", &call.input[1..10])
    };

    let args = if call.input.len() <= 2 {
        "\"\"".to_string()
    } else {
        format!("hex\"{}\"", &call.input[2..])
    };

    let mut fn_call = format!("{}.{}", contract_var, call.ty);
    if call.value != U256::ZERO {
        fn_call.push_str(format!("{{value: {}}}", call.value).as_str());
    }
    fn_call.push_str(format!("({});", args).as_str());

    (fn_signature, fn_call)
}

fn generate_hardhat_comment(
    call: &Call,
    sender_var: &str,
    receiver_var: &str,
    return_vars: &HashMap<String, ReturnData>,
) -> (String, String) {
    let mut named_addresses = HashMap::new();
    let args = decode_bytes_arg(
        &call.input[10..],
        sender_var,
        receiver_var,
        return_vars,
        &mut named_addresses,
    );

    let fn_call = format!("// harhat.console.log({});", args.join(", "));
    (String::new(), fn_call)
}

fn call_with_selector(
    call: &Call,
    contract_var: &str,
    sender_var: &str,
    receiver_var: &str,
    return_vars: &HashMap<String, ReturnData>,
    named_addresses: &mut HashMap<String, String>,
) -> (String, String) {
    let fn_selector = &call.input[0..10];
    let fn_signature = format!("{}()", &call.input[1..10]);
    let args = decode_bytes_arg(
        &call.input[10..],
        sender_var,
        receiver_var,
        return_vars,
        named_addresses,
    );

    let mut fn_call = format!("{}.{}", contract_var, call.ty);
    if call.value != U256::ZERO {
        fn_call.push_str(format!("{{value: {}}}", call.value).as_str());
    }
    if args.is_empty() {
        fn_call.push_str(format!("(abi.encodeWithSelector({}));", fn_selector).as_str());
    } else {
        fn_call.push_str(format!("(abi.encodeWithSelector({}, {}));", fn_selector, args.join(", ")).as_str());
    }

    (fn_signature, fn_call)
}

fn format_fn_sig(fn_signature: &str, parsed_call_type: &ParsedCallType) -> String {
    match parsed_call_type {
        ParsedCallType::Create | ParsedCallType::Create2 => "constructor()".to_string(),
        ParsedCallType::SelfDestruct => String::new(),
        _ => fn_signature.to_string(),
    }
}

fn format_fn_args(
    args: &[DecodedArg],
    sender_var: &str,
    receiver_var: &str,
    return_vars: &HashMap<String, ReturnData>,
    parsed_call_type: &ParsedCallType,
) -> String {
    let args = args
        .iter()
        .map(|a| {
            if a.ty == "address" && a.value == sender_var {
                "tx.origin".to_string()
            } else if a.ty == "address" && a.value == receiver_var {
                "r".to_string()
            } else if a.value != "0" && return_vars.contains_key(&a.value) {
                return_vars.get(&a.value).unwrap().try_replace(&a.ty, &a.value)
            } else if parsed_call_type == &ParsedCallType::HardhatCheat && a.ty != "string" {
                format!("{}({})", a.ty, a.value)
            } else {
                a.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(", ");

    args
}

fn format_fn_call(
    call: &Call,
    parsed_input: &ParsedInput,
    parsed_call_type: &ParsedCallType,
    target_is_contract: bool,
    contract_var: &str,
    args: &str,
) -> String {
    let contract_name = call.target_var[..1].to_uppercase() + &call.target_var[1..];
    let target = if target_is_contract && parsed_call_type == &ParsedCallType::Interface {
        format!("{}(payable({}))", contract_name, contract_var)
    } else if parsed_call_type == &ParsedCallType::Interface {
        format!("I({})", contract_var)
    } else {
        contract_var.to_string()
    };

    match parsed_call_type {
        ParsedCallType::DelegateCall => call_with_signature(target, call, parsed_input, args),
        ParsedCallType::HardhatCheat => call_hardhat_cheatcode(parsed_input, args),
        _ => call_with_interface(target, call, parsed_input, args),
    }
}

// Only support console2 for now.
fn call_hardhat_cheatcode(parsed_input: &ParsedInput, args: &str) -> String {
    format!("{}.{}({});", "console2", parsed_input.fn_name, args)
}

fn call_with_signature(target: String, call: &Call, parsed_input: &ParsedInput, args: &str) -> String {
    let fn_name = &call.ty;

    let mut fn_args = format!("abi.encodeWithSignature(\"{}\"", parsed_input.fn_signature);
    if args.is_empty() {
        fn_args.push(')');
    } else {
        fn_args.push_str(format!(", {})", args).as_str());
    };

    let mut fn_call = format!("{}.{}", target, fn_name);
    if call.value != U256::ZERO {
        fn_call.push_str(format!("{{value: {}}}", call.value).as_str());
    }
    fn_call.push_str(format!("({});", fn_args).as_str());
    fn_call
}

fn call_with_interface(target: String, call: &Call, parsed_input: &ParsedInput, args: &str) -> String {
    let mut fn_call = format!("{}.{}", target, parsed_input.fn_name);
    if call.value != U256::ZERO {
        fn_call.push_str(format!("{{value: {}}}", call.value).as_str());
    }
    fn_call.push_str(format!("({});", args).as_str());
    fn_call
}

fn decode_bytes_arg(
    arg: &str,
    sender_var: &str,
    receiver_var: &str,
    return_vars: &HashMap<String, ReturnData>,
    named_addresses: &mut HashMap<String, String>,
) -> Vec<String> {
    // try decode bytes
    let bytes = hex::decode(arg).unwrap();
    let mut abi = Abi::new();
    abi.try_decode_bytes(&bytes);
    let decoded = abi.take_bytes();
    if decoded.len() != 1 {
        return vec![arg.to_string()];
    }
    let decoded = decoded.into_iter().next().unwrap();

    named_addresses.extend(abi.take_addresses());

    decoded
        .parts
        .into_iter()
        .map(|DecodedArg { ty, value, .. }| {
            if ty == "address" && value == sender_var {
                "tx.origin".to_string()
            } else if ty == "address" && value == receiver_var {
                "r".to_string()
            } else if value != "0" && return_vars.contains_key(&value) {
                return_vars.get(&value).unwrap().try_replace(&ty, &value)
            } else {
                value.to_string()
            }
        })
        .collect::<Vec<_>>()
}

fn build_sub_contracts(contracts: &mut HashMap<String, Contract>) {
    let concise_contracts = contracts.values().map(SubContract::from).collect::<Vec<_>>();
    for contract in contracts.values_mut() {
        contract.build_sub_contracts(&concise_contracts);
    }

    let sub_contract_map = contracts
        .values()
        .map(|c| (c.name.to_lowercase(), c.sub_contracts.clone()))
        .collect::<HashMap<_, _>>();
    for contract in contracts.values_mut() {
        contract.flat_nested_sub_contracts(&sub_contract_map);
    }
}
