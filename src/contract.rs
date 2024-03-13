use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt::Display,
    mem,
};

use alloy_primitives::U256;
use anyhow::Result;
use serde::Serialize;
use tracing::error;

use crate::{
    abi::{
        self,
        types::{DecodedArg, MemoryVar, StructDef},
        Abi,
    },
    config::HARDHAT_CHEAT_ADDR,
    utils::{self, hash_to_name},
};

#[derive(Debug, Serialize, Default)]
pub struct Contract {
    pub name: String,
    pub addr: String,
    /// setUp or constructor
    pub setup_constructor: Option<SetupConstructor>,
    /// map<var_name, SubContract>
    #[serde(skip)]
    pub sub_contracts: HashMap<String, SubContract>,
    /// Ordered sub_contracts
    /// It takes the ownership of `sub_contracts` when `self.generate` is
    /// called.
    pub ordered_sub_contracts: Vec<SubContract>,
    /// map<var_name, address>
    pub named_addresses: BTreeMap<String, String>,
    /// The calls in `test1()` including all root_calls of txs.
    pub test1_calls: Vec<String>,
    /// The calls in `test2()` including all root_calls of txs.
    pub test2_calls: Vec<String>,
    /// map<fn_signature, Function>
    #[serde(skip)]
    pub functions: HashMap<String, Function>,
    /// Ordered functions, the root_fn is always the first one.
    /// It takes the ownership of `functions` when `self.tidy_functions` is
    /// called.
    pub ordered_functions: Vec<ConciseFn>,
    /// Counter variables to record the number of calls of functions.
    pub counters: Vec<String>,
    /// map<fn_signature, UnresolvedFn>
    pub fallback: HashMap<String, UnresolvedFn>,
    /// salt is used to predict the contract address.
    #[serde(skip)]
    pub salt: Option<String>,

    // Use multi boolean values instead of an enum to make the template easier.
    pub is_receiver: bool,
    pub is_inner: bool,
}

#[derive(Debug, Serialize, Default)]
pub struct SetupConstructor {
    pub fn_def: String,
    pub fn_calls: Vec<String>,
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct SubContract {
    pub name: String,
    pub var_name: String,
    pub addr: String,
    // Use multi boolean values instead of an enum to make the template easier.
    pub is_receiver: bool,
    pub is_inner: bool,
    /// salt is used to predict the contract address.
    pub salt: Option<String>,
    /// initcode hash is used to predict the contract address.
    pub initcode_hash: Option<InitCodeHash>,
    /// str_constructor_args is used in the template.
    /// e.g. `a_x6dd0, a_x6dd1`
    pub str_constructor_args: String,

    // constructor_args is used to build the constructor.
    // map<var_name, value>
    #[serde(skip)]
    constructor_args: HashMap<String, String>,
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct InitCodeHash {
    pub var: String,
    pub value: String,
}

#[derive(Debug, Default)]
pub struct Function {
    /// Is the function is a view function.
    pub is_view: bool,
    /// The function signature to define a function.
    pub fn_def_signature: String,
    /// return signature to parse the output
    pub ret_signature: String,
    /// If a function is called multiple times, the call_group of each call may
    /// be different.
    pub call_groups: Vec<CallGroup>,
    /// Is payable
    pub payable: bool,
}

/// A group of calls in a `if` block.
#[derive(Debug, Default, Clone)]
pub struct CallGroup {
    /// The calls of this group.
    pub calls: Vec<ParsedCall>,
    /// The output of this group.
    pub raw_output: String,
    /// The decoded output of this group.
    pub decoded_output: Vec<String>,
    /// The number of times this group repeats.
    /// (repeats, last_idx)
    pub repeats: (usize, usize),
}

#[derive(Debug, Serialize, Default)]
pub struct ConciseFn {
    /// Is the function is a view function.
    pub is_view: bool,
    /// The function signature to define a function.
    pub fn_def_signature: String,
    /// return signature
    pub ret_def_signature: String,
    /// The counter to record the number of calls of this function.
    pub counter: String,
    /// Serialized function calls
    pub call_groups: Vec<ConciseCallGroup>,
    /// Is payable
    pub payable: bool,
}

/// A group of calls in a `if` block.
#[derive(Debug, Serialize, Default, Clone)]
pub struct ConciseCallGroup {
    /// The calls of this group.
    pub calls: Vec<String>,
    /// The outputs of this group.
    pub outputs: Vec<String>,
    /// The condition of this `if` block.
    /// `<= 5` means `if (counter <= 5)`
    pub cond: String,
}

#[derive(Debug, Serialize, Default)]
pub struct UnresolvedFn {
    pub fn_selector: String,
    pub fn_signature: String,
}

#[derive(Debug, Eq, PartialEq, Default, Clone)]
pub enum ParsedCallType {
    #[default]
    Interface,
    Raw,
    SendValue,
    Create,
    Create2,
    SelfDestruct,
    DelegateCall,
    HardhatCheat,
    WithSelector,
    Parentheses,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ParsedCall {
    pub ty: ParsedCallType,
    // call, staticcall, ...
    pub sol_ty: String,
    pub caller: String,
    pub target: String,
    pub fn_signature: String,
    pub ret_signature: String,
    pub fn_call: String,
    pub raw_input: String,
    pub raw_output: String,
    pub value: U256,
    pub sub_calls: Vec<ParsedCall>,

    /// the memory variables that are used in this function call.
    pub memory_vars: Vec<MemoryVar>,
    /// map<var_name, address>
    pub named_addresses: HashMap<String, String>,
    /// map<struct_signature, struct_def>
    pub struct_defs: HashMap<String, StructDef>,
    /// map<return_value, ReturnData>, duplicated return values are merged.
    pub return_vars: HashMap<String, ReturnData>,
    /// Raw return data, duplicated return values are not merged.
    pub return_data: Vec<ReturnData>,
    /// e.g. uint256 return_var = abi.decode(output, (uint256));
    pub ret_decode_call: Option<String>,
    /// If the call is a `CREATE2`, it has a salt
    pub salt: Option<String>,
    /// The comment of the function call.
    pub comment: Option<String>,
    /// Is the target is a contract generated by GF?
    pub target_is_contract: bool,
    /// VmState to set the vm state, e.g. `vm.createSelectFork/vm.warp ...`
    pub vm_state: Option<VmState>,
    /// visible inner_create_variables to avoid duplicate definitions.
    pub inner_create_vars: HashSet<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct VmState {
    pub forked_rpc: String,
    pub tx_hash: String,
    pub block_number: String,
    pub block_timestamp: String,
}

impl VmState {
    pub fn generate(&self, is_first_call: bool) -> Vec<String> {
        if is_first_call {
            vec![format!(
                "vm.createSelectFork(\"{}\", {}); // tx.blockNumber - 1",
                self.forked_rpc, self.block_number
            )]
        } else {
            vec![
                format!("vm.warp({});", self.block_timestamp),
                format!("vm.roll({});", self.block_number),
            ]
        }
    }
}

#[derive(Debug, Serialize, Default, Clone, PartialEq, Eq)]
pub struct ReturnData {
    pub ty: String,
    pub var: String,
    pub value: String,
    pub is_dynamic: bool,
}

impl Display for ReturnData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_dynamic {
            write!(f, "// {} memory {} = {};", self.ty, self.var, self.value)
        } else {
            write!(f, "// {} {} = {};", self.ty, self.var, self.value)
        }
    }
}

impl Contract {
    pub fn new(addr: String, is_receiver: bool, is_inner: bool, salt: Option<String>) -> Self {
        let mut name = hash_to_name(&addr);
        // Capitalize the first letter of the contract name
        // so that the lowercase variable name can be used.
        name = name[..1].to_uppercase() + &name[1..];

        Self {
            name,
            addr,
            is_receiver,
            is_inner,
            salt,
            ..Default::default()
        }
    }

    pub fn generate(
        &mut self,
        // map<contract_var, sub_contracts>
        all_contracts: &HashMap<String, HashMap<String, SubContract>>,
        last_txhash: &str,
        root_fn_sigs: &[&str],
        interface: &mut HashSet<String>,
        struct_defs: &HashMap<String, StructDef>,
    ) {
        if self.is_receiver {
            self.build_setup(last_txhash);
            self.build_receiver_constructor();
        } else {
            self.build_constructor(interface, all_contracts, struct_defs);
        }
        self.tidy_functions(root_fn_sigs, interface, all_contracts, struct_defs);
        self.named_addresses.remove(&self.name.to_lowercase());
        self.order_sub_contracts();
    }

    pub fn build_function(&mut self, call: ParsedCall, struct_defs: &HashMap<String, StructDef>) {
        let mut func = if let Some(func) = self.functions.remove(&call.fn_signature) {
            func
        } else {
            match call.generate_function(struct_defs) {
                Ok(func) => func,
                Err(_) => {
                    return;
                }
            }
        };

        let decoded_output = self.parse_output(&func.ret_signature, &call.raw_output);
        func.call_groups
            .push(CallGroup::new(call.sub_calls, call.raw_output, decoded_output));

        self.functions.insert(call.fn_signature, func);
    }

    pub fn setup_test1_vm_state(&mut self, first_state: VmState, last_state: VmState) {
        let calls = vec![
            format!(
                "vm.createSelectFork(\"{}\", {}); // tx.blockNumber - 1",
                last_state.forked_rpc, last_state.block_number
            ),
            format!(
                "// vm.createSelectFork(\"{}\", bytes32({}));",
                first_state.forked_rpc, first_state.tx_hash
            ),
            String::new(),
        ];

        self.test1_calls.extend(calls);
    }

    pub fn push_test1_call(&mut self, root_call: ParsedCall, is_last_call: bool) {
        self.named_addresses.extend(root_call.named_addresses.clone());
        let calls = root_call.generate_test1_call(is_last_call, self);
        self.test1_calls.extend(calls);
    }

    pub fn push_test2_call(&mut self, root_call: ParsedCall, is_first_call: bool, is_last_call: bool) {
        self.named_addresses.extend(root_call.named_addresses.clone());
        let calls = root_call.generate_test2_call(is_first_call, is_last_call, self);
        self.test2_calls.extend(calls);
    }

    pub fn init_address_vars(&self) -> Vec<String> {
        let mut calls = vec![];
        for sub in &self.ordered_sub_contracts {
            if let Some(ref salt) = sub.salt {
                if let Some(ref initcode_hash) = sub.initcode_hash {
                    calls.push(format!("bytes32 {} = {};", initcode_hash.var, initcode_hash.value));
                    calls.push(format!(
                        "{} = address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), r, bytes32({:?}), {})))));",
                        sub.var_name, salt, initcode_hash.var
                    ));
                }
            } else if !sub.is_inner {
                calls.push(format!(
                    "{} = address(new {}({}));",
                    sub.var_name, sub.name, sub.str_constructor_args
                ));
            }
        }
        calls
    }

    pub fn tidy_functions(
        &mut self,
        root_fn_sigs: &[&str],
        interface: &mut HashSet<String>,
        all_contracts: &HashMap<String, HashMap<String, SubContract>>,
        struct_defs: &HashMap<String, StructDef>,
    ) {
        let (mut funcs, mut ordered_funcs) = (vec![], vec![]);
        let functions = mem::take(&mut self.functions);

        for (fn_sig, func) in functions.into_iter() {
            let concise_fn = func.into_concise(self, interface, all_contracts, struct_defs);
            // We just need to make sure the root_fn appears first.
            if self.is_receiver && root_fn_sigs.contains(&fn_sig.as_str()) {
                ordered_funcs.push(concise_fn);
            } else {
                funcs.push(concise_fn);
            }
        }

        self.ordered_functions = ordered_funcs;
        self.ordered_functions.extend(funcs);
    }

    pub fn build_sub_contracts(&mut self, contracts: &[SubContract]) {
        for c in contracts {
            if c.addr == self.addr {
                continue;
            }

            if self.named_addresses.remove(&c.var_name).is_some() {
                self.sub_contracts.insert(c.var_name.clone(), c.clone());
            }
        }
    }

    pub fn flat_nested_sub_contracts(&mut self, sub_contract_map: &HashMap<String, HashMap<String, SubContract>>) {
        let keys = self
            .sub_contracts
            .iter()
            .filter(|(_, c)| c.is_inner)
            .map(|(k, _)| k.clone())
            .collect::<Vec<String>>();
        for v in keys.into_iter() {
            if let Some(sub) = sub_contract_map.get(&v) {
                self.sub_contracts.extend(sub.clone());
            }
        }
        self.sub_contracts.remove(self.name.to_lowercase().as_str());
    }

    pub fn build_sub_contracts_constructor_args(
        &mut self,
        sub_contracts: &mut HashMap<String, HashMap<String, SubContract>>,
    ) {
        let receiver_var = hash_to_name(&self.addr);
        for c in self.sub_contracts.values_mut() {
            c.constructor_args = sub_contracts
                .get(&hash_to_name(&c.addr))
                .map(|c| {
                    c.keys()
                        .map(|contract_var| (format!("a_{}", contract_var), contract_var.to_string()))
                        .collect::<HashMap<_, _>>()
                })
                .unwrap_or_default();

            c.str_constructor_args = c
                .constructor_args
                .values()
                .map(|v| if v == &receiver_var { "r".to_string() } else { v.clone() })
                .collect::<Vec<_>>()
                .join(", ");

            if let Some(ref salt) = c.salt {
                let var = format!("initcodeHash{salt}");
                let value = if c.str_constructor_args.is_empty() {
                    format!("keccak256(type({}).creationCode)", c.name)
                } else {
                    format!(
                        "keccak256(abi.encodePacked(type({}).creationCode, abi.encode({})))",
                        c.name, c.str_constructor_args
                    )
                };
                c.initcode_hash = Some(InitCodeHash { var, value });
            }
        }

        sub_contracts.insert(receiver_var, self.sub_contracts.clone());
    }

    pub fn tidy_named_addresses(&mut self) {
        let sub_contracts = self
            .ordered_sub_contracts
            .iter()
            .map(|c| c.var_name.clone())
            .collect::<HashSet<_>>();
        self.named_addresses.retain(|k, _| !sub_contracts.contains(k));
    }

    fn build_setup(&mut self, last_txhash: &str) {
        let fn_def = "function setUp() public pure".to_string();
        let fn_calls = vec![format!("console2.log(\"{}\");", last_txhash)];

        self.setup_constructor = Some(SetupConstructor { fn_def, fn_calls });
    }

    // Change the constructor of the receiver to a normal function.
    fn build_receiver_constructor(&mut self) {
        if let Some(mut func) = self.functions.remove("constructor()") {
            let fn_sig = "_constructor_()".to_string();
            func.fn_def_signature = fn_sig.clone();
            // Remove the returned runtime code.
            if let Some(c) = func.call_groups.first_mut() {
                c.raw_output = String::new();
                // c.decoded_output = vec![];
            }

            self.functions.insert(fn_sig, func);
        }
    }

    fn build_constructor(
        &mut self,
        interface: &mut HashSet<String>,
        all_contracts: &HashMap<String, HashMap<String, SubContract>>,
        struct_defs: &HashMap<String, StructDef>,
    ) {
        let sub_contracts = self.sub_contracts.clone();
        // subcalls of `CREATE/CREATE2` go into the constructor
        let constructor = self.functions.remove("constructor()");
        if sub_contracts.is_empty() && constructor.is_none() {
            return;
        }

        // constructor(address a_x6dd0, address a_x6dd1) payable
        let fn_def = if sub_contracts.is_empty() {
            "constructor() payable".to_string()
        } else {
            let mut var_names = self.sub_contracts.keys().cloned().collect::<Vec<String>>();
            var_names.sort();
            let args = var_names
                .iter()
                .map(|var_name| format!("address a_{}", var_name))
                .collect::<Vec<_>>()
                .join(", ");
            format!("constructor({}) payable", args)
        };

        let mut fn_calls = vec![];

        // sub_contracts
        // x6dd0 = a_x6dd0; // 0x6dd035a2bd0daf5ae0a73f2442b3ec05766a8b75
        if !sub_contracts.is_empty() {
            fn_calls.extend(
                self.sub_contracts
                    .iter()
                    .map(|(var_name, c)| format!("{} = a_{}; // {}", var_name, var_name, c.addr)),
            );
        }

        // sub_calls
        if let Some(func) = constructor {
            fn_calls.extend(
                func.into_concise(self, interface, all_contracts, struct_defs)
                    .call_groups
                    .into_iter()
                    .flat_map(|c| c.calls),
            );
        }

        self.setup_constructor = Some(SetupConstructor { fn_def, fn_calls });
    }

    fn build_counter_variable(&mut self, fn_signature: &str, func: &mut ConciseFn) {
        if func.call_groups.len() > 1 {
            let counter = format!("t_{}", fn_signature.split('(').next().unwrap_or_default());
            self.counters.push(counter.clone());
            func.counter = counter;
        }
    }

    fn parse_output(&mut self, ret_signature: &str, output: &str) -> Vec<String> {
        if output.is_empty() {
            return vec![];
        }

        if !ret_signature.is_empty() {
            if let Ok(ret) = self.abi_decode_output(ret_signature, output) {
                return ret;
            }
        }

        self.try_decode_output(output)
    }

    fn abi_decode_output(&mut self, ret_sig: &str, output: &str) -> Result<Vec<String>> {
        let mut abi = Abi::new();
        let args = abi.decode_output(ret_sig, output)?;

        let mut ret = vec![];
        // memory vars
        for var in &abi.memory_vars {
            ret.extend(var.generate_sol_code());
        }

        self.named_addresses.extend(abi.take_addresses());
        let args = args.into_iter().map(|a| a.to_string()).collect::<Vec<_>>();

        if args.len() == 1 {
            ret.push(format!("return {};", args[0]));
        } else {
            ret.push(format!("return ({});", args.join(", ")));
        }

        Ok(ret)
    }

    fn try_decode_output(&self, output: &str) -> Vec<String> {
        let parts = output
            .trim_start_matches("0x")
            .as_bytes()
            .chunks(64)
            .collect::<Vec<_>>();

        let mut updated = false;
        let mut chunks = vec![];
        for part in parts {
            let part = String::from_utf8_lossy(part);
            if let Some(addr) = self.bytes32_to_address(&part) {
                updated = true;
                chunks.push(format!("abi.encode(address({}))", addr));
            } else {
                chunks.push(format!("hex\"{}\"", part));
            }
        }

        let return_data = if updated {
            format!("abi.encodePacked({})", chunks.join(", "))
        } else {
            format!("hex\"{}\"", output.trim_start_matches("0x"))
        };

        vec![
            format!("bytes memory rt = {};", return_data),
            "assembly {".to_string(),
            "    return(add(rt, 0x20), mload(rt))".to_string(),
            "}".to_string(),
        ]
    }

    fn bytes32_to_address(&self, bytes32: &str) -> Option<String> {
        abi::bytes32_to_address(bytes32).map(|addr| self.as_named_address(addr))
    }

    fn as_named_address(&self, addr: String) -> String {
        let var_name = hash_to_name(&addr);
        if addr == self.addr {
            "r".to_string()
        } else if self.named_addresses.contains_key(&var_name) {
            var_name
        } else {
            addr
        }
    }

    fn order_sub_contracts(&mut self) {
        let mut ordered: Vec<SubContract> = vec![];
        for (var_name, c) in mem::take(&mut self.sub_contracts) {
            if let Some(idx) = ordered
                .iter()
                .position(|sub| sub.constructor_args.contains_key(&var_name))
            {
                ordered.insert(idx, c);
            } else {
                ordered.push(c);
            }
        }

        self.ordered_sub_contracts = ordered;
    }
}

impl From<&Contract> for SubContract {
    fn from(contract: &Contract) -> Self {
        SubContract {
            name: contract.name.clone(),
            var_name: contract.name.to_lowercase(),
            addr: contract.addr.clone(),
            is_receiver: contract.is_receiver,
            is_inner: contract.is_inner,
            salt: contract.salt.clone(),
            ..Default::default()
        }
    }
}

impl Function {
    pub fn merge_duplicate_calls(&mut self) {
        if self.call_groups.is_empty() {
            return;
        }

        let mut merged_calls = vec![];
        let mut prev = self.call_groups.first().unwrap().clone();
        for (idx, call) in self.call_groups.iter().enumerate().skip(1) {
            if &prev == call {
                prev.repeats.0 += 1;
            } else {
                merged_calls.push(prev);
                prev = call.clone();
            }
            prev.repeats.1 = idx;
        }

        merged_calls.push(prev);
        self.call_groups = merged_calls;
    }

    pub fn into_concise(
        mut self,
        contract: &mut Contract,
        interface: &mut HashSet<String>,
        all_contracts: &HashMap<String, HashMap<String, SubContract>>,
        struct_defs: &HashMap<String, StructDef>,
    ) -> ConciseFn {
        self.merge_duplicate_calls();

        // CallGroup -> ConciseCallGroup
        let concise_calls = self
            .call_groups
            .into_iter()
            .map(|c| c.into_concise(contract, interface, all_contracts, struct_defs))
            .collect::<Vec<_>>();

        let ret_signature = get_ret_def_signature(&self.ret_signature, struct_defs);

        let mut concise_fn = ConciseFn {
            is_view: self.is_view,
            fn_def_signature: self.fn_def_signature.clone(),
            ret_def_signature: ret_signature,
            call_groups: concise_calls,
            payable: self.payable,
            ..Default::default()
        };

        contract.build_counter_variable(&self.fn_def_signature, &mut concise_fn);
        concise_fn
    }
}

impl UnresolvedFn {
    pub fn new(selector: String, signature: String) -> Self {
        UnresolvedFn {
            fn_selector: selector,
            fn_signature: signature,
        }
    }
}

impl ParsedCall {
    pub fn has_memory_vars(&self) -> bool {
        !self.memory_vars.is_empty()
    }

    pub fn take_inner_create_vars(&mut self) -> HashSet<String> {
        mem::take(&mut self.inner_create_vars)
    }

    // Generate the string representation of this function call.
    // The result may be a multi-line string if there are memory variables.
    pub fn generate(
        &mut self,
        receiver_var: &str,
        all_contracts: &HashMap<String, HashMap<String, SubContract>>,
    ) -> Vec<String> {
        if self.ty == ParsedCallType::Parentheses {
            self.inner_create_vars.clear();
            return vec![self.fn_call.clone()];
        }

        let has_memory_vars = self.has_memory_vars();
        let mut fn_calls = vec![];

        if has_memory_vars {
            fn_calls.push(String::new());
        }
        fn_calls.extend(self.generate_memory_vars());

        for r in &self.return_data {
            fn_calls.push(r.to_string());
        }

        match self.ty {
            ParsedCallType::Create | ParsedCallType::Create2 => {
                let sub_var = hash_to_name(&self.target);
                if sub_var == receiver_var {
                    fn_calls.extend(self.call_self_constructor());
                } else {
                    fn_calls.extend(self.call_create_sub_contract(receiver_var, &sub_var, all_contracts));
                }
            }
            _ => {
                fn_calls.extend(self.generate_call_with_comment());
                if let Some(ref ret_decode_call) = self.ret_decode_call {
                    fn_calls.push(ret_decode_call.clone());
                }
            }
        }

        if has_memory_vars {
            fn_calls.push(String::new());
        }

        fn_calls
    }

    /// Generate a function call in the `test1` function.
    pub fn generate_test1_call(&self, is_last_call: bool, contract: &Contract) -> Vec<String> {
        let mut fn_calls = vec![];
        if is_last_call {
            fn_calls.extend(contract.init_address_vars());
        }

        fn_calls.extend(self.generate_memory_vars());
        fn_calls.extend(self.generate_root_call_with_comment(is_last_call));
        fn_calls
    }

    /// Generate a function call in the `test2` function.
    pub fn generate_test2_call(&self, is_first_call: bool, is_last_call: bool, contract: &Contract) -> Vec<String> {
        let mut fn_calls = vec![];
        // The key difference between `test1` and `test2` is that `test2` needs to set the vm state before each call.
        if let Some(vm_state) = &self.vm_state {
            fn_calls.extend(vm_state.generate(is_first_call));
        }

        fn_calls.extend(self.generate_test1_call(is_last_call, contract));
        fn_calls
    }

    pub fn get_interface(&self, struct_defs: &HashMap<String, StructDef>) -> Option<String> {
        if self.ty != ParsedCallType::Interface || self.target_is_contract {
            return None;
        }

        match self.get_fn_def_signature(struct_defs) {
            Ok(fn_def_sig) => {
                let mut res = format!("function {}", fn_def_sig);
                if !self.ret_signature.is_empty() {
                    let sig = get_ret_def_signature(&self.ret_signature, struct_defs);
                    res.push_str(format!(" external payable returns ({})", sig).as_str());
                } else {
                    res.push_str(" external payable");
                }
                Some(res)
            }
            Err(e) => {
                error!("Failed to get fn_def_signature: {}, {:?}", e, self);
                None
            }
        }
    }

    pub fn generate_function(&self, struct_defs: &HashMap<String, StructDef>) -> Result<Function> {
        Ok(Function {
            is_view: self.sol_ty == "staticcall",
            fn_def_signature: self.get_fn_def_signature(struct_defs)?,
            ret_signature: self.ret_signature.clone(),
            payable: self.value != U256::ZERO,
            ..Default::default()
        })
    }

    pub fn add_returns(&mut self, output: &str, var_nonce: usize) -> Result<()> {
        if output.is_empty() {
            return Ok(());
        }

        let mut abi = Abi::new();
        let decoded = abi.decode_output(&self.ret_signature, output)?;
        self.named_addresses.extend(abi.take_addresses());
        self.struct_defs.extend(abi.take_struct_defs());

        let memory_vars = abi.take_memory_vars_map();
        self.return_data = ReturnData::from_decoded_output(decoded, memory_vars, var_nonce);
        for r in &self.return_data {
            self.return_vars.insert(r.value.to_string(), r.clone());
        }

        let vars = self.return_data.iter().map(|r| r.var_declaraion()).collect::<Vec<_>>();
        if self.ty == ParsedCallType::WithSelector {
            let var = self.return_data.first().unwrap().var.clone();
            self.fn_call = format!("(bool {var}_succ, bytes memory {var}_bytes) = {}", self.fn_call);
            self.ret_decode_call = Some(format!(
                "({vars}) = abi.decode({var}_bytes, ({sig}));",
                vars = vars.join(", "),
                var = var,
                sig = self.ret_signature
            ));
        } else {
            self.fn_call = if vars.len() == 1 {
                format!("{} = {}", vars.first().unwrap(), self.fn_call)
            } else {
                format!("({}) = {}", vars.join(", "), self.fn_call)
            };
        }

        Ok(())
    }

    /// Generate a console2.log to log the return values of a parsed_call.
    /// array/bytes values are not supported
    pub fn new_log(&self) -> Option<ParsedCall> {
        if self
            .return_data
            .iter()
            .any(|r| r.ty.ends_with("[]") || r.ty.starts_with("bytes"))
        {
            return None;
        }

        // "uint256 v0 = I(x1578).balanceOf(r);" -> "I(x1578).balanceOf(r)"
        let desc = {
            let start_idx = self.fn_call.find('=').map(|i| i + 2).unwrap_or_default();
            let end_idx = self.fn_call.len() - 1;
            &self.fn_call[start_idx..end_idx]
        };
        let tab = if desc.contains("(r)") { "\\t\\t" } else { "\\t" };

        let values = self
            .return_data
            .iter()
            .map(|r| {
                if r.ty == "uint256" {
                    utils::prettify_value(&r.value)
                } else {
                    r.var.clone()
                }
            })
            .collect::<Vec<_>>();

        let fn_call = format!("console2.log(\"{desc}{tab}->\", {});", values.join(", "));

        Some(ParsedCall {
            ty: ParsedCallType::HardhatCheat,
            sol_ty: "staticcall".to_string(),
            caller: self.caller.clone(),
            target: HARDHAT_CHEAT_ADDR.to_string(),
            fn_call,
            ..Default::default()
        })
    }

    pub fn left_parenthesis() -> Self {
        ParsedCall {
            ty: ParsedCallType::Parentheses,
            sol_ty: "staticcall".to_string(),
            fn_call: "{".to_string(),
            ..Default::default()
        }
    }

    pub fn right_parenthesis() -> Self {
        ParsedCall {
            ty: ParsedCallType::Parentheses,
            sol_ty: "staticcall".to_string(),
            fn_call: "}".to_string(),
            ..Default::default()
        }
    }

    fn generate_memory_vars(&self) -> Vec<String> {
        let mut fn_calls = vec![];
        for var in &self.memory_vars {
            fn_calls.extend(var.generate_sol_code());
        }

        fn_calls
    }

    fn generate_call_with_comment(&self) -> Vec<String> {
        let mut fn_calls = vec![];
        if let Some(comment) = &self.comment {
            fn_calls.push(comment.clone());
        }
        fn_calls.push(self.fn_call.clone());
        fn_calls
    }

    fn generate_root_call_with_comment(&self, is_last_call: bool) -> Vec<String> {
        if is_last_call {
            return self.generate_call_with_comment();
        }

        let mut fn_calls = vec![];
        if let Some(comment) = &self.comment {
            fn_calls.push(comment.clone());
        }
        fn_calls.push(format!("this.{}", self.fn_call));
        fn_calls
    }

    // this._constructor_{value: 100}();
    fn call_self_constructor(&self) -> Vec<String> {
        let fn_call = if let Some(args) = self.constructor_additional_args(&self.salt) {
            format!("this._constructor_{}();", args)
        } else {
            "_constructor_();".to_string()
        };

        vec![fn_call]
    }

    /* *
     * Create a sub contract.
     * e.g.
     * // x7704 is the sub_contract of xa612.
     * address x7704 = address(new X7704(r));
     * // xa612 is the sub_contract of r.
     * xa612 = address(new Xa612(r, x7704));
     */
    fn call_create_sub_contract(
        &mut self,
        receiver_var: &str,
        sub_var: &str,
        // map<contract_var, sub_contracts>
        all_contracts: &HashMap<String, HashMap<String, SubContract>>,
    ) -> Vec<String> {
        let mut fn_calls = vec![];

        let subs = all_contracts.get(receiver_var).unwrap();
        let sub_name = sub_var[..1].to_uppercase() + &sub_var[1..];
        let sub_contract = subs.get(sub_var).expect("sub_contract not found");

        let mut addr_vars = sub_contract.constructor_args.values().cloned().collect::<Vec<String>>();
        addr_vars.sort();
        let args = addr_vars
            .iter()
            .map(|addr_var| {
                if addr_var == receiver_var {
                    "r".to_string()
                } else {
                    if !subs.contains_key(addr_var) && !self.inner_create_vars.contains(addr_var) {
                        // address x7704 = address(new X7704(r));
                        let memory_vars = self
                            .call_create_sub_contract(sub_var, addr_var, all_contracts)
                            .into_iter()
                            .map(|code| {
                                if code.starts_with("address") {
                                    code
                                } else {
                                    format!("address {}", code)
                                }
                            })
                            .collect::<Vec<_>>();
                        fn_calls.extend(memory_vars);
                        self.inner_create_vars.insert(addr_var.clone());
                    }
                    addr_var.clone()
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        // xa612 = address(new Xa612(r, x7704));
        let mut fn_call = format!("{} = address(new {}", sub_var, sub_name);
        if let Some(additional_args) = self.constructor_additional_args(&sub_contract.salt) {
            fn_call.push_str(&additional_args);
        }
        fn_call.push_str(format!("({}));", args).as_str());

        fn_calls.push(fn_call);
        fn_calls
    }

    fn constructor_additional_args(&self, salt: &Option<String>) -> Option<String> {
        if self.value == U256::ZERO && salt.is_none() {
            return None;
        }

        let mut args = vec![];
        if self.value != U256::ZERO {
            args.push(format!("value: {}", self.value));
        }

        if let Some(salt) = salt {
            args.push(format!("salt: bytes32(\"{salt}\")"));
        }

        Some(format!("{{{}}}", args.join(", ")))
    }

    // The fn signature to define a function.
    fn get_fn_def_signature(&self, struct_defs: &HashMap<String, StructDef>) -> Result<String> {
        Abi::new().get_fn_def_signature(&self.fn_signature, struct_defs)
    }
}

impl ReturnData {
    pub fn from_decoded_output(
        decoded: Vec<DecodedArg>,
        memory_vars: HashMap<String, MemoryVar>,
        var_nonce: usize,
    ) -> Vec<Self> {
        decoded
            .into_iter()
            .enumerate()
            .map(|(i, arg)| {
                let var = format!("v{}", var_nonce + i);
                let value = if arg.is_dynamic {
                    memory_vars.get(&arg.value).and_then(|v| v.value()).unwrap_or_default()
                } else {
                    arg.value
                };

                ReturnData {
                    ty: arg.ty,
                    var,
                    value,
                    is_dynamic: arg.is_dynamic,
                }
            })
            .collect()
    }

    pub fn var_declaraion(&self) -> String {
        if self.is_dynamic {
            format!("{} memory {}", self.ty, self.var)
        } else {
            format!("{} {}", self.ty, self.var)
        }
    }

    // Try to replace the `target_val` with `self.var` if the types match.
    pub fn try_replace(&self, target_ty: &str, target_val: &str) -> String {
        if self.ty == target_ty {
            return self.var.clone();
        }

        // type conversion between uints with different size
        if self.ty.starts_with("uint") && target_ty.starts_with("uint") {
            let self_size = self.ty.trim_start_matches("uint").parse::<usize>().unwrap_or_default();
            let target_size = target_ty
                .trim_start_matches("uint")
                .parse::<usize>()
                .unwrap_or_default();
            if self_size > target_size {
                return format!("uint{}({})", target_size, self.var);
            }
        }

        target_val.to_string()
    }
}

impl CallGroup {
    pub fn new(calls: Vec<ParsedCall>, raw_output: String, decoded_output: Vec<String>) -> Self {
        CallGroup {
            calls,
            raw_output,
            decoded_output,
            repeats: (1, 0),
        }
    }

    pub fn into_concise(
        self,
        contract: &mut Contract,
        interface: &mut HashSet<String>,
        all_contracts: &HashMap<String, HashMap<String, SubContract>>,
        struct_defs: &HashMap<String, StructDef>,
    ) -> ConciseCallGroup {
        let receiver_var = contract.name.to_lowercase();
        let cond = self.get_cond();

        let mut calls = vec![];
        let mut inner_create_vars = HashSet::new();
        for mut call in self.calls {
            if let Some(i) = call.get_interface(struct_defs) {
                interface.insert(i);
            }

            call.inner_create_vars.extend(inner_create_vars);
            let fn_calls = call.generate(&receiver_var, all_contracts);
            inner_create_vars = call.take_inner_create_vars();
            calls.extend(fn_calls);
        }

        let outputs = self.decoded_output;
        ConciseCallGroup { calls, outputs, cond }
    }

    fn get_cond(&self) -> String {
        // in the generated code, the `counter++` is always placed before the `if`
        // block. so the `counter` starts from 1.
        if self.repeats.0 == 1 {
            format!(" == {}", self.repeats.1 + 1)
        } else {
            format!(" <= {}", self.repeats.1 + 1)
        }
    }
}

impl PartialEq for CallGroup {
    fn eq(&self, other: &Self) -> bool {
        self.calls == other.calls && self.raw_output == other.raw_output
    }
}

// The return signature to define a function.
fn get_ret_def_signature(ret_sig: &str, struct_defs: &HashMap<String, StructDef>) -> String {
    Abi::new()
        .get_ret_def_signature(ret_sig, struct_defs)
        .unwrap_or_default()
}
