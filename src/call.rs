use alloy_primitives::U256;
use serde_json::Value;

use crate::utils::{checksum, hash_to_name};

#[derive(Debug, Default, Clone)]
pub struct Call {
    pub ty: String,
    pub caller: String,
    pub target: String,
    // the variable name of target
    pub target_var: String,
    pub value: U256,
    pub input: String,
    pub output: String,
    pub sub_calls: Vec<Call>,
}

impl From<&Value> for Call {
    fn from(v: &Value) -> Self {
        Self::from_json(v, "", "")
    }
}

impl Call {
    // parent_ty
    //  - `delegatecall`: `caller` is `parent_addr`
    //  - otherwise:      `caller` is `v.from`
    pub fn from_json(v: &Value, parent_ty: &str, parent_addr: &str) -> Self {
        let ty = v["type"].as_str().unwrap_or_default().to_lowercase();
        let caller = if parent_ty == "delegatecall" {
            parent_addr.to_string()
        } else {
            checksum(v["from"].as_str().unwrap_or_default())
        };

        let target = checksum(v["to"].as_str().unwrap_or_default());
        let target_var = hash_to_name(&target);
        let value = v["value"].as_str().unwrap_or("0x0").to_string();
        let value = U256::from_str_radix(value.trim_start_matches("0x"), 16).unwrap_or_default();
        let input = v["input"].as_str().unwrap_or_default().to_string();
        let output = v["output"].as_str().unwrap_or_default().to_string();
        let default_sub_calls = vec![];
        let sub_calls = v["calls"]
            .as_array()
            .unwrap_or(&default_sub_calls)
            .iter()
            .map(|v| Call::from_json(v, &ty, &target))
            .collect();

        Self {
            ty,
            caller,
            target,
            target_var,
            value,
            input,
            output,
            sub_calls,
        }
    }

    pub fn mock_parent(caller: &str, target: &str, call: &Call) -> Self {
        // set the `caller` of the sub_call to the `target` of the parent call
        let mut call = call.clone();
        call.caller = target.to_string();

        Self {
            ty: "call".to_string(),
            caller: caller.to_string(),
            target: target.to_string(),
            target_var: hash_to_name(target),
            sub_calls: vec![call],
            ..Default::default()
        }
    }
}
