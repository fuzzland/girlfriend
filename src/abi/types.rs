use std::fmt::Display;

use serde::Serialize;

/// Primary values and variables of other types.
#[derive(Debug, Serialize, Default, Clone, PartialEq, Eq)]
pub struct DecodedArg {
    pub ty: String,
    pub value: String,
    pub is_dynamic: bool,
}

/// Bytes
#[derive(Debug, Serialize, Default, Clone, PartialEq, Eq)]
pub struct Bytes {
    pub var_name: String,
    /// some bytes are decoded as a selector with decoded_args.
    pub selector: Option<String>,
    pub parts: Vec<DecodedArg>,
}

/// Struct Definition
#[derive(Debug, Default, Serialize, Clone, PartialEq, Eq)]
pub struct StructDef {
    pub name: String,
    // e.g. uint256 p0
    pub props: Vec<String>,
}

/// Struct Instance
#[derive(Debug, Serialize, Default, Clone, PartialEq, Eq)]
pub struct StructIns {
    pub struct_name: String,
    pub var_name: String,
    pub values: Vec<DecodedArg>,
}

/// Array
#[derive(Debug, Serialize, Default, Clone, PartialEq, Eq)]
pub struct Array {
    /// Solity type
    pub inner_type: String,
    /// Fixed size array has length.
    pub len: Option<usize>,
    /// Variable name
    pub var_name: String,
    /// values or variables of other types.
    pub values: Vec<String>,
}

/// Memory variable
#[derive(Debug, Serialize, Default, Clone, PartialEq, Eq)]
pub enum MemoryVar {
    #[default]
    None,
    Bytes(Bytes),
    Array(Array),
    StructIns(StructIns),
}

impl DecodedArg {
    pub fn new(ty: &str, value: &str, is_dynamic: bool) -> Self {
        Self {
            ty: ty.to_string(),
            value: value.to_string(),
            is_dynamic,
        }
    }

    pub fn replace_sender(&mut self, sender_var: &str) {
        if self.ty == "address" && self.value == sender_var {
            self.value = "tx.origin".to_string();
        }
    }

    pub fn replace_receiver(&mut self, receiver_var: &str) {
        if self.ty == "address" && self.value == receiver_var {
            self.value = "r".to_string();
        }
    }
}

impl Display for DecodedArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(convert) = get_convertion(&self.ty) {
            write!(f, "{convert}({}))", self.value)
        } else {
            write!(f, "{}", self.value)
        }
    }
}

impl Bytes {
    pub fn new(var_name: &str, selector: Option<String>, parts: &[DecodedArg]) -> Self {
        Self {
            var_name: var_name.to_string(),
            selector,
            parts: parts.to_vec(),
        }
    }

    pub fn replace_sender(&mut self, sender_var: &str) {
        for part in self.parts.iter_mut() {
            part.replace_sender(sender_var);
        }
    }

    pub fn replace_receiver(&mut self, receiver_var: &str) {
        for part in self.parts.iter_mut() {
            part.replace_receiver(receiver_var);
        }
    }

    pub fn value(&self) -> String {
        match self.selector {
            Some(ref s) => {
                if self.parts.is_empty() {
                    format!("abi.encodeWithSelector({})", s)
                } else {
                    let args = self.parts.iter().map(|p| p.to_string()).collect::<Vec<_>>();
                    format!("abi.encodeWithSelector({}, {})", s, args.join(", "))
                }
            }
            None => {
                if self.parts.is_empty() {
                    "\"\"".to_string()
                } else if self.parts.len() == 1 && self.parts[0].ty == "bytes" {
                    self.parts[0].to_string()
                } else {
                    let args = self.parts.iter().map(|p| p.to_string()).collect::<Vec<_>>();
                    format!("abi.encode({})", args.join(", "))
                }
            }
        }
    }
}

impl Display for Bytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "bytes memory {} = {};", self.var_name, self.value())
    }
}

impl StructDef {
    pub fn new(name: &str, props: &[String]) -> Self {
        Self {
            name: name.to_string(),
            props: props.to_vec(),
        }
    }
}

impl StructIns {
    pub fn new(struct_name: &str, var_name: &str, values: &[DecodedArg]) -> Self {
        Self {
            struct_name: struct_name.to_string(),
            var_name: var_name.to_string(),
            values: values.to_vec(),
        }
    }

    pub fn replace_sender(&mut self, sender_var: &str) {
        for value in self.values.iter_mut() {
            value.replace_sender(sender_var);
        }
    }

    pub fn replace_receiver(&mut self, receiver_var: &str) {
        for value in self.values.iter_mut() {
            value.replace_receiver(receiver_var);
        }
    }

    pub fn value(&self) -> String {
        let args = self.values.iter().map(|p| p.to_string()).collect::<Vec<_>>();
        format!("{}({})", self.struct_name, args.join(", "))
    }
}

impl Display for StructIns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} memory {} = {};", self.struct_name, self.var_name, self.value())
    }
}

impl Array {
    pub fn new(inner_type: &str, len: Option<usize>, var_name: &str, values: &[String]) -> Self {
        Self {
            inner_type: inner_type.to_string(),
            len,
            var_name: var_name.to_string(),
            values: values.to_vec(),
        }
    }

    pub fn replace_sender(&mut self, sender_var: &str) {
        if self.inner_type == "address" {
            for value in self.values.iter_mut() {
                if value == sender_var {
                    *value = "tx.origin".to_string();
                }
            }
        }
    }

    pub fn replace_receiver(&mut self, receiver_var: &str) {
        if self.inner_type == "address" {
            for value in self.values.iter_mut() {
                if value == receiver_var {
                    *value = "r".to_string();
                }
            }
        }
    }

    pub fn generate_sol_code(&self) -> Vec<String> {
        let mut code = vec![];
        // declaration
        if let Some(len) = self.len {
            code.push(format!("{}[{}] memory {};", self.inner_type, len, self.var_name));
        } else {
            code.push(format!(
                "{}[] memory {} = new {}[]({});",
                self.inner_type,
                self.var_name,
                self.inner_type,
                self.values.len()
            ));
        }

        let convertion = get_convertion(&self.inner_type);
        // assignments
        for (i, value) in self.values.iter().enumerate() {
            if let Some(convertion) = &convertion {
                code.push(format!("{}[{i}] = {convertion}({value}));", self.var_name));
            } else {
                code.push(format!("{}[{i}] = {value};", self.var_name));
            }
        }

        code
    }

    pub fn value(&self) -> String {
        let convertion = get_convertion(&self.inner_type);
        if let Some(convertion) = &convertion {
            let values = self
                .values
                .iter()
                .map(|v| format!("{}({})", convertion, v))
                .collect::<Vec<_>>();
            format!("new {}[]({})", self.inner_type, values.join(", "))
        } else {
            format!("new {}[]({})", self.inner_type, self.values.join(", "))
        }
    }
}

impl MemoryVar {
    pub fn replace_sender(&mut self, sender_var: &str) {
        match self {
            MemoryVar::Bytes(bytes) => bytes.replace_sender(sender_var),
            MemoryVar::Array(array) => array.replace_sender(sender_var),
            MemoryVar::StructIns(struct_ins) => struct_ins.replace_sender(sender_var),
            _ => {}
        }
    }

    pub fn replace_receiver(&mut self, receiver_var: &str) {
        match self {
            MemoryVar::Bytes(bytes) => bytes.replace_receiver(receiver_var),
            MemoryVar::Array(array) => array.replace_receiver(receiver_var),
            MemoryVar::StructIns(struct_ins) => struct_ins.replace_receiver(receiver_var),
            _ => {}
        }
    }

    pub fn generate_sol_code(&self) -> Vec<String> {
        match self {
            MemoryVar::Bytes(bytes) => vec![bytes.to_string()],
            MemoryVar::Array(array) => array.generate_sol_code(),
            MemoryVar::StructIns(struct_ins) => vec![struct_ins.to_string()],
            _ => vec![],
        }
    }

    pub fn into_bytes(self) -> Option<Bytes> {
        match self {
            MemoryVar::Bytes(bytes) => Some(bytes),
            _ => None,
        }
    }

    pub fn var_name(&self) -> Option<String> {
        match self {
            MemoryVar::Bytes(bytes) => Some(bytes.var_name.clone()),
            MemoryVar::Array(array) => Some(array.var_name.clone()),
            MemoryVar::StructIns(struct_ins) => Some(struct_ins.var_name.clone()),
            _ => None,
        }
    }

    pub fn value(&self) -> Option<String> {
        match self {
            MemoryVar::Bytes(bytes) => Some(bytes.value()),
            MemoryVar::Array(array) => Some(array.value()),
            MemoryVar::StructIns(struct_ins) => Some(struct_ins.value()),
            _ => None,
        }
    }
}

fn get_convertion(ty: &str) -> Option<String> {
    if ty.starts_with("bytes") && !ty.ends_with(']') && ty != "bytes" && ty != "bytes32" {
        return Some(format!("{}(bytes32", ty));
    }

    None
}
