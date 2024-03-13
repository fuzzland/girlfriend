use serde_json::{json, Value};
use tracing::error;

#[derive(Debug)]
pub struct KV {
    inner: sled::Db,
}

impl KV {
    pub fn new(db_path: &str) -> Self {
        let db = sled::open(db_path).expect("failed to open db");
        KV { inner: db }
    }

    pub fn set(&self, key: &str, value: &str) {
        self.inner.insert(key, value).expect("failed to insert key-value");
    }

    pub fn get(&self, key: &str) -> Option<String> {
        match self.inner.get(key) {
            Ok(Some(value)) => Some(String::from_utf8(value.to_vec()).expect("failed to convert value to string")),
            Ok(None) => None,
            Err(e) => {
                error!("failed to get value from db: {}", e);
                None
            }
        }
    }

    pub fn load_fn_signatures(&self, data: &str) {
        // {"18160ddd": {"fn_signature": "totalSupply()","ret_signature": "uint256"}}
        let sigs: Value = serde_json::from_str(data).expect("failed to parse fn signatures");
        for (selector, value) in sigs.as_object().unwrap() {
            let fn_signature = value["fn_signature"].as_str().unwrap();
            let ret_signature = value["ret_signature"].as_str().unwrap().to_string();
            self.set_fn_signature(selector, fn_signature, Some(ret_signature));
        }
    }

    pub fn set_fn_signature(&self, selector: &str, fn_signature: &str, ret_signature: Option<String>) {
        let value = json!(
        {
            "fn_signature": fn_signature,
            "ret_signature": ret_signature.unwrap_or_default(),
        });
        self.set(selector, value.to_string().as_str());
    }

    pub fn get_fn_signature(&self, selector: &str) -> Option<(String, String)> {
        match self.get(selector) {
            Some(value) => {
                let value: Value = serde_json::from_str(value.as_str()).expect("failed to parse fn signature");
                let fn_signature = value["fn_signature"].as_str().unwrap().to_string();
                let ret_signature = value["ret_signature"].as_str().unwrap().to_string();
                Some((fn_signature, ret_signature))
            }
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kv() {
        let temp_path = tempfile::Builder::new()
            .prefix("tmp")
            .tempdir()
            .unwrap()
            .path()
            .to_str()
            .unwrap()
            .to_string();

        let kv = KV::new(&temp_path);
        kv.set("key1", "value1");
        kv.set("key2", "value2");
        assert_eq!(kv.get("key1"), Some(String::from("value1")));
        assert_eq!(kv.get("key2"), Some(String::from("value2")));
    }
}
