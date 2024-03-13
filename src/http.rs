use std::{ops::Deref, thread, time::Duration};

use anyhow::Result;
use lazy_static::lazy_static;
use reqwest::{blocking::Response as BlockingResp, header::CONTENT_TYPE, Method, Response};

/// The maximum number of attempts for HTTP requests.
const MAX_ATTEMPTS: usize = 3;

lazy_static! {
    pub static ref HTTPC: BlockingClient = BlockingClient::new();
}

#[derive(Debug, Clone, Default)]
pub struct BlockingClient {
    inner: reqwest::blocking::Client,
}

// Impl `Deref` to allow `Client` to be used as a `reqwest::blocking::Client`.
impl Deref for BlockingClient {
    type Target = reqwest::blocking::Client;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl BlockingClient {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, url: &str) -> Result<BlockingResp> {
        self.try_request(Method::GET, url, None)
    }

    pub fn post(&self, url: &str, body: String) -> Result<BlockingResp> {
        self.try_request(Method::POST, url, Some(body))
    }

    pub fn try_request(&self, method: Method, url: &str, body: Option<String>) -> Result<BlockingResp> {
        let mut req = self.request(method.clone(), url).timeout(Duration::from_secs(180));
        if method == Method::POST {
            let body = body.unwrap_or_default();
            req = req.header(CONTENT_TYPE, "application/json").body(body);
        }

        let mut tries = 0;
        loop {
            match req.try_clone().unwrap().send() {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    tries += 1;
                    thread::sleep(Duration::from_secs(1));
                    if tries >= MAX_ATTEMPTS {
                        return Err(e)?;
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct AsyncClient {
    inner: reqwest::Client,
}

// Impl `Deref` to allow `Client` to be used as a `reqwest::Client`.
impl Deref for AsyncClient {
    type Target = reqwest::Client;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl AsyncClient {
    pub fn new() -> Self {
        let inner = reqwest::Client::builder()
            .timeout(Duration::from_secs(180))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();

        Self { inner }
    }

    pub async fn get(&self, url: &str) -> Result<Response> {
        self.try_request(Method::GET, url, None).await
    }

    pub async fn post(&self, url: &str, body: String) -> Result<Response> {
        self.try_request(Method::POST, url, Some(body)).await
    }

    pub async fn try_request(&self, method: Method, url: &str, body: Option<String>) -> Result<Response> {
        let mut req = self.request(method.clone(), url).timeout(Duration::from_secs(180));
        if method == Method::POST {
            let body = body.unwrap_or_default();
            req = req.header(CONTENT_TYPE, "application/json").body(body);
        }

        let mut tries = 0;
        loop {
            match req.try_clone().unwrap().send().await {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    tries += 1;
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    if tries >= MAX_ATTEMPTS {
                        return Err(e)?;
                    }
                }
            }
        }
    }
}
