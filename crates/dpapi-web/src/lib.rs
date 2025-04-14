#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
#![allow(clippy::new_without_default)] // Default trait can’t be used by wasm consumer anyway

#[macro_use]
extern crate tracing;

mod error;
// mod network_client;
mod transport;

use std::cell::RefCell;
use std::rc::Rc;

use anyhow::Context;
use dpapi::CryptProtectSecretArgs;
use wasm_bindgen::prelude::*;

use crate::error::DpapiError;
// use crate::network_client::WasmNetworkClient;
use crate::transport::WasmTransport;

/// DPAPI command.
#[derive(Clone)]
enum Command {
    /// Encrypts the secret.
    Encrypt {
        /// User's SID.
        sid: String,
        /// Secret to encrypt.
        secret: String,
    },
    /// Decrypts the DPAPI blob.
    Decrypt {
        /// DPAPI blob.
        blob: Vec<u8>,
    },
}

/// DPAPI config.
#[wasm_bindgen]
#[derive(Clone)]
pub struct DpapiConfig(Rc<RefCell<DpapiConfigInner>>);

#[derive(Default)]
struct DpapiConfigInner {
    server: Option<String>,
    proxy: Option<String>,
    username: Option<String>,
    password: Option<String>,
    computer_name: Option<String>,
    command: Option<Command>,
}

#[wasm_bindgen]
impl DpapiConfig {
    /// Initilized the config.
    pub fn new() -> DpapiConfig {
        Self(Rc::new(RefCell::new(DpapiConfigInner::default())))
    }

    /// Set the target RPC server address.
    ///
    /// **Required**.
    pub fn server(&mut self, server: String) -> DpapiConfig {
        self.0.borrow_mut().server = Some(server);
        self.clone()
    }

    /// Set the proxy address.
    ///
    /// **Optional**.
    pub fn proxy(&mut self, proxy_addr: Option<String>) -> DpapiConfig {
        self.0.borrow_mut().proxy = proxy_addr;
        self.clone()
    }

    /// Set the AD user name.
    ///
    /// **Required**.
    pub fn username(&mut self, username: String) -> DpapiConfig {
        self.0.borrow_mut().username = Some(username);
        self.clone()
    }

    /// Set the AD user password.
    ///
    /// **Required**.
    pub fn password(&mut self, password: String) -> DpapiConfig {
        self.0.borrow_mut().password = Some(password);
        self.clone()
    }

    /// Set the client's computer name.
    ///
    /// **Optional**.
    pub fn computer_name(&mut self, computer_name: String) -> DpapiConfig {
        self.0.borrow_mut().computer_name = Some(computer_name);
        self.clone()
    }

    /// Set the encrypt command.
    ///
    /// Either [encrypt] or [decrypt] must be called.
    pub fn encrypt(&mut self, sid: String, secret: String) -> DpapiConfig {
        self.0.borrow_mut().command = Some(Command::Encrypt { sid, secret });
        self.clone()
    }

    /// Set the decrypt command.
    ///
    /// Either [encrypt] or [decrypt] must be called.
    pub fn decrypt(&mut self, blob: Vec<u8>) -> DpapiConfig {
        self.0.borrow_mut().command = Some(Command::Decrypt { blob });
        self.clone()
    }

    /// Run the DPAPI client.
    pub async fn run(&self) -> Result<Vec<u8>, DpapiError> {
        let (server, proxy, username, password, computer_name, command);

        {
            let inner = self.0.borrow_mut();

            server = inner.server.clone().context("server address missing")?;
            proxy = inner.proxy.clone();
            username = inner.username.clone().context("username missing")?;
            password = inner.password.clone().context("password missing")?;
            computer_name = inner.computer_name.clone();
            command = inner.command.clone().context("command missing")?;
        }

        match command {
            Command::Encrypt { sid, secret } => Ok(Box::pin(dpapi::n_crypt_protect_secret::<WasmTransport>(
                CryptProtectSecretArgs {
                    data: secret.into_bytes().into(),
                    sid,
                    root_key_id: None,
                    server: &server,
                    proxy: None,
                    username: &username,
                    password: password.into(),
                    client_computer_name: computer_name,
                },
            ))
            .await?),
            Command::Decrypt { blob } => Ok(Box::pin(dpapi::n_crypt_unprotect_secret::<WasmTransport>(
                &blob,
                &server,
                None,
                &username,
                password.into(),
                computer_name,
            ))
            .await?
            .as_ref()
            .to_owned()),
        }
    }
}

/// Initializes the panic hook and logger.
#[wasm_bindgen]
pub fn dpapi_init(log_level: &str) {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    //
    // For more details see
    // https://github.com/rustwasm/console_error_panic_hook#readme
    #[cfg(feature = "panic_hook")]
    console_error_panic_hook::set_once();

    if let Ok(level) = log_level.parse::<tracing::Level>() {
        set_logger_once(level);
    }
}

fn set_logger_once(level: tracing::Level) {
    use tracing_subscriber::filter::LevelFilter;
    use tracing_subscriber::fmt::time::UtcTime;
    use tracing_subscriber::prelude::*;
    use tracing_web::MakeConsoleWriter;

    static INIT: std::sync::Once = std::sync::Once::new();

    INIT.call_once(|| {
        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_timer(UtcTime::rfc_3339()) // std::time is not available in browsers
            .with_writer(MakeConsoleWriter);

        let level_filter = LevelFilter::from_level(level);

        tracing_subscriber::registry().with(fmt_layer).with(level_filter).init();

        debug!("DPAPI is ready");
    })
}
