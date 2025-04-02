#![warn(clippy::large_futures)]

mod cli;
mod logging;
mod network_client;
mod transport;

use std::fs;
use std::io::{stdin, stdout, Read, Result, Write};

use dpapi::client::CryptProtectSecretArgs;

use crate::cli::{Decrypt, Dpapi, DpapiCmd, Encrypt};
use crate::network_client::ReqwestNetworkClient;
use crate::transport::NativeTransport;

async fn run(data: Dpapi) -> Result<()> {
    logging::init_logging();

    let Dpapi {
        server,
        proxy_address,
        username,
        password,
        computer_name,
        subcommand,
    } = data;

    match subcommand {
        DpapiCmd::Encrypt(Encrypt { sid, secret }) => {
            let secret = if let Some(secret) = secret {
                secret.into_bytes()
            } else {
                stdin().bytes().collect::<Result<Vec<_>>>()?
            };

            let blob = Box::pin(dpapi::n_crypt_protect_secret::<NativeTransport>(
                CryptProtectSecretArgs {
                    data: secret.into(),
                    sid,
                    root_key_id: None,
                    server: &server,
                    proxy_addr: proxy_address,
                    username: &username,
                    password: password.into(),
                    client_computer_name: computer_name,
                },
                &mut ReqwestNetworkClient::new(),
            ))
            .await
            .unwrap();

            stdout().write_all(&blob)?;
        }
        DpapiCmd::Decrypt(Decrypt { file }) => {
            let blob = if let Some(file) = file {
                fs::read(file)?
            } else {
                stdin().bytes().collect::<Result<Vec<_>>>()?
            };

            let secret = Box::pin(dpapi::n_crypt_unprotect_secret::<NativeTransport>(
                &blob,
                &server,
                proxy_address,
                &username,
                password.into(),
                computer_name,
                &mut ReqwestNetworkClient::new(),
            ))
            .await
            .unwrap();

            stdout().write_all(secret.as_ref())?;
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    match Dpapi::from_env() {
        Ok(flags) => run(flags).await,
        Err(err) => err.exit(),
    }
}
