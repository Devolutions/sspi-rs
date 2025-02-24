mod cli;
mod logging;

use std::fs;
use std::io::{stdin, stdout, Read, Result, Write};

use crate::cli::{Decrypt, Dpapi, DpapiCmd, Encrypt};

fn run(data: Dpapi) -> Result<()> {
    logging::init_logging();

    let Dpapi {
        server,
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

            let blob = dpapi::n_crypt_protect_secret(
                secret.into(),
                sid,
                None,
                &server,
                &username,
                password.into(),
                computer_name,
            )
            .unwrap();

            stdout().write_all(&blob)?;
        }
        DpapiCmd::Decrypt(Decrypt { file }) => {
            let blob = if let Some(file) = file {
                fs::read(file)?
            } else {
                stdin().bytes().collect::<Result<Vec<_>>>()?
            };

            let secret =
                dpapi::n_crypt_unprotect_secret(&blob, &server, &username, password.into(), computer_name).unwrap();

            stdout().write_all(secret.as_ref())?;
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    match Dpapi::from_env() {
        Ok(flags) => run(flags),
        Err(err) => err.exit(),
    }
}
