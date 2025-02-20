mod cli;
mod logging;

use std::fs;
use std::io::{stdin, stdout, Read, Result, Write};

use clap::Parser;

use self::cli::{Cli, Command};

fn main() -> Result<()> {
    let Cli {
        command,
        server,
        username,
        password,
        computer_name,
    } = Cli::parse();

    logging::init_logging();

    match command {
        Command::Encrypt { sid, secret } => {
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
        Command::Decrypt { file } => {
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
