use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Encrypt secret.
    ///
    /// This command simulates the `NCryptProtectSecret` function. The encrypted secret (DPAPI blob) will be printed to stdout.
    Encrypt {
        /// User's SID.
        #[arg(long, short = 'i')]
        sid: String,

        /// Secret to encrypt.
        ///
        /// This parameter is optional. If not provided, the app will try to read the secret from stdin.
        #[arg(long)]
        secret: Option<String>,
    },

    /// Decrypt DPAPI blob.
    ///
    /// This command simulates the `NCryptUnprotectSecret` function. The decrypted secret will be printed to stdout.
    Decrypt {
        /// Path to file that contains DPAPI blob.
        ///
        /// This parameter is optional. If not provided, the app will try to read the DPAPI blob from stdin.
        #[arg(long, short = 'f')]
        file: Option<PathBuf>,
    },
}

/// DPAPI cli client.
///
/// This app is used to encrypt/decrypt secrets using the DPAPI.
#[derive(Debug, Parser)]
#[command(version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Target server hostname.
    ///
    /// For example, `win-956cqossjtf.tbt.com`.
    #[arg(long, short = 's')]
    pub server: String,

    /// The username to decrypt/encrypt the DPAPI blob.
    ///
    /// The username can be specified in FQDN (DOMAIN\username) or UPN (username@domain) format.
    #[arg(long, short = 'u')]
    pub username: String,

    /// User's password.
    #[arg(long, short = 'p')]
    pub password: String,

    /// Client's computer name.
    ///
    /// This parameter is optional. If not provided, the current computer name will be used.
    #[arg(long)]
    pub computer_name: Option<String>,
}
