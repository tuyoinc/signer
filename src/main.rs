//! tuyo-signer: an offline signer for Tuyo agents.

mod backends;
mod config;
mod error;
mod fsutil;
mod keys;
mod mcp;
mod service;
mod state;
mod touchid;
mod update;

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use serde_json::json;

use backends::{FileBackend, KeyStorage, KeychainBackend, StorageSetting};
use config::{Config, Overrides};
use error::SignerError;
use service::{Hooks, Service};
use state::StateStore;
use update::Updater;

#[derive(Parser)]
#[command(
    name = "tuyo-signer",
    version,
    about = "Offline signer for Tuyo agents. Keeps secp256k1 keys in the OS keychain or an owner-only file and signs hashes."
)]
struct Cli {
    /// Profile name (TUYO_SIGNER_PROFILE, default "default").
    #[arg(long, global = true)]
    profile: Option<String>,
    /// Profile directory (TUYO_SIGNER_DATA_DIR).
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    /// Key storage for new signers: auto, keychain or file (TUYO_SIGNER_KEY_STORAGE, default auto).
    #[arg(long, global = true)]
    storage: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the MCP server on stdin and stdout.
    Mcp,
    /// List the profile's signers.
    List,
    /// Show one signer.
    Get { tag: String },
    /// Create a signer, or show the existing one with this tag.
    Create {
        tag: String,
        /// macOS: require Touch ID for every signature. Cannot be changed later.
        #[arg(long)]
        require_touch_id: bool,
    },
    /// Sign a 32-byte hash with personal_sign (EIP-191).
    SignHash {
        /// The signer's address or tag.
        #[arg(long)]
        signer: String,
        /// The 32-byte hash, 0x-prefixed.
        #[arg(long)]
        hash: String,
    },
    /// Show version, configuration and update status.
    Status {
        /// Check for a new release now.
        #[arg(long)]
        check: bool,
    },
    /// Install the latest release over this binary.
    Update,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // Errors never include keys, signatures or file contents.
            let _ = writeln!(
                std::io::stderr(),
                "{}",
                json!({"code": error.code, "message": error.message})
            );
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), SignerError> {
    let config = Config::load(Overrides {
        profile: cli.profile,
        data_dir: cli.data_dir,
        storage: cli.storage,
    })?;
    let updater = Updater::from_env();
    let service = Service {
        store: StateStore::new(config.data_dir.clone()),
        storage: KeyStorage {
            keychain: Box::new(KeychainBackend::new(&config.data_dir)),
            file: Box::new(FileBackend::new(config.key_dir.clone())),
            setting: config.storage,
            keychain_usable: Box::new(backends::keychain_usable),
        },
        hooks: Hooks::system(),
    };

    match cli.command {
        Command::Mcp => {
            background_update(updater);
            let updater = Updater::from_env();
            let server = mcp::Server {
                service: &service,
                updater: &updater,
                profile: config.profile.clone(),
                storage: config.storage.as_str(),
            };
            server
                .run(std::io::stdin().lock(), std::io::stdout().lock())
                .map_err(|_| {
                    SignerError::new("io_error", "The MCP connection closed unexpectedly.")
                })
        }
        Command::List => print(service.list_signers()?),
        Command::Get { tag } => print(service.get_signer(&tag)?),
        Command::Create {
            tag,
            require_touch_id,
        } => print(service.create_signer(&tag, require_touch_id)?),
        Command::SignHash { signer, hash } => print(service.sign_hash(&signer, &hash)?),
        Command::Status { check } => {
            let check_error = if check {
                updater.check(true).err()
            } else {
                None
            };
            let mut status = serde_json::to_value(updater.status()).expect("serializable");
            status["profile"] = json!(config.profile);
            status["dataDirectory"] = json!(config.data_dir);
            status["keyDirectory"] = json!(config.key_dir);
            status["keyStorage"] = json!(config.storage.as_str());
            if config.storage == StorageSetting::Auto {
                status["keychainUsable"] = json!(backends::keychain_usable());
            }
            status["touchIdAvailable"] = json!(touchid::available().is_ok());
            if let Some(error) = check_error {
                status["checkError"] = json!({"code": error.code, "message": error.message});
            }
            print(status)
        }
        Command::Update => match updater.apply()? {
            Some(version) => print(json!({"updated": true, "version": version})),
            None => print(json!({"updated": false, "version": update::VERSION})),
        },
    }
}

/// Checks for a release at most once a day while the MCP server runs, and
/// installs it when TUYO_SIGNER_AUTO_UPDATE=1 (for agent machines we run).
/// The new version takes effect on the next start.
fn background_update(updater: Updater) {
    let var = |name: &str| std::env::var(name).unwrap_or_default();
    if !updater.enabled() || var("TUYO_SIGNER_UPDATE_CHECK") == "0" {
        return;
    }
    let auto = var("TUYO_SIGNER_AUTO_UPDATE") == "1";
    std::thread::spawn(move || {
        if updater.check(false).is_ok() && auto && updater.status().update_available {
            match updater.apply() {
                Ok(Some(version)) => eprintln!(
                    "tuyo-signer: installed {version}; it takes effect on the next start."
                ),
                Ok(None) => {}
                Err(error) => eprintln!("tuyo-signer: automatic update failed: {}", error.code),
            }
        }
    });
}

fn print(value: impl serde::Serialize) -> Result<(), SignerError> {
    println!(
        "{}",
        serde_json::to_string_pretty(&value).expect("serializable")
    );
    Ok(())
}
