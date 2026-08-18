#![forbid(unsafe_code)]

//! Entry point of the ciphr server.
//!
//! Two arguments and no more: the configuration file, and `--check-config` to validate
//! it without starting. Everything else lives in the configuration file, because a
//! flag that changes behaviour is a difference between what the file says and what the
//! process does.

use std::process::ExitCode;

use ciphr_server::{Config, Server};

fn main() -> ExitCode {
    let mut arguments = std::env::args().skip(1);
    let first = arguments.next();

    let (config_path, check_only) = match first.as_deref() {
        Some("--check-config") => (arguments.next(), true),
        Some("--help" | "-h") | None => {
            usage();
            return ExitCode::from(2);
        }
        Some(path) => (Some(path.to_owned()), false),
    };

    let Some(config_path) = config_path else {
        usage();
        return ExitCode::from(2);
    };

    match run(&config_path, check_only) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // The one place in the workspace that writes to stderr: a process that
            // cannot start has to say why, and there is no audit trail to say it to.
            eprintln!("ciphr-server: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(config_path: &str, check_only: bool) -> Result<(), Box<dyn core::error::Error>> {
    let config = Config::load(config_path)?;

    if check_only {
        // Prepared but not served: this checks the policy file, the store, the master
        // key, and every audit device, which is most of what can be wrong.
        let _server = Server::prepare(config)?;
        println!("configuration and policies are usable");
        return Ok(());
    }

    let server = Server::prepare(config)?;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(server.serve())?;
    Ok(())
}

fn usage() {
    println!("usage: ciphr-server <config.toml>");
    println!("       ciphr-server --check-config <config.toml>");
}
