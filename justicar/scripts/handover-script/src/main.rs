mod args;

use args::Args;
use clap::Parser;
use std::{path::Path, process::Stdio};
use tokio::{
    io::{AsyncBufReadExt, BufReader, BufWriter},
    process::{Child, ChildStdout, Command},
};
#[tokio::main]
async fn main() {
    let args = Args::parse();
    let client_version: u64;
    let server_version: u64;
    match tokio::fs::read_link(&args.client_version_path).await {
        Ok(real_path) => {
            if let Some(path_str) = real_path.to_str() {
                client_version = path_str
                    .split("/")
                    .last()
                    .expect("no last version number")
                    .parse::<u64>()
                    .expect("parse current ceseal version from str to u64 failed!");
            } else {
                panic!("can't get real path of current ceseal");
            }
        }
        Err(e) => panic!("Error reading symlink {}: {}", args.client_version_path, e),
    }
    log(format!("Current version: {}", client_version));

    // Get the path to the current Ceseal version and check whether it has been initialized.
    let current_ceseal_runtime_data_path = Path::new(&args.client_version_path)
        .join(&args.ceseal_protected_files_path)
        .join("runtime-data.seal");
    if current_ceseal_runtime_data_path.exists() {
        log(format!("runtime-data.seal exists, no need to handover"));
        return;
    }
}

const LOG_PREFIX: &str = "[🧑‍⚖️]";
fn log(log_text: String) {
    println!("{} {}", LOG_PREFIX, log_text)
}
