//! SIRA CLI — handshake, send, ping against any SIRA server.

mod wire;

use clap::{Parser, Subcommand};
use std::time::Instant;

use wire::{connect_ws_session, http_post_handshake, send_beat, send_clsend};

fn http_ws_bases(host: &str) -> (String, String) {
    let s = host.trim();
    if s.starts_with("http://") {
        let ws = s.replacen("http://", "ws://", 1);
        return (s.to_string(), ws);
    }
    if s.starts_with("https://") {
        let ws = s.replacen("https://", "wss://", 1);
        return (s.to_string(), ws);
    }
    if s.starts_with("ws://") {
        let http = s.replacen("ws://", "http://", 1);
        return (http, s.to_string());
    }
    if s.starts_with("wss://") {
        let http = s.replacen("wss://", "https://", 1);
        return (http, s.to_string());
    }
    (format!("http://{s}"), format!("ws://{s}"))
}

#[derive(Parser)]
#[command(name = "sira-cli", version, about = "SIRA CLI — test any SIRA server from terminal")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run POST /h only; print derived AES key prefix and cookie prefix
    Handshake {
        #[arg(long)]
        host: String,
        #[arg(long, default_value_t = false)]
        persistent: bool,
    },
    /// Full handshake + one CLsend round-trip
    Send {
        #[arg(long)]
        host: String,
        #[arg(long, default_value_t = false)]
        persistent: bool,
        #[arg(long, default_value_t = false)]
        raw: bool,
        /// JSON action (e.g. '{"type":"hello"}')
        json: String,
    },
    /// Heartbeat (BEAT) round-trip
    Ping {
        #[arg(long)]
        host: String,
        #[arg(long, default_value_t = 1)]
        count: u32,
    },
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Handshake {
            host,
            persistent,
        } => {
            let (http_base, _) = http_ws_bases(&host);
            println!("Connecting to {http_base}/h ...");
            let (key, cookie) = http_post_handshake(&http_base, persistent).await?;
            println!("Session established.");
            println!("AES key: {}...", hex::encode(&key[..8]));
            let show = cookie.chars().take(20).collect::<String>();
            println!("Cookie:  __s={show}...");
            println!("OK");
            Ok(())
        }
        Commands::Send {
            host,
            persistent,
            raw,
            json,
        } => {
            let (http_base, ws_base) = http_ws_bases(&host);
            println!("Connecting...");
            let t0 = Instant::now();
            let (key, cookie) = http_post_handshake(&http_base, persistent).await?;
            println!("Handshake: OK");
            let action: serde_json::Value =
                serde_json::from_str(&json).map_err(|e| format!("invalid JSON: {e}"))?;
            println!("Sending: {}", serde_json::to_string(&action).unwrap_or_default());
            let mut session = connect_ws_session(&ws_base, &cookie, key).await?;
            println!("Waiting for response...");
            let render = send_clsend(&mut session, action, raw).await?;
            let elapsed = t0.elapsed().as_millis();
            println!(
                "Response: {}",
                serde_json::to_string_pretty(&render).map_err(|e| e.to_string())?
            );
            println!("Round trip: {elapsed}ms");
            println!("OK");
            Ok(())
        }
        Commands::Ping { host, count } => {
            let (http_base, ws_base) = http_ws_bases(&host);
            println!("Connecting...");
            let (key, cookie) = http_post_handshake(&http_base, false).await?;
            println!("Handshake: OK");
            let mut session = connect_ws_session(&ws_base, &cookie, key).await?;
            for i in 0..count {
                if count > 1 {
                    println!("Ping {} / {} ...", i + 1, count);
                } else {
                    println!("Sending BEAT...");
                }
                let d = send_beat(&mut session).await?;
                println!("BEAT received: {}ms", d.as_millis());
            }
            println!("OK");
            Ok(())
        }
    }
}
