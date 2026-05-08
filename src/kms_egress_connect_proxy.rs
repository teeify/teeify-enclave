//! Local HTTP `CONNECT` proxy so the AWS SDK can tunnel HTTPS (e.g. KMS) through the parent blind
//! courier: each `CONNECT` becomes our `host:port\\n` line on VSOCK :5006, then bytes are bridged.
//! The SDK is configured with explicit [`ProxyConfig::https`] (no `HTTPS_PROXY` env; Rust 2024 makes
//! `set_var` unsafe for concurrent reads).

use std::io;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use url::Url;

const DEFAULT_PROXY_PORT: u16 = 5107;
pub(crate) const ENV_PROXY_PORT: &str = "TEEIFY_KMS_HTTPS_PROXY_PORT";

static INIT: Mutex<Option<u16>> = Mutex::const_new(None);

/// Bind loopback CONNECT proxy and spawn accept loop. Returns the port (for `ProxyConfig`).
pub async fn ensure_started() -> u16 {
    let mut g = INIT.lock().await;
    if let Some(p) = *g {
        return p;
    }
    let port: u16 = std::env::var(ENV_PROXY_PORT)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_PROXY_PORT);
    let addr = format!("127.0.0.1:{port}");
    let listener = TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("KMS egress CONNECT proxy bind {addr}: {e}"));

    println!("🔒 KMS: HTTPS via CONNECT proxy http://127.0.0.1:{port} → VSOCK egress :5006");

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((sock, _)) => {
                    println!("🔍 Proxy: Accepted connection from SDK!");
                    println!("🔒 KMS Proxy: AWS SDK successfully connected to local tunnel!");
                    tokio::spawn(async move {
                        let _ = handle_connect_client(sock).await;
                    });
                }
                Err(e) => eprintln!("kms CONNECT proxy accept: {e}"),
            }
        }
    });

    *g = Some(port);
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    port
}

async fn handle_connect_client(mut inbound: TcpStream) -> Result<(), io::Error> {
    let mut reader = tokio::io::BufReader::new(&mut inbound);
    let mut first = String::new();
    reader.read_line(&mut first).await?;
    println!("🔍 Proxy: Read first line: {:?}", first);
    let parts: Vec<&str> = first.split_whitespace().collect();
    if parts.len() < 2 || !parts[0].eq_ignore_ascii_case("CONNECT") {
        return Ok(());
    }
    let authority = parts[1];
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line == "\r\n" || line == "\n" {
            break;
        }
    }

    // Peek-ahead TLS bytes already read into BufReader must be forwarded on the tunnel.
    let leftover = reader.buffer().to_vec();

    let u = match Url::parse(&format!("http://{authority}")) {
        Ok(u) => u,
        Err(_) => return Ok(()),
    };
    let Some(host) = u.host_str() else {
        return Ok(());
    };
    let port = u.port_or_known_default().unwrap_or(443);

    let mut tunnel = match crate::egress::egress_bridged_stream(host, port).await {
        Ok(t) => t,
        Err(e) => {
            println!("❌ Proxy Error: Could not bridge egress: {:?}", e);
            return Ok(());
        }
    };

    let mut inbound = reader.into_inner();
    inbound
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await?;
    inbound.flush().await?;
    if !leftover.is_empty() {
        tunnel.write_all_flush(&leftover).await?;
    }

    crate::egress::copy_bidirectional_tunnel(&mut inbound, &mut tunnel).await?;
    println!("✅ Proxy: Tunnel established successfully!");
    Ok(())
}
