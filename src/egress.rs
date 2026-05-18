//! Egress: HTTP(S) for the enclave by tunneling to the parent host on VSOCK port 5006.
//! On each connection, the first line is `host:port\\n`; the host opens TCP to that target and
//! `copy_bidirectional`s. TLS is end-to-end in the enclave (this module); the host is a byte pipe.
//!
//! Dev (non-Linux): TCP `127.0.0.1:5006` instead of VSOCK.

use std::cell::RefCell;
use std::io;
use std::sync::OnceLock;
use std::time::Duration;

use boa_engine::error::{JsError, JsNativeError};
use boa_engine::object::ObjectInitializer;
use boa_engine::property::PropertyKey;
use boa_engine::property::Attribute;
use boa_engine::{js_string, Context, JsArgs, JsResult, JsValue, NativeFunction, JsString};
use k256::ecdsa::SigningKey;
use sha3::{Digest, Keccak256};
use rustls::ClientConfig;
use rustls::RootCertStore;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use url::Url;

#[cfg(target_os = "linux")]
use tokio_vsock::VsockStream;
#[cfg(not(target_os = "linux"))]
use tokio::net::TcpStream;

const EGRESS_PROXY_PORT: u16 = 5006;
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// Parent instance VSOCK CID. AWS Nitro uses 3. Override: `TEEIFY_PARENT_VSOCK_CID`.
#[cfg(target_os = "linux")]
fn parent_vsock_cid() -> u32 {
    std::env::var("TEEIFY_PARENT_VSOCK_CID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3)
}

fn tls_config() -> std::sync::Arc<ClientConfig> {
    static S: OnceLock<std::sync::Arc<ClientConfig>> = OnceLock::new();
    S.get_or_init(|| {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        std::sync::Arc::new(
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        )
    })
    .clone()
}

/// EIP-191 `personal_sign`: `keccak256("\x19Ethereum Signed Message:\n" + len + msg)` then ECDSA
/// with recovery; returns 65-byte `r||s||v` hex (`v` = recovery id + 27).
fn ethereum_personal_sign_hex(sk: &SigningKey, message: &str) -> Result<String, String> {
    let msg_bytes = message.as_bytes();
    let prefix = format!("\x19Ethereum Signed Message:\n{}", msg_bytes.len());
    let mut preimage = Vec::with_capacity(prefix.len() + msg_bytes.len());
    preimage.extend_from_slice(prefix.as_bytes());
    preimage.extend_from_slice(msg_bytes);

    let digest = Keccak256::digest(&preimage);
    let (sig, recid) = sk
        .sign_prehash_recoverable(&digest)
        .map_err(|e| format!("ecdsa: {e}"))?;

    let mut compact = [0u8; 65];
    compact[..64].copy_from_slice(<[u8; 64]>::from(sig.to_bytes()).as_slice());
    compact[64] = recid
        .to_byte()
        .checked_add(27)
        .ok_or_else(|| "invalid recovery id for Ethereum v byte".to_string())?;

    Ok(format!("0x{}", hex::encode(compact)))
}

/// Register `globalThis.teeify = { fetch, signMessage }`.
///
/// `signMessage` uses the enclave wallet key (`personal_sign` / EIP-191 over the UTF-8 string).
pub fn register_teeify(context: &mut Context, wallet: &SigningKey) -> JsResult<()> {
    let sk_sign = wallet.clone();
    // SAFETY: Capture is a plain `SigningKey` (no `Gc` / JS values). Safe for Boa's non-traced closure.
    let sign_message = unsafe {
        NativeFunction::from_closure(move |_this, args, ctx| {
            let arg0 = args.get_or_undefined(0);
            if arg0.is_undefined() || arg0.is_null() {
                return Err(
                    JsNativeError::typ()
                        .with_message("teeify.signMessage: string payload is required")
                        .into(),
                );
            }
            let payload = arg0
                .to_string(ctx)?
                .to_std_string_escaped();
            let hex_sig = ethereum_personal_sign_hex(&sk_sign, &payload).map_err(|e| -> JsError {
                JsNativeError::error()
                    .with_message(format!("teeify.signMessage: {e}"))
                    .into()
            })?;
            Ok(JsValue::from(JsString::from(hex_sig)))
        })
    };

    let mut init = ObjectInitializer::new(context);
    init.function(
        NativeFunction::from_async_fn(teeify_fetch),
        js_string!("fetch"),
        2,
    );
    init.function(sign_message, js_string!("signMessage"), 1);
    let obj = init.build();
    context.register_global_property(js_string!("teeify"), obj, Attribute::all())?;
    Ok(())
}

fn parse_fetch_options(
    args: &[JsValue],
    ctx: &RefCell<&mut Context>,
) -> Result<(String, String, Option<String>, Vec<(String, String)>), boa_engine::error::JsError> {
    let mut c = ctx.borrow_mut();
    let url_v = args.get_or_undefined(0);
    if url_v.is_undefined() || url_v.is_null() {
        return Err(
            JsNativeError::typ().with_message("teeify.fetch: first argument (url) is required")
                .into(),
        );
    }
    let url_s = url_v
        .to_string(&mut c)?
        .to_std_string_escaped();
    if url_s.is_empty() {
        return Err(JsNativeError::typ().with_message("teeify.fetch: url is empty").into());
    }

    let mut method = "GET".to_string();
    let mut body: Option<String> = None;
    let mut headers: Vec<(String, String)> = Vec::new();

    if let Some(o) = args.get(1).and_then(JsValue::as_object) {
        let m = o.get(js_string!("method"), &mut c)?;
        if !m.is_undefined() {
            let s = m.to_string(&mut c)?.to_std_string_escaped();
            if !s.is_empty() {
                method = s;
            }
        }

        let b = o.get(js_string!("body"), &mut c)?;
        if !b.is_undefined() && !b.is_null() {
            body = Some(b.to_string(&mut c)?.to_std_string_escaped());
        }

        let h = o.get(js_string!("headers"), &mut c)?;
        if let Some(ho) = h.as_object() {
            for key in ho.own_property_keys(&mut c)? {
                let name: String = match &key {
                    PropertyKey::String(s) => s.to_std_string_escaped(),
                    PropertyKey::Index(_) | PropertyKey::Symbol(_) => {
                        continue;
                    }
                };
                if name.is_empty() {
                    continue;
                }
                if name.eq_ignore_ascii_case("host")
                    || name.eq_ignore_ascii_case("content-length")
                    || name.eq_ignore_ascii_case("connection")
                {
                    continue;
                }
                let v = ho.get(key, &mut c)?;
                if v.is_undefined() {
                    continue;
                }
                let vs = v.to_string(&mut c)?.to_std_string_escaped();
                headers.push((name, vs));
            }
        }
    }
    drop(c);
    Ok((url_s, method, body, headers))
}

pub(crate) enum Tunnel {
    #[cfg(target_os = "linux")]
    Vsock(VsockStream),
    #[cfg(not(target_os = "linux"))]
    Tcp(TcpStream),
}

impl Tunnel {
    pub(crate) async fn write_all_flush(&mut self, buf: &[u8]) -> io::Result<()> {
        match self {
            #[cfg(target_os = "linux")]
            Self::Vsock(s) => {
                s.write_all(buf).await?;
                s.flush().await
            }
            #[cfg(not(target_os = "linux"))]
            Self::Tcp(s) => {
                s.write_all(buf).await?;
                s.flush().await
            }
        }
    }
}

/// Raw VSOCK/TCP connection to the parent egress courier (`:5006`) without a target line yet.
pub(crate) async fn open_tunnel() -> io::Result<Tunnel> {
    #[cfg(target_os = "linux")]
    {
        VsockStream::connect(parent_vsock_cid(), u32::from(EGRESS_PROXY_PORT))
            .await
            .map(Tunnel::Vsock)
    }
    #[cfg(not(target_os = "linux"))]
    {
        TcpStream::connect((
            "127.0.0.1",
            EGRESS_PROXY_PORT,
        ))
            .await
            .map(Tunnel::Tcp)
    }
}

/// Open the blind tunnel and send `host:port\\n` so the host dials the real remote (e.g. KMS :443).
pub(crate) async fn egress_bridged_stream(host: &str, port: u16) -> io::Result<Tunnel> {
    let mut t = open_tunnel().await?;
    let line = format!("{host}:{port}\n");
    t.write_all_flush(line.as_bytes()).await?;
    Ok(t)
}

pub(crate) async fn copy_bidirectional_tunnel(
    tcp_peer: &mut tokio::net::TcpStream,
    tunnel: &mut Tunnel,
) -> io::Result<()> {
    let _ = match tunnel {
        #[cfg(target_os = "linux")]
        Tunnel::Vsock(s) => tokio::io::copy_bidirectional(tcp_peer, s).await?,
        #[cfg(not(target_os = "linux"))]
        Tunnel::Tcp(s) => tokio::io::copy_bidirectional(tcp_peer, s).await?,
    };
    Ok(())
}

async fn run_https_fetch(
    url: &Url,
    method: &str,
    body: Option<&str>,
    extra_headers: &[(String, String)],
) -> Result<Vec<u8>, boa_engine::error::JsError> {
    let h = url
        .host_str()
        .ok_or::<boa_engine::error::JsError>(
            JsNativeError::typ()
                .with_message("teeify.fetch: url has no host")
                .into(),
        )?;
    let port = url.port_or_known_default().unwrap_or(443);
    let line = format!("{h}:{port}\n");

    let mut t = open_tunnel()
        .await
        .map_err(|e| JsNativeError::error().with_message(format!("egress socket: {e}")))?;
    t.write_all_flush(line.as_bytes())
        .await
        .map_err(|e| JsNativeError::error().with_message(format!("egress target line: {e}")))?;

    let host_for_tls = h.to_string();
    let connector = tokio_rustls::TlsConnector::from(tls_config());
    let dns = ServerName::try_from(host_for_tls.clone()).map_err(|_| {
        JsNativeError::error().with_message("teeify.fetch: invalid TLS server name (SNI)")
    })?;

    let mut tls = match t {
        #[cfg(target_os = "linux")]
        Tunnel::Vsock(s) => connector
            .connect(dns, s)
            .await
            .map_err(|e| JsNativeError::error().with_message(format!("TLS handshake: {e}")))?,
        #[cfg(not(target_os = "linux"))]
        Tunnel::Tcp(s) => connector
            .connect(dns, s)
            .await
            .map_err(|e| JsNativeError::error().with_message(format!("TLS handshake: {e}")))?,
    };

    let req = build_http_request(url, method, body, extra_headers);
    tls.write_all(req.as_bytes())
        .await
        .map_err(|e| JsNativeError::error().with_message(format!("egress write: {e}")))?;
    read_response_capped(tls).await
}

async fn run_http_fetch(
    url: &Url,
    method: &str,
    body: Option<&str>,
    extra_headers: &[(String, String)],
) -> Result<Vec<u8>, boa_engine::error::JsError> {
    let h = url
        .host_str()
        .ok_or::<boa_engine::error::JsError>(
            JsNativeError::typ()
                .with_message("teeify.fetch: url has no host")
                .into(),
        )?;
    let port = url.port_or_known_default().unwrap_or(80);
    let line = format!("{h}:{port}\n");

    let mut t = open_tunnel()
        .await
        .map_err(|e| JsNativeError::error().with_message(format!("egress socket: {e}")))?;
    t.write_all_flush(line.as_bytes())
        .await
        .map_err(|e| JsNativeError::error().with_message(format!("egress target line: {e}")))?;

    let mut t = match t {
        #[cfg(target_os = "linux")]
        Tunnel::Vsock(s) => s,
        #[cfg(not(target_os = "linux"))]
        Tunnel::Tcp(s) => s,
    };

    let req = build_http_request(url, method, body, extra_headers);
    t.write_all(req.as_bytes())
        .await
        .map_err(|e| JsNativeError::error().with_message(format!("egress write: {e}")))?;
    read_response_capped(t).await
}

fn build_http_request(
    url: &Url,
    method: &str,
    body: Option<&str>,
    extra_headers: &[(String, String)],
) -> String {
    let path = if url.path().is_empty() {
        "/".to_string()
    } else {
        url.path().to_string()
    };
    let query = url
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let request_path = format!("{path}{query}");
    let host = url.host_str().unwrap_or("");

    let mut r = format!(
        "{method} {request_path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: teeify-enclave/1\r\n"
    );
    for (k, v) in extra_headers {
        if k.eq_ignore_ascii_case("connection") {
            continue;
        }
        r.push_str(&format!("{k}: {v}\r\n"));
    }
    r.push_str("Connection: close\r\n");
    if let Some(b) = body {
        r.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    r.push_str("\r\n");
    if let Some(b) = body {
        r.push_str(b);
    }
    r
}

async fn read_response_capped(
    mut read: impl AsyncReadExt + Unpin,
) -> Result<Vec<u8>, boa_engine::error::JsError> {
    let response_fut = async {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 16 * 1024];
        loop {
            match read.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => {
                    if buf.len() + n > MAX_RESPONSE_BYTES {
                        return Err(
                            JsNativeError::error()
                                .with_message("teeify.fetch: response exceeded size limit (4 MiB)")
                                .into(),
                        );
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    // Server closed TCP without TLS close_notify (common for CDNs). Treat as EOF.
                    break;
                }
                Err(e) => {
                    return Err(
                        JsNativeError::error()
                            .with_message(format!("egress read: {e}"))
                            .into(),
                    );
                }
            }
        }
        Ok::<Vec<u8>, boa_engine::error::JsError>(buf)
    };

    timeout(Duration::from_secs(10), response_fut).await.map_err(|_| -> JsError {
        JsNativeError::error()
            .with_message("teeify.fetch: response read timed out (10s)")
            .into()
    })?
}

fn parse_http_response(bytes: &[u8]) -> Result<String, String> {
    let crlf_crlf = b"\r\n\r\n";
    let header_end = bytes
        .windows(4)
        .position(|w| w == crlf_crlf)
        .ok_or_else(|| "Incomplete HTTP response (no header/body delimiter)".to_string())?;

    let headers_str = String::from_utf8_lossy(&bytes[..header_end]);
    let mut body = &bytes[header_end + 4..];

    let is_chunked = headers_str
        .to_lowercase()
        .contains("transfer-encoding: chunked");

    if is_chunked {
        let mut dechunked = Vec::new();
        loop {
            if body.is_empty() {
                return Err("Incomplete chunked encoding (unexpected EOF before size line)".to_string());
            }
            let Some(crlf_pos) = body.windows(2).position(|w| w == b"\r\n") else {
                return Err("Incomplete chunked encoding (missing CRLF after size)".to_string());
            };
            let size_str = std::str::from_utf8(&body[..crlf_pos])
                .map_err(|_| "Invalid UTF-8 in chunk-size line".to_string())?;
            let size_token = size_str.split(';').next().unwrap_or("").trim();
            let size = usize::from_str_radix(size_token, 16)
                .map_err(|_| format!("Invalid chunk size: {:?}", size_token))?;

            body = &body[crlf_pos + 2..];

            if size == 0 {
                break;
            }

            if body.len() < size + 2 {
                return Err(format!(
                    "Incomplete chunk body (need {} bytes incl. CRLF, have {})",
                    size + 2,
                    body.len()
                ));
            }

            dechunked.extend_from_slice(&body[..size]);
            if body.get(size..size + 2) != Some(&[b'\r', b'\n']) {
                return Err("Malformed chunk framing (missing trailing CRLF)".to_string());
            }
            body = &body[size + 2..];
        }

        Ok(String::from_utf8_lossy(&dechunked).into_owned())
    } else {
        Ok(String::from_utf8_lossy(body).into_owned())
    }
}

/// After de-chunking: strip leading/trailing whitespace and NUL, then slice the outermost `{`/`}` or `[`/`]`.
fn extract_json_boundary(payload: &str) -> Result<String, String> {
    let trimmed = payload.trim_matches(|c: char| c.is_whitespace() || c == '\0');

    let start = trimmed.find('{').or_else(|| trimmed.find('['));
    let end = trimmed.rfind('}').or_else(|| trimmed.rfind(']'));
    match (start, end) {
        (Some(s), Some(e)) if e > s => Ok(trimmed[s..=e].to_string()),
        _ => Err("Could not locate JSON boundaries in response body".to_string()),
    }
}

async fn teeify_fetch(
    _this: &JsValue,
    args: &[JsValue],
    context: &RefCell<&mut Context>,
) -> JsResult<JsValue> {
    let (url_s, method, body, extra_headers) = parse_fetch_options(args, context)?;

    let url = Url::parse(&url_s)
        .map_err(|e| JsNativeError::typ().with_message(format!("teeify.fetch: bad url: {e}")))?;

    let body_ref = body.as_deref();
    let bytes: Vec<u8> = match url.scheme() {
        "https" => run_https_fetch(&url, &method, body_ref, &extra_headers).await?,
        "http" => run_http_fetch(&url, &method, body_ref, &extra_headers).await?,
        other => {
            return Err(
                JsNativeError::typ()
                    .with_message(format!(
                        "teeify.fetch: unsupported url scheme {other} (use http: or https:)"
                    ))
                    .into(),
            );
        }
    };

    let decoded_body = parse_http_response(&bytes).map_err(|e| -> JsError {
        JsNativeError::error()
            .with_message(format!("teeify.fetch HTTP decode error: {e}"))
            .into()
    })?;

    let json_str = extract_json_boundary(&decoded_body).map_err(|e| -> JsError {
        JsNativeError::error()
            .with_message(format!("teeify.fetch JSON boundary error: {e}"))
            .into()
    })?;

    Ok(JsValue::from(JsString::from(json_str)))
}
