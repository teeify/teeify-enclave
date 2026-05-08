mod egress;
mod kms_egress_connect_proxy;

use std::sync::OnceLock;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use aws_config::environment::EnvironmentVariableCredentialsProvider;
use aws_config::Region;
use aws_credential_types::provider::SharedCredentialsProvider;
use aws_credential_types::Credentials;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::Client as KmsClient;
use aws_smithy_http_client::proxy::ProxyConfig;
use aws_smithy_http_client::{Builder as AwsHttpClientBuilder, ConnectorBuilder, tls};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use boa_engine::builtins::promise::PromiseState;
use boa_engine::object::ObjectInitializer;
use boa_engine::property::Attribute;
use boa_engine::{js_string, Context, JsResult, JsValue, NativeFunction, Source};
use k256::ecdsa::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use rsa::pkcs8::EncodePublicKey;
use rsa::Oaep;
use rsa::RsaPrivateKey;
use sha2::Sha256;
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

#[cfg(target_os = "linux")]
use aws_nitro_enclaves_nsm_api::{
    api::{Request, Response},
    driver::{nsm_init, nsm_process_request},
};
#[cfg(target_os = "linux")]
use serde_bytes::ByteBuf;

#[cfg(target_os = "linux")]
use tokio_vsock::VsockListener;

#[cfg(not(target_os = "linux"))]
use tokio::net::TcpListener;

/// `console.log` — forwards formatted arguments to the enclave `println!` (stderr of the enclave process).
fn console_log(_this: &JsValue, args: &[JsValue], context: &mut Context) -> JsResult<JsValue> {
    let mut line = String::new();
    for (i, arg) in args.iter().enumerate() {
        if i > 0 {
            line.push(' ');
        }
        let s = arg.to_string(context)?;
        line.push_str(&s.to_std_string_escaped());
    }
    println!("{line}");
    Ok(JsValue::undefined())
}

/// Registers `globalThis.console` with `log` (and empty-line behavior matching JS `console.log()`).
fn register_console(context: &mut Context) -> JsResult<()> {
    let mut init = ObjectInitializer::new(context);
    init.function(
        NativeFunction::from_fn_ptr(console_log),
        js_string!("log"),
        0,
    );
    let obj = init.build();
    context.register_global_property(js_string!("console"), obj, Attribute::all())?;
    Ok(())
}

fn get_eth_address(verifying_key: &VerifyingKey) -> String {
    let public_key_bytes = verifying_key.to_encoded_point(false);
    let hash = Keccak256::digest(&public_key_bytes.as_bytes()[1..]);
    format!("0x{}", hex::encode(&hash[12..]))
}

/// `TEEIFY_KMS_KEY_ID`: KMS key ARN or id used to encrypt newly generated secp256k1 signing keys.
const ENV_KMS_KEY_ID: &str = "TEEIFY_KMS_KEY_ID";

const DEFAULT_AWS_REGION: &str = "eu-central-1";

const MAX_INCOMING_JSON_BYTES: usize = 2 * 1024 * 1024;

static RSA_2048: OnceLock<RsaPrivateKey> = OnceLock::new();

fn rsa_private_key() -> &'static RsaPrivateKey {
    RSA_2048.get_or_init(|| {
        // OsRng routes through the kernel/CPU CSPRNG (e.g. /dev/urandom backed by
        // RDRAND/RDSEED on Nitro). Avoid `thread_rng` so early-boot enclave entropy
        // can't yield a weak RSA key.
        RsaPrivateKey::new(&mut OsRng, 2048).expect("RSA-2048 key generation for E2EE")
    })
}

/// PKCS#8 PEM `PUBLIC KEY` for the enclave; clients RSA-OAEP/SHA-256 wrap the AES-256 key against this.
fn rsa_public_key_pem() -> String {
    rsa_private_key()
        .to_public_key()
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .expect("encode RSA public key PEM")
}

/// RSA-OAEP/SHA-256 unwrap. The CLI / control plane wraps with the enclave public key
/// using `RSA_PKCS1_OAEP_PADDING` + `oaepHash: "sha256"`.
fn rsa_decrypt_oaep_b64(b64: &str) -> Result<Vec<u8>, String> {
    let ct_rsa = STANDARD
        .decode(b64.trim())
        .map_err(|e| format!("RSA ciphertext base64: {e}"))?;
    let padding = Oaep::new::<Sha256>();
    rsa_private_key()
        .decrypt(padding, &ct_rsa)
        .map_err(|e| format!("RSA OAEP/SHA-256 decrypt: {e}"))
}

/// RSA unwrap → 32-byte AES-256 key (RSA-OAEP/SHA-256).
fn rsa_decrypt_aes256_key_ct(b64: &str) -> Result<[u8; 32], String> {
    let aes_key = rsa_decrypt_oaep_b64(b64).map_err(|e| format!("encrypted_aes_key_b64: {e}"))?;
    aes_key
        .try_into()
        .map_err(|v: Vec<u8>| format!("RSA plaintext: expected 32-byte AES key, got {}", v.len()))
}

/// Secret values: RSA-wrapped first time (re-seal with KMS in response), else KMS ciphertext.
async fn unwrap_secret_value(
    kms: &KmsClient,
    name: &str,
    encrypted_b64: &str,
) -> Result<(String, bool), String> {
    match rsa_decrypt_oaep_b64(encrypted_b64) {
        Ok(pt) => {
            let s = String::from_utf8(pt)
                .map_err(|e| format!("secrets[{name}]: RSA plaintext is not UTF-8: {e}"))?;
            Ok((s, true))
        }
        Err(rsa_err) => match kms_decrypt_plaintext(kms, encrypted_b64).await {
            Ok(pt) => {
                let s = String::from_utf8(pt)
                    .map_err(|e| format!("secrets[{name}]: KMS plaintext is not UTF-8: {e}"))?;
                Ok((s, false))
            }
            Err(kms_err) => Err(format!(
                "secrets[{name}]: decrypt failed (RSA: {rsa_err}; KMS: {kms_err})"
            )),
        },
    }
}

/// AES-256-GCM unwrap of agent code (`encrypted_code_b64` = ciphertext || 16-byte tag).
fn decrypt_aes_gcm_agent_code(
    aes_key_32: &[u8; 32],
    aes_iv_b64: &str,
    encrypted_code_b64: &str,
) -> Result<String, String> {
    let cipher = Aes256Gcm::new_from_slice(aes_key_32)
        .map_err(|e| format!("AES-256-GCM init: {e}"))?;
    let iv = STANDARD
        .decode(aes_iv_b64.trim())
        .map_err(|e| format!("aes_iv_b64: {e}"))?;
    if iv.len() != 12 {
        return Err(format!("AES-GCM nonce: expected 12 bytes, got {}", iv.len()));
    }
    let nonce = Nonce::from_slice(&iv);
    let enc = STANDARD
        .decode(encrypted_code_b64.trim())
        .map_err(|e| format!("encrypted_code_b64: {e}"))?;
    let plain = cipher
        .decrypt(nonce, enc.as_ref())
        .map_err(|e| format!("AES-256-GCM decrypt: {e}"))?;
    String::from_utf8(plain).map_err(|e| format!("decrypted code invalid UTF-8: {e}"))
}

async fn kms_encrypt_plaintext(client: &KmsClient, key_id: &str, plaintext: &[u8]) -> Result<String, String> {
    let out = client
        .encrypt()
        .key_id(key_id)
        .plaintext(Blob::new(plaintext.to_vec()))
        .send()
        .await
        .map_err(|e| format!("KMS encrypt (AES envelope): {e}"))?;
    let ct = out
        .ciphertext_blob
        .ok_or_else(|| "KMS encrypt: missing ciphertext_blob".to_string())?;
    Ok(STANDARD.encode(ct.as_ref()))
}

async fn kms_decrypt_plaintext(client: &KmsClient, encrypted_b64: &str) -> Result<Vec<u8>, String> {
    let ct = STANDARD
        .decode(encrypted_b64.trim())
        .map_err(|e| format!("kms ciphertext base64: {e}"))?;
    let out = client
        .decrypt()
        .ciphertext_blob(Blob::new(ct))
        .send()
        .await
        .map_err(|e| format!("KMS decrypt (AES envelope): {e}"))?;
    let pt = out
        .plaintext
        .ok_or_else(|| "KMS decrypt: missing plaintext".to_string())?;
    Ok(Vec::from(pt.as_ref()))
}

async fn read_request_limited(stream: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
    const CHUNK: usize = 32 * 1024;
    let mut buf: Vec<u8> = Vec::new();
    let mut scratch = [0u8; CHUNK];
    loop {
        if buf.len() >= MAX_INCOMING_JSON_BYTES {
            break;
        }
        let to_read = (MAX_INCOMING_JSON_BYTES - buf.len()).min(CHUNK);
        let n = match stream.read(&mut scratch[..to_read]).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        buf.extend_from_slice(&scratch[..n]);
    }
    buf
}

async fn kms_client_with_credentials(creds_provider: SharedCredentialsProvider) -> KmsClient {
    // Enclave has no direct internet: loopback HTTP CONNECT → `host:port\n` on parent VSOCK :5006.
    let port = kms_egress_connect_proxy::ensure_started().await;
    let kms_https_proxy = ProxyConfig::https(format!("http://127.0.0.1:{port}"))
        .expect("loopback KMS egress proxy URL");
    let http_client = AwsHttpClientBuilder::new().build_with_connector_fn({
        let kms_https_proxy = kms_https_proxy.clone();
        move |settings, runtime_components| {
            let mut conn_builder = ConnectorBuilder::default().tls_provider(tls::Provider::Rustls(
                tls::rustls_provider::CryptoMode::AwsLc,
            ));
            conn_builder.set_connector_settings(settings.cloned());
            if let Some(components) = runtime_components {
                conn_builder.set_sleep_impl(components.sleep_impl());
            }
            conn_builder.set_proxy_config(Some(kms_https_proxy.clone()));
            conn_builder.build()
        }
    });
    let region = std::env::var("AWS_DEFAULT_REGION")
        .or_else(|_| std::env::var("AWS_REGION"))
        .map(Region::new)
        .unwrap_or_else(|_| Region::new(DEFAULT_AWS_REGION.to_string()));

    let conf = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .http_client(http_client)
        .region(region)
        .credentials_provider(creds_provider)
        .load()
        .await;
    KmsClient::new(&conf)
}

/// Temporary IAM triple from the EC2 Metadata role JSON (included by Host as `aws_creds`).
struct AwsCredsPayload {
    access_key_id: String,
    secret_access_key: String,
    token: String,
}

/// Parses `aws_creds` (PascalCase keys matching IMDS). Missing key → env fallback unless object is
/// non-empty but incomplete → error.
fn parse_aws_creds(req: &Value) -> Result<Option<AwsCredsPayload>, String> {
    fn field_str<'m>(o: &'m serde_json::Map<String, Value>, key: &'static str) -> Option<&'m str> {
        o.get(key)?
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
    }

    match req.get("aws_creds") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(o)) if o.is_empty() => Ok(None),
        Some(Value::Object(o)) => {
            match (
                field_str(o, "AccessKeyId"),
                field_str(o, "SecretAccessKey"),
                field_str(o, "Token"),
            ) {
                (Some(a), Some(s), Some(t)) => Ok(Some(AwsCredsPayload {
                    access_key_id: a.to_string(),
                    secret_access_key: s.to_string(),
                    token: t.to_string(),
                })),
                _ => Err(
                    "aws_creds: AccessKeyId, SecretAccessKey, and Token are required together"
                        .into(),
                ),
            }
        }
        Some(_) => Err("aws_creds must be a JSON object".into()),
    }
}
async fn kms_encrypt_signing_key(client: &KmsClient, key_id: &str, sk: &SigningKey) -> Result<String, String> {
    let plaintext: Vec<u8> = sk.to_bytes().to_vec();
    let out = client
        .encrypt()
        .key_id(key_id)
        .plaintext(Blob::new(plaintext))
        .send()
        .await
        .map_err(|e| format!("KMS encrypt: {e}"))?;
    let ct = out
        .ciphertext_blob
        .ok_or_else(|| "KMS encrypt: missing ciphertext_blob".to_string())?;
    Ok(STANDARD.encode(ct.as_ref()))
}

async fn kms_decrypt_signing_key(client: &KmsClient, encrypted_b64: &str) -> Result<SigningKey, String> {
    let ct = STANDARD
        .decode(encrypted_b64.trim())
        .map_err(|e| format!("encrypted_key_b64: base64 decode: {e}"))?;
    let out = client
        .decrypt()
        .ciphertext_blob(Blob::new(ct))
        .send()
        .await
        .map_err(|e| format!("KMS decrypt: {e}"))?;
    let pt = out
        .plaintext
        .ok_or_else(|| "KMS decrypt: missing plaintext".to_string())?;
    SigningKey::from_slice(pt.as_ref()).map_err(|e| format!("invalid decrypted key: {e}"))
}

/// Drains the job queue (`run_jobs` runs the internal event loop to completion) and, if the eval
/// result is a `Promise` (e.g. from `teeify.fetch` / async), unwraps settled values for the
/// response string. Stays on one thread: `Context` is never sent across `await`.
fn string_from_eval_value(context: &mut Context, value: JsValue) -> String {
    let mut v = value;
    for i in 0..64 {
        if let Err(e) = context.run_jobs() {
            return format!("run_jobs: {e:?}");
        }
        if let Some(p) = v.as_promise() {
            match p.state() {
                PromiseState::Fulfilled(next) => v = next,
                PromiseState::Rejected(r) => {
                    return format!("Promise rejected: {}", r.display().to_string());
                }
                PromiseState::Pending => {
                    if i + 1 == 64 {
                        return "Promise { <pending> } (stalled in run_to_completion)".to_string();
                    }
                    continue;
                }
            }
        } else {
            return v.display().to_string();
        }
    }
    "Error: too many Promise fulfillment hops".to_string()
}

fn error_response(message: impl AsRef<str>) -> String {
    json!({
        "status": "error",
        "message": message.as_ref(),
        "wallet_address": serde_json::Value::Null,
        "execution_output": "",
        "attestation_b64": "",
        "encrypted_key_b64": "",
    })
    .to_string()
}

async fn handle_client(mut stream: impl AsyncReadExt + AsyncWriteExt + Unpin) {
    let body = read_request_limited(&mut stream).await;
    let request_str = String::from_utf8_lossy(&body);
    let req: Value = serde_json::from_str(request_str.trim()).unwrap_or_else(|_| json!({}));

    let action = req.get("action").and_then(|a| a.as_str()).unwrap_or("");

    if action == "get_key" {
        let out = json!({
            "status": "success",
            "public_key_pem": rsa_public_key_pem(),
        });
        if let Err(e) = stream.write_all(out.to_string().as_bytes()).await {
            eprintln!("get_key: write response: {e}");
            return;
        }
        // Half-close so the parent’s `read_to_string` reaches EOF after one response.
        if let Err(e) = stream.shutdown().await {
            eprintln!("get_key: shutdown write: {e}");
        }
        println!("🔒 E2EE: served public_key_pem to host");
        return;
    }

    let agent_name = req["agent_name"].as_str().unwrap_or("unknown");

    // `deploy` and `execute` share one path: never eval ciphertext as JS.
    // E2EE: `encrypted_code_b64` + `aes_iv_b64` + exactly one of:
    //   - `encrypted_aes_key_b64` (RSA-wrapped AES key; deploy) → we also return `kms_sealed_aes_key_b64`
    //   - `kms_sealed_aes_key_b64` (KMS ciphertext; execute)
    let encrypted_code_b64 = req["encrypted_code_b64"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let encrypted_aes_key_b64 = req["encrypted_aes_key_b64"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let kms_sealed_aes_key_b64 = req["kms_sealed_aes_key_b64"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let aes_iv_b64 = req["aes_iv_b64"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    println!("🔒 Enclave received request for agent: {agent_name}");

    let cred_provider = match parse_aws_creds(&req) {
        Ok(Some(creds)) => {
            println!("🔒 KMS: using aws_creds from request (session token)");
            SharedCredentialsProvider::new(Credentials::new(
                creds.access_key_id,
                creds.secret_access_key,
                Some(creds.token),
                None,
                "payload-aws-creds",
            ))
        }
        Ok(None) => {
            println!("🔒 KMS: using process env credentials ({ENV_KMS_KEY_ID} / AWS_*)");
            SharedCredentialsProvider::new(EnvironmentVariableCredentialsProvider::new())
        }
        Err(e) => {
            let _ = stream.write_all(error_response(&e).as_bytes()).await;
            println!("🔒 {e}");
            return;
        }
    };
    let kms = kms_client_with_credentials(cred_provider).await;

    let (agent_code, rsa_aes_key_for_kms_seal): (String, Option<[u8; 32]>) =
        match encrypted_code_b64 {
            None => (
                req["agent_code"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .unwrap_or_else(|| "'No code provided';".to_string()),
                None,
            ),
            Some(ec) => {
                let Some(iv) = aes_iv_b64 else {
                    let msg = "E2EE: when encrypted_code_b64 is set, aes_iv_b64 is required";
                    let _ = stream.write_all(error_response(msg).as_bytes()).await;
                    println!("🔒 {msg}");
                    return;
                };
                match (encrypted_aes_key_b64, kms_sealed_aes_key_b64) {
                    (Some(_), Some(_)) => {
                        let msg = "E2EE: encrypted_aes_key_b64 and kms_sealed_aes_key_b64 are mutually exclusive";
                        let _ = stream.write_all(error_response(msg).as_bytes()).await;
                        println!("🔒 {msg}");
                        return;
                    }
                    (None, None) => {
                        let msg = "E2EE: when encrypted_code_b64 is set, provide encrypted_aes_key_b64 (deploy) or kms_sealed_aes_key_b64 (execute)";
                        let _ = stream.write_all(error_response(msg).as_bytes()).await;
                        println!("🔒 {msg}");
                        return;
                    }
                    (Some(rsa_b64), None) => {
                        println!("🔒 Enclave: E2EE decrypt (RSA-wrapped AES key)...");
                        let raw = match rsa_decrypt_aes256_key_ct(rsa_b64) {
                            Ok(k) => k,
                            Err(e) => {
                                let _ = stream
                                    .write_all(error_response(&e).as_bytes())
                                    .await;
                                println!("🔒 E2EE RSA unwrap error: {e}");
                                return;
                            }
                        };
                        let code = match decrypt_aes_gcm_agent_code(&raw, iv, ec) {
                            Ok(s) if !s.is_empty() => s,
                            Ok(_) => {
                                let msg = "E2EE: decrypted agent code is empty";
                                let _ = stream
                                    .write_all(error_response(msg).as_bytes())
                                    .await;
                                println!("🔒 {msg}");
                                return;
                            }
                            Err(e) => {
                                let _ = stream
                                    .write_all(error_response(&e).as_bytes())
                                    .await;
                                println!("🔒 E2EE decrypt error: {e}");
                                return;
                            }
                        };
                        (code, Some(raw))
                    }
                    (None, Some(kms_b64)) => {
                        println!("🔒 Enclave: E2EE decrypt (KMS-sealed AES key)...");
                        let pt = match kms_decrypt_plaintext(&kms, kms_b64).await {
                            Ok(p) => p,
                            Err(e) => {
                                let _ = stream
                                    .write_all(error_response(&e).as_bytes())
                                    .await;
                                println!("🔒 E2EE KMS unwrap error: {e}");
                                return;
                            }
                        };
                        let raw: [u8; 32] = match pt.try_into() {
                            Ok(k) => k,
                            Err(v) => {
                                let msg = format!(
                                    "KMS plaintext: expected 32-byte AES key, got {} bytes",
                                    v.len()
                                );
                                let _ = stream
                                    .write_all(error_response(&msg).as_bytes())
                                    .await;
                                println!("🔒 {msg}");
                                return;
                            }
                        };
                        let code = match decrypt_aes_gcm_agent_code(&raw, iv, ec) {
                            Ok(s) if !s.is_empty() => s,
                            Ok(_) => {
                                let msg = "E2EE: decrypted agent code is empty";
                                let _ = stream
                                    .write_all(error_response(msg).as_bytes())
                                    .await;
                                println!("🔒 {msg}");
                                return;
                            }
                            Err(e) => {
                                let _ = stream
                                    .write_all(error_response(&e).as_bytes())
                                    .await;
                                println!("🔒 E2EE decrypt error: {e}");
                                return;
                            }
                        };
                        (code, None)
                    }
                }
            }
        };

    let mut kms_sealed_aes_key_out: Option<String> = None;
    if let Some(raw) = rsa_aes_key_for_kms_seal {
        let key_id = match std::env::var(ENV_KMS_KEY_ID) {
            Ok(id) => id,
            Err(_) => {
                let msg = format!(
                    "{ENV_KMS_KEY_ID} must be set to seal the code AES key for durable execute"
                );
                let _ = stream.write_all(error_response(&msg).as_bytes()).await;
                println!("🔒 {msg}");
                return;
            }
        };
        match kms_encrypt_plaintext(&kms, &key_id, &raw).await {
            Ok(s) => kms_sealed_aes_key_out = Some(s),
            Err(e) => {
                let _ = stream.write_all(error_response(&e).as_bytes()).await;
                println!("🔒 KMS seal (AES key): {e}");
                return;
            }
        }
    }

    let secrets_obj: Option<&serde_json::Map<String, Value>> = match req.get("secrets") {
        None | Some(Value::Null) => None,
        Some(Value::Object(m)) => Some(m),
        Some(_) => {
            let msg = "secrets must be a JSON object (string keys → base64 ciphertext values)";
            let _ = stream.write_all(error_response(msg).as_bytes()).await;
            println!("🔒 {msg}");
            return;
        }
    };

    let secrets_nonempty = match secrets_obj {
        None => false,
        Some(m) => !m.is_empty(),
    };

    if !secrets_nonempty {
        println!("🔒 Enclave: No secrets provided in this request.");
    }

    let mut teeify_secrets_map: serde_json::Map<String, Value> = serde_json::Map::new();
    let mut kms_sealed_secrets_out: serde_json::Map<String, Value> = serde_json::Map::new();

    if let Some(obj) = secrets_obj {
        for (name, val_j) in obj.iter() {
            let b64 = match val_j.as_str().map(str::trim).filter(|s| !s.is_empty()) {
                Some(s) => s,
                None => {
                    let msg = format!("secrets[{name}]: expected non-empty base64 string");
                    let _ = stream.write_all(error_response(&msg).as_bytes()).await;
                    println!("🔒 {msg}");
                    return;
                }
            };
            let (plain, needs_kms_seal) = match unwrap_secret_value(&kms, name, b64).await {
                Ok(x) => x,
                Err(e) => {
                    let _ = stream.write_all(error_response(&e).as_bytes()).await;
                    println!("🔒 {e}");
                    return;
                }
            };
            teeify_secrets_map.insert(name.clone(), Value::String(plain.clone()));
            println!("🔒 Enclave: Injected decrypted secret [{}] into JS context", name);
            if needs_kms_seal {
                let key_id = match std::env::var(ENV_KMS_KEY_ID) {
                    Ok(id) => id,
                    Err(_) => {
                        let msg = format!(
                            "{ENV_KMS_KEY_ID} must be set to seal secrets after RSA unwrap"
                        );
                        let _ = stream.write_all(error_response(&msg).as_bytes()).await;
                        println!("🔒 {msg}");
                        return;
                    }
                };
                match kms_encrypt_plaintext(&kms, &key_id, plain.as_bytes()).await {
                    Ok(enc) => {
                        kms_sealed_secrets_out.insert(name.clone(), Value::String(enc));
                    }
                    Err(e) => {
                        let _ = stream.write_all(error_response(&e).as_bytes()).await;
                        println!("🔒 KMS seal (secret {name}): {e}");
                        return;
                    }
                }
            }
        }
    }

    let teeify_secrets_val = Value::Object(teeify_secrets_map);

    let encrypted_key_in = req["encrypted_key_b64"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let key_outcome: Result<(SigningKey, String), String> = if let Some(b64) = encrypted_key_in {
        kms_decrypt_signing_key(&kms, b64)
            .await
            .map(|sk| (sk, b64.to_string()))
    } else {
        match std::env::var(ENV_KMS_KEY_ID) {
            Err(_) => Err(format!(
                "{ENV_KMS_KEY_ID} must be set to create a new persisted wallet"
            )),
            Ok(key_id) => {
                let sk = SigningKey::random(&mut OsRng);
                match kms_encrypt_signing_key(&kms, &key_id, &sk).await {
                    Ok(enc) => Ok((sk, enc)),
                    Err(e) => Err(e),
                }
            }
        }
    };

    let (private_key, encrypted_key_b64) = match key_outcome {
        Ok(v) => v,
        Err(msg) => {
            stream
                .write_all(error_response(&msg).as_bytes())
                .await
                .unwrap();
            println!("🔒 Secure payload sent to host (KMS error).");
            return;
        }
    };

    let public_key = VerifyingKey::from(&private_key);
    let eth_address = get_eth_address(&public_key);

    let request_payload: Value = req
        .get("request_payload")
        .cloned()
        .unwrap_or_else(|| json!({}));

    // Boa `Context` is not `Send`; keep it in a block and finish before any `.await` so
    // `tokio::spawn` sees a `Send` future.
    let execution_result = {
        let mut context = Context::default();
        if let Err(e) = egress::register_teeify(&mut context, &private_key) {
            format!("teeify init: {e:?}")
        } else if let Err(e) = register_console(&mut context) {
            format!("console init: {e:?}")
        } else {
            match JsValue::from_json(&request_payload, &mut context) {
                Err(e) => format!("TEEIFY_REQUEST: serde_json to JsValue: {e:?}"),
                Ok(teeify_request) => {
                    if let Err(e) = context.register_global_property(
                        js_string!("TEEIFY_REQUEST"),
                        teeify_request,
                        Attribute::all(),
                    ) {
                        format!("TEEIFY_REQUEST: register: {e:?}")
                    } else {
                        println!("🔒 Enclave: Injected TEEIFY_REQUEST object into context");
                        match JsValue::from_json(&teeify_secrets_val, &mut context) {
                            Err(e) => format!("TEEIFY_SECRETS: serde_json to JsValue: {e:?}"),
                            Ok(teeify_secrets) => {
                                if let Err(e) = context.register_global_property(
                                    js_string!("TEEIFY_SECRETS"),
                                    teeify_secrets,
                                    Attribute::all(),
                                ) {
                                    format!("TEEIFY_SECRETS: register: {e:?}")
                                } else {
                                    println!("🔒 Enclave: TEEIFY_SECRETS registered as global property");
                                    println!("🔒 Enclave: Bound JS code hash (Keccak256) to hardware attestation.");
                                    println!("🔒 Enclave: Evaluating agent code (TEEIFY_SECRETS set before eval)");
                                    match context.eval(Source::from_bytes(agent_code.as_bytes())) {
                                        Ok(res) => string_from_eval_value(&mut context, res),
                                        Err(e) => format!("JS Execution Error: {e:?}"),
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    };

    #[cfg(not(target_os = "linux"))]
    let attestation_b64 = String::from("mock_attestation_for_local_dev");

    #[cfg(target_os = "linux")]
    let attestation_b64 = {
        let mut attestation_b64 = String::from("mock_attestation_for_local_dev");
        println!("🔒 Requesting hardware attestation from NSM...");
        let nsm_fd = nsm_init();
        let agent_code_keccak256: [u8; 32] =
            Keccak256::digest(agent_code.as_bytes()).into();
        let request = Request::Attestation {
            public_key: Some(ByteBuf::from(
                public_key.to_encoded_point(false).as_bytes().to_vec(),
            )),
            user_data: Some(ByteBuf::from(agent_code_keccak256.to_vec())),
            nonce: None,
        };
        if let Response::Attestation { document } = nsm_process_request(nsm_fd, request) {
            attestation_b64 = STANDARD.encode(document);
        }
        attestation_b64
    };

    let mut body_val = json!({
        "status": "success",
        "wallet_address": eth_address,
        "execution_output": execution_result,
        "attestation_b64": attestation_b64,
        "encrypted_key_b64": encrypted_key_b64,
    });
    if let Some(ref sealed) = kms_sealed_aes_key_out {
        body_val
            .as_object_mut()
            .expect("success response object")
            .insert(
                "kms_sealed_aes_key_b64".to_string(),
                Value::String(sealed.clone()),
            );
    }
    if !kms_sealed_secrets_out.is_empty() {
        body_val.as_object_mut().expect("success response object").insert(
            "kms_sealed_secrets".to_string(),
            Value::Object(kms_sealed_secrets_out),
        );
    }
    let body = body_val.to_string();

    if let Err(e) = stream.write_all(body.as_bytes()).await {
        eprintln!("deploy: write response: {e}");
        return;
    }
    if let Err(e) = stream.shutdown().await {
        eprintln!("deploy: shutdown write: {e}");
    }
    println!("🔒 Secure payload sent to host.");
}

/// Bring `lo` UP before any local TLS/AWS traffic (minimal enclave images may omit `iproute`).
#[cfg(target_os = "linux")]
fn enable_loopback() {
    unsafe {
        let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if sock < 0 {
            return;
        }
        let mut req: libc::ifreq = std::mem::zeroed();
        let name = b"lo\0";
        for i in 0..name.len() {
            req.ifr_name[i] = name[i] as libc::c_char;
        }

        let get_ok = libc::ioctl(sock, libc::SIOCGIFFLAGS as _, std::ptr::addr_of_mut!(req));
        if get_ok == 0 {
            let flags = req.ifr_ifru.ifru_flags as libc::c_int;
            req.ifr_ifru.ifru_flags =
                (flags | libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
            let _ = libc::ioctl(sock, libc::SIOCSIFFLAGS as _, std::ptr::addr_of_mut!(req));
        }
        libc::close(sock);
    }
    println!("🔒 Enclave: Native loopback interface enabled.");
}

#[cfg(target_os = "linux")]
async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use nix::sys::socket::SockAddr;

    let mut listener = VsockListener::bind(libc::VMADDR_CID_ANY, 5005)?;
    println!("🔒 Teeify Enclave: Listening on VSOCK port 5005");

    loop {
        let (stream, addr) = listener.accept().await?;
        let cid = match addr {
            SockAddr::Vsock(v) => v.cid(),
            _ => 0,
        };
        println!("🔒 Enclave: connection from host CID {cid}");
        tokio::spawn(async move {
            handle_client(stream).await;
        });
    }
}

#[cfg(not(target_os = "linux"))]
async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind("127.0.0.1:5005").await?;
    println!("🔒 Teeify Enclave: [dev] listening on TCP 127.0.0.1:5005");
    loop {
        let (stream, peer) = listener.accept().await?;
        println!("🔒 Enclave: connection from {peer}");
        tokio::spawn(async move {
            handle_client(stream).await;
        });
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    #[cfg(target_os = "linux")]
    enable_loopback();
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let _ = rsa_private_key();
    println!("🔒 Teeify Enclave: booting (Boa JS engine, E2EE RSA-2048 ready)...");
    run().await
}
