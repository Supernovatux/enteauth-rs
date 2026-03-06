use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use rusqlite::Connection;
use secret_service::{EncryptionType, SecretService};
use sodiumoxide::crypto::secretstream::xchacha20poly1305::{Header, Key, Stream};
use url::Url;

const KEYRING_ATTR_VALUE: &str = "io.ente.auth.secureStorage";
const DB_FILENAME: &str = ".ente.authenticator.db";
const APP_DATA_DIR: &str = "io.ente.auth";

fn db_path() -> std::path::PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| {
            let home = std::env::var("HOME").unwrap_or_default();
            std::path::PathBuf::from(format!("{home}/.local/share"))
        })
        .join(APP_DATA_DIR)
        .join(DB_FILENAME)
}

async fn get_auth_secret_key() -> Result<Vec<u8>> {
    let ss = SecretService::connect(EncryptionType::Dh)
        .await
        .context("Failed to connect to secret service (is a keyring daemon running?)")?;

    let result = ss
        .search_items(HashMap::from([("account", KEYRING_ATTR_VALUE)]))
        .await
        .context("Failed to search keyring")?;

    let item = result
        .unlocked
        .first()
        .or_else(|| result.locked.first())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Ente Auth secrets not found in keyring. Is Ente Auth installed and logged in?"
            )
        })?;

    let secret_bytes = item.get_secret().await.context("Failed to read secret from keyring")?;
    let secret_json =
        String::from_utf8(secret_bytes).context("Keyring secret is not valid UTF-8")?;
    let secrets: HashMap<String, String> =
        serde_json::from_str(&secret_json).context("Failed to parse keyring secret as JSON")?;
    let key_b64 = secrets
        .get("auth_secret_key")
        .ok_or_else(|| anyhow::anyhow!("auth_secret_key not found in keyring JSON blob"))?;
    B64.decode(key_b64).context("Failed to base64-decode auth_secret_key")
}

fn get_entities(db: &std::path::Path) -> Result<Vec<(String, String)>> {
    let conn = Connection::open_with_flags(
        db,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("Failed to open database at {}", db.display()))?;

    let mut stmt = conn.prepare("SELECT encryptedData, header FROM entities")?;
    let rows = stmt
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("Failed to read rows from entities table")?;
    Ok(rows)
}

fn decrypt_entity(enc_data_b64: &str, header_b64: &str, key_bytes: &[u8]) -> Result<String> {
    let header_bytes = B64.decode(header_b64).context("Failed to base64-decode header")?;
    let ciphertext = B64.decode(enc_data_b64).context("Failed to base64-decode ciphertext")?;

    let key = Key::from_slice(key_bytes)
        .ok_or_else(|| anyhow::anyhow!("Invalid key length (need 32 bytes)"))?;
    let header = Header::from_slice(&header_bytes)
        .ok_or_else(|| anyhow::anyhow!("Invalid header length (need 24 bytes)"))?;

    let mut stream = Stream::init_pull(&header, &key)
        .map_err(|_| anyhow::anyhow!("Failed to init secretstream pull state"))?;
    let (plaintext, _tag) = stream
        .pull(&ciphertext, None)
        .map_err(|_| anyhow::anyhow!("Decryption failed (wrong key or corrupt data)"))?;

    // Plaintext is a JSON-encoded string: `"otpauth://..."` — unwrap the outer quotes.
    let uri: String =
        serde_json::from_slice(&plaintext).context("Decrypted payload is not a JSON string")?;
    Ok(uri)
}

/// Uppercase the `algorithm` param and strip Ente's `codeDisplay` param.
/// totp-rs rejects unknown params and requires uppercase algorithm names.
fn normalize_uri(uri: &str) -> Result<String> {
    let mut url = Url::parse(uri).context("Failed to parse otpauth URI")?;
    let params: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(k, _)| k != "codeDisplay")
        .map(|(k, v)| {
            if k == "algorithm" || k == "secret" {
                (k.into_owned(), v.to_uppercase())
            } else {
                (k.into_owned(), v.into_owned())
            }
        })
        .collect();
    {
        let mut s = url.query_pairs_mut();
        s.clear();
        for (k, v) in &params {
            s.append_pair(k, v);
        }
    }
    Ok(url.to_string())
}

fn drop_query_param(uri: &str, param: &str) -> String {
    match Url::parse(uri) {
        Ok(mut url) => {
            let params: Vec<(String, String)> = url
                .query_pairs()
                .filter(|(k, _)| k != param)
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect();
            {
                let mut s = url.query_pairs_mut();
                s.clear();
                for (k, v) in &params {
                    s.append_pair(k, v);
                }
            }
            url.to_string()
        }
        Err(_) => uri.to_owned(),
    }
}

struct Code {
    issuer: String,
    account: String,
    code: String,
    remaining: u64,
    period: u64,
}

/// Try to copy `text` to the clipboard via wl-copy (Wayland) or xclip/xsel (X11).
/// Returns Ok if any backend succeeded, Err otherwise — caller should warn but not fail.
fn copy_to_clipboard(text: &str) -> Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let backends: &[(&str, &[&str])] = &[
        ("wl-copy", &[]),
        ("xclip", &["-selection", "clipboard"]),
        ("xsel", &["--clipboard", "--input"]),
    ];

    for (cmd, args) in backends {
        let Ok(mut child) = Command::new(cmd)
            .args(*args)
            .stdin(Stdio::piped())
            .spawn()
        else {
            continue;
        };
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(text.as_bytes());
        }
        if child.wait().map(|s| s.success()).unwrap_or(false) {
            return Ok(());
        }
    }
    Err(anyhow::anyhow!("no clipboard tool found (tried wl-copy, xclip, xsel)"))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let no_copy = args.iter().any(|a| a == "--no-copy");
    let json_out = args.iter().any(|a| a == "--json");
    let query = args.into_iter().find(|a| !a.starts_with("--"));

    let key = get_auth_secret_key().await?;

    let db = db_path();
    if !db.exists() {
        bail!("Database not found at {}", db.display());
    }

    let rows = get_entities(&db)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    let mut codes: Vec<Code> = Vec::new();
    for (enc_data, header) in rows {
        let uri = match decrypt_entity(&enc_data, &header, &key) {
            Ok(u) => u,
            Err(_) => continue,
        };
        let normalized = match normalize_uri(&uri) {
            Ok(u) => u,
            Err(_) => continue,
        };
        let totp = match totp_rs::TOTP::from_url_unchecked(&normalized) {
            Ok(t) => t,
            Err(totp_rs::TotpUrlError::IssuerMistmatch(_, _)) => {
                // Path label and `issuer` query param disagree (e.g. account migrated to
                // a different org). Drop the `issuer` query param and retry so the label
                // in the path is used as the sole source of truth.
                let without_issuer = drop_query_param(&normalized, "issuer");
                match totp_rs::TOTP::from_url_unchecked(&without_issuer) {
                    Ok(t) => t,
                    Err(_) => continue,
                }
            }
            Err(_) => continue,
        };
        let code = match totp.generate_current() {
            Ok(c) => c,
            Err(_) => continue,
        };
        let period = totp.step;
        let remaining = period - (now % period);
        codes.push(Code {
            issuer: totp.issuer.unwrap_or_default(),
            account: totp.account_name,
            code,
            remaining,
            period,
        });
    }

    if let Some(ref q) = query {
        let q = q.to_lowercase();
        codes.retain(|c| {
            c.issuer.to_lowercase().contains(&q) || c.account.to_lowercase().contains(&q)
        });
    }

    if codes.is_empty() {
        if let Some(q) = query {
            eprintln!("No codes found matching '{q}'.");
        } else {
            eprintln!("No codes found.");
        }
        return Ok(());
    }

    if json_out {
        let arr: Vec<serde_json::Value> = codes
            .iter()
            .map(|c| {
                serde_json::json!({
                    "issuer":    c.issuer,
                    "account":   c.account,
                    "code":      c.code,
                    "remaining": c.remaining,
                    "period":    c.period,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&arr)?);
        return Ok(());
    }

    if codes.len() == 1 && !no_copy {
        if let Err(e) = copy_to_clipboard(&codes[0].code) {
            eprintln!("warning: could not copy to clipboard: {e}");
        }
    }

    let w_issuer = codes.iter().map(|c| c.issuer.len()).max().unwrap_or(0).max(6);
    let w_account = codes.iter().map(|c| c.account.len()).max().unwrap_or(0).max(7);

    let header_line = format!(
        "{:<w_issuer$}  {:<w_account$}  {:<8}  Expires",
        "Issuer", "Account", "Code"
    );
    println!("{header_line}");
    println!("{}", "-".repeat(header_line.len()));

    for c in &codes {
        let bar = "#".repeat((10.0 * c.remaining as f64 / c.period as f64).round() as usize);
        println!(
            "{:<w_issuer$}  {:<w_account$}  {:<8}  {:>2}s {bar}",
            c.issuer, c.account, c.code, c.remaining
        );
    }

    Ok(())
}
