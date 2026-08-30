//! Offline signing helper for `scripts/publish-release.ps1`.
//!
//! The private seed is deliberately read from an ignored local file. This
//! binary only emits a base64 signature and refuses a key whose public half is
//! not one of the release keys compiled into the client.

use anyhow::{bail, Context, Result};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};

fn decode_seed(raw: &str) -> Result<[u8; 32]> {
    let hex = raw.trim();
    if hex.len() != 64 {
        bail!("la clé de publication doit être une graine Ed25519 hexadécimale de 32 octets");
    }
    let mut seed = [0u8; 32];
    for (slot, pair) in seed.iter_mut().zip(hex.as_bytes().as_chunks::<2>().0) {
        let pair = std::str::from_utf8(pair).expect("hex is ASCII");
        *slot = u8::from_str_radix(pair, 16)
            .with_context(|| "la clé de publication contient un caractère non hexadécimal")?;
    }
    Ok(seed)
}

fn read_key(key_path: &str) -> Result<SigningKey> {
    let seed = decode_seed(
        &std::fs::read_to_string(key_path)
            .with_context(|| format!("lecture de la clé {key_path}"))?,
    )?;
    Ok(SigningKey::from_bytes(&seed))
}

fn public_hex(key: &SigningKey) -> String {
    key.verifying_key()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn sign(key_path: &str, manifest_path: &str) -> Result<String> {
    let key = read_key(key_path)?;
    let public_hex = public_hex(&key);
    if !luavault_lib::RELEASE_PUBLIC_KEYS
        .iter()
        .any(|allowed| *allowed == public_hex)
    {
        bail!("la clé privée ne correspond à aucune clé publique compilée");
    }

    let manifest = std::fs::read(manifest_path)
        .with_context(|| format!("lecture du manifeste {manifest_path}"))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(key.sign(&manifest).to_bytes()))
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [command, key_path] if command == "public-key" => {
            println!("{}", public_hex(&read_key(key_path)?));
        }
        [command, key_path, manifest_path] if command == "sign" => {
            println!("{}", sign(key_path, manifest_path)?);
        }
        _ => {
            bail!("usage: lvrelease public-key <clé-privée> | sign <clé-privée> <manifest.json>");
        }
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("lvrelease: {error:#}");
        std::process::exit(1);
    }
}
