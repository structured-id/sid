// SPDX-License-Identifier: AGPL-3.0-only
//! A new key for the web client a UI host signs in as (`private_key_jwt`,
//! RFC 7523 §2.2): the private key the host reads, the public JWK Set the
//! installation registers.

use std::io::Write as _;
use std::path::Path;

use anyhow::Context as _;
use secrecy::ExposeSecret as _;
use sid_authn::client_key::ClientKey;

/// Write a new Ed25519 client key: the PKCS#8 PEM private key to `private`,
/// readable by its owner only and never printed, and its public JWK Set to
/// `public`. An existing file is never overwritten: replacing a registered
/// key would lock the client out. Returns the key's id.
pub fn generate(private: &Path, public: &Path) -> anyhow::Result<String> {
    // Checked first so a taken public path (a dangling link included) writes
    // no private key at all; the creation itself still refuses a file that
    // appeared since.
    anyhow::ensure!(
        std::fs::symlink_metadata(public).is_err(),
        "{public:?} cannot be created (it must not exist yet)"
    );
    let (key, pem) = ClientKey::generate_ed25519()?;
    let jwks = key
        .public_jwks()
        .context("a generated key derives its public half")?;
    write_new(private, pem.expose_secret().as_bytes(), 0o600)?;
    if let Err(e) = write_new(public, &serde_json::to_vec_pretty(&jwks)?, 0o644) {
        // This call created the private key, so taking it back removes
        // nothing that was there before, and the command can be run again.
        if let Err(removal) = std::fs::remove_file(private) {
            return Err(e.context(format!(
                "and the new private key {private:?} could not be removed: {removal}"
            )));
        }
        return Err(e);
    }
    Ok(key.kid().unwrap_or_default().to_owned())
}

/// `sid-ui-host keygen <private-key.pem> <public-jwks.json>`: the arguments
/// after the command name, and what to print once the key is written.
pub fn keygen(args: &[String]) -> anyhow::Result<String> {
    let [private, public] = args else {
        anyhow::bail!("usage: sid-ui-host keygen <private-key.pem> <public-jwks.json>");
    };
    let kid = generate(Path::new(private), Path::new(public))?;
    Ok(format!(
        "client key {kid} written: private {private}, public {public}"
    ))
}

/// Create `path` with `contents`, refusing an existing file.
fn write_new(path: &Path, contents: &[u8], mode: u32) -> anyhow::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, mode);
    #[cfg(not(unix))]
    let _ = mode;
    let mut file = options
        .open(path)
        .with_context(|| format!("{path:?} cannot be created (it must not exist yet)"))?;
    file.write_all(contents)
        .with_context(|| format!("writing {path:?}"))
}

#[cfg(test)]
mod tests;
