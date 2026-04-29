use std::fs;
use std::path::Path;

use bech32::Hrp;
use log::{error, info};

/// Re-encode `AGE-PLUGIN-YUBIKEY-1` identities in a file to
/// `AGE-PLUGIN-YUBIKEY-AGENT-`, preserving the bech32 payload.
///
/// Writes atomically (tmp + rename) and saves the original as `{path}.bak`.
/// Refuses to run if the backup file already exists.
pub fn convert_identities(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let bak_path = format!("{path}.bak");
    if Path::new(&bak_path).exists() {
        return Err(format!(
            "refusing to overwrite existing backup at {bak_path}; move or remove it and rerun"
        )
        .into());
    }

    let content = fs::read_to_string(path).inspect_err(|e| error!("Failed to read {path}: {e}"))?;

    let mut new_content = String::with_capacity(content.len());
    let mut modified = false;

    let new_hrp =
        Hrp::parse("AGE-PLUGIN-YUBIKEY-AGENT-").expect("Hardcoded HRP string is always valid");

    for line in content.lines() {
        if line.starts_with("AGE-PLUGIN-YUBIKEY-1") {
            let (_hrp, data) = bech32::decode(line)?;
            let new_str = bech32::encode::<bech32::Bech32>(new_hrp, &data)?;

            new_content.push_str(&new_str.to_uppercase());
            modified = true;
        } else {
            new_content.push_str(line);
        }

        new_content.push('\n');
    }

    if !modified {
        info!("No AGE-PLUGIN-YUBIKEY-1 identities found in {path}");
        return Ok(());
    }

    let tmp_path = format!("{path}.tmp");

    fs::copy(path, &bak_path)
        .inspect_err(|e| error!("Failed to create backup at {bak_path}: {e}"))?;
    fs::write(&tmp_path, &new_content)
        .inspect_err(|e| error!("Failed to write {tmp_path}: {e}"))?;
    fs::rename(&tmp_path, path)
        .inspect_err(|e| error!("Failed to rename {tmp_path} to {path}: {e}"))?;

    info!("Converted identities in {path} to AGE-PLUGIN-YUBIKEY-AGENT-; original saved as {bak_path}");
    Ok(())
}
