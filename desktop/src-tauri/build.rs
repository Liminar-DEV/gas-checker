use std::path::{Path, PathBuf};

fn hex_key(text: &str) -> Result<[u8; 32], String> {
    let text = text.trim().as_bytes();
    if text.len() != 64 {
        return Err("expected 64 hex characters (32 bytes)".into());
    }
    let digit = |c: u8| (c as char).to_digit(16).map(|d| d as u8).ok_or_else(|| "non-hex character".to_string());
    let mut key = [0u8; 32];
    for (byte, pair) in key.iter_mut().zip(text.chunks(2)) {
        *byte = digit(pair[0])? << 4 | digit(pair[1])?;
    }
    Ok(key)
}

/// File format: 12-byte nonce || AES-256-GCM ciphertext || 16-byte tag.
fn decrypt_rules(blob: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    if blob.len() < 12 + 16 {
        return Err("file is too short".into());
    }
    let (nonce, data) = blob.split_at(12);
    Aes256Gcm::new_from_slice(key)
        .map_err(|e| e.to_string())?
        .decrypt(Nonce::from_slice(nonce), data)
        .map_err(|_| "wrong key or corrupted file".to_string())
}

/// Writes OUT_DIR/rules_active.rs: the decrypted private rules when the key is set, else the open stub.
fn prepare_rules() {
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let out = PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("rules_active.rs");
    let encrypted = manifest.join("rules").join("rules_private.rs.enc");
    let open = manifest.join("src").join("rules_open.rs");
    println!("cargo:rerun-if-env-changed=GASCHECKER_RULES_KEY");
    println!("cargo:rerun-if-changed={}", encrypted.display());
    println!("cargo:rerun-if-changed={}", open.display());

    let key = std::env::var("GASCHECKER_RULES_KEY").ok().filter(|key| !key.trim().is_empty());
    match key {
        Some(key) if encrypted.is_file() => {
            let plain = hex_key(&key)
                .map_err(|e| format!("GASCHECKER_RULES_KEY is invalid: {e}"))
                .and_then(|key| {
                    let blob = std::fs::read(&encrypted).map_err(|e| format!("cannot read {}: {e}", encrypted.display()))?;
                    decrypt_rules(&blob, &key).map_err(|e| format!("cannot decrypt rules/rules_private.rs.enc: {e}"))
                })
                .unwrap_or_else(|e| panic!("{e}; refusing to fall back to the open rules"));
            write_if_changed(&out, &plain);
        }
        _ => {
            println!("cargo:warning=сборка с открытыми правилами, частичная проверка");
            write_if_changed(&out, &std::fs::read(&open).expect("cannot read src/rules_open.rs"));
        }
    }
}

// Untouched mtime keeps cargo from recompiling when nothing changed.
fn write_if_changed(path: &Path, bytes: &[u8]) {
    if std::fs::read(path).ok().as_deref() != Some(bytes) {
        std::fs::write(path, bytes).expect("cannot write rules_active.rs");
    }
}

fn main() {
    prepare_rules();
    let mut attributes = tauri_build::Attributes::new();
    // Force elevation: the checker must run as administrator so it can read the game's
    // process memory (including a game launched elevated). Windows prompts UAC on launch
    // and refuses to start the app without it.
    #[cfg(windows)]
    {
        attributes = attributes
            .windows_attributes(tauri_build::WindowsAttributes::new().app_manifest(ADMIN_MANIFEST));
    }
    tauri_build::try_build(attributes).expect("failed to run tauri-build");
}

// Mirrors Tauri's default app manifest (DPI awareness, long paths, UTF-8, common controls)
// but raises the requested execution level to requireAdministrator.
#[cfg(windows)]
const ADMIN_MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*" />
    </dependentAssembly>
  </dependency>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">permonitorv2, permonitor</dpiAwareness>
      <longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>
      <activeCodePage xmlns="http://schemas.microsoft.com/SMI/2019/WindowsSettings">UTF-8</activeCodePage>
    </windowsSettings>
  </application>
</assembly>
"#;
