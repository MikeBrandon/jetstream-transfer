//! On-disk persistence for the device identity.
//!
//! The private key is wrapped with DPAPI under the current user account on
//! Windows, so lifting the file onto another machine or into another user's
//! session yields nothing. On other platforms we fall back to a `0600` file,
//! which is the same protection SSH gives `id_ed25519`.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::identity::Identity;

/// File magic plus format version. Bumping the trailing digit lets a future
/// build recognise and migrate an older key file instead of failing on it.
const MAGIC: &[u8; 8] = b"JETKEY01";

const WRAP_PLAINTEXT: u8 = 0;
const WRAP_DPAPI_USER: u8 = 1;

const KEY_FILE: &str = "device.key";

/// Where Jetstream keeps per-user state.
///
/// - Windows: `%LOCALAPPDATA%\Jetstream`
/// - macOS: `~/Library/Application Support/Jetstream`
/// - Linux: `~/.local/share/Jetstream`
///
/// Built from the platform's *local* data directory rather than via
/// `ProjectDirs`, which would nest a qualifier and organisation this project
/// does not have and produce something like `…\Jetstream\Jetstream\data`.
///
/// Local rather than roaming on Windows, deliberately: a DPAPI-wrapped key that
/// roamed to another machine could not be unwrapped there, so roaming it would
/// only produce confusing failures.
pub fn default_data_dir() -> Result<PathBuf> {
    let dirs = directories::BaseDirs::new().ok_or(Error::NoDataDir)?;
    Ok(dirs.data_local_dir().join("Jetstream"))
}

/// The folder whose presence beside the executable means "run portable".
pub const PORTABLE_DIR: &str = "Jetstream Data";

/// How the private key is protected at rest.
///
/// This is a security-relevant choice, so it is explicit at the call site rather
/// than inferred inside `save`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyProtection {
    /// DPAPI-wrapped to the current Windows user. The file is useless if copied
    /// to another machine or another account — which is the point.
    User,
    /// Stored unwrapped, so one identity can travel with the executable.
    ///
    /// Necessarily weaker: anyone who can read the file has the device's private
    /// key. That is the same exposure as an unencrypted `id_ed25519`, and it is
    /// the unavoidable cost of an identity that must work on a machine whose
    /// DPAPI master key we have never seen.
    Portable,
}

/// Where this copy of Jetstream keeps its state, and how it protects its key.
#[derive(Debug, Clone)]
pub struct Location {
    pub dir: PathBuf,
    pub protection: KeyProtection,
}

impl Location {
    pub fn is_portable(&self) -> bool {
        self.protection == KeyProtection::Portable
    }
}

/// Decide where to keep state, in precedence order:
///
/// 1. `JETSTREAM_DATA_DIR` — an explicit override. Still per-user protected,
///    because its purpose is running two independent devices on one machine.
/// 2. A `Jetstream Data` folder beside the executable — portable mode.
/// 3. The per-user application data directory.
///
/// Detection is by folder rather than a marker file so that it is visible and
/// self-explaining: the data sits where the flag is, and deleting the folder is
/// the whole of "stop being portable".
pub fn resolve_location() -> Result<Location> {
    choose_location(
        std::env::var_os("JETSTREAM_DATA_DIR").map(PathBuf::from),
        portable_data_dir(),
    )
}

/// The precedence rule itself, with both inputs passed in.
///
/// Split out so it is testable without mutating process environment variables —
/// which every other test in the process would see, and which Rust 2024 marks
/// `unsafe` for exactly that reason.
fn choose_location(override_dir: Option<PathBuf>, portable: Option<PathBuf>) -> Result<Location> {
    if let Some(dir) = override_dir {
        return Ok(Location {
            dir,
            protection: KeyProtection::User,
        });
    }

    if let Some(dir) = portable {
        return Ok(Location {
            dir,
            protection: KeyProtection::Portable,
        });
    }

    Ok(Location {
        dir: default_data_dir()?,
        protection: KeyProtection::User,
    })
}

/// The portable data directory, if this copy is running as one.
///
/// Only an existing directory counts. Creating it on demand would silently turn
/// an installed copy portable the first time it ran from a folder it could
/// write to, stranding the user's existing identity and pairings.
pub fn portable_data_dir() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let candidate = exe.parent()?.join(PORTABLE_DIR);
    candidate.is_dir().then_some(candidate)
}

/// Load the device identity from `dir`, creating one on first run.
///
/// This is the normal entry point. A device id is meant to be stable forever —
/// changing it invalidates every pairing the user has made — so a corrupt or
/// unreadable key file is surfaced as an error rather than silently replaced.
pub fn load_or_create(dir: &Path) -> Result<Identity> {
    load_or_create_protected(dir, KeyProtection::User)
}

/// As [`load_or_create`], choosing how a newly generated key is protected.
///
/// Only affects creation. Reading handles either wrapping, so a portable copy
/// still opens a key file written by an installed one on the same account.
pub fn load_or_create_protected(dir: &Path, protection: KeyProtection) -> Result<Identity> {
    match load(dir) {
        Ok(identity) => Ok(identity),
        Err(Error::Io(e)) if e.kind() == ErrorKind::NotFound => {
            let identity = Identity::generate()?;
            save_protected(dir, &identity, protection)?;
            tracing::info!(
                device_id = %identity.device_id().short(),
                fingerprint = %identity.device_id().fingerprint(),
                "generated a new device identity"
            );
            Ok(identity)
        }
        Err(e) => Err(e),
    }
}

pub fn load(dir: &Path) -> Result<Identity> {
    let path = dir.join(KEY_FILE);
    let raw = Zeroizing::new(fs::read(&path)?);
    let malformed = |detail: &str| Error::MalformedIdentity {
        path: path.display().to_string(),
        detail: detail.to_string(),
    };

    let Some((magic, rest)) = raw.split_at_checked(MAGIC.len()) else {
        return Err(malformed("file is truncated"));
    };
    if magic != MAGIC {
        return Err(malformed(
            "not a Jetstream key file (bad magic) — refusing to overwrite it",
        ));
    }
    let Some((&mode, payload)) = rest.split_first() else {
        return Err(malformed("file is missing its wrapping mode byte"));
    };

    let pkcs8 = match mode {
        WRAP_PLAINTEXT => Zeroizing::new(payload.to_vec()),
        WRAP_DPAPI_USER => unwrap_key(payload)?,
        other => return Err(malformed(&format!("unknown wrapping mode {other}"))),
    };

    Identity::from_pkcs8_der(&pkcs8)
}

pub fn save(dir: &Path, identity: &Identity) -> Result<()> {
    save_protected(dir, identity, KeyProtection::User)
}

pub fn save_protected(dir: &Path, identity: &Identity, protection: KeyProtection) -> Result<()> {
    fs::create_dir_all(dir)?;

    let (mode, payload) = match protection {
        KeyProtection::User => wrap_key(identity.pkcs8_der())?,
        KeyProtection::Portable => (WRAP_PLAINTEXT, identity.pkcs8_der().to_vec()),
    };
    let mut file = Vec::with_capacity(MAGIC.len() + 1 + payload.len());
    file.extend_from_slice(MAGIC);
    file.push(mode);
    file.extend_from_slice(&payload);

    // Write to a sibling temp file and rename, so an interrupted write can
    // never leave a half-written identity behind. `fs::rename` replaces the
    // destination atomically on both Windows and Unix.
    let path = dir.join(KEY_FILE);
    let tmp = dir.join(format!("{KEY_FILE}.tmp"));
    fs::write(&tmp, &file)?;
    restrict_permissions(&tmp)?;

    if let Err(e) = fs::rename(&tmp, &path) {
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<()> {
    // On Windows the confidentiality guarantee comes from DPAPI wrapping the
    // contents, not from the file ACL, and %LOCALAPPDATA% is already per-user.
    Ok(())
}

#[cfg(windows)]
fn wrap_key(pkcs8: &[u8]) -> Result<(u8, Vec<u8>)> {
    Ok((WRAP_DPAPI_USER, dpapi::protect(pkcs8)?))
}

#[cfg(windows)]
fn unwrap_key(payload: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    dpapi::unprotect(payload)
}

#[cfg(not(windows))]
fn wrap_key(pkcs8: &[u8]) -> Result<(u8, Vec<u8>)> {
    Ok((WRAP_PLAINTEXT, pkcs8.to_vec()))
}

#[cfg(not(windows))]
fn unwrap_key(_payload: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    Err(Error::Crypto(
        "this key file is DPAPI-wrapped and can only be read on the Windows account that wrote it"
            .into(),
    ))
}

#[cfg(windows)]
mod dpapi {
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    };
    use windows::core::PCWSTR;
    use zeroize::Zeroizing;

    use crate::error::{Error, Result};

    /// Secondary entropy mixed into the DPAPI key. Ties the ciphertext to this
    /// application, so another program running as the same user cannot unwrap
    /// our key file just by calling `CryptUnprotectData` on it.
    const ENTROPY: &[u8] = b"jetstream.identity.v1";

    /// Owns the `LocalAlloc`d buffer DPAPI returns, so every exit path frees it.
    struct OutBlob(CRYPT_INTEGER_BLOB);

    impl OutBlob {
        fn as_slice(&self) -> &[u8] {
            if self.0.pbData.is_null() {
                return &[];
            }
            // SAFETY: DPAPI reported success, so pbData points at cbData
            // initialised bytes that stay valid until we LocalFree them in Drop.
            unsafe { std::slice::from_raw_parts(self.0.pbData, self.0.cbData as usize) }
        }
    }

    impl Drop for OutBlob {
        fn drop(&mut self) {
            if !self.0.pbData.is_null() {
                // SAFETY: pbData came from DPAPI, which allocates with LocalAlloc.
                unsafe { LocalFree(Some(HLOCAL(self.0.pbData.cast()))) };
            }
        }
    }

    /// DPAPI takes `*mut` even for inputs it only reads, so hand it a copy we
    /// own rather than casting away `const` on a caller's slice.
    fn blob(buf: &mut [u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB {
            cbData: buf.len() as u32,
            pbData: buf.as_mut_ptr(),
        }
    }

    pub fn protect(plain: &[u8]) -> Result<Vec<u8>> {
        let mut input = Zeroizing::new(plain.to_vec());
        let mut entropy = ENTROPY.to_vec();
        let mut out = OutBlob(CRYPT_INTEGER_BLOB::default());

        // SAFETY: all three blobs point at live buffers for the duration of the
        // call, and `out` takes ownership of whatever DPAPI allocates.
        unsafe {
            CryptProtectData(
                &blob(&mut input),
                PCWSTR::null(),
                Some(&blob(&mut entropy)),
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out.0,
            )
        }
        .map_err(|e| Error::Crypto(format!("DPAPI could not wrap the identity key: {e}")))?;

        Ok(out.as_slice().to_vec())
    }

    pub fn unprotect(wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let mut input = wrapped.to_vec();
        let mut entropy = ENTROPY.to_vec();
        let mut out = OutBlob(CRYPT_INTEGER_BLOB::default());

        // SAFETY: as in `protect`.
        unsafe {
            CryptUnprotectData(
                &blob(&mut input),
                None,
                Some(&blob(&mut entropy)),
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out.0,
            )
        }
        .map_err(|_| Error::IdentityUnwrap)?;

        Ok(Zeroizing::new(out.as_slice().to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_an_identity_on_first_run_then_reuses_it() {
        let dir = tempfile::tempdir().unwrap();

        let first = load_or_create(dir.path()).unwrap();
        let second = load_or_create(dir.path()).unwrap();

        assert_eq!(
            first.device_id(),
            second.device_id(),
            "a second run must not mint a new identity"
        );
        assert!(dir.path().join(KEY_FILE).exists());
    }

    #[test]
    fn a_portable_key_is_readable_without_dpapi() {
        // The whole point of portable mode: the file must open on a machine
        // whose DPAPI master key wrote nothing, so it cannot be wrapped.
        let dir = tempfile::tempdir().unwrap();

        let created = load_or_create_protected(dir.path(), KeyProtection::Portable).unwrap();
        let on_disk = fs::read(dir.path().join(KEY_FILE)).unwrap();
        assert_eq!(
            on_disk[MAGIC.len()],
            WRAP_PLAINTEXT,
            "a portable key must not be wrapped to this user"
        );

        let reopened = load(dir.path()).unwrap();
        assert_eq!(created.device_id(), reopened.device_id());
    }

    #[test]
    fn an_existing_key_keeps_its_wrapping_regardless_of_the_request() {
        // Reading handles either mode, and creation is the only thing the
        // choice affects — so plugging a drive into a second machine must not
        // rewrite, or fail on, the identity already there.
        let dir = tempfile::tempdir().unwrap();

        let first = load_or_create_protected(dir.path(), KeyProtection::Portable).unwrap();
        let before = fs::read(dir.path().join(KEY_FILE)).unwrap();

        let second = load_or_create_protected(dir.path(), KeyProtection::User).unwrap();
        let after = fs::read(dir.path().join(KEY_FILE)).unwrap();

        assert_eq!(first.device_id(), second.device_id());
        assert_eq!(before, after, "an existing key must be left alone");
    }

    #[test]
    fn portable_mode_needs_the_folder_to_already_exist() {
        // Creating it on demand would turn an installed copy portable the first
        // time it ran somewhere writable, stranding the real identity.
        let exe_dir = std::env::current_exe().unwrap();
        let exe_dir = exe_dir.parent().unwrap();

        // The test binary's own directory has no such folder, so this is the
        // negative case; asserting it never invents one.
        if !exe_dir.join(PORTABLE_DIR).is_dir() {
            assert!(portable_data_dir().is_none());
            assert!(!exe_dir.join(PORTABLE_DIR).exists());
        }
    }

    #[test]
    fn an_explicit_data_dir_wins_and_stays_user_protected() {
        // `JETSTREAM_DATA_DIR` exists to run two devices on one machine, which
        // is not portability — the key should still be wrapped to this user,
        // even when a portable folder is also present.
        let location = choose_location(
            Some(PathBuf::from("D:/explicit")),
            Some(PathBuf::from("D:/portable")),
        )
        .unwrap();

        assert_eq!(location.dir, PathBuf::from("D:/explicit"));
        assert_eq!(location.protection, KeyProtection::User);
        assert!(!location.is_portable());
    }

    #[test]
    fn a_portable_folder_beside_the_exe_wins_over_per_user_state() {
        let location = choose_location(None, Some(PathBuf::from("D:/Jetstream/Jetstream Data")))
            .unwrap();

        assert_eq!(location.dir, PathBuf::from("D:/Jetstream/Jetstream Data"));
        assert!(location.is_portable());
    }

    #[test]
    fn without_either_signal_state_is_per_user() {
        let location = choose_location(None, None).unwrap();

        assert!(!location.is_portable());
        assert!(location.dir.ends_with("Jetstream"));
    }

    #[test]
    fn key_file_does_not_contain_the_raw_private_key_on_windows() {
        let dir = tempfile::tempdir().unwrap();
        let identity = load_or_create(dir.path()).unwrap();
        let on_disk = fs::read(dir.path().join(KEY_FILE)).unwrap();

        assert!(on_disk.starts_with(MAGIC));

        if cfg!(windows) {
            assert_eq!(on_disk[MAGIC.len()], WRAP_DPAPI_USER);
            assert!(
                !on_disk
                    .windows(identity.pkcs8_der().len())
                    .any(|w| w == identity.pkcs8_der()),
                "DPAPI-wrapped file must not contain the plaintext key"
            );
        }
    }

    #[test]
    fn refuses_to_clobber_an_unrecognised_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path()).unwrap();
        fs::write(dir.path().join(KEY_FILE), b"definitely not our key file").unwrap();

        let err = load_or_create(dir.path()).unwrap_err();
        assert!(
            matches!(err, Error::MalformedIdentity { .. }),
            "expected a malformed-identity error, got {err:?}"
        );
    }

    #[test]
    fn reports_truncated_key_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path()).unwrap();
        fs::write(dir.path().join(KEY_FILE), &MAGIC[..4]).unwrap();

        assert!(matches!(
            load(dir.path()).unwrap_err(),
            Error::MalformedIdentity { .. }
        ));
    }

    #[test]
    fn missing_directory_reads_as_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist");

        match load(&missing) {
            Err(Error::Io(e)) if e.kind() == ErrorKind::NotFound => {}
            other => panic!("expected NotFound, got {other:?}"),
        }
    }
}
