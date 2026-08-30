//! Turning untrusted path strings from a peer into paths that are safe to
//! create inside a destination directory.
//!
//! Everything a sender puts in a manifest is hostile until proven otherwise.
//! The failure this module exists to prevent is a manifest entry like
//! `..\..\Windows\System32\evil.dll`, or `C:\Windows\...`, escaping the folder
//! the user chose. That check happens once, at parse time, before a single
//! file is created — not scattered through the write path where one missed
//! branch is a vulnerability.
//!
//! A second class of problem is Windows-specific and Dukto gets it wrong:
//! reserved device names, trailing dots and spaces, characters NTFS forbids,
//! and paths past `MAX_PATH`. Those make transfers fail confusingly rather than
//! dangerously, but they fail constantly on real folders — anything unzipped
//! from a Linux tarball is a candidate.

use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Longest single path component we accept, in bytes.
///
/// NTFS caps a component at 255 UTF-16 code units; this bounds the UTF-8 form
/// generously while still refusing something absurd.
const MAX_COMPONENT_BYTES: usize = 255;

/// Longest relative path we accept, in bytes.
///
/// Well past anything real. Present so a manifest cannot make us build an
/// unbounded string.
const MAX_PATH_BYTES: usize = 4096;

/// Depth limit, to stop `a/a/a/...` from exhausting the stack in a recursive
/// consumer or hitting filesystem nesting limits.
const MAX_DEPTH: usize = 64;

/// Windows device names, reserved in *every* directory.
///
/// Reserved with any extension too: `CON`, `CON.txt`, and `CON.tar.gz` all
/// refer to the console device.
const WINDOWS_RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", //
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", //
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Characters NTFS forbids in a name, beyond the path separators.
const WINDOWS_FORBIDDEN_CHARS: &[char] = &['<', '>', ':', '"', '|', '?', '*'];

/// A relative path that has been validated as safe to join onto a destination.
///
/// Always uses `/` separators, regardless of platform, so the same manifest
/// means the same thing on both ends. The only way to build one is
/// [`RelPath::parse`], and it can only be constructed from a string that has
/// already been checked — so a `RelPath` in hand is a proof, not a hope.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RelPath(String);

impl RelPath {
    /// Validate an untrusted path string from a manifest.
    ///
    /// Accepts either separator on input, since a sender may be on any
    /// platform, and normalises to `/`.
    pub fn parse(raw: &str) -> Result<Self> {
        if raw.is_empty() {
            return Err(reject(raw, "path is empty"));
        }
        if raw.len() > MAX_PATH_BYTES {
            return Err(reject(raw, "path is implausibly long"));
        }
        if raw.contains('\0') {
            // A NUL truncates the path in any C API underneath us, so
            // `safe.txt\0../../evil` could be created as something else
            // entirely.
            return Err(reject(raw, "path contains a NUL byte"));
        }

        // Reject drive letters and UNC before component parsing, because
        // `C:foo` is a *drive-relative* path on Windows and would otherwise
        // look like an ordinary component.
        if raw.starts_with('/') || raw.starts_with('\\') {
            return Err(reject(raw, "path is absolute"));
        }
        if has_drive_prefix(raw) {
            return Err(reject(raw, "path names a drive"));
        }

        let mut components = Vec::new();
        for part in raw.split(['/', '\\']) {
            match part {
                // Collapse `a//b` and `a/./b`; both are harmless and common
                // from sloppy senders.
                "" | "." => continue,
                ".." => return Err(reject(raw, "path escapes the destination with '..'")),
                _ => components.push(validate_component(raw, part)?),
            }
        }

        if components.is_empty() {
            return Err(reject(raw, "path resolves to nothing"));
        }
        if components.len() > MAX_DEPTH {
            return Err(reject(raw, "path is nested too deeply"));
        }

        Ok(Self(components.join("/")))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The final component — the file or directory name.
    pub fn file_name(&self) -> &str {
        self.0.rsplit('/').next().unwrap_or(&self.0)
    }

    /// The first component. Used for transfer previews, where showing the
    /// top-level names tells a user what they are about to accept.
    pub fn top_level(&self) -> &str {
        self.0.split('/').next().unwrap_or(&self.0)
    }

    pub fn depth(&self) -> usize {
        self.0.split('/').count()
    }

    /// The parent directories that must exist before this path can be created,
    /// outermost first.
    pub fn ancestors(&self) -> Vec<RelPath> {
        let parts: Vec<&str> = self.0.split('/').collect();
        (1..parts.len())
            .map(|i| RelPath(parts[..i].join("/")))
            .collect()
    }

    /// Join onto a destination directory.
    ///
    /// Safe by construction: a `RelPath` cannot contain `..`, a root, or a
    /// drive, so the result is always inside `destination`.
    pub fn resolve_in(&self, destination: &Path) -> PathBuf {
        let mut path = destination.to_path_buf();
        for part in self.0.split('/') {
            path.push(part);
        }
        path
    }

    /// Build a `RelPath` from a path produced by our own directory walk.
    ///
    /// Separate from [`RelPath::parse`] only in intent — it applies exactly the
    /// same checks, because a local path can be just as awkward as a remote
    /// one, and it is better to refuse to send a file than to send one the
    /// receiver must reject.
    pub fn from_local(relative: &Path) -> Result<Self> {
        let mut parts = Vec::new();
        for component in relative.components() {
            match component {
                Component::Normal(part) => {
                    let text = part.to_str().ok_or_else(|| {
                        Error::Protocol(format!(
                            "path {:?} is not valid UTF-8 and cannot be sent",
                            relative.display()
                        ))
                    })?;
                    parts.push(text);
                }
                Component::CurDir => continue,
                _ => {
                    return Err(Error::Protocol(format!(
                        "path {:?} is not relative",
                        relative.display()
                    )));
                }
            }
        }
        Self::parse(&parts.join("/"))
    }
}

impl std::fmt::Display for RelPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for RelPath {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        Self::parse(&value)
    }
}

impl From<RelPath> for String {
    fn from(value: RelPath) -> Self {
        value.0
    }
}

fn reject(path: &str, reason: &str) -> Error {
    // Truncated so a hostile path cannot flood the log, and escaped so control
    // characters in it cannot rewrite the operator's terminal.
    let shown: String = path.chars().take(80).collect();
    Error::Protocol(format!("unsafe path {shown:?}: {reason}"))
}

fn validate_component(raw: &str, part: &str) -> Result<String> {
    if part.len() > MAX_COMPONENT_BYTES {
        return Err(reject(raw, "a path component is too long"));
    }

    if let Some(c) = part.chars().find(|c| c.is_control()) {
        return Err(reject(raw, &format!("component contains control character {c:?}")));
    }
    if let Some(c) = part.chars().find(|c| WINDOWS_FORBIDDEN_CHARS.contains(c)) {
        return Err(reject(
            raw,
            &format!("component contains {c:?}, which Windows does not allow in a name"),
        ));
    }

    // Windows silently strips these when creating a file, so `evil.txt.` and
    // `evil.txt` would collide — and a check performed on the un-stripped name
    // would be checking a name that never reaches the disk.
    if part.ends_with('.') || part.ends_with(' ') {
        return Err(reject(raw, "component ends with a dot or space"));
    }

    if is_windows_reserved(part) {
        return Err(reject(
            raw,
            &format!("{part:?} is a reserved Windows device name"),
        ));
    }

    Ok(part.to_string())
}

/// `C:\...`, `C:/...`, or the drive-relative `C:foo`.
fn has_drive_prefix(raw: &str) -> bool {
    let mut chars = raw.chars();
    matches!((chars.next(), chars.next()), (Some(c), Some(':')) if c.is_ascii_alphabetic())
}

/// Reserved device names are matched on the stem, case-insensitively, so
/// `con`, `CON`, and `Con.txt` are all caught.
fn is_windows_reserved(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or(component);
    WINDOWS_RESERVED
        .iter()
        .any(|reserved| stem.eq_ignore_ascii_case(reserved))
}

/// Prefix a path with `\\?\` so Windows skips `MAX_PATH` and its own
/// normalisation pass.
///
/// The prefix only works on a fully-qualified path with no `.`/`..` and no
/// forward slashes, so this canonicalises first and returns the input unchanged
/// if it cannot. Non-Windows targets get the path back untouched.
pub fn to_extended_length(path: &Path) -> PathBuf {
    #[cfg(not(windows))]
    {
        path.to_path_buf()
    }

    #[cfg(windows)]
    {
        const VERBATIM: &str = r"\\?\";

        let text = path.to_string_lossy();
        if text.starts_with(VERBATIM) {
            return path.to_path_buf();
        }

        // Must be absolute for the verbatim prefix to be meaningful.
        if !path.is_absolute() {
            return path.to_path_buf();
        }

        // Verbatim paths are passed to the filesystem uninterpreted, so any
        // remaining forward slash would become part of a filename.
        let normalized = text.replace('/', r"\");
        if normalized.contains(r"\.\") || normalized.contains(r"\..\") {
            return path.to_path_buf();
        }

        // A UNC path becomes \\?\UNC\server\share.
        if let Some(rest) = normalized.strip_prefix(r"\\") {
            return PathBuf::from(format!(r"{VERBATIM}UNC\{rest}"));
        }

        PathBuf::from(format!("{VERBATIM}{normalized}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_paths() {
        for input in [
            "notes.txt",
            "photos/2026/summer.jpg",
            "a/b/c/d/e.bin",
            "spaces are fine.txt",
            "unicode-日本語-café.txt",
            "dots.in.name.tar.gz",
        ] {
            assert!(RelPath::parse(input).is_ok(), "should accept {input:?}");
        }
    }

    #[test]
    fn normalises_separators_and_redundant_components() {
        assert_eq!(RelPath::parse(r"a\b\c.txt").unwrap().as_str(), "a/b/c.txt");
        assert_eq!(RelPath::parse("a//b///c.txt").unwrap().as_str(), "a/b/c.txt");
        assert_eq!(RelPath::parse("./a/./b.txt").unwrap().as_str(), "a/b.txt");
        assert_eq!(RelPath::parse(r"a/b\c/d.txt").unwrap().as_str(), "a/b/c/d.txt");
    }

    /// The one that matters. Every entry here is a real escape attempt.
    #[test]
    fn refuses_every_way_out_of_the_destination() {
        for attack in [
            "../evil.txt",
            "../../../../Windows/System32/drivers/etc/hosts",
            r"..\..\evil.dll",
            "good/../../evil.txt",
            "good/./../../evil.txt",
            "/etc/passwd",
            r"\Windows\System32\evil.dll",
            r"C:\Windows\System32\evil.dll",
            "C:/Windows/evil.dll",
            "C:evil.dll",
            r"\\server\share\evil.dll",
            "..",
            "../",
            "a/..",
        ] {
            let result = RelPath::parse(attack);
            assert!(
                result.is_err(),
                "SECURITY: {attack:?} was accepted as {:?}",
                result.map(|p| p.as_str().to_string())
            );
        }
    }

    #[test]
    fn a_parsed_path_always_stays_inside_the_destination() {
        // Property check on the guarantee `resolve_in` relies on: whatever a
        // sender writes, the resolved path is under the destination.
        let destination = Path::new(if cfg!(windows) { r"C:\dest" } else { "/dest" });

        for input in ["a.txt", "a/b/c.txt", "./x/y.bin", r"deep\nested\file.dat"] {
            let resolved = RelPath::parse(input).unwrap().resolve_in(destination);
            assert!(
                resolved.starts_with(destination),
                "{input:?} resolved outside the destination: {resolved:?}"
            );
            assert!(
                !resolved.components().any(|c| c == Component::ParentDir),
                "{input:?} resolved with a parent component: {resolved:?}"
            );
        }
    }

    #[test]
    fn refuses_windows_reserved_device_names() {
        for reserved in ["CON", "con", "Con.txt", "NUL", "aux.tar.gz", "COM1", "lpt9.dat"] {
            assert!(
                RelPath::parse(reserved).is_err(),
                "{reserved:?} is a reserved device name and must be refused"
            );
            assert!(
                RelPath::parse(&format!("folder/{reserved}")).is_err(),
                "{reserved:?} is reserved in subdirectories too"
            );
        }

        // Names that merely start with a reserved word are fine.
        assert!(RelPath::parse("console.txt").is_ok());
        assert!(RelPath::parse("connection.log").is_ok());
        assert!(RelPath::parse("nullable.rs").is_ok());
    }

    #[test]
    fn refuses_names_windows_would_silently_rewrite() {
        assert!(RelPath::parse("trailing.").is_err());
        assert!(RelPath::parse("trailing ").is_err());
        assert!(RelPath::parse("folder./file.txt").is_err());
    }

    #[test]
    fn refuses_characters_ntfs_forbids() {
        for bad in ["a<b.txt", "a>b.txt", "a\"b.txt", "a|b.txt", "a?b.txt", "a*b.txt", "a:b.txt"] {
            assert!(RelPath::parse(bad).is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn refuses_nul_and_control_characters() {
        assert!(RelPath::parse("safe.txt\0../../evil").is_err());
        assert!(RelPath::parse("bell\x07.txt").is_err());
        assert!(RelPath::parse("newline\n.txt").is_err());
    }

    #[test]
    fn refuses_absurd_sizes() {
        assert!(RelPath::parse("").is_err());
        assert!(RelPath::parse(&"a".repeat(MAX_COMPONENT_BYTES + 1)).is_err());
        assert!(RelPath::parse(&"a/".repeat(MAX_DEPTH + 2)).is_err());
        assert!(RelPath::parse(&"ab/".repeat(MAX_PATH_BYTES)).is_err());
    }

    #[test]
    fn exposes_the_pieces_the_ui_needs() {
        let path = RelPath::parse("photos/2026/summer.jpg").unwrap();

        assert_eq!(path.file_name(), "summer.jpg");
        assert_eq!(path.top_level(), "photos");
        assert_eq!(path.depth(), 3);
        assert_eq!(
            path.ancestors().iter().map(RelPath::as_str).collect::<Vec<_>>(),
            ["photos", "photos/2026"]
        );

        let flat = RelPath::parse("readme.md").unwrap();
        assert_eq!(flat.file_name(), "readme.md");
        assert_eq!(flat.top_level(), "readme.md");
        assert!(flat.ancestors().is_empty());
    }

    #[test]
    fn survives_a_serde_round_trip_and_revalidates() {
        let path = RelPath::parse("a/b/c.txt").unwrap();
        let encoded = postcard::to_stdvec(&path).unwrap();
        assert_eq!(postcard::from_bytes::<RelPath>(&encoded).unwrap(), path);

        // Deserialization must re-run validation: a hostile peer writes the
        // wire format directly and never calls `parse`.
        let hostile = postcard::to_stdvec(&"../../evil.txt".to_string()).unwrap();
        assert!(
            postcard::from_bytes::<RelPath>(&hostile).is_err(),
            "SECURITY: deserialization bypassed path validation"
        );
    }

    #[test]
    fn from_local_matches_parse() {
        let path = RelPath::from_local(Path::new("photos/2026/summer.jpg")).unwrap();
        assert_eq!(path.as_str(), "photos/2026/summer.jpg");

        assert!(RelPath::from_local(Path::new("../escape.txt")).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn extended_length_prefix_is_applied_to_absolute_paths() {
        let long = Path::new(r"C:\dest").join("x".repeat(300));
        let extended = to_extended_length(&long);

        assert!(
            extended.to_string_lossy().starts_with(r"\\?\C:\dest"),
            "got {extended:?}"
        );

        // Idempotent, so it is safe to apply more than once.
        assert_eq!(to_extended_length(&extended), extended);

        // Relative paths are left alone: the prefix would be meaningless.
        let relative = Path::new(r"dest\file.txt");
        assert_eq!(to_extended_length(relative), relative);
    }

    #[cfg(windows)]
    #[test]
    fn extended_length_handles_unc_paths() {
        let unc = Path::new(r"\\server\share\file.txt");
        assert_eq!(
            to_extended_length(unc).to_string_lossy(),
            r"\\?\UNC\server\share\file.txt"
        );
    }
}
