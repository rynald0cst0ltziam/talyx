//! Safe archive extraction — both formats used here (`tar`, `zip`) have
//! their own documented path-traversal protection (verified directly
//! against each crate's docs before relying on it, not assumed):
//! `tar::Archive::unpack` rejects `..` entries and validates symlink
//! targets; `zip::ZipArchive::extract` sanitizes every path via
//! `ZipFile::enclosed_name` and only follows a symlink whose canonicalized
//! target stays inside the destination. Both extract into a directory this
//! module creates fresh per package version (see `cache.rs`), which
//! nothing else touches concurrently, so the "TOCTOU under concurrent
//! destination mutation" caveat `tar`'s own docs call out doesn't apply
//! here.

use crate::RegistryError;
use std::fs::File;
use std::io::Cursor;
use std::path::Path;

/// Extracts a gzip-compressed tarball (npm's `.tgz`, a PyPI sdist's
/// `.tar.gz`) already in memory into `dest`, which must not exist yet.
pub(crate) fn extract_tar_gz(bytes: &[u8], dest: &Path) -> Result<(), RegistryError> {
    std::fs::create_dir_all(dest).map_err(RegistryError::Io)?;
    let gz = flate2::read::GzDecoder::new(Cursor::new(bytes));
    let mut archive = tar::Archive::new(gz);
    archive
        .unpack(dest)
        .map_err(|e| RegistryError::Extraction(format!("tar unpack failed: {e}")))
}

/// Extracts a zip archive (a Python wheel, `.whl`) already in memory into
/// `dest`, which must not exist yet.
pub(crate) fn extract_zip(bytes: &[u8], dest: &Path) -> Result<(), RegistryError> {
    std::fs::create_dir_all(dest).map_err(RegistryError::Io)?;
    let reader = Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(reader)
        .map_err(|e| RegistryError::Extraction(format!("not a valid zip archive: {e}")))?;
    archive
        .extract(dest)
        .map_err(|e| RegistryError::Extraction(format!("zip extract failed: {e}")))
}

/// Writes `bytes` to a fresh file at `path` (parent must already exist).
/// Used to persist the archive itself alongside the extracted content for
/// inspection/audit — not required for scanning, but cheap and useful
/// when a human wants to see exactly what was fetched.
pub(crate) fn write_archive(bytes: &[u8], path: &Path) -> Result<(), RegistryError> {
    use std::io::Write;
    let mut f = File::create(path).map_err(RegistryError::Io)?;
    f.write_all(bytes).map_err(RegistryError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_temp_dir(name: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "agentguard-registry-extract-test-{}-{}-{}",
            std::process::id(),
            n,
            name
        ))
    }

    fn build_tar_gz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            for (path, content) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_path(path).unwrap();
                header.set_size(content.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append(&header, *content).unwrap();
            }
            builder.finish().unwrap();
        }
        gzip(&tar_bytes)
    }

    /// Writes a raw GNU tar header's `name` field directly, bypassing
    /// `Header::set_path`'s own `..`-rejecting validation entirely — this
    /// is what actually simulates a hand-crafted malicious archive. A
    /// real attacker who compromises a registry response controls the
    /// raw tar bytes directly; they don't go through this crate's own
    /// `Header::set_path`, so a test that does go through it would only
    /// prove the WRITE side rejects the attack, not that `extract_tar_gz`
    /// (the READ side, the code actually exposed to a hostile archive)
    /// does.
    fn build_tar_gz_with_raw_unchecked_path(path: &str, content: &[u8]) -> Vec<u8> {
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            let mut header = tar::Header::new_gnu();
            let gnu = header.as_gnu_mut().unwrap();
            let name_bytes = path.as_bytes();
            assert!(name_bytes.len() < gnu.name.len(), "test path too long for a raw GNU name field");
            gnu.name[..name_bytes.len()].copy_from_slice(name_bytes);
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            builder.append(&header, content).unwrap();
            builder.finish().unwrap();
        }
        gzip(&tar_bytes)
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut gz_bytes = Vec::new();
        {
            let mut encoder = flate2::write::GzEncoder::new(&mut gz_bytes, flate2::Compression::default());
            use std::io::Write;
            encoder.write_all(bytes).unwrap();
            encoder.finish().unwrap();
        }
        gz_bytes
    }

    #[test]
    fn extracts_a_well_behaved_tarball() {
        let dest = unique_temp_dir("tar-benign");
        let archive = build_tar_gz(&[("package/index.js", b"console.log('hi');")]);
        extract_tar_gz(&archive, &dest).unwrap();
        let content = std::fs::read_to_string(dest.join("package").join("index.js")).unwrap();
        assert_eq!(content, "console.log('hi');");
        std::fs::remove_dir_all(&dest).ok();
    }

    #[test]
    fn refuses_to_extract_a_tarball_entry_that_escapes_the_destination() {
        // A hand-crafted malicious archive with a raw, unvalidated `..`
        // path (see build_tar_gz_with_raw_unchecked_path's comment for
        // why the high-level builder API can't be used for this case —
        // it rejects `..` itself). Proves the crate-level protection this
        // module's doc comment claims, rather than trusting the claim.
        let dest = unique_temp_dir("tar-zipslip");
        let archive = build_tar_gz_with_raw_unchecked_path("../../evil.txt", b"pwned");
        let result = extract_tar_gz(&archive, &dest);

        // Whether `unpack` errors outright or silently skips the bad
        // entry, the load-bearing assertion is the same: nothing must
        // land outside `dest`.
        let escaped_path = dest.parent().unwrap().parent().unwrap().join("evil.txt");
        assert!(
            !escaped_path.exists(),
            "a '../../' entry must never be written outside the destination directory"
        );
        let _ = result;

        std::fs::remove_dir_all(&dest).ok();
    }

    fn build_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let cursor = Cursor::new(&mut buf);
            let mut writer = zip::ZipWriter::new(cursor);
            let options: zip::write::FileOptions<()> =
                zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
            for (path, content) in entries {
                use std::io::Write;
                writer.start_file(*path, options).unwrap();
                writer.write_all(content).unwrap();
            }
            writer.finish().unwrap();
        }
        buf
    }

    #[test]
    fn extracts_a_well_behaved_zip() {
        let dest = unique_temp_dir("zip-benign");
        let archive = build_zip(&[("pkg/__init__.py", b"# hi")]);
        extract_zip(&archive, &dest).unwrap();
        let content = std::fs::read_to_string(dest.join("pkg").join("__init__.py")).unwrap();
        assert_eq!(content, "# hi");
        std::fs::remove_dir_all(&dest).ok();
    }

    #[test]
    fn refuses_to_extract_a_zip_entry_that_escapes_the_destination() {
        let dest = unique_temp_dir("zip-zipslip");
        let archive = build_zip(&[("pkg/__init__.py", b"benign"), ("../../evil.txt", b"pwned")]);
        let result = extract_zip(&archive, &dest);

        let escaped_path = dest.parent().unwrap().parent().unwrap().join("evil.txt");
        assert!(
            !escaped_path.exists(),
            "a '../../' entry must never be written outside the destination directory"
        );
        let _ = result;

        std::fs::remove_dir_all(&dest).ok();
    }
}
