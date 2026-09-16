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
use std::io::{Cursor, Read};
use std::path::Path;

/// Total uncompressed bytes any single package may expand to. The
/// download itself is already capped at 200 MB (see `fetch.rs`), but
/// compression ratios of 1000:1 are routine and >100000:1 is achievable,
/// so the download cap alone bounds nothing: a 200 MB archive of
/// compressible filler expands to hundreds of gigabytes and fills the
/// disk. Real packages are nowhere near this — the largest legitimate npm
/// packages are tens of MB unpacked — so 512 MB refuses a bomb without
/// ever refusing a genuine package.
const MAX_TOTAL_UNCOMPRESSED_BYTES: u64 = 512 * 1024 * 1024;

/// Entry-count cap, the other half of the same attack: millions of
/// zero-byte entries cost almost nothing to compress but exhaust inodes
/// and stall the walker that scans the result.
const MAX_ENTRIES: usize = 20_000;

/// Headroom over `MAX_TOTAL_UNCOMPRESSED_BYTES` for the tar stream's own
/// headers and block padding, so the generic stream backstop can't fire
/// before the per-entry check that produces an actionable message.
const STREAM_CAP_SLACK_BYTES: u64 = 64 * 1024 * 1024;

fn too_big(kind: &str, detail: String) -> RegistryError {
    RegistryError::Extraction(format!(
        "refusing to extract this package — {kind} ({detail}). \
         A package this large is treated as a decompression bomb, not scanned."
    ))
}

/// Extracts a gzip-compressed tarball (npm's `.tgz`, a PyPI sdist's
/// `.tar.gz`) already in memory into `dest`, which must not exist yet.
///
/// Bounded twice over: the decompressed STREAM is hard-capped by a
/// `take`, so even a tar header that lies about its entry sizes cannot
/// cause an unbounded write, and the per-entry declared sizes are summed
/// and checked as they're read.
pub(crate) fn extract_tar_gz(bytes: &[u8], dest: &Path) -> Result<(), RegistryError> {
    std::fs::create_dir_all(dest).map_err(RegistryError::Io)?;
    let gz = flate2::read::GzDecoder::new(Cursor::new(bytes));
    // The stream cap is a BACKSTOP for a header that lies about its own
    // entry sizes, not the primary gate — hence the slack over
    // MAX_TOTAL_UNCOMPRESSED_BYTES. Without it, a tar whose headers are
    // honest would trip this generic limit mid-entry (a confusing "unpack
    // failed" error) before the per-entry check below could refuse it
    // with a real explanation.
    let limited = gz.take(MAX_TOTAL_UNCOMPRESSED_BYTES + STREAM_CAP_SLACK_BYTES);
    let mut archive = tar::Archive::new(limited);

    let entries = archive
        .entries()
        .map_err(|e| RegistryError::Extraction(format!("tar read failed: {e}")))?;

    let mut count = 0usize;
    let mut declared_total = 0u64;
    for entry in entries {
        let mut entry =
            entry.map_err(|e| RegistryError::Extraction(format!("tar entry failed: {e}")))?;

        count += 1;
        if count > MAX_ENTRIES {
            let _ = std::fs::remove_dir_all(dest);
            return Err(too_big("too many entries", format!("more than {MAX_ENTRIES}")));
        }

        // Checked BEFORE unpacking, so the entry that would cross the
        // line is never written at all.
        let next_total =
            declared_total.saturating_add(entry.header().size().unwrap_or(0));
        if next_total > MAX_TOTAL_UNCOMPRESSED_BYTES {
            let _ = std::fs::remove_dir_all(dest);
            return Err(too_big(
                "uncompressed size over the limit",
                format!("{next_total} bytes declared, limit {MAX_TOTAL_UNCOMPRESSED_BYTES}"),
            ));
        }
        declared_total = next_total;

        // `unpack_in` keeps tar's own path-traversal and symlink-target
        // validation (the protection `unpack` gave us before this loop
        // existed) — it refuses any entry that would land outside `dest`.
        entry
            .unpack_in(dest)
            .map_err(|e| RegistryError::Extraction(format!("tar unpack failed: {e}")))?;
    }

    // The `take` ran out, meaning the real decompressed stream was larger
    // than the cap regardless of what the headers claimed.
    if archive.into_inner().limit() == 0 {
        let _ = std::fs::remove_dir_all(dest);
        return Err(too_big(
            "decompressed stream over the limit",
            format!("more than {MAX_TOTAL_UNCOMPRESSED_BYTES} bytes"),
        ));
    }
    Ok(())
}

/// Extracts a zip archive (a Python wheel, `.whl`) already in memory into
/// `dest`, which must not exist yet.
///
/// The central directory's declared sizes are checked BEFORE anything is
/// written (that is what a classic zip bomb inflates), and the bytes
/// actually written are verified afterwards in case the directory lied.
pub(crate) fn extract_zip(bytes: &[u8], dest: &Path) -> Result<(), RegistryError> {
    std::fs::create_dir_all(dest).map_err(RegistryError::Io)?;
    let reader = Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(reader)
        .map_err(|e| RegistryError::Extraction(format!("not a valid zip archive: {e}")))?;

    if archive.len() > MAX_ENTRIES {
        let _ = std::fs::remove_dir_all(dest);
        return Err(too_big(
            "too many entries",
            format!("{} entries, limit {MAX_ENTRIES}", archive.len()),
        ));
    }

    let declared_total: u64 = (0..archive.len())
        .filter_map(|i| archive.by_index(i).ok().map(|f| f.size()))
        .fold(0u64, |acc, n| acc.saturating_add(n));
    if declared_total > MAX_TOTAL_UNCOMPRESSED_BYTES {
        let _ = std::fs::remove_dir_all(dest);
        return Err(too_big(
            "uncompressed size over the limit",
            format!("{declared_total} bytes declared, limit {MAX_TOTAL_UNCOMPRESSED_BYTES}"),
        ));
    }

    archive
        .extract(dest)
        .map_err(|e| RegistryError::Extraction(format!("zip extract failed: {e}")))?;

    let written = dir_size_bytes(dest);
    if written > MAX_TOTAL_UNCOMPRESSED_BYTES {
        let _ = std::fs::remove_dir_all(dest);
        return Err(too_big(
            "extracted size over the limit",
            format!("{written} bytes written, limit {MAX_TOTAL_UNCOMPRESSED_BYTES}"),
        ));
    }
    Ok(())
}

/// Sum of regular-file sizes under `root`. Symlinks are not followed
/// (`metadata` on the DirEntry would follow them and could double-count
/// or escape the tree); `symlink_metadata` reports the link itself.
fn dir_size_bytes(root: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(meta) = entry.path().symlink_metadata() else {
                continue;
            };
            if meta.is_dir() {
                stack.push(entry.path());
            } else if meta.is_file() {
                total = total.saturating_add(meta.len());
            }
        }
    }
    total
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
            "talyx-registry-extract-test-{}-{}-{}",
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

    /// A tar whose header DECLARES `declared_size` bytes while carrying
    /// almost no actual payload — the shape of a decompression bomb, and
    /// the case `extract_tar_gz` must refuse from the header alone,
    /// before writing anything.
    fn build_tar_gz_with_declared_size(path: &str, declared_size: u64) -> Vec<u8> {
        let mut tar_bytes = Vec::new();
        {
            let mut header = tar::Header::new_gnu();
            header.set_path(path).unwrap();
            header.set_size(declared_size);
            header.set_mode(0o644);
            header.set_cksum();
            tar_bytes.extend_from_slice(header.as_bytes());
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
    fn refuses_a_tarball_that_declares_more_than_the_uncompressed_cap() {
        // A decompression bomb's defining property is a huge DECLARED
        // size behind a tiny compressed payload, which is exactly what
        // this builds: one entry whose header claims 600 MB. The refusal
        // must happen before a single byte is written — asserted below by
        // `dest` not existing — so this test is also instant, rather than
        // actually spilling half a gigabyte onto the CI runner's disk.
        let dest = unique_temp_dir("tar-bomb");
        let archive = build_tar_gz_with_declared_size("package/filler.bin", 600 * 1024 * 1024);

        let result = extract_tar_gz(&archive, &dest);
        assert!(result.is_err(), "a 600 MB declared expansion must be refused");
        let msg = format!("{:?}", result.unwrap_err());
        assert!(
            msg.contains("decompression bomb"),
            "expected a bomb refusal, got: {msg}"
        );
        assert!(
            !dest.exists(),
            "a refused extraction must not leave a partially-written tree behind"
        );
        std::fs::remove_dir_all(&dest).ok();
    }

    #[test]
    fn refuses_an_archive_with_more_entries_than_the_cap() {
        // The other half of the same attack: millions of near-empty
        // entries, cheap to compress, expensive in inodes and in the walk
        // that scans the result. Exercised on the zip path because it
        // reads the entry count from the central directory and refuses
        // before writing anything — the tar path enforces the identical
        // cap but can only do so while streaming, which would mean
        // actually creating 20,000 files just to prove `>` works.
        let dest = unique_temp_dir("zip-entries");
        let names: Vec<String> = (0..(MAX_ENTRIES + 10)).map(|i| format!("f{i}.txt")).collect();
        let refs: Vec<(&str, &[u8])> =
            names.iter().map(|n| (n.as_str(), b"x" as &[u8])).collect();
        let archive = build_zip(&refs);

        let result = extract_zip(&archive, &dest);
        assert!(result.is_err(), "more than {MAX_ENTRIES} entries must be refused");
        assert!(
            format!("{:?}", result.unwrap_err()).contains("too many entries"),
            "expected an entry-count refusal"
        );
        assert!(!dest.exists(), "a refused extraction must not leave files behind");
        std::fs::remove_dir_all(&dest).ok();
    }

    #[test]
    fn refuses_a_zip_that_declares_more_than_the_uncompressed_cap() {
        let dest = unique_temp_dir("zip-bomb");
        // `Stored` entries declare their real size, so a handful of large
        // highly-compressible members is enough to cross the cap in the
        // central directory — refused before extraction begins.
        let chunk = vec![0u8; 64 * 1024 * 1024];
        let names: Vec<String> = (0..9).map(|i| format!("filler{i}.bin")).collect();
        let refs: Vec<(&str, &[u8])> =
            names.iter().map(|n| (n.as_str(), chunk.as_slice())).collect();
        let archive = build_zip(&refs);

        let result = extract_zip(&archive, &dest);
        assert!(result.is_err(), "576 MB declared must be refused");
        assert!(
            format!("{:?}", result.unwrap_err()).contains("decompression bomb"),
            "expected a bomb refusal"
        );
        std::fs::remove_dir_all(&dest).ok();
    }

    #[test]
    fn a_normal_sized_package_is_still_extracted_after_the_caps_exist() {
        // The caps must not become a regression for real packages: a few
        // MB across a few hundred files is an ordinary npm package.
        let dest = unique_temp_dir("tar-normal");
        let body = vec![b'a'; 16 * 1024];
        let names: Vec<String> = (0..200).map(|i| format!("package/src/m{i}.js")).collect();
        let refs: Vec<(&str, &[u8])> =
            names.iter().map(|n| (n.as_str(), body.as_slice())).collect();
        let archive = build_tar_gz(&refs);

        extract_tar_gz(&archive, &dest).expect("an ordinary package must still extract");
        assert!(dest.join("package").join("src").join("m0.js").exists());
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
