//! Manual, network-hitting proof that fetch_and_extract works against the
//! real npm and PyPI registries. Not a `#[test]` deliberately -- every
//! other test in this workspace is hermetic/offline, and this one isn't,
//! so it stays an opt-in example: `cargo run -p agentguard-registry
//! --example fetch_demo`.

use agentguard_core::ArtifactSource;

fn main() {
    let cache_dir = std::env::temp_dir().join("agentguard-registry-fetch-demo");
    println!("cache dir: {}", cache_dir.display());

    let cases = [
        ArtifactSource::Registry {
            name: "@modelcontextprotocol/server-filesystem".to_string(),
            registry: "npm".to_string(),
        },
        ArtifactSource::Registry {
            name: "left-pad@1.3.0".to_string(),
            registry: "npm".to_string(),
        },
        ArtifactSource::Registry {
            name: "black==24.1.0".to_string(),
            registry: "pypi".to_string(),
        },
    ];

    for source in &cases {
        println!("\n=== {source:?} ===");
        match agentguard_registry::fetch_and_extract(source, &cache_dir) {
            Ok(pkg) => {
                println!("resolved version: {}", pkg.resolved_version);
                println!("extracted to: {}", pkg.extracted_dir.display());
                let count = walkdir_count(&pkg.extracted_dir);
                println!("files extracted: {count}");
            }
            Err(e) => println!("FAILED: {e}"),
        }
    }
}

fn walkdir_count(dir: &std::path::Path) -> usize {
    fn recurse(dir: &std::path::Path, count: &mut usize) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                recurse(&path, count);
            } else {
                *count += 1;
            }
        }
    }
    let mut count = 0;
    recurse(dir, &mut count);
    count
}
