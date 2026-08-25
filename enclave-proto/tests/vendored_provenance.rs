//! Guards the two invariants that keep the vendored proto slice honest.
//!
//! `enclave.rs` is committed pre-generated: there is no `build.rs` and no
//! `prost-build` anywhere in the repo, deliberately, so that PCR0 does not
//! depend on which `protoc`/`prost-build` version a builder happens to have.
//! The cost of that choice is that `proto/enclave.proto` is inert - editing it
//! changes nothing, and the schema silently drifts from the code.
//!
//! Nothing but prose stood between us and that drift, and the prose has already
//! been wrong once (the blob-hash table shipped with two incorrect hashes). So
//! assert it instead:
//!
//!   1. README's blob-hash table == the files actually on disk. Catches any
//!      edit to `enclave.rs` or `enclave.proto`, including a hand-edit of the
//!      file marked "do not edit" and a re-sync that forgot the table.
//!   2. README's `Commit` == the `rev` `parent/Cargo.toml` pins. Catches a
//!      one-sided re-sync, where the parent moves to a new schema and the
//!      enclave keeps compiling against the old one.
//!
//! Neither can verify the vendored bytes against the private upstream - that
//! needs credentials this build deliberately does not have. `README.md` documents
//! the manual procedure for anyone who does have them.

use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    let p = root().join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
}

/// Git's blob object id: `sha1("blob " + len + "\0" + bytes)`. Matches what
/// `git hash-object <file>` prints, which is the command README.md tells the
/// reader to run.
fn git_blob_sha1(path: &Path) -> String {
    let bytes =
        std::fs::read(path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let mut msg = format!("blob {}\0", bytes.len()).into_bytes();
    msg.extend_from_slice(&bytes);
    hex(&sha1(&msg))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA-1 (RFC 3174). Inlined rather than pulled from crates.io: this crate ships
/// with exactly one dependency on purpose, and a self-contained implementation
/// keeps the provenance check auditable without adding to the lockfile.
fn sha1(msg: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

    let bit_len = (msg.len() as u64) * 8;
    let mut padded = msg.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// The 40-hex id quoted on a line mentioning `needle`. Several lines can mention
/// the same path - README.md lists `rust-gen/src/enclave/enclave.rs` in both the
/// file-mapping table and the blob-hash table - so take the first line that
/// carries an id, not merely the first that matches.
fn quoted_sha_on_line(haystack: &str, needle: &str, what: &str) -> String {
    let mut seen = 0usize;
    for line in haystack.lines().filter(|l| l.contains(needle)) {
        seen += 1;
        if let Some(id) = line
            .split(['`', '"'])
            .find(|f| f.len() == 40 && f.chars().all(|c| c.is_ascii_hexdigit()))
        {
            return id.to_string();
        }
    }
    panic!("{what}: {seen} line(s) mention {needle:?}, none carry a 40-hex id");
}

#[test]
fn readme_blob_hashes_match_the_vendored_files() {
    let readme = read("README.md");

    for (upstream_path, local_path) in [
        ("rust-gen/src/enclave/enclave.rs", "src/enclave.rs"),
        ("proto/enclave/enclave.proto", "proto/enclave.proto"),
    ] {
        let documented = quoted_sha_on_line(&readme, upstream_path, "README blob-hash table");
        let actual = git_blob_sha1(&root().join(local_path));

        assert_eq!(
            documented, actual,
            "\n\nenclave-proto/{local_path} does not match the hash README.md documents \
             for upstream {upstream_path}.\n\
             \n  README.md says : {documented}\n  file on disk is : {actual}\n\n\
             Either the vendored file was edited (it must stay verbatim - see \
             enclave-proto/README.md), or it was re-synced from a new upstream commit \
             and the README table was not updated. Re-sync BOTH files and the whole \
             Provenance section together, then `git hash-object` them to refresh the table.\n"
        );
    }
}

#[test]
fn readme_commit_matches_the_rev_parent_pins() {
    let readme = read("README.md");
    let documented = quoted_sha_on_line(&readme, "| Commit |", "README Provenance table");

    let parent_manifest = read("../parent/Cargo.toml");
    let pinned = quoted_sha_on_line(
        &parent_manifest,
        "federated-signer-proto",
        "parent/Cargo.toml federated-signer-proto dependency",
    );

    assert_eq!(
        documented,
        pinned,
        "\n\nThe vendored slice and the parent are pinned to DIFFERENT upstream commits.\n\
         \n  enclave-proto/README.md Commit : {documented}\n  parent/Cargo.toml rev          : {pinned}\n\n\
         The enclave compiles against the vendored slice and the parent against the git \
         crate, so a split pin means the two halves speak different wire schemas - a field \
         renumbering would surface as a mis-parsed request at runtime, not as a build \
         failure. Re-vendor enclave-proto/ from the rev parent pins (or move both together).\n"
    );
}

/// The re-sync procedure is only trustworthy if the README keeps saying how to
/// run it, so fail if the Provenance section is gutted.
#[test]
fn readme_still_documents_the_resync_procedure() {
    let readme = read("README.md");
    for marker in [
        "## Provenance",
        "git hash-object",
        "rust-gen/src/enclave/enclave.rs",
        "proto/enclave/enclave.proto",
    ] {
        assert!(
            readme.contains(marker),
            "enclave-proto/README.md no longer contains {marker:?}. The vendored slice has no \
             build.rs, so this README is the only description of how to re-sync it - keep the \
             Provenance section and its verification commands intact."
        );
    }
}
