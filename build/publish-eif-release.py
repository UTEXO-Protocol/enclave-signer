#!/usr/bin/env python3
"""Publish existing Stage build artifacts; never run downloaded binaries."""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile


PROFILES = {
    "stage-signet": ("signet", "Public Signet"),
    "stage-mainnet": ("bitcoin", "Bitcoin Mainnet"),
}
ROLES = ("burn", "mint")
COMMON = ("PCR.json", "IMAGE-ENV.json", "SHA256SUMS", "metadata.json",
          "utexo-bridge-parent", "utexo-bridge-parent-cli", "HOST-SHA256SUMS")
OUTPUT = Path("release-output")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def api(path, missing_ok=False):
    result = subprocess.run(["gh", "api", path], capture_output=True, text=True)
    data = json.loads(result.stdout)
    if missing_ok and result.returncode and str(data.get("status")) == "404":
        return None
    require(result.returncode == 0, f"GitHub API failed: {path}")
    return data


def profile_settings(profile):
    require(profile in PROFILES, "Unsupported release profile")
    return PROFILES[profile]


def inputs():
    values = {key: os.environ[key] for key in
              ("GH_REPO", "RELEASE_SHA", "RELEASE_TAG")}
    require(re.fullmatch(r"[\w.-]+/[\w.-]+", values["GH_REPO"]), "Invalid repository")
    require(re.fullmatch(r"[0-9a-f]{40}", values["RELEASE_SHA"]), "Expected full lowercase commit SHA")
    profile = values["BUILD_PROFILE"] = os.environ.get("BUILD_PROFILE", "stage-signet")
    profile_settings(profile)
    require(re.fullmatch(re.escape(profile) + r"-v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?",
                         values["RELEASE_TAG"]), f"Tag must be {profile}-vX.Y.Z (optional suffix)")
    return values


def unused_tag(repo, tag):
    require(api(f"repos/{repo}/git/ref/tags/{tag}", missing_ok=True) is None,
            "Tag already exists; use a new version")
    require(api(f"repos/{repo}/releases/tags/{tag}", missing_ok=True) is None,
            "Release already exists; never overwrite a published bundle")


def validate_run(info, repo, sha):
    require(info.get("status") == "completed" and info.get("conclusion") == "success",
            "Build EIF must have completed successfully")
    require(info.get("head_sha") == sha, "Build run SHA mismatch")
    require(info.get("path") == ".github/workflows/build-eif.yml", "Not a Build EIF run")
    require(info.get("event") in ("workflow_dispatch", "push"), "Untrusted build trigger")
    require(info.get("head_repository", {}).get("full_name") == repo,
            "Build must come from this repository")


def validate():
    values = inputs()
    branch = os.environ["SOURCE_BRANCH"]
    build_run = os.environ["BUILD_RUN_ID"]
    require(branch in ("dev", "stage"), "Only dev/stage are supported")
    require(re.fullmatch(r"[1-9][0-9]*", build_run), "Invalid build run ID")
    sha, repo, tag = (values[k] for k in ("RELEASE_SHA", "GH_REPO", "RELEASE_TAG"))
    subprocess.run(["git", "merge-base", "--is-ancestor", sha, f"origin/{branch}"], check=True)
    info = api(f"repos/{repo}/actions/runs/{build_run}")
    validate_run(info, repo, sha)
    unused_tag(repo, tag)
    return values


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read_json(path):
    require(path.stat().st_size < 1024 * 1024, f"Oversized JSON: {path.name}")
    return json.loads(path.read_text())


def verify_sums(directory, manifest, expected):
    entries = {}
    for line in (directory / manifest).read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)", line)
        require(match is not None, f"Invalid checksum record in {manifest}")
        checksum, name = match.groups()
        require(name not in entries, f"Duplicate checksum for {name}")
        entries[name] = checksum
    require(set(entries) == set(expected), f"Unexpected checksum file set in {manifest}")
    for name, checksum in entries.items():
        require(digest(directory / name) == checksum, f"Checksum mismatch: {name}")


def file_names(role):
    return (f"utexo-bridge-enclave-{role}.eif", *COMMON)


def verify_bundle(directory, reference, role, sha, build_run, profile="stage-signet"):
    network, label = profile_settings(profile)
    names = file_names(role)
    for name in names:
        for root in (directory, reference):
            path = root / name
            require(path.is_file() and not path.is_symlink() and path.stat().st_size > 0,
                    f"Missing or invalid {role}/{name}")
        require(digest(directory / name) == digest(reference / name),
                f"S3 differs from the Build EIF Actions artifact: {role}/{name}")
    verify_sums(directory, "SHA256SUMS", [names[0]])
    verify_sums(directory, "HOST-SHA256SUMS", ["utexo-bridge-parent", "utexo-bridge-parent-cli"])
    metadata = read_json(directory / "metadata.json")
    expected = {"git_sha": sha, "variant": f"rgb-{role}", "build_profile": profile,
                "eif_name": names[0], "run_id": build_run}
    require(all(metadata.get(k) == v for k, v in expected.items()), f"Wrong {role} metadata")
    require(not metadata.get("debug_features"), "Debug build features cannot be published")
    pcrs = read_json(directory / "PCR.json")
    require(pcrs.get("HashAlgorithm") in ("Sha384", "Sha384 { ... }"),
            "Expected Sha384 PCR measurements")
    for key in ("PCR0", "PCR1", "PCR2"):
        value = pcrs.get(key)
        require(isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{96}", value)
                and int(value, 16) != 0, f"Invalid or zero {role} {key}")
    raw_env = read_json(directory / "IMAGE-ENV.json")
    require(isinstance(raw_env, list), "Expected image environment array")
    image_env = {}
    for entry in raw_env:
        require(isinstance(entry, str) and "=" in entry, "Invalid image environment")
        key, value = entry.split("=", 1)
        require(key not in image_env, f"Duplicate image setting: {key}")
        image_env[key] = value
    require(image_env.get("BITCOIN_NETWORK") == network, f"Expected {label} image")
    if profile == "stage-mainnet":
        for key, value in {"BTC_RELAY_MODE": "required", "SPV_MIN_CONFIRMATIONS": "3",
                           "EVM_FINALITY_TAG": "finalized"}.items():
            require(image_env.get(key) == value, f"Mainnet requires {key}={value}")
    require(image_env.get("EVM_CHAIN_ID") == "42161", "Expected Arbitrum One image")
    asset = image_env.get("RGB_ASSET_ID", "")
    require(re.fullmatch(r"rgb:[A-Za-z0-9_~:.-]+", asset) and metadata.get("rgb_asset_id") == asset,
            "Missing or inconsistent RGB asset")
    return {"pcrs": pcrs, "rgb_asset_id": asset,
            "files": {name: digest(directory / name) for name in names}}


def package(bundles, references, output, sha, build_run, tag, repo, branch, profile="stage-signet"):
    network, label = profile_settings(profile)
    # Validate both roles before producing any publishable output.
    roles = {role: verify_bundle(bundles / role, references / role, role, sha, build_run, profile)
             for role in ROLES}
    require(roles["mint"]["rgb_asset_id"] == roles["burn"]["rgb_asset_id"], "Roles use different assets")
    require(roles["mint"]["pcrs"]["PCR0"] != roles["burn"]["pcrs"]["PCR0"], "Roles share a PCR0")
    output.mkdir()
    assets = output / "assets"
    assets.mkdir()
    for role in ROLES:
        with tarfile.open(assets / f"{tag}-{role}.tar.gz", "w:gz") as archive:
            for name in file_names(role):
                path = bundles / role / name
                info = archive.gettarinfo(str(path), arcname=f"{role}/{name}")
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mode = 0o755 if name in ("utexo-bridge-parent", "utexo-bridge-parent-cli") else 0o644
                with path.open("rb") as stream:
                    archive.addfile(info, stream)
        shutil.copyfile(bundles / role / "PCR.json", assets / f"PCR-{role}.json")
    manifest = {"release_tag": tag, "git_sha": sha, "source_branch": branch,
                "build_profile": profile, "bitcoin_network": network, "evm_chain_id": 42161,
                "build_url": f"https://github.com/{repo}/actions/runs/{build_run}", "roles": roles}
    (assets / "release-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (assets / "SHA256SUMS").write_text("".join(
        f"{digest(path)}  {path.name}\n" for path in sorted(assets.iterdir())))
    notes = [f"# Stage / {label} — {tag}", "",
             "Recommended artifacts for Stage signers. This is a Stage prerelease.", "",
             f"- Bitcoin: **{label}**", "- EVM: **Arbitrum One (42161)**",
             f"- Build profile: `{profile}`", f"- Source branch: `{branch}`",
             f"- Source commit: `{sha}`", f"- [Build EIF run]({manifest['build_url']})", ""]
    for role in ROLES:
        notes += [f"## {role.title()}", "", f"Download `{tag}-{role}.tar.gz`.", ""]
        notes += [f"- {key}: `{roles[role]['pcrs'][key]}`" for key in ("PCR0", "PCR1", "PCR2")]
        notes += [""]
    notes += ["## Verify the download", "", "Download `SHA256SUMS` and all release assets, then run:",
              "", "```sh", "sha256sum --check SHA256SUMS", "```", "",
              "Each role archive contains its EIF, PCR.json, IMAGE-ENV.json, metadata.json,",
              "Parent, CLI and build checksums. release-manifest.json hashes every file in each archive.",
              "Use the Burn archive for a Burn cosigner. Use the CLI from the same release.", "",
              "Publication does not deploy a signer or prove the current Stage deployment.",
              "These are build measurements, not a live AWS attestation. Verify the signer's",
              "attestation and approved identity separately. Validation assumptions",
              f"are those of the source commit's {profile} profile.", ""]
    (output / "notes.md").write_text("\n".join(notes))


def prepare():
    values = validate()
    sha, repo, tag = (values[k] for k in ("RELEASE_SHA", "GH_REPO", "RELEASE_TAG"))
    profile = values["BUILD_PROFILE"]
    build_run = os.environ["BUILD_RUN_ID"]
    bucket = os.environ["EIF_S3_BUCKET"]
    require(re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket), "Invalid EIF_S3_BUCKET")
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        for role in ROLES:
            destination = root / "s3" / role
            destination.mkdir(parents=True)
            reference = root / "actions" / role
            reference.mkdir(parents=True)
            run("gh", "run", "download", build_run, "--repo", repo, "--name",
                f"eif-{sha}-{role}-{profile}", "--dir", str(reference))
            for name in file_names(role):
                run("aws", "s3", "cp", f"s3://{bucket}/eif/{sha}/{profile}/rgb-{role}/{name}",
                    str(destination / name), "--only-show-errors")
        package(root / "s3", root / "actions", OUTPUT, sha, build_run, tag, repo, os.environ["SOURCE_BRANCH"], profile)


def publish():
    values = inputs()
    repo, sha, tag = (values[k] for k in ("GH_REPO", "RELEASE_SHA", "RELEASE_TAG"))
    profile = values["BUILD_PROFILE"]
    network, label = profile_settings(profile)
    assets = OUTPUT / "assets"
    names = {f"{tag}-{role}.tar.gz" for role in ROLES} | {
        "PCR-burn.json", "PCR-mint.json", "release-manifest.json"}
    require({p.name for p in assets.iterdir()} == names | {"SHA256SUMS"}, "Unexpected release assets")
    verify_sums(assets, "SHA256SUMS", names)
    manifest = read_json(assets / "release-manifest.json")
    require(manifest.get("git_sha") == sha and manifest.get("release_tag") == tag
            and manifest.get("build_profile") == profile and manifest.get("bitcoin_network") == network,
            "Prepared release does not match publication inputs")
    unused_tag(repo, tag)
    # Creating the ref fails on a concurrent publisher; never move an existing tag.
    run("gh", "api", f"repos/{repo}/git/refs", "-f", f"ref=refs/tags/{tag}", "-f", f"sha={sha}")
    run("gh", "release", "create", tag, *[str(p) for p in sorted(assets.iterdir())],
        "--repo", repo, "--verify-tag", "--draft", "--prerelease", "--latest=false",
        "--title", f"Stage / {label} — {tag}", "--notes-file", str(OUTPUT / "notes.md"))
    # A failed upload leaves a draft, never a partially published signer release.
    with tempfile.TemporaryDirectory() as temporary:
        run("gh", "release", "download", tag, "--repo", repo, "--dir", temporary)
        for path in assets.iterdir():
            require(digest(Path(temporary) / path.name) == digest(path), "Uploaded asset mismatch")
    run("gh", "release", "edit", tag, "--repo", repo, "--draft=false", "--prerelease", "--latest=false")
    url = f"https://github.com/{repo}/releases/tag/{tag}"
    print(url)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as stream:
            stream.write(f"Published [Stage / {label} release]({url}).\n")


if __name__ == "__main__":
    try:
        {"validate": validate, "prepare": prepare, "publish": publish}[sys.argv[1]]()
    except (ValueError, KeyError, IndexError, OSError, subprocess.CalledProcessError) as error:
        sys.exit(f"Release failed: {error}")
