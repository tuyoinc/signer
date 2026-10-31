#!/usr/bin/env python3
"""Writes SHA256SUMS and the update manifest for a directory of release assets.

    release_manifest.py DIR --repo tuyoinc/signer --tag v0.1.0 [--minimum-version 0.1.0]

The manifest maps each Rust target triple to its asset's URL and SHA-256.
It is signed separately (see RELEASING.md); the binary trusts nothing else.
"""

import argparse
import hashlib
import json
import pathlib
import re

# Release asset -> the target triples it serves.
ASSETS = {
    "tuyo-signer-x86_64-unknown-linux-musl": ["x86_64-unknown-linux-musl"],
    "tuyo-signer-aarch64-unknown-linux-musl": ["aarch64-unknown-linux-musl"],
    "tuyo-signer-universal-apple-darwin": ["aarch64-apple-darwin", "x86_64-apple-darwin"],
    "tuyo-signer-x86_64-pc-windows-msvc.exe": ["x86_64-pc-windows-msvc"],
}

SEMVER = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=pathlib.Path)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--minimum-version")
    parser.add_argument("--base-url", help="Where the assets are served (default: the GitHub release)")
    args = parser.parse_args()

    version = args.tag.removeprefix("v")
    if not SEMVER.match(version):
        raise SystemExit(f"{args.tag} is not a semantic version tag")
    if args.minimum_version and not SEMVER.match(args.minimum_version):
        raise SystemExit(f"{args.minimum_version} is not a semantic version")

    sums = []
    assets = {}
    for name, targets in ASSETS.items():
        path = args.directory / name
        if not path.is_file():
            raise SystemExit(f"missing release asset {name}")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        sums.append(f"{digest}  {name}")
        base = args.base_url or f"https://github.com/{args.repo}/releases/download/{args.tag}/"
        url = f"{base}{name}"
        for target in targets:
            assets[target] = {"url": url, "sha256": digest}

    manifest = {
        "name": "tuyo-signer",
        "version": version,
        "minimumVersion": args.minimum_version,
        "assets": assets,
    }
    (args.directory / "SHA256SUMS").write_text("\n".join(sums) + "\n")
    (args.directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
