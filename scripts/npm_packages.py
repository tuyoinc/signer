#!/usr/bin/env python3
"""Builds the npm packages from a directory of release assets.

    npm_packages.py ASSETS OUT --version 0.1.0

`@tuyo/signer` holds a small launcher and lists one package per platform as
optionalDependencies; npm installs only the one matching the machine, with no
install scripts, so `npx -y @tuyo/signer mcp` works behind proxies and with
--ignore-scripts.
"""

import argparse
import json
import pathlib
import shutil

# npm package suffix -> (release asset, os, cpu list, binary name)
PLATFORMS = {
    "darwin": ("tuyo-signer-universal-apple-darwin", "darwin", ["arm64", "x64"], "tuyo-signer"),
    "linux-x64": ("tuyo-signer-x86_64-unknown-linux-musl", "linux", ["x64"], "tuyo-signer"),
    "linux-arm64": ("tuyo-signer-aarch64-unknown-linux-musl", "linux", ["arm64"], "tuyo-signer"),
    "win32-x64": ("tuyo-signer-x86_64-pc-windows-msvc.exe", "win32", ["x64"], "tuyo-signer.exe"),
}

COMMON = {
    "license": "MIT OR Apache-2.0",
    "repository": {"type": "git", "url": "git+https://github.com/tuyoinc/signer.git"},
    "homepage": "https://github.com/tuyoinc/signer",
}


def write(path: pathlib.Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("assets", type=pathlib.Path)
    parser.add_argument("out", type=pathlib.Path)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parent.parent

    for suffix, (asset, os_name, cpus, binary) in PLATFORMS.items():
        package = args.out / f"signer-{suffix}"
        (package / "bin").mkdir(parents=True, exist_ok=True)
        target = package / "bin" / binary
        shutil.copyfile(args.assets / asset, target)
        target.chmod(0o755)
        write(package / "package.json", {
            "name": f"@tuyo/signer-{suffix}",
            "version": args.version,
            "description": f"tuyo-signer binary for {os_name} ({', '.join(cpus)}).",
            "os": [os_name],
            "cpu": cpus,
            "files": ["bin"],
            "preferUnplugged": True,
            **COMMON,
        })

    launcher = args.out / "signer"
    (launcher / "bin").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(root / "npm" / "tuyo-signer.js", launcher / "bin" / "tuyo-signer.js")
    shutil.copyfile(root / "README.md", launcher / "README.md")
    write(launcher / "package.json", {
        "name": "@tuyo/signer",
        "version": args.version,
        "description": "Offline signer for Tuyo agents, as an MCP server and command line tool.",
        "bin": {"tuyo-signer": "bin/tuyo-signer.js"},
        "files": ["bin", "README.md"],
        "optionalDependencies": {f"@tuyo/signer-{s}": args.version for s in PLATFORMS},
        **COMMON,
    })


if __name__ == "__main__":
    main()
