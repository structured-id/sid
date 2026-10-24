#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Qualify the archive through fresh external RustCrypto consumers."""

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import tempfile
import tomllib


def run(root, env, *argv, capture=False):
    result = subprocess.run(
        argv, cwd=root, env=env, check=True, text=True,
        stdout=subprocess.PIPE if capture else None,
    )
    return result.stdout


def main():
    root = Path(__file__).resolve().parent.parent
    work = Path(tempfile.mkdtemp(prefix="sid-crypto-package-"))
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(work / "target")
    try:
        version = tomllib.loads((root / "crates/sid-crypto/Cargo.toml").read_text())["package"]["version"]
        name = f"sid-crypto-{version}"
        run(root, env, "cargo", "package", "--locked", "-p", "sid-crypto")
        archive = work / "target/package" / f"{name}.crate"
        checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
        package = work / "source"
        with tarfile.open(archive) as packed:
            for member in packed.getmembers():
                path = PurePosixPath(member.name)
                if path.is_absolute() or ".." in path.parts or path.parts[0] != name:
                    raise ValueError(f"invalid archive path: {member.name}")
                if member.isdir():
                    continue
                if not member.isfile():
                    raise ValueError(f"non-file archive member: {member.name}")
                destination = package.joinpath(*path.parts[1:])
                destination.parent.mkdir(parents=True, exist_ok=True)
                with packed.extractfile(member) as source, destination.open("wb") as output:
                    shutil.copyfileobj(source, output)
        manifest = tomllib.loads((package / "Cargo.toml").read_text())
        if manifest["package"]["license"] != "Apache-2.0":
            raise ValueError("the packaged license must be Apache-2.0")
        for filename in ("LICENSE", "LICENSE-MIT", "NOTICES"):
            if not (package / filename).is_file():
                raise ValueError(f"missing legal file: {filename}")
        for dependency in manifest.get("dependencies", {}).values():
            if isinstance(dependency, dict) and ("path" in dependency or "git" in dependency):
                raise ValueError("normal dependencies must resolve through the registry")
        native = {"aws-lc-rs", "aws-lc-sys", "aws-lc-fips-sys", "ring", "cc", "cmake", "bindgen", "openssl", "openssl-sys"}
        for profile in ("tls", "jwt", "primitives"):
            consumer = work / profile
            shutil.copytree(root / "ci/crypto-consumer", consumer)
            consumer_manifest = consumer / "Cargo.toml"
            consumer_manifest.write_text(consumer_manifest.read_text().replace('"@PACKAGE@"', json.dumps(str(package))))
            flags = ("--manifest-path", str(consumer_manifest), "--no-default-features", "--features", profile)
            # A new consumer directory has no transplanted lockfile or workspace.
            graph = run(root, env, "cargo", "tree", *flags, "-e", "normal,build", "--prefix", "none", "-f", "{p}", capture=True)
            packages = {line.split()[0] for line in graph.splitlines() if line.strip()}
            forbidden = native | {"sid-keys", "sid-core", "sid-plugin", "sid-authn", "sid-storage", "sid-server"}
            if profile != "jwt":
                forbidden.add("jsonwebtoken")
            if profile != "tls":
                forbidden.update({"rustls", "rustls-pki-types", "rustls-webpki"})
            unexpected = sorted(packages & forbidden)
            if unexpected:
                raise ValueError(f"{profile} dependency closure: {unexpected}")
            run(root, env, "cargo", "run", "--locked", *flags)
            print(f"verified: fresh {profile} consumer", flush=True)
        print(f"verified: {name}.crate sha256={checksum}", flush=True)
    except BaseException:
        print(f"failed package evidence preserved in {work}", flush=True)
        raise
    else:
        shutil.rmtree(work)


if __name__ == "__main__":
    main()
