#!/usr/bin/env python3
"""Package completed-kernel external C module inputs, without building a kernel."""

import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def file_identity(root):
    files = {}
    for path in sorted(root.rglob("*")):
        name = path.relative_to(root).as_posix()
        if path.is_symlink():
            files[name] = {"symlink": os.readlink(path)}
        elif path.is_file():
            with path.open("rb") as f:
                digest = hashlib.file_digest(f, "sha256").hexdigest()
            files[name] = {"sha256": digest, "bytes": path.stat().st_size}
    return files


def package(source, obj, io, gitdir):
    git = ["git", "--git-dir=" + str(gitdir), "--work-tree=" + str(source)]
    commit = subprocess.check_output(git + ["rev-parse", "HEAD"], text=True).strip()
    if commit != os.environ["SHA"]:
        raise ValueError("source commit mismatch")
    if (
        subprocess.run(git + ["diff", "--quiet", "HEAD", "--"], check=False).returncode
        != 0
    ):
        raise ValueError("source has tracked changes")
    required = [
        "Module.symvers",
        "vmlinux",
        ".config",
        "include/config/kernel.release",
        "include/config/auto.conf",
        "include/generated/compile.h",
        "include/generated/autoconf.h",
        "include/generated/utsrelease.h",
    ]
    for name in required:
        path = obj / name
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError("missing completed-kernel input: " + name)
    release = (obj / "include/config/kernel.release").read_text().strip()
    compiler = [
        line
        for line in (obj / "include/generated/compile.h").read_text().splitlines()
        if line.startswith("#define LINUX_COMPILER ")
    ]
    if len(compiler) != 1 or not release:
        raise ValueError("missing compiled release/compiler identity")
    output = io / "out"
    output.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="module-build-", dir=io) as temp:
        root = Path(temp)
        build = root / "build"
        command = "$(srctree)/scripts/package/install-extmod-build " + shlex.quote(
            str(build)
        )
        subprocess.run(
            [
                "make",
                "-s",
                "-C",
                str(source),
                "O=" + str(obj),
                "run-command",
                "KBUILD_RUN_COMMAND=" + command,
            ],
            check=True,
        )
        shutil.copyfile(obj / ".config", build / ".config")
        shutil.copyfile(obj / "vmlinux", build / "vmlinux")
        shutil.copyfile(io / "config", root / "input.config")
        files = file_identity(root)
        identity = {
            "schema": "maclab.module-build/1",
            "source_repo": os.environ["URL"],
            "source_commit": commit,
            "release": release,
            "linux_compiler": compiler[0],
            "files": files,
        }
        (root / "IDENTITY.json").write_text(
            json.dumps(identity, indent=2, sort_keys=True) + "\n"
        )
        staged = root / "module-build.tar.zst"
        subprocess.run(
            [
                "tar",
                "-C",
                str(root),
                "--zstd",
                "-cf",
                str(staged),
                "IDENTITY.json",
                "input.config",
                "build",
            ],
            check=True,
        )
        os.replace(staged, output / "module-build.tar.zst")


if __name__ == "__main__":
    try:
        package(*(Path(arg).resolve() for arg in sys.argv[1:]))
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        sys.exit("module-build: " + str(error))
