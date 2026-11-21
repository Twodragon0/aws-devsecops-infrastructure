#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
lambda_dir="$root/modules/lambda"
build_dir=$(mktemp -d)
trap 'python3 -c "import shutil, sys; shutil.rmtree(sys.argv[1])" "$build_dir"' EXIT

docker run --rm --platform linux/amd64 --entrypoint python \
  --user "$(id -u):$(id -g)" \
  -v "$root/requirements.lock:/tmp/requirements.lock:ro" \
  -v "$build_dir:/build" \
  public.ecr.aws/lambda/python:3.12@sha256:f229f304f82f5016fe26e4714d05b6a8196e0c6c61b463112841a5e3c3647163 \
  -m pip install --disable-pip-version-check --no-cache-dir --no-compile --only-binary=:all: \
  --requirement /tmp/requirements.lock --target /build/python

python3 - "$build_dir" "$lambda_dir" <<'PY'
from pathlib import Path
from shutil import copyfileobj
from sys import argv
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

build_dir, lambda_dir = map(Path, argv[1:])

def write_zip(output, root, files):
    with ZipFile(output, "w") as archive:
        for path in files:
            entry = ZipInfo(path.relative_to(root).as_posix())
            entry.compress_type = ZIP_DEFLATED
            entry.create_system = 3
            entry.external_attr = (0o100000 | (path.stat().st_mode & 0o755)) << 16
            with path.open("rb") as source, archive.open(entry, "w") as target:
                copyfileobj(source, target)

layer_files = sorted(path for path in (build_dir / "python").rglob("*") if path.is_file())
write_zip(build_dir / "lambda_layer.zip", build_dir, layer_files)
write_zip(build_dir / "aws_monitor.zip", lambda_dir, [lambda_dir / "aws_monitor.py"])
PY

mv -- "$build_dir/lambda_layer.zip" "$build_dir/aws_monitor.zip" "$lambda_dir/"
