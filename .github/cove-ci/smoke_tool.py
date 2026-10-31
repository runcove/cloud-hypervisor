#!/usr/bin/env python3
"""smoke_tool.py -- the helpers smoke.sh needs that bash does badly.

Used by smoke.sh and by cove-release.yml's `smoke` job. Standard library only.

Subcommands:

  initramfs --busybox FILE --out FILE
      Writes the guest's initramfs: a gzip'd newc cpio holding a static
      busybox, /dev/console and INIT (below) as /init. Every byte is fixed by
      the busybox's bytes (mtime 0, uid 0, inodes in order, gzip mtime 0), so
      the same pinned busybox always gives the same sha256.

  api SOCKET METHOD ENDPOINT [JSON]
      One call to Cloud Hypervisor's HTTP API over its unix socket
      (http://localhost/api/v1/ENDPOINT), what ch-remote does. The response
      body goes to stdout. Exit 0 on a 2xx answer, 1 on any other answer or
      none (connection refused, timeout).

  field JSONFILE PATH
      Prints one value from a JSON document ('-' is stdin), PATH dotted
      (config.cpus.boot_vcpus). Exit 1 when the path is not there.

  rewrite-config SNAPDIR --disk P --serial P --console P [--kernel P] [--initramfs P]
      Points a snapshot's config.json at this run's files: its one disk, its
      serial and virtio-console logs, and (when the snapshot names them) the
      kernel and initramfs. A clone or a wake needs it: the snapshot records
      the paths of the VM it came from. Exit 1 when config.json is not the
      shape this expects (one disk, a serial and a console section).

  pack OUTDIR --snapshot DIR --disk FILE --version V --hb N
              --kernel-sha256 X --initramfs-sha256 Y
      Writes OUTDIR/ch-smoke-checkpoint.tar.gz (checkpoint/CHECKPOINT,
      checkpoint/disk.raw, checkpoint/snapshot/*) and
      OUTDIR/ch-smoke-checkpoint.tar.gz.sha256 (one sha256sum line).

  unpack TARBALL DEST
      Extracts a checkpoint written by pack into DEST/checkpoint. The tarball
      comes from a published release, so it refuses anything pack would not
      have written: a member that is not a plain file or directory (links,
      devices), a path outside checkpoint/ (absolute, '..'), more than
      SIZE_CAP bytes, or a CHECKPOINT file that does not parse.

  info CHECKPOINT KEY
      Prints one key of a CHECKPOINT file, after checking the whole file.

Exit codes: 0 done; 1 the thing asked about failed (an API call, a config
shape, a missing field); 2 usage (argparse); 93 could not run safely (an
input missing or malformed: a busybox that is not a static x86-64 ELF, a
checkpoint that is not what pack writes).
"""

import argparse
import gzip
import hashlib
import http.client
import io
import json
import os
import re
import socket
import sys
import tarfile

TARBALL = "ch-smoke-checkpoint.tar.gz"
# smoke.sh's VERSION shape: a release tag, or git describe output for a test build.
VERSION_RE = re.compile(r"^v[0-9]+\.[0-9]+(\.[0-9]+)?(-[A-Za-z0-9._-]+)?$")
# A checkpoint is guest RAM (256 MiB) plus a 64 MiB disk and a few small files;
# 4 GiB leaves room for a bigger guest and stops a runaway one.
SIZE_CAP = 4 << 30

# The guest's /init. busybox sh, no network, no modules (the kernel has none).
# It prints CH-SMOKE-BOOTED once, after writing a mark to the disk's first
# sector and reading it back, then a heartbeat every second, forever:
#   CH-SMOKE-HB <n> cpus=<online list> mem_kb=<MemTotal> queues=<q> disk=<ok|err>
# <q> is how many blk-mq queues the guest sees on its disk
# (/sys/block/vda/mq/*), so smoke.sh can check num_queues=2 reached it.
# Each heartbeat first writes its own line to the disk's second sector with
# fsync, so `disk=ok` means the virtio-blk device took a write at that moment.
# The boot-time readback of the first sector may be served from the guest's
# page cache: the mark smoke.sh finds in the image on the host is what proves
# that write reached the device.
# It onlines any hotplugged vCPU (the kernel brings memory online by itself:
# CONFIG_MHP_DEFAULT_ONLINE_TYPE_ONLINE_AUTO). Lines go to the virtio-console
# (hvc0), which smoke.sh reads, and to /dev/console (the serial port).
INIT = r"""#!/bin/busybox sh
/bin/busybox mkdir -p /proc /sys /dev /tmp
/bin/busybox --install -s /bin
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev 2>/dev/null
say() { echo "$*"; [ -c /dev/hvc0 ] && echo "$*" > /dev/hvc0; }
mark="CH-SMOKE-DISK $(cat /proc/sys/kernel/random/boot_id)"
printf '%s\n' "$mark" | dd of=/dev/vda bs=512 count=1 conv=sync,fsync 2>/dev/null
back=$(dd if=/dev/vda bs=512 count=1 2>/dev/null | head -n 1)
if [ "$back" = "$mark" ]; then say "CH-SMOKE-DISK-OK"; else say "CH-SMOKE-DISK-FAIL"; fi
say "CH-SMOKE-BOOTED"
n=0
while :; do
  n=$((n + 1))
  for f in /sys/devices/system/cpu/cpu[0-9]*/online; do
    [ -f "$f" ] && [ "$(cat "$f")" = 0 ] && echo 1 > "$f" 2>/dev/null
  done
  cpus=$(cat /sys/devices/system/cpu/online)
  mem=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
  queues=$(ls /sys/block/vda/mq 2>/dev/null | wc -l)
  line="CH-SMOKE-HB $n cpus=$cpus mem_kb=$mem queues=$queues"
  if printf '%s\n' "$line" | dd of=/dev/vda bs=512 seek=1 count=1 conv=sync,fsync 2>/dev/null; then
    say "$line disk=ok"
  else
    say "$line disk=err"
  fi
  sleep 1
done
"""


def cannot(msg):
    print(f"smoke_tool: CANNOT -- {msg} (exit 93)", file=sys.stderr)
    sys.exit(93)


def failed(msg):
    print(f"smoke_tool: FAILED -- {msg}", file=sys.stderr)
    sys.exit(1)


# --- initramfs ---------------------------------------------------------------

def _newc(ino, name, mode, data=b"", rdev=(0, 0)):
    name_b = name.encode() + b"\0"
    fields = (ino, mode, 0, 0, 1, 0, len(data), 0, 0, rdev[0], rdev[1], len(name_b), 0)
    head = b"070701" + b"".join(b"%08X" % f for f in fields)
    out = head + name_b
    out += b"\0" * (-len(out) % 4)
    out += data
    out += b"\0" * (-len(out) % 4)
    return out


def initramfs_bytes(busybox):
    if busybox[:4] != b"\x7fELF" or busybox[4] != 2 or busybox[18:20] != b"\x3e\x00":
        cannot("the busybox is not an x86-64 ELF")
    entries = [
        (".", 0o040755, b"", (0, 0)),
        ("bin", 0o040755, b"", (0, 0)),
        ("bin/busybox", 0o100755, busybox, (0, 0)),
        ("dev", 0o040755, b"", (0, 0)),
        ("dev/console", 0o020600, b"", (5, 1)),
        ("init", 0o100755, INIT.encode(), (0, 0)),
        ("proc", 0o040755, b"", (0, 0)),
        ("sys", 0o040755, b"", (0, 0)),
        ("tmp", 0o041777, b"", (0, 0)),
    ]
    cpio = b"".join(_newc(i + 1, n, m, d, r) for i, (n, m, d, r) in enumerate(entries))
    cpio += _newc(0, "TRAILER!!!", 0)
    buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buf, mtime=0, compresslevel=9) as g:
        g.write(cpio)
    return buf.getvalue()


def cmd_initramfs(a):
    try:
        with open(a.busybox, "rb") as f:
            busybox = f.read()
    except OSError as e:
        cannot(f"cannot read the busybox: {e}")
    data = initramfs_bytes(busybox)
    tmp = a.out + ".part"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, a.out)
    print(f"initramfs {a.out} sha256={hashlib.sha256(data).hexdigest()} bytes={len(data)}")


# --- api -----------------------------------------------------------------------

class _UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path, timeout):
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self._path)
        self.sock = s


def cmd_api(a):
    if not re.fullmatch(r"[a-z]+\.[a-z\-_]+", a.endpoint):
        cannot(f"endpoint {a.endpoint!r} is not an API endpoint name")
    body = None
    headers = {}
    if a.json is not None:
        try:
            json.loads(a.json)
        except ValueError:
            cannot(f"the request body is not JSON: {a.json!r}")
        body = a.json.encode()
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
    try:
        conn = _UnixHTTP(a.socket, float(os.environ.get("SMOKE_API_TIMEOUT", "120")))
        conn.request(a.method, f"/api/v1/{a.endpoint}", body=body, headers=headers)
        r = conn.getresponse()
        data = r.read()
    except (OSError, http.client.HTTPException) as e:
        failed(f"{a.method} {a.endpoint}: no answer on {a.socket}: {e}")
    sys.stdout.write(data.decode("utf-8", "replace"))
    if not 200 <= r.status < 300:
        failed(f"{a.method} {a.endpoint}: HTTP {r.status}: {data.decode('utf-8', 'replace')[:300]}")


# --- field ---------------------------------------------------------------------

def cmd_field(a):
    try:
        doc = json.load(sys.stdin if a.file == "-" else open(a.file))
    except (OSError, ValueError) as e:
        failed(f"not JSON: {e}")
    cur = doc
    for part in a.path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            failed(f"no {a.path} in the document")
        cur = cur[part]
    print(json.dumps(cur) if isinstance(cur, (dict, list)) else cur)


# --- rewrite-config ------------------------------------------------------------

def cmd_rewrite_config(a):
    path = os.path.join(a.snapdir, "config.json")
    try:
        with open(path) as f:
            cfg = json.load(f)
    except (OSError, ValueError) as e:
        failed(f"cannot read {path}: {e}")
    disks = cfg.get("disks")
    if not isinstance(disks, list) or len(disks) != 1 or not isinstance(disks[0], dict):
        failed(f"{path}: expected exactly one disk, found {disks!r}")
    for key in ("serial", "console"):
        if not isinstance(cfg.get(key), dict):
            failed(f"{path}: no {key} section")
    disks[0]["path"] = a.disk
    cfg["serial"].update({"file": a.serial, "mode": "File"})
    cfg["console"].update({"file": a.console, "mode": "File"})
    payload = cfg.get("payload")
    if isinstance(payload, dict):
        if a.kernel and payload.get("kernel"):
            payload["kernel"] = a.kernel
        if a.initramfs and payload.get("initramfs"):
            payload["initramfs"] = a.initramfs
    tmp = path + ".part"
    with open(tmp, "w") as f:
        json.dump(cfg, f)
    os.replace(tmp, path)


# --- pack / unpack / info ------------------------------------------------------

CHECKPOINT_KEYS = ("format", "version", "hb", "disk", "kernel_sha256", "initramfs_sha256")


def checkpoint_text(version, hb, ksha, isha):
    return "".join(f"{k}={v}\n" for k, v in zip(CHECKPOINT_KEYS, ("1", version, hb, "disk.raw", ksha, isha)))


def parse_checkpoint(text):
    out = {}
    for line in text.splitlines():
        m = re.fullmatch(r"([a-z0-9_]+)=([A-Za-z0-9._-]+)", line)
        if not m or m.group(1) in out:
            cannot(f"CHECKPOINT line {line!r} is not one key=value")
        out[m.group(1)] = m.group(2)
    if tuple(out) != CHECKPOINT_KEYS:
        cannot(f"CHECKPOINT keys are {list(out)}, expected {list(CHECKPOINT_KEYS)}")
    if out["format"] != "1" or not VERSION_RE.match(out["version"]) or not out["hb"].isdigit() \
            or out["disk"] != "disk.raw" \
            or not all(re.fullmatch(r"[0-9a-f]{64}", out[k]) for k in ("kernel_sha256", "initramfs_sha256")):
        cannot(f"CHECKPOINT values are malformed: {out}")
    return out


def _add(tar, arcname, data=None, path=None):
    ti = tarfile.TarInfo(arcname)
    ti.mtime, ti.uid, ti.gid, ti.uname, ti.gname = 0, 0, 0, "", ""
    if data is None and path is None:
        ti.type, ti.mode = tarfile.DIRTYPE, 0o755
        tar.addfile(ti)
        return
    ti.mode = 0o644
    if path is not None:
        if not os.path.isfile(path) or os.path.islink(path):
            failed(f"{path} is not a regular file")
        ti.size = os.lstat(path).st_size
        with open(path, "rb") as f:
            tar.addfile(ti, f)
    else:
        ti.size = len(data)
        tar.addfile(ti, io.BytesIO(data))


def cmd_pack(a):
    if not VERSION_RE.match(a.version) or not a.hb.isdigit():
        cannot(f"version {a.version!r} or hb {a.hb!r} is malformed")
    for k in (a.kernel_sha256, a.initramfs_sha256):
        if not re.fullmatch(r"[0-9a-f]{64}", k):
            cannot(f"{k!r} is not a sha256")
    names = sorted(os.listdir(a.snapshot))
    if "config.json" not in names:
        failed(f"{a.snapshot} holds no config.json: {names}")
    out = os.path.join(a.outdir, TARBALL)
    tmp = out + ".part"
    with open(tmp, "wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=6) as gz:
            with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tar:
                _add(tar, "checkpoint")
                _add(tar, "checkpoint/CHECKPOINT",
                     data=checkpoint_text(a.version, a.hb, a.kernel_sha256, a.initramfs_sha256).encode())
                _add(tar, "checkpoint/disk.raw", path=a.disk)
                _add(tar, "checkpoint/snapshot")
                for n in names:
                    _add(tar, f"checkpoint/snapshot/{n}", path=os.path.join(a.snapshot, n))
    os.replace(tmp, out)
    h = hashlib.sha256()
    with open(out, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    with open(out + ".sha256", "w") as f:
        f.write(f"{h.hexdigest()}  {TARBALL}\n")
    print(f"packed {out} sha256={h.hexdigest()}")


def cmd_unpack(a):
    dest = os.path.realpath(a.dest)
    total = 0
    try:
        tar = tarfile.open(a.tarball, mode="r:gz")
    except (OSError, tarfile.TarError) as e:
        cannot(f"{a.tarball} is not a gzip'd tar: {e}")
    with tar:
        try:
            members = tar.getmembers()
        except (OSError, tarfile.TarError, EOFError) as e:
            cannot(f"{a.tarball} cannot be read: {e}")
        # Every member is checked before anything is written.
        for m in members:
            parts = m.name.split("/")
            if m.name.startswith("/") or ".." in parts or parts[0] != "checkpoint" or "" in parts:
                cannot(f"{a.tarball}: member {m.name!r} is outside checkpoint/")
            if not (m.isdir() or m.isfile()):
                cannot(f"{a.tarball}: member {m.name!r} is not a plain file or directory")
            total += m.size
            if total > SIZE_CAP:
                cannot(f"{a.tarball}: more than {SIZE_CAP} bytes")
        try:
            for m in members:
                target = os.path.join(dest, m.name)
                if m.isdir():
                    os.makedirs(target, mode=0o755, exist_ok=True)
                    continue
                os.makedirs(os.path.dirname(target), exist_ok=True)
                src = tar.extractfile(m)
                # O_EXCL: a member named twice is refused, never overwritten.
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
                with os.fdopen(fd, "wb") as f:
                    for chunk in iter(lambda: src.read(1 << 20), b""):
                        f.write(chunk)
        except (OSError, tarfile.TarError, EOFError) as e:
            cannot(f"{a.tarball} cannot be extracted: {e}")
    for need in ("checkpoint/CHECKPOINT", "checkpoint/disk.raw", "checkpoint/snapshot/config.json"):
        if not os.path.isfile(os.path.join(dest, need)):
            cannot(f"{a.tarball} holds no {need}")
    with open(os.path.join(dest, "checkpoint/CHECKPOINT")) as f:
        parse_checkpoint(f.read())


def cmd_info(a):
    try:
        with open(a.checkpoint) as f:
            text = f.read()
    except OSError as e:
        cannot(f"cannot read {a.checkpoint}: {e}")
    info = parse_checkpoint(text)
    if a.key not in info:
        failed(f"no {a.key} in {a.checkpoint}")
    print(info[a.key])


def main(argv=None):
    p = argparse.ArgumentParser(prog="smoke_tool.py")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("initramfs")
    s.add_argument("--busybox", required=True)
    s.add_argument("--out", required=True)
    s = sub.add_parser("api")
    s.add_argument("socket")
    s.add_argument("method", choices=("GET", "PUT"))
    s.add_argument("endpoint")
    s.add_argument("json", nargs="?")
    s = sub.add_parser("field")
    s.add_argument("file")
    s.add_argument("path")
    s = sub.add_parser("rewrite-config")
    s.add_argument("snapdir")
    for k in ("--disk", "--serial", "--console"):
        s.add_argument(k, required=True)
    s.add_argument("--kernel")
    s.add_argument("--initramfs")
    s = sub.add_parser("pack")
    s.add_argument("outdir")
    for k in ("--snapshot", "--disk", "--version", "--hb", "--kernel-sha256", "--initramfs-sha256"):
        s.add_argument(k, required=True)
    s = sub.add_parser("unpack")
    s.add_argument("tarball")
    s.add_argument("dest")
    s = sub.add_parser("info")
    s.add_argument("checkpoint")
    s.add_argument("key")
    a = p.parse_args(argv)
    {"initramfs": cmd_initramfs, "api": cmd_api, "field": cmd_field,
     "rewrite-config": cmd_rewrite_config, "pack": cmd_pack, "unpack": cmd_unpack,
     "info": cmd_info}[a.cmd](a)


if __name__ == "__main__":
    main()
