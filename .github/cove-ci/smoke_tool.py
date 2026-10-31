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
      kernel and initramfs. A clone needs it: the snapshot records the paths of
      the VM it came from. Exit 1 when config.json is not the shape this
      expects (one disk, a serial and a console section).

Exit codes: 0 done; 1 the thing asked about failed (an API call, a config
shape, a missing field); 2 usage (argparse); 93 could not run safely (an
input missing or malformed: a busybox that is not a static x86-64 ELF).
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
    a = p.parse_args(argv)
    {"initramfs": cmd_initramfs, "api": cmd_api, "field": cmd_field,
     "rewrite-config": cmd_rewrite_config}[a.cmd](a)


if __name__ == "__main__":
    main()
