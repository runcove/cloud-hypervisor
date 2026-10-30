// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

// Helpers for issuing `BLKDISCARD` / `BLKZEROOUT` ioctls on block devices,
// and the `punch_hole` / `write_zeroes` / `write_zeroes_unmap` dispatchers
// used by the raw I/O backends.
//
// The kernel ioctl numbers and argument layout are stable userspace ABI
// (see `include/uapi/linux/fs.h`):
//
// ```c
// #define BLKDISCARD  _IO(0x12, 119)   /* arg: const __u64 range[2] = { start, len } */
// #define BLKZEROOUT  _IO(0x12, 127)   /* arg: const __u64 range[2] = { start, len } */
// ```
//
// The kernel does `copy_from_user(range, arg, sizeof(range))`, i.e. it reads
// 16 bytes through the single pointer it is given, so we must pass a single
// `__u64[2]` array rather than two separate `*const u64` pointers.

use std::fs::File;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};

use vmm_sys_util::write_zeroes::{PunchHole, WriteZeroesAt};

// `_IO(0x12, 119)` — issue a discard request to a block device.
pub const BLKDISCARD: libc::c_ulong = 0x1277;
// `_IO(0x12, 127)` — write zeroes to a range of a block device, with a
// kernel-side fallback to writing zero pages when the hardware has no native
// `WRITE_ZEROES`.
pub const BLKZEROOUT: libc::c_ulong = 0x127f;

// Issue a `BLK*` range ioctl with proper `[start, len]` argument.
fn blk_range_ioctl(fd: RawFd, request: libc::c_ulong, offset: u64, length: u64) -> io::Result<()> {
    let range: [u64; 2] = [offset, length];
    // SAFETY: `fd` is a valid block-device fd owned by the caller; `&range`
    // is a 16-byte array matching the kernel's expected `__u64[2]` layout
    // and lives for the duration of the call.
    let ret = unsafe { libc::ioctl(fd, request as _, &range) };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

// Discard (TRIM/UNMAP) the byte range `[offset, offset + length)` on the
// block device referenced by `fd`.
pub(crate) fn blkdiscard(fd: RawFd, offset: u64, length: u64) -> io::Result<()> {
    blk_range_ioctl(fd, BLKDISCARD, offset, length)
}

// Zero the byte range `[offset, offset + length)` on the block device
// referenced by `fd`. The kernel falls back to writing explicit zero pages
// when the device has no hardware `WRITE_ZEROES`.
pub(crate) fn blkzeroout(fd: RawFd, offset: u64, length: u64) -> io::Result<()> {
    blk_range_ioctl(fd, BLKZEROOUT, offset, length)
}

/// Maps the result of `BLKDISCARD`: a device that does not support discard
/// reports success, as discard is only a hint.
pub(crate) fn discard_result(result: io::Result<()>) -> io::Result<()> {
    match result {
        Err(e) if e.raw_os_error() == Some(libc::EOPNOTSUPP) => Ok(()),
        result => result,
    }
}

// The kernel interfaces that clear a range of a block device. Tests implement
// this to stand in for devices that a regular file cannot imitate.
trait BlockDevice {
    // `BLKDISCARD`: a hint, after which the range need not read back as zeroes.
    fn discard(&mut self, offset: u64, length: u64) -> io::Result<()>;
    // `fallocate(FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE)`: the device's
    // write zeroes command, allowed to deallocate the range. EOPNOTSUPP if the
    // device has none.
    fn fallocate_punch_hole(&mut self, offset: u64, length: u64) -> io::Result<()>;
    // `BLKZEROOUT`: the device's write zeroes command without deallocating,
    // or else the kernel writes zero pages.
    fn zeroout(&mut self, offset: u64, length: u64) -> io::Result<()>;
}

impl BlockDevice for File {
    fn discard(&mut self, offset: u64, length: u64) -> io::Result<()> {
        blkdiscard(self.as_raw_fd(), offset, length)
    }

    fn fallocate_punch_hole(&mut self, offset: u64, length: u64) -> io::Result<()> {
        PunchHole::punch_hole(self, offset, length)
    }

    fn zeroout(&mut self, offset: u64, length: u64) -> io::Result<()> {
        blkzeroout(self.as_raw_fd(), offset, length)
    }
}

fn block_device_discard(device: &mut impl BlockDevice, offset: u64, length: u64) -> io::Result<()> {
    discard_result(device.discard(offset, length))
}

// A failure other than EOPNOTSUPP is not retried: the device has the command
// and it failed, so the guest gets the error. EOPNOTSUPP from `BLKZEROOUT` is
// an error too: unlike a discard, a write zeroes must not report success when
// nothing was zeroed.
fn block_device_write_zeroes_unmap(
    device: &mut impl BlockDevice,
    offset: u64,
    length: u64,
) -> io::Result<()> {
    match device.fallocate_punch_hole(offset, length) {
        Err(e) if e.raw_os_error() == Some(libc::EOPNOTSUPP) => device.zeroout(offset, length),
        result => result,
    }
}

// Punch a hole in `fd` over the byte range `[offset, offset + length)`.
//
// On block devices this is a discard: route through `BLKDISCARD`, which may
// leave the range reading back as anything, and report success if the device
// does not support it, as a discard is only a hint. Use [`write_zeroes_unmap`]
// when the range must read back as zeroes. On regular files use `PunchHole`,
// falling back to `WriteZeroesAt` on EOPNOTSUPP (e.g. tmpfs).
pub(crate) fn punch_hole(
    file: &mut File,
    is_blkdev: bool,
    offset: u64,
    length: u64,
) -> io::Result<()> {
    if is_blkdev {
        return block_device_discard(file, offset, length);
    }
    match file.punch_hole(offset, length) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::EOPNOTSUPP) => {
            file.write_all_zeroes_at(offset, length as usize)?;
            Ok(())
        }
        Err(e) => Err(e),
    }
}

// Zero the byte range `[offset, offset + length)` in `fd`.
//
// Uses `BLKZEROOUT` on block devices, which never deallocates the range, and
// `WriteZeroesAt` on regular files, which tries fallocate and falls back to
// positional writes on EOPNOTSUPP (e.g. tmpfs).
pub(crate) fn write_zeroes(
    file: &mut File,
    is_blkdev: bool,
    offset: u64,
    length: u64,
) -> io::Result<()> {
    if is_blkdev {
        return blkzeroout(file.as_raw_fd(), offset, length);
    }
    file.write_all_zeroes_at(offset, length as usize)?;
    Ok(())
}

// Zero the byte range `[offset, offset + length)` in `fd`, deallocating it if
// possible: the range reads back as zeroes on success, and deallocating it is
// only preferred.
//
// On block devices `fallocate(FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE)`
// issues the device's write zeroes command, without `REQ_NOUNMAP` and without
// a fallback to writing zero pages, and returns EOPNOTSUPP if the device has
// no such command. `BLKZEROOUT` then zeroes the range the slow way, keeping it
// allocated. `BLKDISCARD` is not an option: it does not guarantee zeroes (a
// partial dm-thin block, a device without discard zeroes data), and the kernel
// itself drops EOPNOTSUPP from the device. On regular files a punched hole
// reads as zeroes, so use [`punch_hole`].
pub(crate) fn write_zeroes_unmap(
    file: &mut File,
    is_blkdev: bool,
    offset: u64,
    length: u64,
) -> io::Result<()> {
    if is_blkdev {
        return block_device_write_zeroes_unmap(file, offset, length);
    }
    punch_hole(file, false, offset, length)
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::os::unix::fs::FileExt;
    use std::os::unix::io::FromRawFd;

    use super::*;

    // Create a memfd backed file. memfd uses the same backing as tmpfs,
    // so fallocate with ZERO_RANGE and PUNCH_HOLE returns EOPNOTSUPP,
    // exercising the fallback path.
    fn memfd_file() -> File {
        let name = CString::new("ch_sparse_test").unwrap();
        // SAFETY: memfd_create is a safe syscall that returns a new fd.
        let fd = unsafe { libc::memfd_create(name.as_ptr(), 0) };
        assert!(fd >= 0, "memfd_create failed");
        // SAFETY: fd is a valid open file descriptor we just created.
        unsafe { File::from_raw_fd(fd) }
    }

    #[test]
    fn write_zeroes_fallback() {
        let mut f = memfd_file();
        f.write_all_at(&vec![0xAA; 4096], 0).unwrap();

        write_zeroes(&mut f, false, 512, 1024).unwrap();

        let mut buf = vec![0xFFu8; 4096];
        f.read_exact_at(&mut buf, 0).unwrap();

        assert!(buf[..512].iter().all(|&b| b == 0xAA));
        assert!(buf[512..1536].iter().all(|&b| b == 0));
        assert!(buf[1536..].iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn punch_hole_fallback() {
        let mut f = memfd_file();
        f.write_all_at(&vec![0xBB; 4096], 0).unwrap();

        punch_hole(&mut f, false, 1024, 2048).unwrap();

        let mut buf = vec![0xFFu8; 4096];
        f.read_exact_at(&mut buf, 0).unwrap();

        assert!(buf[..1024].iter().all(|&b| b == 0xBB));
        assert!(buf[1024..3072].iter().all(|&b| b == 0));
        assert!(buf[3072..].iter().all(|&b| b == 0xBB));
    }

    // What the tests below can show: which kernel interfaces the block device
    // paths call and how they treat the results, against a device whose
    // behaviour is scripted here, namely one whose discard succeeds without
    // zeroing. It is not a block device, so it cannot show that the kernel
    // keeps its side of the bargain; the loop device tests in
    // `formats::raw` run the real syscalls.
    const FAKE_SIZE: usize = 4096;

    #[derive(Default)]
    struct FakeBlockDevice {
        data: Vec<u8>,
        // The errno each interface fails with, if any.
        discard_errno: Option<i32>,
        punch_hole_errno: Option<i32>,
        zeroout_errno: Option<i32>,
        calls: Vec<&'static str>,
    }

    impl FakeBlockDevice {
        fn new() -> Self {
            FakeBlockDevice {
                data: vec![0xAA; FAKE_SIZE],
                ..Default::default()
            }
        }

        fn zero(
            &mut self,
            call: &'static str,
            errno: Option<i32>,
            offset: u64,
            length: u64,
        ) -> io::Result<()> {
            self.calls.push(call);
            if let Some(errno) = errno {
                return Err(io::Error::from_raw_os_error(errno));
            }
            self.data[offset as usize..(offset + length) as usize].fill(0);
            Ok(())
        }

        fn is_zeroed(&self) -> bool {
            self.data[..512].iter().all(|&b| b == 0xAA)
                && self.data[512..1536].iter().all(|&b| b == 0)
                && self.data[1536..].iter().all(|&b| b == 0xAA)
        }

        fn is_untouched(&self) -> bool {
            self.data.iter().all(|&b| b == 0xAA)
        }
    }

    impl BlockDevice for FakeBlockDevice {
        // Succeeds and leaves the old data in place, as a discard may.
        fn discard(&mut self, _: u64, _: u64) -> io::Result<()> {
            self.calls.push("discard");
            match self.discard_errno {
                Some(errno) => Err(io::Error::from_raw_os_error(errno)),
                None => Ok(()),
            }
        }

        fn fallocate_punch_hole(&mut self, offset: u64, length: u64) -> io::Result<()> {
            self.zero("fallocate", self.punch_hole_errno, offset, length)
        }

        fn zeroout(&mut self, offset: u64, length: u64) -> io::Result<()> {
            self.zero("zeroout", self.zeroout_errno, offset, length)
        }
    }

    #[test]
    fn write_zeroes_unmap_does_not_rely_on_discard() {
        let mut device = FakeBlockDevice::new();
        block_device_write_zeroes_unmap(&mut device, 512, 1024).unwrap();
        assert_eq!(device.calls, ["fallocate"]);
        assert!(device.is_zeroed());
    }

    #[test]
    fn write_zeroes_unmap_falls_back_to_zeroout() {
        let mut device = FakeBlockDevice {
            punch_hole_errno: Some(libc::EOPNOTSUPP),
            ..FakeBlockDevice::new()
        };
        block_device_write_zeroes_unmap(&mut device, 512, 1024).unwrap();
        assert_eq!(device.calls, ["fallocate", "zeroout"]);
        assert!(device.is_zeroed());
    }

    #[test]
    fn write_zeroes_unmap_fails_if_nothing_can_zero() {
        let mut device = FakeBlockDevice {
            discard_errno: Some(libc::EOPNOTSUPP),
            punch_hole_errno: Some(libc::EOPNOTSUPP),
            zeroout_errno: Some(libc::EOPNOTSUPP),
            ..FakeBlockDevice::new()
        };
        let error = block_device_write_zeroes_unmap(&mut device, 512, 1024).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EOPNOTSUPP));
        assert_eq!(device.calls, ["fallocate", "zeroout"]);
        assert!(device.is_untouched());
    }

    #[test]
    fn write_zeroes_unmap_returns_other_errors() {
        // The command exists and failed: writing zero pages over a device
        // that just reported an error, or no space, is not a fallback.
        let mut device = FakeBlockDevice {
            punch_hole_errno: Some(libc::ENOSPC),
            ..FakeBlockDevice::new()
        };
        let error = block_device_write_zeroes_unmap(&mut device, 512, 1024).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ENOSPC));
        assert_eq!(device.calls, ["fallocate"]);

        let mut device = FakeBlockDevice {
            punch_hole_errno: Some(libc::EOPNOTSUPP),
            zeroout_errno: Some(libc::EIO),
            ..FakeBlockDevice::new()
        };
        let error = block_device_write_zeroes_unmap(&mut device, 512, 1024).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
    }

    #[test]
    fn discard_stays_a_hint() {
        let mut device = FakeBlockDevice::new();
        block_device_discard(&mut device, 512, 1024).unwrap();
        assert_eq!(device.calls, ["discard"]);
        assert!(device.is_untouched());

        let mut device = FakeBlockDevice {
            discard_errno: Some(libc::EOPNOTSUPP),
            ..FakeBlockDevice::new()
        };
        block_device_discard(&mut device, 512, 1024).unwrap();
        assert_eq!(device.calls, ["discard"]);

        let mut device = FakeBlockDevice {
            discard_errno: Some(libc::EIO),
            ..FakeBlockDevice::new()
        };
        let error = block_device_discard(&mut device, 512, 1024).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
    }

    #[test]
    fn write_zeroes_unmap_on_a_regular_file_punches_a_hole() {
        let mut f = memfd_file();
        f.write_all_at(&vec![0xCC; 4096], 0).unwrap();

        write_zeroes_unmap(&mut f, false, 1024, 2048).unwrap();

        let mut buf = vec![0xFFu8; 4096];
        f.read_exact_at(&mut buf, 0).unwrap();

        assert!(buf[..1024].iter().all(|&b| b == 0xCC));
        assert!(buf[1024..3072].iter().all(|&b| b == 0));
        assert!(buf[3072..].iter().all(|&b| b == 0xCC));
    }
}
