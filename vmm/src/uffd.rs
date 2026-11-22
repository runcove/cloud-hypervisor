// Copyright © 2026 Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0

//! Minimal userfaultfd bindings for demand-paged snapshot restore.
//!
//! Prefers `/dev/userfaultfd` (Linux 6.1+) over the `userfaultfd(2)` syscall
//! to create a fault descriptor, falling back to the syscall when the device
//! is unavailable. Then uses `UFFDIO_API` / `UFFDIO_REGISTER` / `UFFDIO_COPY`
//! ioctls to handle page faults from a background thread.
//!
//! Unlike an mmap(MAP_PRIVATE) overlay approach, UFFD does not replace the
//! original memory mapping, so it remains compatible with VFIO device
//! passthrough and shared-memory-backed guest RAM.

use std::fs::{File, OpenOptions};
use std::io::{self, Error, Read};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::Path;
use std::{fmt, thread};

use vm_allocator::page_size::get_page_size;
use vm_migration::protocol::{MemoryRange, Request, Response, Status};

use crate::migration::transport::SocketStream;
use crate::sparse::{seek_data, seek_hole};
use crate::userfaultfd;

#[repr(C)]
struct UffdioApi {
    pub api: u64,
    pub features: u64,
    pub ioctls: u64,
}

#[repr(C)]
struct UffdioRegister {
    pub range_start: u64,
    pub range_len: u64,
    pub mode: u64,
    pub ioctls: u64,
}

#[repr(C)]
struct UffdioCopy {
    pub dst: u64,
    pub src: u64,
    pub len: u64,
    pub mode: u64,
    pub copy: i64,
}

#[repr(C)]
struct UffdioContinue {
    pub range_start: u64,
    pub range_len: u64,
    pub mode: u64,
    pub mapped: i64,
}

/// Flat representation of `struct uffd_msg` (32 bytes).
///
/// The kernel struct contains an 8-byte header followed by a 24-byte
/// union (`arg`). We only use the `arg.pagefault` variant, so the
/// union is flattened into its pagefault fields here. The trailing
/// 8 bytes (`arg.pagefault.feat` + padding) are unused.
#[repr(C)]
pub(crate) struct UffdMsg {
    pub event: u8,
    _reserved1: u8,
    _reserved2: u16,
    _reserved3: u32,
    pub pf_flags: u64,
    pub pf_address: u64,
    _pad: [u8; 8],
}

const _: () = assert!(size_of::<UffdMsg>() == 32);

/// Try to obtain a userfaultfd via /dev/userfaultfd (Linux 6.1+).
///
/// This bypasses the capability and sysctl checks that gate the syscall,
/// requiring only file permissions on the device node.
fn try_dev_userfaultfd() -> Result<OwnedFd, Error> {
    let dev = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/userfaultfd")?;
    let flags = libc::O_CLOEXEC | libc::O_NONBLOCK;
    // SAFETY: USERFAULTFD_IOC_NEW on a valid /dev/userfaultfd fd returns a new
    // userfaultfd file descriptor.
    let fd = unsafe {
        libc::ioctl(
            dev.as_raw_fd(),
            userfaultfd::USERFAULTFD_IOC_NEW as libc::Ioctl,
            flags,
        )
    };
    if fd < 0 {
        return Err(Error::last_os_error());
    }
    // SAFETY: the ioctl returned a valid fd above.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Create a userfaultfd file descriptor and perform the API handshake.
///
/// Prefers `/dev/userfaultfd` (no capability/sysctl requirements, just file
/// permissions) and falls back to the `userfaultfd(2)` syscall.
pub(crate) fn create(required_features: u64) -> Result<OwnedFd, Error> {
    let fd = match try_dev_userfaultfd() {
        Ok(fd) => fd,
        Err(_) => {
            // SAFETY: `userfaultfd` syscall with O_CLOEXEC | O_NONBLOCK flags.
            let raw =
                unsafe { libc::syscall(libc::SYS_userfaultfd, libc::O_CLOEXEC | libc::O_NONBLOCK) };
            if raw < 0 {
                return Err(Error::last_os_error());
            }
            // SAFETY: the syscall returned a valid fd above.
            unsafe { OwnedFd::from_raw_fd(raw as RawFd) }
        }
    };

    let mut api = UffdioApi {
        api: userfaultfd::UFFD_API,
        features: required_features,
        ioctls: 0,
    };
    // SAFETY: `api` is a valid, correctly-sized struct for this ioctl.
    let ret = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            userfaultfd::UFFDIO_API as libc::Ioctl,
            &mut api,
        )
    };
    if ret < 0 {
        return Err(Error::last_os_error());
    }

    Ok(fd)
}

/// Register a memory range for missing-page fault handling.
pub(crate) fn register(
    fd: BorrowedFd<'_>,
    addr: u64,
    len: u64,
    uffd_requires_minor_mode: bool,
) -> Result<u64, Error> {
    let mode = if uffd_requires_minor_mode {
        userfaultfd::UFFDIO_REGISTER_MODE_MISSING | userfaultfd::UFFDIO_REGISTER_MODE_MINOR
    } else {
        userfaultfd::UFFDIO_REGISTER_MODE_MISSING
    };

    let mut reg = UffdioRegister {
        range_start: addr,
        range_len: len,
        mode,
        ioctls: 0,
    };
    // SAFETY: `reg` is a valid, correctly-sized struct for this ioctl.
    let ret = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            userfaultfd::UFFDIO_REGISTER as libc::Ioctl,
            &mut reg,
        )
    };
    if ret < 0 {
        return Err(Error::last_os_error());
    }
    Ok(reg.ioctls)
}

/// Unregister a memory range from UFFD fault handling.
pub(crate) fn unregister(fd: BorrowedFd<'_>, addr: u64, len: u64) -> Result<(), Error> {
    let mut range = UffdioRange { start: addr, len };
    // SAFETY: `range` is a valid, correctly-sized struct for this ioctl.
    let ret = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            userfaultfd::UFFDIO_UNREGISTER as libc::Ioctl,
            &mut range,
        )
    };
    if ret < 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

/// Resolve a page fault by copying data into the faulted address.
pub(crate) fn copy(fd: BorrowedFd<'_>, dst: u64, src: *const u8, len: u64) -> Result<(), Error> {
    let mut cp = UffdioCopy {
        dst,
        src: src as u64,
        len,
        mode: 0,
        copy: 0,
    };
    loop {
        // SAFETY: `cp` is a valid, correctly-sized struct for this ioctl.
        let ret = unsafe {
            libc::ioctl(
                fd.as_raw_fd(),
                userfaultfd::UFFDIO_COPY as libc::Ioctl,
                &mut cp,
            )
        };
        if ret >= 0 {
            return Ok(());
        }

        let error = Error::last_os_error();
        if error.raw_os_error() != Some(libc::EAGAIN) {
            return Err(error);
        }
        thread::yield_now();
    }
}

/// Allocate a zero-filled buffer to resolve UFFD faults with.
pub(crate) fn allocate_zero_buffer(len: usize) -> Vec<u8> {
    let buf = vec![0u8; len];

    // Ensure the page tables of the buffer exist, so UFFDIO_COPY works
    // with it on 1 GiB pages.
    let base_page_size = get_page_size() as usize;
    let start = buf.as_ptr() as usize & !(base_page_size - 1);
    // SAFETY: the range only covers pages backing `buf`.
    let ret = unsafe {
        libc::madvise(
            start as *mut libc::c_void,
            buf.as_ptr() as usize + buf.len() - start,
            libc::MADV_POPULATE_READ,
        )
    };
    if ret != 0 {
        log::warn!(
            "UFFD handler: failed to populate zero buffer: {}",
            io::Error::last_os_error()
        );
    }

    buf
}

/// Resolves a minor page fault by installing PTEs for a range.
pub(crate) fn uffd_continue(fd: BorrowedFd<'_>, dst: u64, len: u64) -> Result<(), Error> {
    let mut cont = UffdioContinue {
        range_start: dst,
        range_len: len,
        mode: 0,
        mapped: 0,
    };
    loop {
        // SAFETY: `cont` is a valid, correctly-sized struct for this ioctl.
        let ret = unsafe {
            libc::ioctl(
                fd.as_raw_fd(),
                userfaultfd::UFFDIO_CONTINUE as libc::Ioctl,
                &mut cont,
            )
        };
        if ret >= 0 {
            return Ok(());
        }

        let error = Error::last_os_error();
        if error.raw_os_error() != Some(libc::EAGAIN) {
            return Err(error);
        }
        thread::yield_now();
    }
}

#[repr(C)]
struct UffdioRange {
    start: u64,
    len: u64,
}

#[repr(C)]
struct UffdioZeropage {
    range: UffdioRange,
    mode: u64,
    zeropage: i64,
}

#[repr(C)]
struct UffdioPoison {
    range: UffdioRange,
    mode: u64,
    updated: i64,
}

/// A guest memory range registered with userfaultfd, plus where its bytes
/// live for the data source.
#[derive(Clone, Copy, Debug)]
pub(crate) struct UffdRange {
    pub host_addr: u64,
    pub length: u64,
    pub source_offset: u64,
    pub page_size: u64,
}

impl UffdRange {
    pub(crate) fn num_pages(&self) -> u64 {
        self.length.div_ceil(self.page_size)
    }

    pub(crate) fn page_addr(&self, page_idx: u64) -> u64 {
        self.host_addr + page_idx * self.page_size
    }

    pub(crate) fn page_source_offset(&self, page_idx: u64) -> u64 {
        self.source_offset + page_idx * self.page_size
    }

    pub(crate) fn page_index_of(&self, addr: u64) -> Option<u64> {
        let page_addr = addr & !(self.page_size - 1);
        (page_addr >= self.host_addr && page_addr < self.host_addr + self.length)
            .then(|| (page_addr - self.host_addr) / self.page_size)
    }
}

pub(crate) struct UffdHole {
    pub host_addr: u64,
    pub length: u64,
}

/// A userfaultfd and the ranges registered in it, at the addresses they are
/// mapped at in the process owning it.
pub(crate) struct Uffd {
    fd: OwnedFd,
    ranges: Box<[UffdRange]>,
    holes: Box<[UffdHole]>,
}

impl Uffd {
    pub(crate) fn new(
        fd: OwnedFd,
        ranges: Box<[UffdRange]>,
        holes: Box<[UffdHole]>,
    ) -> Result<Self, Error> {
        // SAFETY: `F_GETFL` takes no argument.
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(Error::last_os_error());
        }
        // SAFETY: `F_SETFL` takes an integer argument, no pointer.
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(Error::last_os_error());
        }
        Ok(Self { fd, ranges, holes })
    }

    pub(crate) fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    pub(crate) fn ranges(&self) -> &[UffdRange] {
        &self.ranges
    }

    pub(crate) fn holes(&self) -> &[UffdHole] {
        &self.holes
    }

    pub(crate) fn locate_hole(&self, addr: u64) -> Option<&UffdHole> {
        self.holes
            .iter()
            .find(|hole| addr >= hole.host_addr && addr < hole.host_addr + hole.length)
    }

    /// Returns the `(range_idx, page_idx)` containing `addr`.
    pub(crate) fn locate(&self, addr: u64) -> Option<(usize, u64)> {
        self.ranges
            .iter()
            .enumerate()
            .find_map(|(range_idx, range)| {
                range
                    .page_index_of(addr)
                    .map(|page_idx| (range_idx, page_idx))
            })
    }
}

/// Provider of guest-memory page contents for a UFFD handler.
pub(crate) trait UffdMemorySource: Send {
    fn resolve(
        &mut self,
        uffd_fd: BorrowedFd<'_>,
        range: &UffdRange,
        page_idx: u64,
    ) -> Result<(), io::Error>;

    fn requires_uffd_minor_mode(&self) -> bool;
}

/// Source that reads pages from a local snapshot file.
///
/// A page wholly inside a hole of the file is resolved with zeroes without
/// reading the file: a buffered read of a hole would leave a zero page in the
/// host page cache for every hole page the guest touches. Holes are looked up
/// when a page is resolved, with `lseek(SEEK_DATA)`, rather than listed
/// up front, so that a fragmented file costs nothing before the guest runs
/// and no memory beyond the one extent kept here.
///
/// The kernel's readahead is turned off for the file, as it reads past the
/// end of a data extent into the hole beside it and caches zero pages there.
/// The source reads ahead itself instead, inside the data extent of the page
/// it reads. The advice holds for the open file description, so `file` must
/// be opened for the source alone, not cloned from a file read elsewhere.
pub(crate) struct FileUffdMemorySource {
    file: File,
    buf: Vec<u8>,
    /// The extent of `file` the last lookup found. Pages are mostly resolved
    /// in order (the background fill walks them so), so most lookups land in
    /// the extent the one before found and need no system call.
    extent: Option<FileExtent>,
    /// False once `lseek(SEEK_DATA)` has failed other than for lack of data
    /// (the filesystem does not support `SEEK_HOLE`): every page is then
    /// read from the file.
    seek_holes: bool,
    zeroes: Vec<u8>,
    /// The page the source last asked the kernel to read ahead from, and the
    /// end of what it asked for.
    read_ahead: (u64, u64),
    /// How much the source last asked for, before cutting it at the end of
    /// an extent. Reads in order grow it, up to `READ_AHEAD`.
    read_ahead_size: u64,
    /// Whether the last window may end at or past the end of its data
    /// extent. Otherwise it ends inside data, so no later extent can follow
    /// on from it.
    read_ahead_at_extent_end: bool,
    /// Whether the kernel's own readahead is on for the file: off while the
    /// source reads ahead itself.
    kernel_read_ahead: bool,
    /// What the source did, logged when it is dropped: lseek calls made,
    /// pages resolved with zeroes as holes, and pages read from the file.
    lookups: u64,
    hole_pages: u64,
    read_pages: u64,
}

/// `[start, end)` offsets of a file, all of it a hole or all of it data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileExtent {
    start: u64,
    end: u64,
    hole: bool,
}

impl FileUffdMemorySource {
    pub(crate) fn new(file: File) -> Self {
        let mut source = Self {
            file,
            buf: Vec::new(),
            extent: None,
            seek_holes: true,
            zeroes: Vec::new(),
            read_ahead: (0, 0),
            read_ahead_size: 0,
            read_ahead_at_extent_end: false,
            kernel_read_ahead: true,
            lookups: 0,
            hole_pages: 0,
            read_pages: 0,
        };
        source.set_kernel_read_ahead(false);
        source
    }

    /// A file for a source to read `snapshot` through: `snapshot` opened
    /// again through `/proc/self/fd`, a new open file description of the
    /// same inode, so that the advice the source gives does not reach
    /// whoever else reads `snapshot`.
    ///
    /// Where that fails, as where `/proc` is not mounted, it is a clone
    /// (`dup`) of `snapshot` instead, and the restore still reads the same
    /// pages of the same inode. What the clone gives up is that separation:
    /// the two share one open file description, so the source's
    /// `POSIX_FADV_RANDOM` turns the kernel's readahead off for `snapshot`
    /// too. A copy-on-access VM's snapshot writer then reads the pages the
    /// guest never accessed from `snapshot` without kernel readahead, which
    /// is slower but reads the same bytes. Both read at explicit offsets
    /// (`pread`, `lseek(SEEK_DATA)`), so the file position they now share
    /// changes nothing.
    pub(crate) fn open_file(snapshot: &File) -> io::Result<File> {
        Self::open_file_in(snapshot, Path::new("/proc/self/fd"))
    }

    /// `open_file` with `fd_dir` in place of `/proc/self/fd`.
    ///
    /// A file opened through `fd_dir` is used only if it is the same inode
    /// as `snapshot` (same `st_dev` and `st_ino`): if something other than
    /// the kernel's `/proc` is mounted there, the source would otherwise
    /// serve the guest another file's pages. Where it is not, the source
    /// reads through a clone as where the open fails.
    pub(crate) fn open_file_in(snapshot: &File, fd_dir: &Path) -> io::Result<File> {
        let path = fd_dir.join(snapshot.as_raw_fd().to_string());
        let why = match File::open(&path) {
            Ok(reopened) => match Self::same_inode(snapshot, &reopened) {
                Ok(true) => return Ok(reopened),
                Ok(false) => "it opened a different file".to_string(),
                Err(e) => format!("cannot compare it with the snapshot file: {e}"),
            },
            Err(e) => e.to_string(),
        };
        log::warn!(
            "UFFD restore: cannot open the snapshot file again through {}: {why}; \
             reading it through a clone of its descriptor, which shares the \
             source's readahead advice with the snapshot writer",
            path.display()
        );
        snapshot.try_clone()
    }

    /// Whether `a` and `b` are the same inode: the same `st_dev` and
    /// `st_ino`, from the metadata of each (`statx` or `fstat`, depending
    /// on the libc).
    fn same_inode(a: &File, b: &File) -> io::Result<bool> {
        let (a, b) = (a.metadata()?, b.metadata()?);
        Ok(a.dev() == b.dev() && a.ino() == b.ino())
    }

    /// Turns the kernel's readahead on the file on or off. This fails only
    /// where the file cannot read ahead anyway (a pipe).
    fn set_kernel_read_ahead(&mut self, on: bool) {
        let advice = if on {
            libc::POSIX_FADV_NORMAL
        } else {
            libc::POSIX_FADV_RANDOM
        };
        advise(&self.file, 0, 0, advice);
        self.kernel_read_ahead = on;
    }

    /// Stops looking holes up after `op` failed at `pos`: every page is then
    /// read from the file, which is correct whatever the failure was.
    fn stop_seeking(&mut self, op: &str, pos: u64, e: &io::Error) {
        log::info!(
            "UFFD restore: lseek({op}) at {pos:#x} of the snapshot file failed \
             (errno {}), every fault reads the file from now on: {e}",
            e.raw_os_error().unwrap_or(0)
        );
        self.seek_holes = false;
        self.extent = None;
        // Without extents the source cannot read ahead: the kernel does.
        self.set_kernel_read_ahead(true);
    }

    /// Whether `[pos, pos + len)` of the file lies wholly inside one hole.
    /// Only offsets inside the file count: a read past its end fails rather
    /// than reading zeroes, so the space past it is not a hole.
    fn in_hole(&mut self, pos: u64, len: u64) -> bool {
        if !self.seek_holes {
            return false;
        }
        if let Some(e) = self.extent
            && e.start <= pos
            && pos < e.end
        {
            return e.hole && pos.saturating_add(len) <= e.end;
        }
        self.lookups += 1;
        let hole_end = match seek_data(self.file.as_fd(), pos) {
            Ok(Some(data)) if data < pos.saturating_add(len) => {
                // The page holds data. Keep the extent it starts so that the
                // pages after this one need no lookup, as for the pages of
                // a hole.
                self.lookups += 1;
                match seek_hole(self.file.as_fd(), data) {
                    Ok(end) if end > data => {
                        self.extent = Some(FileExtent {
                            start: data,
                            end,
                            hole: false,
                        });
                    }
                    Ok(_) => {}
                    Err(e) => self.stop_seeking("SEEK_HOLE", data, &e),
                }
                return false;
            }
            Ok(Some(data)) => data,
            // No data at or after pos: in a hole that runs to the end of the
            // file, or at or past the end.
            Ok(None) => match self.file.metadata() {
                Ok(m) => m.len(),
                Err(_) => return false,
            },
            Err(e) => {
                self.stop_seeking("SEEK_DATA", pos, &e);
                return false;
            }
        };
        if hole_end <= pos {
            return false;
        }
        self.extent = Some(FileExtent {
            start: pos,
            end: hole_end,
            hole: true,
        });
        pos.saturating_add(len) <= hole_end
    }

    /// Asks the kernel to read the file ahead of a read of `len` bytes at
    /// `pos`, never past the end of the data extent `pos` is in. A read that
    /// does not follow on from the last one asks for nothing more, so that
    /// scattered reads cache only the pages read. A read that follows on, or
    /// reaches half way through the last window, asks for the next window:
    /// `READ_AHEAD_MIN` bytes first, then four, then two times as many each
    /// time, up to `READ_AHEAD`, so that reads in order find their pages
    /// already read. The first page of a data extent follows on from a
    /// window that ended at the end of the extent before it.
    ///
    /// With huge pages the window can be shorter than the read, so reads in
    /// order do not grow it; each read still caches its whole page.
    ///
    /// Called after the read, not before: the advice can block, and the
    /// read must not wait for it. What is asked for does not depend on the
    /// read, only on `pos`, `len` and the extent `in_hole` found.
    fn read_ahead_in_extent(&mut self, pos: u64, len: u64) {
        let Some(extent) = self
            .extent
            .filter(|e| !e.hole && e.start <= pos && pos < e.end)
        else {
            return;
        };
        let (start, end) = self.read_ahead;
        // Four times as large while small, as the kernel grows its own.
        let factor = if self.read_ahead_size < READ_AHEAD / 4 {
            4
        } else {
            2
        };
        let grown = (self.read_ahead_size * factor).min(READ_AHEAD);
        let (from, size) = if start < end && start <= pos && pos <= end {
            if end - pos > self.read_ahead_size / 2 {
                return;
            }
            (end, grown)
        } else if start < end
            && self.read_ahead_at_extent_end
            && pos == extent.start
            && pos > end
            && {
                // `extent.start` is where `in_hole` looked the extent up, so
                // `pos` is the first read in it, not necessarily the extent's
                // first page. It is that page, following on from a window
                // that ended at the end of the extent before it past one hole,
                // if the next data after the window starts at `pos`.
                self.lookups += 1;
                matches!(seek_data(self.file.as_fd(), end), Ok(Some(data)) if data == pos)
            }
        {
            (pos, grown)
        } else {
            // The window is the read itself, sized so that a read following
            // on from it asks for `READ_AHEAD_MIN`.
            self.read_ahead = (pos, pos.saturating_add(len));
            self.read_ahead_size = READ_AHEAD_MIN / 4;
            self.read_ahead_at_extent_end = self.read_ahead.1 >= extent.end;
            return;
        };
        let to = extent.end.min(from.saturating_add(size));
        if from < to {
            // The kernel may read less than asked, capped by the device's
            // readahead limits; a later read then reads the rest itself.
            advise(&self.file, from, to - from, libc::POSIX_FADV_WILLNEED);
            self.read_ahead = (pos, to);
            self.read_ahead_size = size;
            self.read_ahead_at_extent_end = to == extent.end;
        }
    }
}

/// The first window the source asks the kernel to read, when a read follows
/// on from one that did not.
const READ_AHEAD_MIN: u64 = 64 << 10;

/// The most the source asks the kernel to read ahead at once, as reads in
/// order grow the window. With a cold page cache, reading the 571 MB of data
/// of a sparse 2 GiB file in order took 6.4 s on XFS and 4.2 s on btrfs,
/// against 11.3 s and 4.3 s with the kernel's readahead (one run each).
const READ_AHEAD: u64 = 512 << 10;

/// `posix_fadvise(2)` on `[offset, offset + len)` of `file`, all of it when
/// `len` is 0. Advice only changes how the file is cached, so a failure is
/// ignored.
fn advise(file: &File, offset: u64, len: u64, advice: libc::c_int) {
    // SAFETY: FFI call on an fd `file` owns; no memory is passed.
    unsafe {
        libc::posix_fadvise(
            file.as_raw_fd(),
            offset as libc::off_t,
            len as libc::off_t,
            advice,
        )
    };
}

impl UffdMemorySource for FileUffdMemorySource {
    fn resolve(
        &mut self,
        uffd_fd: BorrowedFd<'_>,
        range: &UffdRange,
        page_idx: u64,
    ) -> Result<(), io::Error> {
        let page_size = range.page_size as usize;
        let page_addr = range.page_addr(page_idx);
        let file_pos = range.page_source_offset(page_idx);

        if self.in_hole(file_pos, range.page_size) {
            // A copied page of zeroes, private to this VM like every page it
            // touches, rather than the zero page every process shares.
            copy_zeroes(uffd_fd, range, page_idx, &mut self.zeroes)?;
            self.hole_pages += 1;
            return Ok(());
        }

        if self.buf.len() < page_size {
            self.buf.resize(page_size, 0);
        }
        self.file
            .read_exact_at(&mut self.buf[..page_size], file_pos)?;
        self.read_pages += 1;

        match copy(uffd_fd, page_addr, self.buf.as_ptr(), range.page_size) {
            Ok(()) => {}
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
                // Installed concurrently. Wake any blocked threads.
                if let Err(e) = wake(uffd_fd, page_addr, range.page_size) {
                    log::warn!("UFFDIO_WAKE failed at {page_addr:#x}: {e}");
                }
            }
            Err(e) => return Err(e),
        }
        // Read ahead only once the faulting page is in place: WILLNEED can
        // block while it submits the I/O, and the vCPU waiting on this
        // fault would wait for it too. A failed read or copy returns its
        // error without asking for anything.
        self.read_ahead_in_extent(file_pos, range.page_size);
        Ok(())
    }

    fn requires_uffd_minor_mode(&self) -> bool {
        false
    }
}

impl Drop for FileUffdMemorySource {
    fn drop(&mut self) {
        log::info!(
            "UFFD restore: snapshot file pages resolved: holes={} read={} lookups={}",
            self.hole_pages,
            self.read_pages,
            self.lookups
        );
    }
}

/// Memory source that provides pages content over a socket.
pub(crate) struct SocketUffdMemorySource {
    stream: SocketStream,
    shared_backing: bool,
    buf: Vec<u8>,
}

impl SocketUffdMemorySource {
    pub(crate) fn new(stream: SocketStream, shared_backing: bool) -> Self {
        Self {
            stream,
            shared_backing,
            buf: Vec::new(),
        }
    }

    /// Returns the length of the inline page payload the peer is about to send
    /// (0 when the page was written directly into shared memory).
    fn request_page(&mut self, gpa: u64, len: u64) -> Result<u64, io::Error> {
        Request::page_fault()
            .write_to(&mut self.stream)
            .map_err(io_other)?;
        MemoryRange { gpa, length: len }
            .write_to(&mut self.stream)
            .map_err(io_other)?;

        let resp = Response::read_from(&mut self.stream).map_err(io_other)?;
        match resp.status() {
            Status::Ok => Ok(resp.length()),
            s => Err(io::Error::other(format!(
                "peer returned {s:?} for PageFault at gpa={gpa:#x} len={len}",
            ))),
        }
    }
}

impl UffdMemorySource for SocketUffdMemorySource {
    fn resolve(
        &mut self,
        uffd_fd: BorrowedFd<'_>,
        range: &UffdRange,
        page_idx: u64,
    ) -> Result<(), io::Error> {
        let page_size = range.page_size;
        let page_addr = range.page_addr(page_idx);
        let page_gpa = range.page_source_offset(page_idx);

        let resp_len = self.request_page(page_gpa, page_size)?;

        if self.shared_backing {
            if resp_len != 0 {
                return Err(io::Error::other(format!(
                    "shared-backing PageFault response carried {resp_len} unexpected bytes",
                )));
            }
            match uffd_continue(uffd_fd, page_addr, page_size) {
                Ok(()) => Ok(()),
                // This is fine, someone mapped the page before us.
                Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
                    if let Err(e) = wake(uffd_fd, page_addr, page_size) {
                        log::warn!("UFFDIO_WAKE failed at {page_addr:#x}: {e}");
                    }
                    Ok(())
                }
                Err(e) => Err(e),
            }
        } else {
            if resp_len != page_size {
                return Err(io::Error::other(format!(
                    "inline PageFault response length {resp_len} != page size {page_size}",
                )));
            }
            let len = page_size as usize;
            if self.buf.len() < len {
                self.buf.resize(len, 0);
            }
            self.stream.read_exact(&mut self.buf[..len])?;
            match copy(uffd_fd, page_addr, self.buf.as_ptr(), page_size) {
                Ok(()) => Ok(()),
                Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
                    if let Err(e) = wake(uffd_fd, page_addr, page_size) {
                        log::warn!("UFFDIO_WAKE failed at {page_addr:#x}: {e}");
                    }
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
    }

    fn requires_uffd_minor_mode(&self) -> bool {
        self.shared_backing
    }
}

impl Drop for SocketUffdMemorySource {
    fn drop(&mut self) {
        // SAFETY: the fd is valid for the duration of this borrow.
        unsafe { libc::shutdown(self.stream.as_fd().as_raw_fd(), libc::SHUT_RDWR) };
    }
}

fn io_other<E: fmt::Display>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}

/// Resolve a missing page fault by mapping a zero-filled page.
pub(crate) fn zeropage(fd: BorrowedFd<'_>, addr: u64, len: u64) -> Result<(), Error> {
    let mut zp = UffdioZeropage {
        range: UffdioRange { start: addr, len },
        mode: 0,
        zeropage: 0,
    };
    loop {
        // SAFETY: `zp` is a valid, correctly-sized struct for this ioctl.
        let ret = unsafe {
            libc::ioctl(
                fd.as_raw_fd(),
                userfaultfd::UFFDIO_ZEROPAGE as libc::Ioctl,
                &mut zp,
            )
        };
        if ret >= 0 {
            return Ok(());
        }

        let error = Error::last_os_error();
        if error.raw_os_error() != Some(libc::EAGAIN) {
            return Err(error);
        }
        thread::yield_now();
    }
}

/// Resolve a missing fault on page `page_idx` of `range` by copying a page
/// of zeroes from `zeroes`, replaced by `allocate_zero_buffer` with one a
/// page long when it is shorter. Unlike `zeropage`, this works on every
/// mapping, hugetlbfs included.
pub(crate) fn copy_zeroes(
    fd: BorrowedFd<'_>,
    range: &UffdRange,
    page_idx: u64,
    zeroes: &mut Vec<u8>,
) -> Result<(), Error> {
    let page_size = range.page_size as usize;
    let page_addr = range.page_addr(page_idx);
    if zeroes.len() < page_size {
        *zeroes = allocate_zero_buffer(page_size);
    }
    match copy(fd, page_addr, zeroes.as_ptr(), range.page_size) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
            // Installed concurrently. Wake any blocked threads.
            if let Err(e) = wake(fd, page_addr, range.page_size) {
                log::warn!("UFFDIO_WAKE failed at {page_addr:#x}: {e}");
            }
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Mark a missing page so that an access to it fails instead of resolving a
/// zero page.
pub(crate) fn poison(fd: BorrowedFd<'_>, addr: u64, len: u64) -> Result<(), Error> {
    let mut poison = UffdioPoison {
        range: UffdioRange { start: addr, len },
        mode: 0,
        updated: 0,
    };
    loop {
        // SAFETY: `poison` is a valid, correctly-sized struct for this ioctl.
        let ret = unsafe {
            libc::ioctl(
                fd.as_raw_fd(),
                userfaultfd::UFFDIO_POISON as libc::Ioctl,
                &mut poison,
            )
        };
        if ret >= 0 {
            return Ok(());
        }

        let error = Error::last_os_error();
        if error.raw_os_error() != Some(libc::EAGAIN) {
            return Err(error);
        }
        thread::yield_now();
    }
}

/// Wake threads waiting on a fault in the given range without copying data.
///
/// Needed after UFFDIO_COPY, UFFDIO_ZEROPAGE or UFFDIO_CONTINUE returns EEXIST:
/// the page was already resolved by a concurrent fault, but any additional
/// threads blocked on that page may not have been woken.
pub(crate) fn wake(fd: BorrowedFd<'_>, addr: u64, len: u64) -> Result<(), Error> {
    let mut range = UffdioRange { start: addr, len };
    // SAFETY: `range` is a valid, correctly-sized struct for this ioctl.
    let ret = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            userfaultfd::UFFDIO_WAKE as libc::Ioctl,
            &mut range,
        )
    };
    if ret < 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

/// Returns whether the page at `addr` in this process is present. For a
/// shared file mapping, this is whether the file holds the page, even if
/// it is not mapped at `addr`.
pub(crate) fn page_present(addr: u64) -> Result<bool, Error> {
    let mut vec = 0u8;
    // SAFETY: mincore() writes one byte for the single page at `addr`.
    let ret = unsafe { libc::mincore(addr as *mut libc::c_void, 1, &mut vec) };
    if ret < 0 {
        return Err(Error::last_os_error());
    }
    Ok(vec & 1 != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: u64 = 0x1000;

    // A file of `pages` pages of 4 KiB, data in each page `data` picks and
    // holes elsewhere. None unless SEEK_DATA reports exactly that.
    //
    // The data does not compress, as a guest's memory mostly does not: btrfs
    // mounted with compression reads a compressed extent, up to 128 KiB,
    // whole into the page cache, whatever the advice, which hid the kernel's
    // readahead from the page cache checks below.
    fn file_with_data_pages(pages: u64, data: impl Fn(u64) -> bool) -> Option<File> {
        let file = tempfile::tempfile().unwrap();
        file.set_len(pages * PAGE).unwrap();
        let mut buf = [0u8; PAGE as usize];
        for idx in (0..pages).filter(|&idx| data(idx)) {
            // splitmix64, seeded by the page's index.
            let mut x = idx.wrapping_mul(0x9e37_79b9_7f4a_7c15);
            for word in buf.as_chunks_mut::<8>().0 {
                x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
                let mut z = x;
                z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                *word = (z ^ (z >> 31)).to_ne_bytes();
            }
            file.write_all_at(&buf, idx * PAGE).unwrap();
        }
        for idx in 0..pages {
            let seen = seek_data(file.as_fd(), idx * PAGE);
            if matches!(seen, Ok(Some(off)) if off == idx * PAGE) != data(idx) {
                eprintln!("skipping: SEEK_DATA at page {idx} reports {seen:x?}");
                return None;
            }
        }
        Some(file)
    }

    #[test]
    fn open_file_falls_back_to_a_clone_without_proc() {
        use std::io::{Seek, SeekFrom};

        let file = tempfile::tempfile().unwrap();
        file.write_all_at(&[0x5a; PAGE as usize], 0).unwrap();
        // The open file description is told apart by its position: a clone
        // shares it, a file opened again does not.
        let shares_position = |other: &File| {
            (&*other).seek(SeekFrom::Start(0)).unwrap();
            (&file).seek(SeekFrom::Start(7)).unwrap();
            (&*other).stream_position().unwrap() == 7
        };

        if Path::new("/proc/self/fd").is_dir() {
            let reopened = FileUffdMemorySource::open_file(&file).unwrap();
            assert!(!shares_position(&reopened));
        } else {
            eprintln!("note: /proc is not mounted here, so the reopen is not checked");
        }

        // Where the reopen fails, the source reads the same file through a
        // clone, and reads the right page.
        let no_proc = tempfile::tempdir().unwrap();
        let cloned = FileUffdMemorySource::open_file_in(&file, &no_proc.path().join("fd")).unwrap();
        assert!(shares_position(&cloned));
        let source = FileUffdMemorySource::new(cloned);
        let mut buf = [0u8; PAGE as usize];
        source.file.read_exact_at(&mut buf, 0).unwrap();
        assert_eq!(buf, [0x5a; PAGE as usize]);
    }

    #[test]
    fn open_file_falls_back_to_a_clone_when_the_reopen_is_another_file() {
        use std::fs;
        use std::io::{Seek, SeekFrom};

        let file = tempfile::tempfile().unwrap();
        file.write_all_at(&[0x5a; PAGE as usize], 0).unwrap();
        // Something other than /proc where the fd directory should be: the
        // name of `file`'s fd opens another file, which the source must not
        // serve the guest.
        let fake_proc = tempfile::tempdir().unwrap();
        let other = fake_proc.path().join(file.as_raw_fd().to_string());
        fs::write(&other, [0xa5; PAGE as usize]).unwrap();

        let opened = FileUffdMemorySource::open_file_in(&file, fake_proc.path()).unwrap();
        // It is a clone of `file`: one open file description, so a seek on
        // one moves the other.
        (&opened).seek(SeekFrom::Start(0)).unwrap();
        (&file).seek(SeekFrom::Start(7)).unwrap();
        assert_eq!((&opened).stream_position().unwrap(), 7);
        let mut buf = [0u8; PAGE as usize];
        opened.read_exact_at(&mut buf, 0).unwrap();
        assert_eq!(buf, [0x5a; PAGE as usize]);
    }

    #[test]
    fn in_hole_finds_each_hole_of_a_fragmented_file() {
        // 2048 holes of one page each, between pages of data.
        let pages = 4096;
        let Some(file) = file_with_data_pages(pages, |idx| idx % 2 == 0) else {
            return;
        };
        let mut source = FileUffdMemorySource::new(file.try_clone().unwrap());
        for idx in 0..pages {
            assert_eq!(source.in_hole(idx * PAGE, PAGE), idx % 2 == 1, "page {idx}");
        }
        // Out of order, as guest faults come, the answers are the same.
        let mut source = FileUffdMemorySource::new(file);
        for idx in (0..pages).rev().chain((0..pages).step_by(7)) {
            assert_eq!(source.in_hole(idx * PAGE, PAGE), idx % 2 == 1, "page {idx}");
        }
        // Only the last extent found is kept, however many holes there are.
        assert!(source.extent.is_some());
    }

    #[test]
    fn in_hole_on_a_file_without_holes() {
        let pages = 64;
        let Some(file) = file_with_data_pages(pages, |_| true) else {
            return;
        };
        let mut source = FileUffdMemorySource::new(file);
        for idx in 0..pages {
            assert!(!source.in_hole(idx * PAGE, PAGE), "page {idx}");
            // The first lookup found the one extent, which answers the rest.
            assert_eq!(
                source.extent,
                Some(FileExtent {
                    start: 0,
                    end: pages * PAGE,
                    hole: false
                })
            );
        }
    }

    #[test]
    fn in_hole_looks_up_each_extent_once() {
        // Data in pages 0 to 15 and 48 to 63, a hole in between.
        let pages = 64;
        let Some(file) = file_with_data_pages(pages, |idx| !(16..48).contains(&idx)) else {
            return;
        };
        let mut source = FileUffdMemorySource::new(file);
        for idx in 0..pages {
            assert_eq!(source.in_hole(idx * PAGE, PAGE), (16..48).contains(&idx));
        }
        // SEEK_DATA and SEEK_HOLE for each data extent, SEEK_DATA for the
        // hole; every other page was answered from the extent kept.
        assert_eq!(source.lookups, 5);
        // Faults back inside the last extent need no lookup either.
        for idx in (48..pages).rev() {
            assert!(!source.in_hole(idx * PAGE, PAGE));
        }
        assert_eq!(source.lookups, 5);
    }

    #[test]
    fn in_hole_needs_the_whole_page_inside_one_hole() {
        // Data in pages 0 and 5, holes in pages 1 to 4 and 6 to 7, the
        // second running to the end of the file.
        let Some(file) = file_with_data_pages(8, |idx| idx == 0 || idx == 5) else {
            return;
        };
        let mut source = FileUffdMemorySource::new(file);
        // A fault inside a hole, then one earlier in the same hole.
        assert!(source.in_hole(0x3000, PAGE));
        assert!(source.in_hole(0x1000, PAGE));
        assert!(source.in_hole(0x2000, 0x2000));
        assert!(source.in_hole(0x1000, 0x4000));
        // A fault on data.
        assert!(!source.in_hole(0, PAGE));
        assert!(!source.in_hole(0x5000, PAGE));
        // Straddling a hole's start or end.
        assert!(!source.in_hole(0x0800, PAGE));
        assert!(!source.in_hole(0x4800, PAGE));
        assert!(!source.in_hole(0x1000, 0x5000));
        // The hole at the end of the file, but not past the end.
        assert!(source.in_hole(0x6000, PAGE));
        assert!(source.in_hole(0x7000, PAGE));
        assert!(!source.in_hole(0x7800, PAGE));
        assert!(!source.in_hole(0x8000, PAGE));
        assert!(!source.in_hole(0x10000, PAGE));
    }

    #[test]
    fn in_hole_without_seek_hole_reads_every_page() {
        // lseek fails on a pipe, as SEEK_DATA does where SEEK_HOLE is
        // unsupported: every page is then read.
        let mut fds = [0; 2];
        // SAFETY: pipe() writes two new fds into `fds`.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: both fds were just created and are owned here only.
        let (read_end, _write_end) =
            unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) };
        let mut source = FileUffdMemorySource::new(read_end);
        assert!(!source.kernel_read_ahead);
        assert!(!source.in_hole(0, PAGE));
        assert!(!source.seek_holes);
        // The kernel reads ahead again, as the source no longer can.
        assert!(source.kernel_read_ahead);
        assert!(!source.in_hole(PAGE, PAGE));
        assert_eq!(source.extent, None);
    }

    // Pages of `file` in the page cache, of the `pages` pages from 0.
    fn cached_pages(file: &File, pages: u64) -> Vec<u64> {
        use std::ptr;

        let len = (pages * PAGE) as usize;
        // SAFETY: maps `len` bytes of `file` read-only; unmapped below.
        let addr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        assert_ne!(addr, libc::MAP_FAILED);
        let mut vec = vec![0u8; pages as usize];
        // SAFETY: `vec` holds one byte per page of the mapping.
        assert_eq!(unsafe { libc::mincore(addr, len, vec.as_mut_ptr()) }, 0);
        // SAFETY: unmaps the mapping made above.
        unsafe { libc::munmap(addr, len) };
        (0..pages)
            .filter(|&idx| vec[idx as usize] & 1 != 0)
            .collect()
    }

    // The filesystem `file` is on, for the notes below.
    fn fs_name(file: &File) -> String {
        use std::mem;

        // SAFETY: a statfs is plain data, for which all zeroes is valid.
        let mut st: libc::statfs = unsafe { mem::zeroed() };
        // SAFETY: fstatfs() writes only `st`, for an fd `file` owns.
        if unsafe { libc::fstatfs(file.as_raw_fd(), &mut st) } != 0 {
            return "an unknown filesystem".to_string();
        }
        let name = match st.f_type {
            libc::BTRFS_SUPER_MAGIC => "btrfs",
            libc::EXT4_SUPER_MAGIC => "ext4",
            libc::XFS_SUPER_MAGIC => "xfs",
            libc::TMPFS_MAGIC => "tmpfs",
            libc::OVERLAYFS_SUPER_MAGIC => "overlayfs",
            other => return format!("the filesystem of type {other:#x}"),
        };
        name.to_string()
    }

    // Drops `file` from the page cache. False where its pages stay cached,
    // as on tmpfs, where page cache checks are moot. Pages still being read
    // ahead cannot be dropped yet, so it tries again for a while.
    fn drop_cached(file: &File, pages: u64) -> bool {
        use std::time::Duration;

        // Dirty pages stay cached.
        file.sync_all().unwrap();
        for _ in 0..50 {
            // SAFETY: drops the clean pages of `file` from the page cache.
            let ret =
                unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) };
            assert_eq!(ret, 0);
            if cached_pages(file, pages).is_empty() {
                return true;
            }
            thread::sleep(Duration::from_millis(10));
        }
        eprintln!(
            "note: on {}, POSIX_FADV_DONTNEED leaves the file in the page cache (on tmpfs \
             the page cache is the file), so the page cache check is moot",
            fs_name(file)
        );
        false
    }

    // Opens `file` afresh, with `advice` if any.
    fn reopen(file: &File, advice: Option<libc::c_int>) -> File {
        let fresh = File::open(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap();
        if let Some(advice) = advice {
            advise(&fresh, 0, 0, advice);
        }
        fresh
    }

    // Reads the pages `idxs` of `file` through `read`, starting with none
    // cached, and returns the pages cached then. Leaves none cached.
    fn cached_after_reads(file: &File, read: &File, idxs: &[u64], pages: u64) -> Vec<u64> {
        assert!(drop_cached(file, pages));
        for idx in idxs {
            read.read_exact_at(&mut [0u8; PAGE as usize], idx * PAGE)
                .unwrap();
        }
        let cached = cached_pages(file, pages);
        drop_cached(file, pages);
        cached
    }

    // The pages cached by reads of `idxs` on `file` opened afresh, with no
    // advice and with POSIX_FADV_RANDOM. None where that check is moot: the
    // file stays in the page cache (tmpfs) or the advice changes nothing.
    fn kernel_read_ahead_effect(file: &File, idxs: &[u64], pages: u64) -> Option<[Vec<u64>; 2]> {
        if !drop_cached(file, pages) {
            return None;
        }
        let normal = cached_after_reads(file, &reopen(file, None), idxs, pages);
        let random = cached_after_reads(
            file,
            &reopen(file, Some(libc::POSIX_FADV_RANDOM)),
            idxs,
            pages,
        );
        if normal == random {
            eprintln!(
                "note: on {}, reads of pages {idxs:?} cache pages {normal:?} with the kernel's \
                 readahead on and off alike, so the page cache check is moot",
                fs_name(file)
            );
            return None;
        }
        Some([normal, random])
    }

    #[test]
    fn source_turns_kernel_read_ahead_off() {
        let pages = 64;
        let Some(file) = file_with_data_pages(pages, |_| true) else {
            return;
        };
        let reads = [8, 9, 10, 11];
        let effect = kernel_read_ahead_effect(&file, &reads, pages);
        let source = FileUffdMemorySource::new(reopen(&file, None));
        assert!(!source.kernel_read_ahead);
        // Reads in order through the source's file cache fewer pages than
        // the kernel reads ahead for them.
        if let Some([normal, _]) = effect {
            let cached = cached_after_reads(&file, &source.file, &reads, pages);
            assert!(cached.len() < normal.len(), "{cached:?} {normal:?}");
        }
    }

    // What POSIX_FADV_RANDOM is for: reads in order of a data extent with a
    // hole after it, as a guest's faults on the pages a snapshot holds, read
    // ahead into the hole with the kernel's readahead on (the control: the
    // test can see readahead) and cache only the pages read through the
    // source's file. A lone read away from the start of a file is not read
    // ahead even with readahead on, so the extent is read in order.
    #[test]
    fn source_reads_nothing_ahead_into_a_hole() {
        // Data in pages 0 to 15, a hole of 4 MiB from page 16 to the end.
        let pages = 1024;
        let data = |idx| idx < 16;
        let Some(file) = file_with_data_pages(pages, data) else {
            return;
        };
        let fs = fs_name(&file);
        if !drop_cached(&file, pages) {
            eprintln!("skipping: on {fs} the page cache cannot be emptied, so cannot be checked");
            return;
        }
        let reads: Vec<u64> = (0..pages).filter(|&idx| data(idx)).collect();
        let normal = cached_after_reads(&file, &reopen(&file, None), &reads, pages);
        let source = FileUffdMemorySource::new(reopen(&file, None));
        let cached = cached_after_reads(&file, &source.file, &reads, pages);
        let in_hole = |cached: &[u64]| cached.iter().filter(|&&idx| !data(idx)).count();
        eprintln!(
            "{fs}: {} pages read; with readahead {} cached, {} of them in the hole; \
             through the source {} cached, {} in the hole",
            reads.len(),
            normal.len(),
            in_hole(&normal),
            cached.len(),
            in_hole(&cached)
        );
        if in_hole(&normal) == 0 {
            eprintln!(
                "skipping: on {fs} the kernel read nothing ahead into the hole even with its \
                 readahead on (cached {normal:?}), so this test cannot see readahead here"
            );
            return;
        }
        assert_eq!(cached, reads);
    }

    #[test]
    fn read_ahead_stays_inside_the_data_extent() {
        // Data in pages 0 to 199 and 264 to 299, a hole in between.
        let ra_min = READ_AHEAD_MIN / PAGE;
        let ra = READ_AHEAD / PAGE;
        assert_eq!((ra_min, ra), (16, 128), "windows below assume these");
        let pages = 300;
        let data = |idx| !(200..264).contains(&idx);
        let Some(file) = file_with_data_pages(pages, data) else {
            return;
        };
        let checks_cache = drop_cached(&file, pages);
        let mut source = FileUffdMemorySource::new(file.try_clone().unwrap());
        let mut buf = [0u8; PAGE as usize];
        // Each data page in order, as resolve reads it.
        let mut windows = Vec::new();
        for idx in (0..pages).filter(|&idx| data(idx)) {
            assert!(!source.in_hole(idx * PAGE, PAGE));
            source.read_ahead_in_extent(idx * PAGE, PAGE);
            if windows.last() != Some(&source.read_ahead) {
                windows.push(source.read_ahead);
            }
            source.file.read_exact_at(&mut buf, idx * PAGE).unwrap();
        }
        // The first page alone; from the second page on, a window of 16
        // pages, then 64, then 128, each asked for half way through the last
        // and cut at the end of the extent. The second extent follows on
        // from the first past the hole, so its window stays at 128 pages,
        // cut at the end of the file.
        assert_eq!(
            windows,
            [(0, 1), (1, 17), (9, 81), (49, 200), (264, 300)].map(|(s, e)| (s * PAGE, e * PAGE))
        );
        // Nothing read ahead into the hole.
        if checks_cache {
            let cached = cached_pages(&file, pages);
            assert!(cached.iter().all(|&idx| data(idx)), "cached {cached:?}");
        }
    }

    #[test]
    fn scattered_reads_read_nothing_ahead() {
        let pages = 300;
        let Some(file) = file_with_data_pages(pages, |_| true) else {
            return;
        };
        let reads = [150, 10, 280, 12];
        // What the reads cache on their own, with no readahead.
        let read_alone = drop_cached(&file, pages).then(|| {
            let random = reopen(&file, Some(libc::POSIX_FADV_RANDOM));
            cached_after_reads(&file, &random, &reads, pages)
        });
        let mut source = FileUffdMemorySource::new(reopen(&file, None));
        let mut buf = [0u8; PAGE as usize];
        for idx in reads {
            assert!(!source.in_hole(idx * PAGE, PAGE));
            source.read_ahead_in_extent(idx * PAGE, PAGE);
            assert_eq!(source.read_ahead, (idx * PAGE, (idx + 1) * PAGE));
            source.file.read_exact_at(&mut buf, idx * PAGE).unwrap();
        }
        if let Some(read_alone) = read_alone {
            assert_eq!(cached_pages(&file, pages), read_alone);
        }
    }

    #[test]
    fn stopping_hole_lookups_turns_kernel_read_ahead_back_on() {
        let pages = 64;
        let Some(file) = file_with_data_pages(pages, |_| true) else {
            return;
        };
        let reads = [8, 9, 10, 11];
        let effect = kernel_read_ahead_effect(&file, &reads, pages);
        let mut source = FileUffdMemorySource::new(reopen(&file, None));
        source.stop_seeking("SEEK_DATA", 0, &io::Error::from_raw_os_error(libc::EIO));
        assert!(source.kernel_read_ahead);
        assert!(!source.in_hole(0, PAGE));
        source.read_ahead_in_extent(0, PAGE);
        assert_eq!(source.read_ahead, (0, 0));
        // Reads in order cache more than the pages read: the kernel reads
        // ahead for them.
        if effect.is_some() {
            let cached = cached_after_reads(&file, &source.file, &reads, pages);
            assert!(cached.len() > reads.len(), "{cached:?}");
        }
    }

    // Resolves the read of `len` bytes at page `idx` as `resolve` does, up to
    // the read, and returns the window then.
    fn read_ahead_for(source: &mut FileUffdMemorySource, idx: u64, len: u64) -> (u64, u64) {
        assert!(!source.in_hole(idx * PAGE, len));
        source.read_ahead_in_extent(idx * PAGE, len);
        source.read_ahead
    }

    #[test]
    fn forward_jump_into_a_new_extent_reads_nothing_ahead() {
        // Data in pages 0 to 99 and 164 to 299, a hole in between.
        let pages = 300;
        let data = |idx| !(100..164).contains(&idx);
        let Some(file) = file_with_data_pages(pages, data) else {
            return;
        };
        let pg = |(s, e): (u64, u64)| (s * PAGE, e * PAGE);

        // A window that ends inside data: a jump past it into the next
        // extent, data in between, needs no lseek to tell it does not follow
        // on.
        let mut source = FileUffdMemorySource::new(file.try_clone().unwrap());
        read_ahead_for(&mut source, 0, PAGE);
        assert_eq!(read_ahead_for(&mut source, 1, PAGE), pg((1, 17)));
        let lookups = source.lookups;
        assert_eq!(read_ahead_for(&mut source, 200, PAGE), pg((200, 201)));
        // Two to find the extent of page 200, none to check the window.
        assert_eq!(source.lookups, lookups + 2);

        // A window that ends at the end of its extent: a jump into the next
        // extent past its first page, data in between, looks the next data
        // up from the end of the window, which is not the page read.
        let mut source = FileUffdMemorySource::new(file.try_clone().unwrap());
        read_ahead_for(&mut source, 98, PAGE);
        assert_eq!(read_ahead_for(&mut source, 99, PAGE), pg((99, 100)));
        assert!(source.read_ahead_at_extent_end);
        let lookups = source.lookups;
        assert_eq!(read_ahead_for(&mut source, 180, PAGE), pg((180, 181)));
        assert_eq!(source.lookups, lookups + 3);
        assert_eq!(source.read_ahead_size, READ_AHEAD_MIN / 4);

        // The same window, then the first page of the next extent: it
        // follows on, past the hole.
        let mut source = FileUffdMemorySource::new(file);
        read_ahead_for(&mut source, 98, PAGE);
        read_ahead_for(&mut source, 99, PAGE);
        assert_eq!(read_ahead_for(&mut source, 164, PAGE), pg((164, 228)));
    }

    #[test]
    fn read_ahead_of_huge_pages_stays_inside_the_data_extent() {
        // Four huge pages of data, one of hole, then one of data.
        const HUGE: u64 = 2 << 20;
        let per_huge = HUGE / PAGE;
        let pages = 6 * per_huge;
        let data = |idx| idx / per_huge != 4;
        let Some(file) = file_with_data_pages(pages, data) else {
            return;
        };
        let mut source = FileUffdMemorySource::new(file);
        let mut windows = Vec::new();
        for huge in (0..6).filter(|&huge| huge != 4) {
            let window = read_ahead_for(&mut source, huge * per_huge, HUGE);
            windows.push((window.0 / PAGE, window.1 / PAGE));
        }
        // The first read is its own window. The next follows on and asks for
        // 16 pages, its own first ones, so the third does not follow on from
        // that window and starts again. The last huge page holds a new extent
        // that does not follow on from the window inside the one before it.
        let p = per_huge;
        assert_eq!(
            windows,
            [
                (0, p),
                (p, p + 16),
                (2 * p, 3 * p),
                (3 * p, 3 * p + 16),
                (5 * p, 6 * p)
            ]
        );
        // No window reaches the hole.
        assert!(windows.iter().all(|&(s, e)| e <= 4 * p || s >= 5 * p));
    }

    // The file source runs on the vmm thread, where it is built, and on the
    // uffd-handler thread, which inherits the vmm thread's filter. Each
    // system call it makes must pass that filter: one that does not killed
    // every UFFD restore with SIGSYS. The filter here fails a refused call
    // with EUCLEAN rather than killing the test.
    #[cfg(feature = "kvm")]
    #[test]
    fn file_source_passes_the_vmm_seccomp_filter() {
        use std::io::{Seek, SeekFrom};

        use seccompiler::SeccompAction;

        use crate::seccomp_filters::{Thread, get_seccomp_filter};

        // Data in pages 0 to 31 and 48 to 63, a hole in between. None on a
        // filesystem without SEEK_HOLE: the filter is checked all the same,
        // on a plain file, and only the source's own path is skipped.
        let pages = 64;
        let data = |idx| !(32..48).contains(&idx);
        let holey = file_with_data_pages(pages, data);
        if holey.is_none() {
            eprintln!("skipping: the source's own path, the filter is still checked");
        }
        let plain = tempfile::tempfile().unwrap();
        // Made, and removed, outside the filter, which refuses mkdir.
        let no_proc = tempfile::tempdir().unwrap();
        let no_proc_fd = no_proc.path().join("fd");
        // Whether /proc/self/fd reopens `plain` here, checked before the
        // filter is in force, so that a reopen the filter refuses fails the
        // test rather than passing as a fallback. Reading metadata here also
        // settles std's statx probe, so that inside the filter std does not
        // quietly fall back from a refused statx to fstat.
        let proc_usable = File::open(format!("/proc/self/fd/{}", plain.as_raw_fd()))
            .and_then(|f| FileUffdMemorySource::same_inode(&plain, &f))
            .unwrap_or(false);
        plain.metadata().unwrap();
        if !proc_usable {
            eprintln!(
                "note: /proc/self/fd does not reopen a file here, so the reopen \
                 is not checked under the filter"
            );
        }
        let filter = get_seccomp_filter(
            &SeccompAction::Errno(libc::EUCLEAN as u32),
            Thread::Vmm,
            Some(hypervisor::HypervisorType::Kvm),
        )
        .unwrap();
        thread::spawn(move || {
            seccompiler::apply_filter(&filter).unwrap();
            let fadvise = |advice| {
                // SAFETY: FFI call on an fd `plain` owns; no memory is passed.
                unsafe { libc::posix_fadvise(plain.as_raw_fd(), 0, 0, advice) }
            };
            // The filter is in force: advice the source never gives is
            // refused.
            assert_eq!(fadvise(libc::POSIX_FADV_DONTNEED), libc::EUCLEAN);
            // Each advice the source gives passes.
            for advice in [
                libc::POSIX_FADV_RANDOM,
                libc::POSIX_FADV_WILLNEED,
                libc::POSIX_FADV_NORMAL,
            ] {
                assert_eq!(fadvise(advice), 0, "advice {advice}");
            }

            // The file a source reads through, as restore_by_uffd gets it:
            // reopened through /proc and checked to be the same inode, and,
            // where the reopen fails, a clone of the held fd instead. Both
            // paths pass the filter. open_file falls back to a clone when a
            // call is refused, so each path is told apart by whether it
            // shares `plain`'s file position (lseek passes the filter).
            let shares_position = |other: &File| {
                (&*other).seek(SeekFrom::Start(0)).unwrap();
                (&plain).seek(SeekFrom::Start(7)).unwrap();
                (&*other).stream_position().unwrap() == 7
            };
            if proc_usable {
                let reopened = FileUffdMemorySource::open_file(&plain).unwrap();
                assert!(
                    !shares_position(&reopened),
                    "the /proc reopen or its inode check was refused"
                );
                assert!(FileUffdMemorySource::same_inode(&plain, &reopened).unwrap());
            }
            let cloned = FileUffdMemorySource::open_file_in(&plain, &no_proc_fd).unwrap();
            assert!(shares_position(&cloned));

            let Some(file) = holey else {
                return;
            };
            // The source's own path: opened as restore_by_uffd opens it,
            // holes looked up with SEEK_DATA and SEEK_HOLE, the file's size
            // read past the last data, reads ahead and reads in order, and
            // the kernel's readahead turned back on.
            let mut source =
                FileUffdMemorySource::new(FileUffdMemorySource::open_file(&file).unwrap());
            let mut buf = [0u8; PAGE as usize];
            for idx in 0..pages {
                assert_eq!(source.in_hole(idx * PAGE, PAGE), !data(idx), "page {idx}");
                if data(idx) {
                    source.file.read_exact_at(&mut buf, idx * PAGE).unwrap();
                    source.read_ahead_in_extent(idx * PAGE, PAGE);
                }
            }
            assert!(source.seek_holes, "a hole lookup failed");
            assert!(source.read_ahead.1 > PAGE, "nothing was read ahead");
            assert!(!source.in_hole(pages * PAGE, PAGE));
            source.stop_seeking("SEEK_DATA", 0, &io::Error::from_raw_os_error(libc::EIO));
            assert!(source.kernel_read_ahead);
        })
        .join()
        .unwrap();
    }
}
