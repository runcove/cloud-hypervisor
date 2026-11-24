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

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Error, Read};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
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

/// What a snapshot file looked like when it was opened: compared again
/// after a read error, to tell whether the file changed under the VM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FileIdentity {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
}

impl FileIdentity {
    pub(crate) fn of(metadata: &Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            size: metadata.size(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
        }
    }

    /// Names what differs in `now`, as "field old -> new"; empty when
    /// nothing does.
    pub(crate) fn changes(&self, now: &Self) -> Vec<String> {
        let mut changes = Vec::new();
        if (self.dev, self.ino) != (now.dev, now.ino) {
            changes.push(format!(
                "device/inode {}/{} -> {}/{}",
                self.dev, self.ino, now.dev, now.ino
            ));
        }
        if self.size != now.size {
            changes.push(format!("size {} -> {}", self.size, now.size));
        }
        if (self.mtime, self.mtime_nsec) != (now.mtime, now.mtime_nsec) {
            changes.push(format!(
                "mtime {}.{:09} -> {}.{:09}",
                self.mtime, self.mtime_nsec, now.mtime, now.mtime_nsec
            ));
        }
        changes
    }
}

/// The snapshot file's path and its identity when opened.
struct SnapshotOrigin {
    path: PathBuf,
    opened: FileIdentity,
}

/// Source that reads pages from a local snapshot file.
///
/// A page wholly inside a hole of the file is resolved with zeroes without
/// reading the file: a buffered read of a hole would leave a zero page in the
/// host page cache for every hole page the guest touches. Holes are looked up
/// when a page is resolved, with `lseek(SEEK_DATA)`, rather than listed
/// up front, so that a fragmented file costs nothing before the guest runs
/// and no memory beyond the one extent kept here.
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
    /// What the source did, logged when it is dropped: lseek calls made,
    /// pages resolved with zeroes as holes, and pages read from the file.
    lookups: u64,
    hole_pages: u64,
    read_pages: u64,
    origin: Option<SnapshotOrigin>,
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
        Self {
            file,
            buf: Vec::new(),
            extent: None,
            seek_holes: true,
            zeroes: Vec::new(),
            lookups: 0,
            hole_pages: 0,
            read_pages: 0,
            origin: None,
        }
    }

    /// A source for the snapshot file at `path`, which records the file's
    /// identity now so a later read error can say whether it changed.
    pub(crate) fn for_snapshot(file: File, path: &Path) -> io::Result<Self> {
        let opened = FileIdentity::of(&file.metadata()?);
        // Set on a value from `new` rather than with `..Self::new(file)`:
        // the source implements Drop, so its fields cannot be moved out.
        let mut source = Self::new(file);
        source.origin = Some(SnapshotOrigin {
            path: path.to_path_buf(),
            opened,
        });
        Ok(source)
    }

    /// What changed in the snapshot file since it was opened. The path is
    /// stated again to see a replaced file, and the open file to see one
    /// truncated or rewritten in place.
    fn changes_since_open(&self) -> Vec<String> {
        let Some(origin) = &self.origin else {
            return Vec::new();
        };
        let mut changes = Vec::new();
        match fs::metadata(&origin.path) {
            Ok(m) => changes.extend(origin.opened.changes(&FileIdentity::of(&m))),
            Err(e) => changes.push(format!("path no longer stats ({e})")),
        }
        match self.file.metadata() {
            Ok(m) => {
                for change in origin.opened.changes(&FileIdentity::of(&m)) {
                    if !changes.contains(&change) {
                        changes.push(change);
                    }
                }
            }
            Err(e) => changes.push(format!("open file no longer stats ({e})")),
        }
        changes
    }

    /// After a read error, logs what changed in the snapshot file, if
    /// anything did.
    fn report_changed_file(&self) {
        let changes = self.changes_since_open();
        if let (Some(origin), false) = (&self.origin, changes.is_empty()) {
            log::error!(
                "snapshot file changed under a running VM: {}: {}",
                origin.path.display(),
                changes.join(", ")
            );
        }
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
        if let Err(e) = self
            .file
            .read_exact_at(&mut self.buf[..page_size], file_pos)
        {
            self.report_changed_file();
            return Err(e);
        }
        self.read_pages += 1;

        match copy(uffd_fd, page_addr, self.buf.as_ptr(), range.page_size) {
            Ok(()) => Ok(()),
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
                // Installed concurrently. Wake any blocked threads.
                if let Err(e) = wake(uffd_fd, page_addr, range.page_size) {
                    log::warn!("UFFDIO_WAKE failed at {page_addr:#x}: {e}");
                }
                Ok(())
            }
            Err(e) => Err(e),
        }
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
    use std::io::Write;

    use super::*;

    const PAGE: u64 = 0x1000;

    // A file of `pages` pages of 4 KiB, data in each page `data` picks and
    // holes elsewhere. None unless SEEK_DATA reports exactly that.
    fn file_with_data_pages(pages: u64, data: impl Fn(u64) -> bool) -> Option<File> {
        let file = tempfile::tempfile().unwrap();
        file.set_len(pages * PAGE).unwrap();
        for idx in (0..pages).filter(|&idx| data(idx)) {
            file.write_all_at(&[0xa5; PAGE as usize], idx * PAGE)
                .unwrap();
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
        assert!(!source.in_hole(0, PAGE));
        assert!(!source.seek_holes);
        assert!(!source.in_hole(PAGE, PAGE));
        assert_eq!(source.extent, None);
    }

    #[test]
    fn file_identity_names_each_change() {
        let opened = FileIdentity {
            dev: 1,
            ino: 2,
            size: 4096,
            mtime: 100,
            mtime_nsec: 5,
        };
        assert!(opened.changes(&opened).is_empty());
        let now = FileIdentity {
            ino: 3,
            size: 0,
            mtime_nsec: 6,
            ..opened
        };
        assert_eq!(
            opened.changes(&now),
            [
                "device/inode 1/2 -> 1/3",
                "size 4096 -> 0",
                "mtime 100.000000005 -> 100.000000006",
            ]
        );
    }

    #[test]
    fn snapshot_source_sees_truncated_replaced_and_removed_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("memory-ranges");
        File::create(&path)
            .unwrap()
            .write_all(&[0xab; 8192])
            .unwrap();
        let source = FileUffdMemorySource::for_snapshot(File::open(&path).unwrap(), &path).unwrap();
        assert!(source.changes_since_open().is_empty());

        // Truncated in place: the same file, shorter.
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(4096)
            .unwrap();
        let changes = source.changes_since_open();
        assert!(
            changes.contains(&"size 8192 -> 4096".to_string()),
            "{changes:?}"
        );
        assert!(
            !changes.iter().any(|c| c.starts_with("device/inode")),
            "{changes:?}"
        );

        // Replaced: the path names another file.
        let other = dir.path().join("other");
        File::create(&other).unwrap().write_all(&[0; 8192]).unwrap();
        fs::rename(&other, &path).unwrap();
        let changes = source.changes_since_open();
        assert!(
            changes.iter().any(|c| c.starts_with("device/inode")),
            "{changes:?}"
        );

        // Removed: the path no longer stats.
        fs::remove_file(&path).unwrap();
        let changes = source.changes_since_open();
        assert!(
            changes
                .iter()
                .any(|c| c.starts_with("path no longer stats")),
            "{changes:?}"
        );

        // A source opened without a path reports nothing.
        let unnamed = FileUffdMemorySource::new(tempfile::tempfile().unwrap());
        assert!(unnamed.changes_since_open().is_empty());
    }
}
