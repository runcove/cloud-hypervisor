// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::marker::PhantomData;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
mod aio_data_io;
mod blocking_offload;
mod common;
mod completion;
mod guest_memory_target;
mod operation;
mod owned_io_buffer;
#[cfg(feature = "io_uring")]
mod uring_data_io;

use std::str::FromStr;
use std::{io, result};

pub use aio_data_io::AioDataIo;
pub use blocking_offload::OFFLOAD_DEPTH;
#[cfg(test)]
pub(crate) use blocking_offload::fail_next_spawn;
pub(crate) use blocking_offload::{
    BlockingOffload, BlockingOp, BlockingOpFn, offload_fn, spawn_offload,
};
pub(crate) use completion::CompletionCommon;
pub use completion::{AsyncIoCompletion, OffloadedOp};
pub use guest_memory_target::GuestMemoryTarget;
pub use operation::AsyncIoOperation;
pub use owned_io_buffer::OwnedIoBuffer;
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "io_uring")]
pub use uring_data_io::UringDataIo;
use vmm_sys_util::eventfd::EventFd;

use crate::SECTOR_SIZE;

#[derive(Error, Debug)]
pub enum DiskFileError {
    /// Failed getting disk file size.
    #[error("Failed getting disk file size")]
    Size(#[source] io::Error),
    /// Failed creating a new AsyncIo.
    #[error("Failed creating a new AsyncIo")]
    NewAsyncIo(#[source] io::Error),
    /// Resize failed
    #[error("Resize failed")]
    ResizeError(#[source] io::Error),
    /// Flushing cached metadata failed
    #[error("Flushing cached metadata failed")]
    SyncMetadata(#[source] io::Error),
    #[error("Failed cloning disk file")]
    Clone(#[source] io::Error),
}

/// A wrapper for [`RawFd`] capturing the lifetime of a corresponding disk file.
///
/// This fulfills the same role as [`BorrowedFd`] but is tailored to the limitations
/// by some disk implementations, which wrap the effective [`File`]
/// in an `Arc<Mutex<T>>`, making the use of [`BorrowedFd`] impossible.
///
/// [`BorrowedFd`]: std::os::fd::BorrowedFd
#[derive(Copy, Clone, Debug)]
pub struct BorrowedDiskFd<'fd> {
    raw_fd: RawFd,
    _lifetime: PhantomData<&'fd OwnedFd>,
}

impl BorrowedDiskFd<'_> {
    pub(crate) fn new(raw_fd: RawFd) -> Self {
        Self {
            raw_fd,
            _lifetime: PhantomData,
        }
    }
}

impl AsRawFd for BorrowedDiskFd<'_> {
    fn as_raw_fd(&self) -> RawFd {
        self.raw_fd
    }
}

#[derive(Error, Debug)]
pub enum AsyncIoError {
    /// Failed vectored reading from file.
    #[error("Failed vectored reading from file")]
    ReadVectored(#[source] io::Error),
    /// Failed vectored writing to file.
    #[error("Failed vectored writing to file")]
    WriteVectored(#[source] io::Error),
    /// Failed synchronizing file.
    #[error("Failed synchronizing file")]
    Fsync(#[source] io::Error),
    /// Failed punching hole.
    #[error("Failed punching hole")]
    PunchHole(#[source] io::Error),
    /// Failed writing zeroes.
    #[error("Failed writing zeroes")]
    WriteZeroes(#[source] io::Error),
    /// Failed submitting batch requests.
    #[error("Failed submitting batch requests")]
    SubmitBatchRequests(#[source] io::Error),
}

pub type AsyncIoResult<T> = result::Result<T, AsyncIoError>;

/// Runs on a worker thread spawned by an [`AsyncIo`] backend before the
/// thread does any I/O, for instance to apply a seccomp filter.
pub type WorkerThreadInit = Box<dyn FnOnce() -> io::Result<()> + Send>;

/// The most io_uring worker threads (io-wq) the kernel may start for one
/// queue's ring.
///
/// Requests that cannot complete without blocking are handed to a pool of
/// kernel worker threads, which count against the process's task limit. Work
/// on regular files and block devices is "bounded", every other kind is
/// "unbounded"; each kind has its own limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct IoWorkerLimits {
    pub bounded: u32,
    pub unbounded: u32,
}

#[derive(Error, Debug)]
#[error("Expected <bounded>:<unbounded>, two whole numbers: {0}")]
pub struct IoWorkerLimitsParseError(String);

/// Parses `<bounded>:<unbounded>`, for instance `16:4`.
impl FromStr for IoWorkerLimits {
    type Err = IoWorkerLimitsParseError;

    fn from_str(s: &str) -> result::Result<Self, Self::Err> {
        let error = || IoWorkerLimitsParseError(s.to_owned());
        let (bounded, unbounded) = s.split_once(':').ok_or_else(error)?;
        Ok(Self {
            bounded: bounded.parse().map_err(|_| error())?,
            unbounded: unbounded.parse().map_err(|_| error())?,
        })
    }
}

impl IoWorkerLimits {
    /// The limits a disk gets when its configuration sets none.
    pub const DEFAULT: Self = Self {
        bounded: 16,
        unbounded: 4,
    };
}

/// Caps the io_uring workers of `io` at `configured`, or at
/// [`IoWorkerLimits::DEFAULT`] when no limits are configured.
///
/// Configured limits are all or nothing: if they cannot be applied, the error
/// is returned, so a disk never runs uncapped while its configuration says it
/// is capped. The default is best effort: if it cannot be applied (a kernel
/// before 5.15 refuses the call), the error is returned as `Ok(Some(_))` and
/// the ring runs with the kernel's own limits.
pub fn apply_io_worker_limits(
    io: &mut dyn AsyncIo,
    configured: Option<IoWorkerLimits>,
) -> io::Result<Option<io::Error>> {
    match io.set_io_worker_limits(configured.unwrap_or(IoWorkerLimits::DEFAULT)) {
        Ok(()) => Ok(None),
        Err(e) if configured.is_none() => Ok(Some(e)),
        Err(e) => Err(e),
    }
}

pub trait AsyncIo: Send {
    fn notifier(&self) -> &EventFd;

    /// Submits one owned data operation.
    ///
    /// Takes ownership of `op`.
    /// Implementations that complete asynchronously must retain it until its
    /// completion is returned.
    fn submit_data_operation(&mut self, op: AsyncIoOperation) -> AsyncIoResult<()>;

    /// Submits a read from `offset` into guest memory.
    fn read_to_memory(
        &mut self,
        offset: libc::off_t,
        target: GuestMemoryTarget,
        user_data: u64,
    ) -> AsyncIoResult<()> {
        self.submit_data_operation(AsyncIoOperation::read_to_memory(offset, target, user_data))
    }

    /// Submits a write to `offset` from guest memory.
    fn write_from_memory(
        &mut self,
        offset: libc::off_t,
        target: GuestMemoryTarget,
        user_data: u64,
    ) -> AsyncIoResult<()> {
        self.submit_data_operation(AsyncIoOperation::write_from_memory(
            offset, target, user_data,
        ))
    }

    /// Submits a read from `offset` into an owned host-memory buffer.
    fn read_to_vec(
        &mut self,
        offset: libc::off_t,
        buffer: OwnedIoBuffer,
        user_data: u64,
    ) -> AsyncIoResult<()> {
        self.submit_data_operation(AsyncIoOperation::read_to_vec(offset, buffer, user_data))
    }

    /// Submits a write to `offset` from an owned host-memory buffer.
    fn write_from_vec(
        &mut self,
        offset: libc::off_t,
        buffer: OwnedIoBuffer,
        user_data: u64,
    ) -> AsyncIoResult<()> {
        self.submit_data_operation(AsyncIoOperation::write_from_vec(offset, buffer, user_data))
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()>;
    fn punch_hole(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()>;
    fn write_zeroes(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()>;

    /// Submits a write zeroes that may unmap the range. The range must read
    /// back as zeroes, which a punch hole does not guarantee: on a block
    /// device it is a discard, and on a qcow2 overlay it uncovers the backing
    /// file. By default that is therefore a plain write zeroes. The raw
    /// backends override it, to unmap the range where the file allows it and
    /// to report it as a write zeroes when running it on a worker thread.
    fn write_zeroes_unmap(
        &mut self,
        offset: u64,
        length: u64,
        user_data: u64,
    ) -> AsyncIoResult<()> {
        self.write_zeroes(offset, length, user_data)
    }

    /// Returns whether discard and write zeroes requests run on a worker
    /// thread rather than on the calling thread.
    ///
    /// Such a backend accepts at most [`OFFLOAD_DEPTH`] of them whose
    /// completion has not been returned by
    /// [`AsyncIo::next_completed_request`]; it fails further ones with `EIO`.
    /// The caller bounds them, and keeps the rest queued.
    fn offloads_punch_hole_or_write_zeroes(&self) -> bool {
        false
    }

    /// Passes `init` to run on every worker thread this backend has spawned,
    /// before that thread does any I/O. Must be called before any request is
    /// submitted. Backends without worker threads drop it.
    fn set_worker_thread_init(&mut self, _init: WorkerThreadInit) {}

    /// Caps the io_uring worker threads the kernel may start for this
    /// backend's ring. Must be called before any request is submitted, from
    /// any thread: the kernel applies the limits to each thread when it first
    /// submits to the ring. Backends without an io_uring ring start no such
    /// workers and return `Ok`.
    fn set_io_worker_limits(&mut self, _limits: IoWorkerLimits) -> io::Result<()> {
        Ok(())
    }

    /// Returns the next owned completion, if one is available.
    ///
    /// Read completions from owned host-memory buffers return that buffer here.
    fn next_completed_request(&mut self) -> Option<AsyncIoCompletion>;

    fn batch_requests_enabled(&self) -> bool {
        false
    }

    /// Submits a batch of owned data operations.
    ///
    /// Backends either accept the whole batch for eventual completion or return
    /// an error before taking ownership of any operation.
    fn submit_batch_requests(&mut self, batch_request: Vec<AsyncIoOperation>) -> AsyncIoResult<()> {
        if batch_request.is_empty() {
            Ok(())
        } else {
            Err(AsyncIoError::SubmitBatchRequests(io::Error::other(
                "batch requests are not supported by this backend",
            )))
        }
    }

    fn alignment(&self) -> Option<u64> {
        Some(SECTOR_SIZE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Records the limits it is given and refuses them if told to.
    struct FakeIo {
        notifier: EventFd,
        refuse: bool,
        limits: Option<IoWorkerLimits>,
    }

    impl FakeIo {
        fn new(refuse: bool) -> Self {
            Self {
                notifier: EventFd::new(0).unwrap(),
                refuse,
                limits: None,
            }
        }
    }

    impl AsyncIo for FakeIo {
        fn notifier(&self) -> &EventFd {
            &self.notifier
        }
        fn submit_data_operation(&mut self, _op: AsyncIoOperation) -> AsyncIoResult<()> {
            unreachable!()
        }
        fn fsync(&mut self, _user_data: Option<u64>) -> AsyncIoResult<()> {
            unreachable!()
        }
        fn punch_hole(&mut self, _offset: u64, _length: u64, _user_data: u64) -> AsyncIoResult<()> {
            unreachable!()
        }
        fn write_zeroes(
            &mut self,
            _offset: u64,
            _length: u64,
            _user_data: u64,
        ) -> AsyncIoResult<()> {
            unreachable!()
        }
        fn next_completed_request(&mut self) -> Option<AsyncIoCompletion> {
            None
        }
        fn set_io_worker_limits(&mut self, limits: IoWorkerLimits) -> io::Result<()> {
            self.limits = Some(limits);
            if self.refuse {
                Err(io::Error::from_raw_os_error(libc::EINVAL))
            } else {
                Ok(())
            }
        }
    }

    const CONFIGURED: IoWorkerLimits = IoWorkerLimits {
        bounded: 8,
        unbounded: 2,
    };

    #[test]
    fn io_worker_limits_parse() {
        assert_eq!(
            "16:4".parse::<IoWorkerLimits>().unwrap(),
            IoWorkerLimits::DEFAULT
        );
        for bad in ["", "16", "16:", ":4", "16:4:1", "-1:4", "a:4", "16:4.5"] {
            bad.parse::<IoWorkerLimits>().unwrap_err();
        }
    }

    #[test]
    fn apply_io_worker_limits_applies_the_configured_limits() {
        let mut io = FakeIo::new(false);
        assert!(
            apply_io_worker_limits(&mut io, Some(CONFIGURED))
                .unwrap()
                .is_none()
        );
        assert_eq!(io.limits, Some(CONFIGURED));
    }

    #[test]
    fn apply_io_worker_limits_applies_the_default_when_none_is_configured() {
        let mut io = FakeIo::new(false);
        assert!(apply_io_worker_limits(&mut io, None).unwrap().is_none());
        assert_eq!(io.limits, Some(IoWorkerLimits::DEFAULT));
    }

    #[test]
    fn apply_io_worker_limits_fails_when_configured_limits_are_refused() {
        let mut io = FakeIo::new(true);
        let e = apply_io_worker_limits(&mut io, Some(CONFIGURED)).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::EINVAL));
    }

    #[test]
    fn apply_io_worker_limits_runs_uncapped_when_the_default_is_refused() {
        let mut io = FakeIo::new(true);
        let refused = apply_io_worker_limits(&mut io, None).unwrap().unwrap();
        assert_eq!(refused.raw_os_error(), Some(libc::EINVAL));
    }
}
