// Copyright © 2021 Intel Corporation
//
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::collections::HashMap;
use std::os::fd::{AsRawFd, RawFd};
use std::{io, mem};

use io_uring::{IoUring, opcode, squeue, types};
use log::{Level, error, log, warn};
use vmm_sys_util::eventfd::EventFd;

use super::common::{duplicate_user_data_error, validate_batch};
use super::{AsyncIoCompletion, AsyncIoOperation, CompletionCommon};

/// Number of times a data operation is resubmitted after the kernel reports a
/// retryable result before the error is reported to the caller.
const MAX_RESUBMISSIONS: u32 = 8;

/// Returns the errno name of a completion result that means "nothing was done,
/// try again" rather than an actual I/O failure, and `None` for every other
/// result.
fn retryable_errno_name(result: i32) -> Option<&'static str> {
    match -result {
        libc::EAGAIN => Some("EAGAIN"),
        libc::EINTR => Some("EINTR"),
        _ => None,
    }
}

/// A data operation retained until it completes, with what is needed to
/// resubmit it if the kernel reports a retryable result.
struct RetainedOperation {
    op: AsyncIoOperation,
    // The file descriptor the operation was submitted against.
    fd: RawFd,
    // How many times this operation has already been resubmitted.
    resubmissions: u32,
}

/// `io_uring` wrapper for async I/O.
///
/// Holds the `IoUring` and tracks the ops that are pending.
pub struct UringDataIo {
    io_uring: IoUring,
    // `in_flight` tracks every user_data value accepted by the kernel. Owned
    // data operations store `Some(retained)` so their iovecs and backing
    // buffers remain valid until completion, and so they can be resubmitted;
    // metadata operations store `None`.
    in_flight: HashMap<u64, Option<RetainedOperation>>,
    completions: CompletionCommon,
    // `needs_submit_retry` is set when SQEs have been published to the ring,
    // but the submit syscall failed before confirming kernel ownership.
    needs_submit_retry: bool,
}

impl UringDataIo {
    /// Creates an io_uring queue and registers its completion eventfd.
    pub fn new(ring_depth: u32) -> io::Result<Self> {
        let io_uring = IoUring::new(ring_depth)?;
        let completions = CompletionCommon::new();
        io_uring
            .submitter()
            .register_eventfd(completions.notifier().as_raw_fd())?;

        Ok(Self {
            io_uring,
            in_flight: HashMap::new(),
            completions,
            needs_submit_retry: false,
        })
    }

    /// Returns the eventfd signaled when completions are available.
    pub fn notifier(&self) -> &EventFd {
        self.completions.notifier()
    }

    /// Submits one owned read or write operation to the queue.
    pub fn submit_operation(&mut self, fd: RawFd, op: AsyncIoOperation) -> io::Result<()> {
        self.submit_batch(fd, vec![op])
    }

    fn reserve_user_data(&mut self, user_data: u64) -> io::Result<()> {
        if self.in_flight.contains_key(&user_data) {
            return Err(duplicate_user_data_error(user_data));
        }
        self.in_flight.insert(user_data, None);

        Ok(())
    }

    fn submit_kernel_entry(&mut self, user_data: u64, entry: &squeue::Entry) -> io::Result<()> {
        self.reserve_user_data(user_data)?;

        let (submitter, mut sq, _) = self.io_uring.split();
        // SAFETY: the entry has no caller-owned buffer. `user_data` is retained
        // in `in_flight` until the CQE is consumed.
        if let Err(e) = unsafe { sq.push(entry) } {
            self.in_flight.remove(&user_data);
            return Err(io::Error::other(format!("Submission queue is full: {e:?}")));
        }
        sq.sync();

        match submitter.submit() {
            Ok(_) => self.needs_submit_retry = false,
            Err(e) => {
                self.needs_submit_retry = true;
                warn!("io_uring submit failed after SQE was published: {e}");
                self.completions.notifier().write(1).unwrap();
            }
        }

        Ok(())
    }

    /// Submits a batch of owned read and write operations.
    ///
    /// If the io_uring submission queue cannot accept the whole batch, each
    /// operation is completed locally with `-EAGAIN` so callers can observe
    /// every request through the normal completion path.
    pub fn submit_batch(&mut self, fd: RawFd, batch: Vec<AsyncIoOperation>) -> io::Result<()> {
        if batch.is_empty() {
            return Ok(());
        }

        validate_batch(|user_data| self.in_flight.contains_key(&user_data), &batch)?;

        let (submitter, mut sq, _) = self.io_uring.split();
        let available = sq.capacity() - sq.len();
        if batch.len() > available {
            // Not enough space for the batch.
            // Drop sq, which will re-publish an unmodified tail pointer
            drop(sq);
            for op in batch {
                self.completions
                    .complete(AsyncIoCompletion::from_operation(op, -libc::EAGAIN));
            }
            return Ok(());
        }

        let mut signal_completion = false;
        let mut batch = batch.into_iter();
        while let Some(op) = batch.next() {
            let user_data = op.user_data();
            let entry = Self::build_entry(fd, &op);
            self.in_flight.insert(
                user_data,
                Some(RetainedOperation {
                    op,
                    fd,
                    resubmissions: 0,
                }),
            );

            // SAFETY: the SQ capacity was just checked. Every iovec's pointer is retained in
            // self.in_flight before the SQ tail is advanced by sync or drop. in_flight only
            // drops the memory after a completion.
            if let Err(e) = unsafe { sq.push(&entry) } {
                Self::handle_push_failure(
                    &mut self.in_flight,
                    &mut self.completions,
                    user_data,
                    batch.by_ref(),
                    &e,
                );
                signal_completion = true;
                break;
            }
        }

        sq.sync();
        match submitter.submit() {
            Ok(_) => self.needs_submit_retry = false,
            Err(e) => {
                self.needs_submit_retry = true;
                warn!("io_uring submit failed after SQEs were published: {e}");
                signal_completion = true;
            }
        }
        if signal_completion {
            self.completions.notifier().write(1).unwrap();
        }

        Ok(())
    }

    #[cold]
    fn handle_push_failure(
        in_flight: &mut HashMap<u64, Option<RetainedOperation>>,
        completions: &mut CompletionCommon,
        user_data: u64,
        remaining: impl Iterator<Item = AsyncIoOperation>,
        error: &squeue::PushError,
    ) {
        // Since capacity was just checked, this should only happen if the ring
        // state changed unexpectedly. Keep all affected operations memory safe
        // by returning local completions through the normal path.
        let op = in_flight
            .remove(&user_data)
            .flatten()
            .expect("pending operation missing after failed push")
            .op;
        completions.complete(AsyncIoCompletion::from_operation(op, -libc::EAGAIN));
        for op in remaining {
            completions.complete(AsyncIoCompletion::from_operation(op, -libc::EAGAIN));
        }
        warn!("io_uring submission queue became full after capacity check: {error:?}");
    }

    fn build_entry(fd: RawFd, op: &AsyncIoOperation) -> squeue::Entry {
        let iovecs = op.iovecs();
        let fd = types::Fd(fd);
        if op.is_read() {
            opcode::Readv::new(fd, iovecs.as_ptr(), iovecs.len() as u32)
                .offset(op.offset() as u64)
                .build()
                .user_data(op.user_data())
        } else {
            opcode::Writev::new(fd, iovecs.as_ptr(), iovecs.len() as u32)
                .offset(op.offset() as u64)
                .build()
                .user_data(op.user_data())
        }
    }

    /// Submits an io_uring NOP carrying `user_data`.
    pub fn submit_nop(&mut self, user_data: u64) -> io::Result<()> {
        self.submit_kernel_entry(user_data, &opcode::Nop::new().build().user_data(user_data))
    }

    /// Submits an fsync operation carrying `user_data`.
    pub fn submit_fsync(&mut self, fd: RawFd, user_data: u64) -> io::Result<()> {
        self.submit_kernel_entry(
            user_data,
            &opcode::Fsync::new(types::Fd(fd))
                .build()
                .user_data(user_data),
        )
    }

    /// Injects a completion that did not come from a kernel CQE.
    ///
    /// The notifier is signaled so callers can drain it with
    /// [`Self::next_completion`].
    pub fn inject_completion(&mut self, completion: AsyncIoCompletion) {
        self.completions.complete(completion);
    }

    /// Returns the next kernel or injected completion if one is available.
    ///
    /// Consuming a kernel completion returns ownership of any buffer retained
    /// by the corresponding operation. Completions that are retryable rather
    /// than failed are resubmitted here instead of being returned, so the
    /// caller only ever sees a final result.
    pub fn next_completion(&mut self) -> Option<AsyncIoCompletion> {
        if self.needs_submit_retry {
            match self.io_uring.submitter().submit() {
                Ok(_) => self.needs_submit_retry = false,
                Err(e) => warn!("io_uring retry submit failed for retained SQEs: {e}"),
            }
        }

        loop {
            // The completion queue borrows the ring, so take the entry's fields
            // and drop it before handling the completion.
            let next = self
                .io_uring
                .completion()
                .next()
                .map(|entry| (entry.user_data(), entry.result()));

            let Some((user_data, result)) = next else {
                break;
            };

            if let Some(completion) = self.process_completion(user_data, result) {
                return Some(completion);
            }
        }

        self.completions.next_completed()
    }

    /// Turns one raw completion into a completion for the caller.
    ///
    /// Returns `None` when the operation was retryable and has been resubmitted;
    /// its real completion then arrives later.
    fn process_completion(&mut self, user_data: u64, result: i32) -> Option<AsyncIoCompletion> {
        let retained = self.in_flight.remove(&user_data).flatten();

        // Metadata operations are not retained, so they cannot be resubmitted
        // and are reported as-is.
        if let Some(errno) = retryable_errno_name(result)
            && let Some(retained) = retained
        {
            return match self.resubmit(retained, result, errno) {
                Ok(()) => None,
                Err(retained) => Some(AsyncIoCompletion::from_operation(retained.op, result)),
            };
        }

        Some(AsyncIoCompletion::new(
            user_data,
            result,
            retained.and_then(|retained| retained.op.into_completion_buffer()),
        ))
    }

    /// Resubmits an operation the kernel declined to perform.
    ///
    /// The entry carries `IOSQE_ASYNC` so the kernel issues it from an io-wq
    /// worker, which is allowed to block, instead of taking the non-blocking
    /// path that produced the retryable result.
    ///
    /// Hands the operation back when the resubmission bound is exhausted or the
    /// submission queue refuses the entry, so the caller reports the original
    /// result.
    ///
    /// An operation's first resubmission is logged at `warn!` and the rest at
    /// `debug!`, so that a retry is visible at the default log level while a
    /// burst of retries on one operation cannot flood the log.
    fn resubmit(
        &mut self,
        mut retained: RetainedOperation,
        result: i32,
        errno: &'static str,
    ) -> Result<(), Box<RetainedOperation>> {
        let user_data = retained.op.user_data();
        let error = io::Error::from_raw_os_error(-result);

        if retained.resubmissions >= MAX_RESUBMISSIONS {
            warn!(
                "io_uring operation {user_data} still reported {error} after {} resubmissions; reporting it as an error",
                retained.resubmissions
            );
            return Err(Box::new(retained));
        }

        retained.resubmissions += 1;
        let direction = if retained.op.is_read() {
            "read"
        } else {
            "write"
        };
        let level = if retained.resubmissions == 1 {
            Level::Warn
        } else {
            Level::Debug
        };
        log!(
            level,
            "io_uring completion returned {errno} for {direction} user_data={user_data}; resubmitting with IOSQE_ASYNC (attempt {}/{MAX_RESUBMISSIONS})",
            retained.resubmissions
        );

        let entry = Self::build_entry(retained.fd, &retained.op).flags(squeue::Flags::ASYNC);
        // Retain the operation before the SQ tail is advanced so its iovecs and
        // backing buffer stay alive for as long as the kernel can read them.
        self.in_flight.insert(user_data, Some(retained));

        let (submitter, mut sq, _) = self.io_uring.split();
        // SAFETY: the operation is retained in `self.in_flight` until its
        // completion is consumed, which keeps every iovec pointer valid.
        if let Err(e) = unsafe { sq.push(&entry) } {
            // Drop sq, which will re-publish an unmodified tail pointer.
            drop(sq);
            warn!("io_uring submission queue refused a resubmitted operation: {e:?}");
            let retained = self
                .in_flight
                .remove(&user_data)
                .flatten()
                .expect("resubmitted operation missing after failed push");
            return Err(Box::new(retained));
        }
        sq.sync();

        match submitter.submit() {
            Ok(_) => self.needs_submit_retry = false,
            Err(e) => {
                self.needs_submit_retry = true;
                warn!("io_uring submit failed after a resubmitted SQE was published: {e}");
                self.completions.notifier().write(1).unwrap();
            }
        }

        Ok(())
    }
}

impl Drop for UringDataIo {
    fn drop(&mut self) {
        // Closing the ring fd does not cancel io_uring ops that have started.
        // Wait for CQEs before releasing retained iovecs.
        if self.needs_submit_retry {
            if let Err(e) = self.io_uring.submitter().submit() {
                warn!("io_uring drain submit failed for retained SQEs: {e}");
            }
            self.needs_submit_retry = false;
        }

        let max_drain_iterations = self.in_flight.len().saturating_mul(2);
        let mut drain_iterations = 0;
        while !self.in_flight.is_empty() {
            if drain_iterations == max_drain_iterations {
                error!(
                    "io_uring drain abandoned with {} operations still in flight after {} drain iterations",
                    self.in_flight.len(),
                    drain_iterations
                );
                // Keep retained buffers mapped if the ring cannot be drained.
                mem::forget(mem::take(&mut self.in_flight));
                break;
            }
            drain_iterations += 1;

            if let Some(entry) = self.io_uring.completion().next() {
                self.in_flight.remove(&entry.user_data());
                continue;
            }

            // No completion ready: block in the kernel until at least one is.
            if let Err(e) = self.io_uring.submitter().submit_and_wait(1) {
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                error!(
                    "io_uring drain abandoned with {} operations still in flight: {e}",
                    self.in_flight.len()
                );
                // Keep retained buffers mapped if the ring cannot be drained.
                mem::forget(mem::take(&mut self.in_flight));
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::os::fd::{AsRawFd, RawFd};
    use std::thread::sleep;
    use std::time::Duration;

    use vmm_sys_util::tempfile::TempFile;

    use super::{MAX_RESUBMISSIONS, RetainedOperation, UringDataIo};
    use crate::async_io::{AsyncIoCompletion, AsyncIoOperation, OwnedIoBuffer};

    fn wait_for_completion(data_io: &mut UringDataIo) -> AsyncIoCompletion {
        for _ in 0..1000 {
            if let Some(completion) = data_io.next_completion() {
                return completion;
            }
            sleep(Duration::from_millis(1));
        }

        panic!("timed out waiting for io_uring completion");
    }

    // Marks `op` in flight against `fd` exactly as a submission would, so a
    // completion result can be fed to the completion path directly. The kernel
    // cannot be made to report EAGAIN on demand.
    fn mark_in_flight(data_io: &mut UringDataIo, fd: RawFd, op: AsyncIoOperation) {
        data_io.in_flight.insert(
            op.user_data(),
            Some(RetainedOperation {
                op,
                fd,
                resubmissions: 0,
            }),
        );
    }

    #[test]
    fn uring_resubmits_a_retryable_read_and_reports_its_real_result() {
        let file = TempFile::new().unwrap().into_file();
        file.set_len(512).unwrap();
        let fd = file.as_raw_fd();
        let mut data_io = UringDataIo::new(8).unwrap();

        mark_in_flight(
            &mut data_io,
            fd,
            AsyncIoOperation::read_to_vec(0, OwnedIoBuffer::from_vec(vec![0; 512]), 7),
        );

        // A retryable result is never surfaced to the caller.
        assert!(data_io.process_completion(7, -libc::EAGAIN).is_none());
        assert!(data_io.in_flight.contains_key(&7));

        // The resubmission is a real one, and it succeeds.
        let completion = wait_for_completion(&mut data_io);
        assert_eq!(completion.user_data, 7);
        assert_eq!(completion.result, 512);
        assert!(completion.buffer.is_some());
        assert!(!data_io.in_flight.contains_key(&7));
    }

    #[test]
    fn uring_resubmits_a_retryable_write_and_reports_its_real_result() {
        let file = TempFile::new().unwrap().into_file();
        file.set_len(512).unwrap();
        let fd = file.as_raw_fd();
        let mut data_io = UringDataIo::new(8).unwrap();

        mark_in_flight(
            &mut data_io,
            fd,
            AsyncIoOperation::write_from_vec(0, OwnedIoBuffer::from_vec(vec![0xab; 512]), 13),
        );

        assert!(data_io.process_completion(13, -libc::EAGAIN).is_none());
        assert!(data_io.in_flight.contains_key(&13));

        let completion = wait_for_completion(&mut data_io);
        assert_eq!(completion.user_data, 13);
        assert_eq!(completion.result, 512);
        assert!(!data_io.in_flight.contains_key(&13));
    }

    #[test]
    fn uring_reports_a_retryable_metadata_completion_as_is() {
        // Metadata operations are not retained, so there is nothing to
        // resubmit and the result must reach the caller unchanged.
        let file = TempFile::new().unwrap().into_file();
        let fd = file.as_raw_fd();
        let mut data_io = UringDataIo::new(8).unwrap();

        data_io.submit_fsync(fd, 17).unwrap();

        let completion = data_io.process_completion(17, -libc::EAGAIN).unwrap();
        assert_eq!(completion.user_data, 17);
        assert_eq!(completion.result, -libc::EAGAIN);
        assert!(completion.buffer.is_none());
        assert!(!data_io.in_flight.contains_key(&17));
    }

    #[test]
    fn uring_reports_the_error_once_the_resubmission_bound_is_exhausted() {
        // An invalid descriptor keeps every resubmission from touching the
        // buffer while still exercising the full submit path.
        let fd = -1;
        let mut data_io = UringDataIo::new(8).unwrap();

        mark_in_flight(
            &mut data_io,
            fd,
            AsyncIoOperation::read_to_vec(0, OwnedIoBuffer::from_vec(vec![0; 512]), 9),
        );

        for _ in 0..MAX_RESUBMISSIONS {
            assert!(data_io.process_completion(9, -libc::EAGAIN).is_none());
            assert!(data_io.in_flight.contains_key(&9));
        }

        let completion = data_io.process_completion(9, -libc::EAGAIN).unwrap();
        assert_eq!(completion.user_data, 9);
        assert_eq!(completion.result, -libc::EAGAIN);
        assert!(!data_io.in_flight.contains_key(&9));
    }

    #[test]
    fn uring_reports_other_errors_without_resubmitting() {
        let fd = -1;
        let mut data_io = UringDataIo::new(8).unwrap();

        mark_in_flight(
            &mut data_io,
            fd,
            AsyncIoOperation::read_to_vec(0, OwnedIoBuffer::from_vec(vec![0; 512]), 11),
        );

        let completion = data_io.process_completion(11, -libc::EIO).unwrap();
        assert_eq!(completion.user_data, 11);
        assert_eq!(completion.result, -libc::EIO);
        assert!(!data_io.in_flight.contains_key(&11));
    }

    #[test]
    fn uring_rejects_duplicate_user_data_for_metadata_ops() {
        let file = TempFile::new().unwrap().into_file();
        file.set_len(512).unwrap();
        let fd = file.as_raw_fd();
        let mut data_io = UringDataIo::new(8).unwrap();

        data_io
            .submit_operation(
                fd,
                AsyncIoOperation::read_to_vec(0, OwnedIoBuffer::from_vec(vec![0; 512]), 7),
            )
            .unwrap();

        assert_eq!(
            data_io.submit_fsync(fd, 7).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(
            data_io.submit_nop(7).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );

        let completion = wait_for_completion(&mut data_io);
        assert_eq!(completion.user_data, 7);
        assert_eq!(completion.result, 512);
    }

    #[test]
    fn uring_drop_drains_in_flight_operations() {
        let file = TempFile::new().unwrap().into_file();
        file.set_len(8192).unwrap();
        let fd = file.as_raw_fd();
        let mut data_io = UringDataIo::new(8).unwrap();

        for user_data in 0..4 {
            data_io
                .submit_operation(
                    fd,
                    AsyncIoOperation::read_to_vec(
                        0,
                        OwnedIoBuffer::from_vec(vec![0; 512]),
                        user_data,
                    ),
                )
                .unwrap();
        }

        drop(data_io);
    }

    #[test]
    fn uring_queue_full_batch_completes_each_operation() {
        let file = TempFile::new().unwrap().into_file();
        let fd = file.as_raw_fd();
        let mut data_io = UringDataIo::new(1).unwrap();
        let available = {
            let (_, sq, _) = data_io.io_uring.split();
            sq.capacity() - sq.len()
        };
        let batch_len = available + 1;
        let batch: Vec<_> = (0..batch_len as u64)
            .map(|user_data| {
                AsyncIoOperation::read_to_vec(0, OwnedIoBuffer::from_vec(vec![0; 512]), user_data)
            })
            .collect();

        data_io.submit_batch(fd, batch).unwrap();

        let mut completed = Vec::new();
        while let Some(completion) = data_io.next_completion() {
            assert_eq!(completion.result, -libc::EAGAIN);
            assert!(completion.buffer.is_some());
            completed.push(completion.user_data);
        }
        completed.sort_unstable();
        assert_eq!(completed, (0..batch_len as u64).collect::<Vec<_>>());
    }
}
