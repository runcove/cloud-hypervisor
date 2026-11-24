// Copyright © 2021 Intel Corporation
//
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::collections::HashMap;
use std::os::fd::{AsRawFd, RawFd};
use std::{io, mem};

use io_uring::register::Restriction;
use io_uring::{IoUring, opcode, squeue, types};
use log::{Level, error, log, warn};
use vmm_sys_util::eventfd::EventFd;

use super::common::{duplicate_user_data_error, validate_batch};
use super::{AsyncIoCompletion, AsyncIoOperation, CompletionCommon, IoWorkerLimits};

// Linux UAPI constant for enabling a ring created with IORING_SETUP_R_DISABLED
const IORING_REGISTER_ENABLE_RINGS: u8 = 12;

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
    // Set once anything has been submitted to the ring. The ring is then
    // driven by some thread, whose worker pool a later cap would not reach.
    submitted: bool,
}

impl UringDataIo {
    /// Creates an io_uring queue and registers its completion eventfd.
    pub fn new(ring_depth: u32) -> io::Result<Self> {
        let completions = CompletionCommon::new();
        let io_uring = Self::build_ring(ring_depth, completions.notifier(), None)?;

        Ok(Self {
            io_uring,
            in_flight: HashMap::new(),
            completions,
            needs_submit_retry: false,
            submitted: false,
        })
    }

    /// Creates a ring disabled, registers its completion eventfd, the worker
    /// limits `max_workers` if given and the restrictions, then enables it.
    ///
    /// The worker limits are registered before the ring is enabled: once it
    /// is, the restrictions refuse every register op but enabling, so a ring
    /// cannot be capped later.
    fn build_ring(
        ring_depth: u32,
        notifier: &EventFd,
        max_workers: Option<[u32; 2]>,
    ) -> io::Result<IoUring> {
        let io_uring = Self::build_disabled_ring(ring_depth, notifier, max_workers)?;
        io_uring.submitter().register_restrictions(&mut [
            Restriction::register_op(IORING_REGISTER_ENABLE_RINGS),
            Restriction::sqe_op(opcode::Nop::CODE),
            Restriction::sqe_op(opcode::Readv::CODE),
            Restriction::sqe_op(opcode::Writev::CODE),
            Restriction::sqe_op(opcode::Fsync::CODE),
            // IOSQE_ASYNC is the only flag allowed: resubmit() sets it so a
            // retryable read or write is issued from an io-wq worker.
            Restriction::sqe_flags_allowed(squeue::Flags::ASYNC.bits()),
        ])?;
        io_uring.submitter().register_enable_rings()?;

        Ok(io_uring)
    }

    /// The part of `build_ring` before the restrictions: a disabled ring,
    /// which accepts no submission, with its completion eventfd and the
    /// worker limits `max_workers` if given registered. Only `build_ring`
    /// enables one outside tests, after restricting it.
    fn build_disabled_ring(
        ring_depth: u32,
        notifier: &EventFd,
        max_workers: Option<[u32; 2]>,
    ) -> io::Result<IoUring> {
        let io_uring = IoUring::builder().setup_r_disabled().build(ring_depth)?;
        io_uring
            .submitter()
            .register_eventfd(notifier.as_raw_fd())?;

        if let Some(mut max) = max_workers {
            io_uring.submitter().register_iowq_max_workers(&mut max)?;
        }

        Ok(io_uring)
    }

    /// Caps the io_uring worker threads the kernel may start for the thread
    /// that drives this ring (`IORING_REGISTER_IOWQ_MAX_WORKERS`).
    ///
    /// The kernel keeps io_uring workers per thread, not per ring: a thread
    /// has one worker pool, shared by every ring it submits to. The limits
    /// are stored on the ring, and the kernel applies them to a thread's pool
    /// when that thread first uses io_uring, if it does so on this ring. It
    /// does not apply them to a thread that used another ring first, and
    /// called from a thread that has already used io_uring, this also caps
    /// that thread's own pool.
    ///
    /// So the cap holds as configured only for a thread that has not used
    /// io_uring before this ring and drives no other ring. That is true today
    /// because each virtio-block queue gets a new thread that drives just its
    /// own ring. This must be called before that thread submits anything.
    ///
    /// The bounded limit is never set above the ring's size: a ring never has
    /// more requests in flight than it has entries.
    ///
    /// The ring's restrictions refuse this registration once the ring is
    /// enabled, so the ring is replaced by a new one, with the same size and
    /// completion eventfd, that is capped before it is enabled. It is refused
    /// once anything has been submitted to the ring: a replaced ring would
    /// lose requests in flight, and a cap set after the driving thread has
    /// used io_uring would not reach that thread's workers. If the kernel
    /// refuses the limits, the ring in use is kept, uncapped.
    pub fn set_max_workers(&mut self, limits: IoWorkerLimits) -> io::Result<()> {
        // A zero leaves that limit unchanged in the kernel: refuse it rather
        // than silently run uncapped.
        if limits.bounded == 0 || limits.unbounded == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("io_uring worker limits must not be zero: {limits:?}"),
            ));
        }
        if self.submitted || !self.in_flight.is_empty() || self.needs_submit_retry {
            return Err(io::Error::new(
                io::ErrorKind::ResourceBusy,
                "io_uring worker limits must be set before the ring is used",
            ));
        }
        let ring_depth = self.io_uring.params().sq_entries();
        let max = [limits.bounded.min(ring_depth), limits.unbounded];
        self.io_uring = Self::build_ring(ring_depth, self.completions.notifier(), Some(max))?;
        Ok(())
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
        self.submitted = true;
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
        self.submitted = true;

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
    use std::ffi::CString;
    use std::fs::{self, OpenOptions};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::ffi::OsStringExt;
    use std::process::{Command, Stdio};
    use std::sync::Mutex;
    use std::thread::{self, sleep};
    use std::time::Duration;
    use std::{env, io, ptr};

    use io_uring::{IoUring, opcode, squeue, types};
    use vmm_sys_util::tempdir::TempDir;
    use vmm_sys_util::tempfile::TempFile;

    use super::{MAX_RESUBMISSIONS, RetainedOperation, UringDataIo};
    use crate::async_io::{AsyncIoCompletion, AsyncIoOperation, IoWorkerLimits, OwnedIoBuffer};

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

    // Reads the limits now in force for the calling thread's io_uring
    // workers: a zero for both changes nothing and returns the current ones.
    // A data ring's restrictions refuse the registration, so it is made on a
    // ring of its own: the limits are the thread's, whichever ring asks.
    fn worker_limits_in_force() -> [u32; 2] {
        let mut max = [0, 0];
        IoUring::new(1)
            .unwrap()
            .submitter()
            .register_iowq_max_workers(&mut max)
            .unwrap();
        max
    }

    // A ring capped at `limits` if given, without the restrictions, which
    // refuse the opens and tees the worker cap tests block in a worker.
    fn unrestricted_ring(ring_depth: u32, limits: Option<IoWorkerLimits>) -> UringDataIo {
        let mut data_io = UringDataIo::new(ring_depth).unwrap();
        let max = limits.map(|l| [l.bounded, l.unbounded]);
        let io_uring =
            UringDataIo::build_disabled_ring(ring_depth, data_io.completions.notifier(), max)
                .unwrap();
        io_uring.submitter().register_enable_rings().unwrap();
        data_io.io_uring = io_uring;
        data_io
    }

    // Counts every io_uring worker in this process. The kernel names a worker
    // `iou-wrk-<pid>` after its owner's pid in the initial PID namespace, so
    // inside a PID namespace (a container) the suffix matches no tid this
    // process can see: the count cannot tell whose workers they are. It is
    // only meaningful in a process where one measurement alone starts
    // workers, which is what `peak_workers_in_child` runs it in.
    fn worker_count() -> usize {
        fs::read_dir("/proc/self/task")
            .unwrap()
            .filter_map(|task| fs::read_to_string(task.ok()?.path().join("comm")).ok())
            .filter(|comm| comm.starts_with("iou-wrk-"))
            .count()
    }

    // Creates a ring of `count` entries on the calling thread, caps it at
    // `limits` if given, and drives it from a new thread, as a disk's queue
    // is: submits `count` copies of `entry`, each forced to a kernel worker,
    // where it must block. Then calls `unblock`, keeps what it returns until
    // every request has completed, and returns the most workers seen at once.
    fn peak_workers_on_blocked_requests<G>(
        limits: Option<IoWorkerLimits>,
        count: u32,
        entry: impl Fn() -> squeue::Entry + Sync,
        unblock: impl FnOnce() -> G + Send,
    ) -> usize {
        let data_io = unrestricted_ring(count, limits);

        thread::scope(|scope| {
            scope
                .spawn(|| {
                    let mut data_io = data_io;
                    for user_data in 0..u64::from(count) {
                        let entry = entry().flags(squeue::Flags::ASYNC).user_data(user_data);
                        data_io.submit_kernel_entry(user_data, &entry).unwrap();
                    }

                    let mut peak = 0;
                    for _ in 0..25 {
                        peak = peak.max(worker_count());
                        if peak >= count as usize {
                            break;
                        }
                        sleep(Duration::from_millis(20));
                    }

                    let guard = unblock();
                    for _ in 0..count {
                        let completion = wait_for_completion(&mut data_io);
                        assert!(
                            completion.result >= 0,
                            "request failed: {}",
                            completion.result
                        );
                        if completion.result > 0 {
                            // SAFETY: only an open completes with a positive
                            // result here, a file descriptor nothing else owns.
                            unsafe { libc::close(completion.result) };
                        }
                    }
                    drop(guard);
                    peak
                })
                .join()
                .unwrap()
        })
    }

    // Opens of a FIFO that has no writer block in the worker, and count as
    // bounded work.
    fn peak_workers_on_blocked_opens(limits: Option<IoWorkerLimits>, count: u32) -> usize {
        let dir = TempDir::new().unwrap();
        let path = dir.as_path().join("fifo");
        let fifo = CString::new(path.clone().into_os_string().into_vec()).unwrap();
        // SAFETY: `fifo` is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);

        peak_workers_on_blocked_requests(
            limits,
            count,
            || {
                opcode::OpenAt::new(types::Fd(libc::AT_FDCWD), fifo.as_ptr())
                    .flags(libc::O_RDONLY | libc::O_CLOEXEC)
                    .build()
            },
            // A writer lets every open complete, blocked or still queued.
            || OpenOptions::new().write(true).open(&path).unwrap(),
        )
    }

    fn pipe() -> (OwnedFd, OwnedFd) {
        let mut fds = [0; 2];
        // SAFETY: `fds` has room for the two descriptors pipe2 writes.
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        // SAFETY: pipe2 succeeded, so both are open descriptors nothing else owns.
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    // A tee from an empty pipe blocks in the worker, and counts as unbounded
    // work (a pipe is not a regular file or block device).
    fn peak_workers_on_blocked_tees(limits: Option<IoWorkerLimits>, count: u32) -> usize {
        let (input, input_writer) = pipe();
        let (_output, output_writer) = pipe();
        let input_writer = Mutex::new(Some(input_writer));

        peak_workers_on_blocked_requests(
            limits,
            count,
            || {
                opcode::Tee::new(
                    types::Fd(input.as_raw_fd()),
                    types::Fd(output_writer.as_raw_fd()),
                    1,
                )
                .build()
            },
            // Closing the input's only writer ends every tee with 0 bytes.
            || drop(input_writer.lock().unwrap().take()),
        )
    }

    // The measurement `measure_peak_workers` makes when this is set, as
    // `<opens|tees> <count> [<bounded>:<unbounded>]`.
    const MEASUREMENT_ENV: &str = "BLOCK_TEST_IOWQ_MEASUREMENT";
    const PEAK_PREFIX: &str = "IOWQ_PEAK=";

    // Runs one measurement of `peak_workers_on_blocked_opens` ("opens") or
    // `peak_workers_on_blocked_tees` ("tees") in a new process of this test
    // executable, where no other test starts io_uring workers, and returns
    // its peak.
    fn peak_workers_in_child(kind: &str, limits: Option<IoWorkerLimits>, count: u32) -> usize {
        let measurement = match limits {
            Some(l) => format!("{kind} {count} {}:{}", l.bounded, l.unbounded),
            None => format!("{kind} {count}"),
        };
        // The test's name as libtest knows it: its path without the crate.
        let helper = format!(
            "{}::measure_peak_workers",
            module_path!().split_once("::").unwrap().1
        );
        let output = Command::new(env::current_exe().unwrap())
            .args(["--exact", &helper, "--ignored", "--nocapture"])
            .arg("--test-threads=1")
            .env(MEASUREMENT_ENV, &measurement)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "measuring {measurement} failed ({}):\n{stdout}\n{stderr}",
            output.status
        );
        // libtest may print the test's name on the same line, before it.
        stdout
            .lines()
            .find_map(|line| line.split_once(PEAK_PREFIX))
            .unwrap_or_else(|| {
                panic!("measuring {measurement} printed no peak:\n{stdout}\n{stderr}")
            })
            .1
            .trim()
            .parse()
            .unwrap()
    }

    // Not a test of its own: the measurement `peak_workers_in_child` runs in
    // a child process. Without MEASUREMENT_ENV it does nothing.
    #[test]
    #[ignore = "a measurement run by the worker cap tests in a process of its own"]
    fn measure_peak_workers() {
        let Ok(measurement) = env::var(MEASUREMENT_ENV) else {
            return;
        };
        let fields: Vec<&str> = measurement.split_whitespace().collect();
        let (kind, count, limits) = match fields[..] {
            [kind, count] => (kind, count, None),
            [kind, count, limits] => (kind, count, Some(limits.parse().unwrap())),
            _ => panic!("not a measurement: {measurement}"),
        };
        let count = count.parse().unwrap();
        let peak = match kind {
            "opens" => peak_workers_on_blocked_opens(limits, count),
            "tees" => peak_workers_on_blocked_tees(limits, count),
            _ => panic!("not a measurement: {measurement}"),
        };
        println!("{PEAK_PREFIX}{peak}");
    }

    #[test]
    fn uring_caps_bounded_workers() {
        let limits = IoWorkerLimits {
            bounded: 2,
            unbounded: 64,
        };
        let peak = peak_workers_in_child("opens", Some(limits), 32);
        assert!(peak > 0, "the test started no worker");
        assert!(peak <= 2, "{peak} bounded workers under a cap of 2");

        // Without the cap the same requests start more workers than that, so
        // the check above can see a missing cap.
        assert!(peak_workers_in_child("opens", None, 32) > 2);
    }

    #[test]
    fn uring_caps_unbounded_workers() {
        let limits = IoWorkerLimits {
            bounded: 64,
            unbounded: 2,
        };
        let peak = peak_workers_in_child("tees", Some(limits), 32);
        assert!(peak > 0, "the test started no worker");
        assert!(peak <= 2, "{peak} unbounded workers under a cap of 2");

        assert!(peak_workers_in_child("tees", None, 32) > 2);
    }

    #[test]
    fn uring_applies_limits_to_the_thread_that_drives_the_ring() {
        // Capped on this thread, as at device activation; the bounded limit
        // is clamped to the ring's 8 entries.
        let mut data_io = UringDataIo::new(8).unwrap();
        data_io.set_max_workers(IoWorkerLimits::DEFAULT).unwrap();

        let in_force = thread::spawn(move || {
            // The kernel applies the limits when this thread first submits.
            data_io.submit_nop(1).unwrap();
            wait_for_completion(&mut data_io);
            worker_limits_in_force()
        })
        .join()
        .unwrap();
        assert_eq!(in_force, [8, 4]);
    }

    #[test]
    fn uring_caps_a_restricted_ring_larger_than_the_bounded_limit() {
        // The production path: `set_max_workers` on a restricted ring with
        // more entries than the bounded limit, so the limit itself, not the
        // ring's size, is what must reach the kernel.
        let mut data_io = UringDataIo::new(64).unwrap();
        data_io
            .set_max_workers(IoWorkerLimits {
                bounded: 3,
                unbounded: 4,
            })
            .unwrap();

        let in_force = thread::spawn(move || {
            data_io.submit_nop(1).unwrap();
            wait_for_completion(&mut data_io);
            assert_restricted(&mut data_io);
            worker_limits_in_force()
        })
        .join()
        .unwrap();
        assert_eq!(in_force, [3, 4]);
    }

    #[test]
    fn uring_refuses_zero_limits() {
        let mut data_io = UringDataIo::new(8).unwrap();
        for limits in [
            IoWorkerLimits {
                bounded: 0,
                unbounded: 4,
            },
            IoWorkerLimits {
                bounded: 16,
                unbounded: 0,
            },
        ] {
            let e = data_io.set_max_workers(limits).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn uring_reports_limits_the_kernel_refuses() {
        // The kernel refuses a limit above INT_MAX with EINVAL, as a kernel
        // without IORING_REGISTER_IOWQ_MAX_WORKERS refuses every call.
        let mut data_io = UringDataIo::new(8).unwrap();
        let e = data_io
            .set_max_workers(IoWorkerLimits {
                bounded: 16,
                unbounded: u32::MAX,
            })
            .unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::EINVAL));

        // The ring in use is kept: it still works, and is still restricted.
        data_io.submit_nop(1).unwrap();
        assert_eq!(wait_for_completion(&mut data_io).result, 0);
        assert_restricted(&mut data_io);
    }

    // The ring refuses a registration change, a worker cap and a socket
    // operation, as the restrictions `UringDataIo::new` registers make it.
    // The refused worker cap is why `build_ring` registers the cap before it
    // restricts and enables the ring.
    fn assert_restricted(data_io: &mut UringDataIo) {
        assert_eq!(
            data_io
                .io_uring
                .submitter()
                .register_eventfd(data_io.notifier().as_raw_fd())
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EACCES)
        );
        let mut max = [1, 1];
        assert_eq!(
            data_io
                .io_uring
                .submitter()
                .register_iowq_max_workers(&mut max)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EACCES)
        );
        let socket = opcode::Socket::new(libc::AF_UNIX, libc::SOCK_STREAM, 0)
            .build()
            .user_data(u64::MAX);
        data_io.submit_kernel_entry(u64::MAX, &socket).unwrap();
        let completion = wait_for_completion(data_io);
        if completion.result >= 0 {
            // SAFETY: IORING_OP_SOCKET returned a new owned descriptor.
            drop(unsafe { OwnedFd::from_raw_fd(completion.result) });
        }
        assert_eq!(completion.result, -libc::EACCES);
    }

    #[test]
    fn uring_capped_ring_is_restricted_and_signals_the_same_eventfd() {
        // The cap replaces the ring with one capped before it is enabled
        // (v55 restricts every ring, and the restrictions refuse the cap's
        // registration once the ring is enabled). The new ring keeps the
        // restrictions and the completion eventfd callers already wait on.
        let mut data_io = UringDataIo::new(8).unwrap();
        let notifier = data_io.notifier().as_raw_fd();
        data_io.set_max_workers(IoWorkerLimits::DEFAULT).unwrap();
        assert_eq!(data_io.notifier().as_raw_fd(), notifier);

        data_io.submit_nop(1).unwrap();
        for _ in 0..1000 {
            let mut fds = [libc::pollfd {
                fd: notifier,
                events: libc::POLLIN,
                revents: 0,
            }];
            // SAFETY: `fds` is one valid pollfd.
            if unsafe { libc::poll(fds.as_mut_ptr(), 1, 1) } == 1 {
                break;
            }
        }
        assert!(data_io.notifier().read().unwrap() > 0);
        assert_eq!(wait_for_completion(&mut data_io).result, 0);
        assert_restricted(&mut data_io);
    }

    #[test]
    fn uring_refuses_limits_once_the_ring_is_in_use() {
        // Replacing a ring with requests in flight would lose them.
        let mut data_io = UringDataIo::new(8).unwrap();
        data_io.submit_nop(1).unwrap();
        let e = data_io
            .set_max_workers(IoWorkerLimits::DEFAULT)
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::ResourceBusy);
        assert_eq!(wait_for_completion(&mut data_io).result, 0);

        // Drained, the ring has still been used: its driving thread's
        // workers would not take a cap set now.
        assert!(data_io.in_flight.is_empty());
        let e = data_io
            .set_max_workers(IoWorkerLimits::DEFAULT)
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::ResourceBusy);
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
    fn uring_rejects_socket_operations() {
        let mut data_io = UringDataIo::new(8).unwrap();
        let socket = opcode::Socket::new(libc::AF_UNIX, libc::SOCK_STREAM, 0)
            .build()
            .user_data(1);
        data_io.submit_kernel_entry(1, &socket).unwrap();
        let completion = wait_for_completion(&mut data_io);
        if completion.result >= 0 {
            // SAFETY: IORING_OP_SOCKET returned a new owned descriptor.
            drop(unsafe { OwnedFd::from_raw_fd(completion.result) });
        }
        assert_eq!(completion.result, -libc::EACCES);

        let connect = opcode::Connect::new(types::Fd(-1), ptr::null(), 0)
            .build()
            .user_data(2);
        data_io.submit_kernel_entry(2, &connect).unwrap();
        assert_eq!(wait_for_completion(&mut data_io).result, -libc::EACCES);
    }

    #[test]
    fn uring_rejects_sqe_flags() {
        let mut data_io = UringDataIo::new(8).unwrap();
        let nop = opcode::Nop::new()
            .build()
            .flags(squeue::Flags::IO_DRAIN)
            .user_data(1);
        data_io.submit_kernel_entry(1, &nop).unwrap();
        assert_eq!(wait_for_completion(&mut data_io).result, -libc::EACCES);

        data_io.submit_nop(2).unwrap();
        assert_eq!(wait_for_completion(&mut data_io).result, 0);
    }

    #[test]
    fn uring_allows_the_async_flag_a_resubmission_sets() {
        let mut data_io = UringDataIo::new(8).unwrap();
        let nop = opcode::Nop::new()
            .build()
            .flags(squeue::Flags::ASYNC)
            .user_data(1);
        data_io.submit_kernel_entry(1, &nop).unwrap();
        assert_eq!(wait_for_completion(&mut data_io).result, 0);
    }

    #[test]
    fn uring_rejects_registration_changes() {
        let data_io = UringDataIo::new(8).unwrap();
        assert_eq!(
            data_io
                .io_uring
                .submitter()
                .register_eventfd(data_io.notifier().as_raw_fd())
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EACCES)
        );
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
