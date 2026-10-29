// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

//! Runs blocking discard and write zeroes requests off the queue thread.
//!
//! On block devices, discard and write zeroes are the `BLKDISCARD` and
//! `BLKZEROOUT` ioctls, which only return once the device has processed the
//! whole range. Linux AIO has no command for them and io_uring only gained an
//! asynchronous discard (`BLOCK_URING_CMD_DISCARD`) in Linux 6.12, with no
//! write zeroes counterpart, so issuing them from the virtio queue thread
//! stalls every other request on that queue for the device's discard latency. A slow
//! backend (thin provisioning, network block devices) can then starve reads
//! and writes behind a run of discards.
//!
//! [`BlockingOffload`] runs these requests on one worker thread per async I/O
//! object and posts their completions through the backend's completion
//! eventfd, so the device completes them like any other asynchronous request.
//! Each request stays in the device's in-flight list until its completion is
//! consumed, so pause and snapshot wait for it as they do for io_uring and AIO
//! requests.
//!
//! At most [`OFFLOAD_DEPTH`] operations are accepted in flight per worker.
//! The device bounds them further, across all of its queues, so that a pause,
//! which stops taking new requests and waits for the ones in flight, waits
//! for at most `OFFLOAD_DEPTH` operations whatever the number of queues.
//!
//! If the worker cannot be spawned, creating the async I/O object fails:
//! running the operations inline instead would bring back the stall.

use std::collections::VecDeque;
use std::fs::File;
use std::io;
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use log::{error, warn};
use vmm_sys_util::eventfd::EventFd;

use super::common::errno_result;
use super::{AsyncIoCompletion, WorkerThreadInit};
use crate::sparse::{punch_hole, write_zeroes};

/// Maximum number of offloaded operations in flight, per async I/O object
/// and, as the device bounds them, per device.
///
/// The worker runs one operation at a time, so a depth above one only keeps
/// the next operation queued for the worker while the device consumes the
/// previous completion. Beyond that, the depth bounds the time a pause waits
/// (up to `OFFLOAD_DEPTH` times the device's discard latency, against the
/// device's 30 s drain timeout): 4 keeps a pause under the timeout for
/// operations of up to 7 s each.
pub const OFFLOAD_DEPTH: usize = 4;

/// A blocking operation that can be offloaded.
#[derive(Clone, Copy, Debug)]
pub(crate) enum BlockingOp {
    PunchHole,
    WriteZeroes,
}

/// Executes a [`BlockingOp`] over `[offset, offset + length)` of a file.
pub(crate) type BlockingOpFn = fn(&mut File, BlockingOp, u64, u64) -> io::Result<()>;

/// Executes a [`BlockingOp`] on a block device.
pub(crate) fn block_device_op(
    file: &mut File,
    op: BlockingOp,
    offset: u64,
    length: u64,
) -> io::Result<()> {
    match op {
        BlockingOp::PunchHole => punch_hole(file, true, offset, length),
        BlockingOp::WriteZeroes => write_zeroes(file, true, offset, length),
    }
}

/// Returns the function to offload discard and write zeroes with, if the
/// disk is a block device.
pub(crate) fn offload_fn(is_block_device: bool) -> Option<BlockingOpFn> {
    is_block_device.then_some(block_device_op as BlockingOpFn)
}

/// Spawns a worker running `run` on a clone of `file`, if `run` is set.
///
/// Fails rather than returning no worker when it cannot be spawned, so the
/// operations never fall back to running on the queue thread.
pub(crate) fn spawn_offload(
    file: &File,
    notifier: &EventFd,
    run: Option<BlockingOpFn>,
) -> io::Result<Option<BlockingOffload>> {
    run.map(|run| BlockingOffload::new(file.try_clone()?, notifier, OFFLOAD_DEPTH, run))
        .transpose()
}

#[cfg(test)]
use std::cell::Cell;

#[cfg(test)]
thread_local! {
    static FAIL_NEXT_SPAWN: Cell<bool> = const { Cell::new(false) };
}

/// Makes the next [`BlockingOffload::new`] on this thread fail.
#[cfg(test)]
pub(crate) fn fail_next_spawn() {
    FAIL_NEXT_SPAWN.with(|fail| fail.set(true));
}

struct Job {
    op: BlockingOp,
    offset: u64,
    length: u64,
    user_data: u64,
}

enum Message {
    Init(WorkerThreadInit),
    Job(Job),
}

type CompletionList = Arc<Mutex<VecDeque<AsyncIoCompletion>>>;

fn eio() -> io::Error {
    io::Error::from_raw_os_error(libc::EIO)
}

fn complete(
    completions: &CompletionList,
    notifier: &EventFd,
    user_data: u64,
    result: io::Result<()>,
) {
    let result = match result {
        Ok(()) => 0,
        Err(e) => errno_result(&e),
    };
    completions
        .lock()
        .unwrap()
        .push_back(AsyncIoCompletion::from_offload(user_data, result));
    // Signal after queuing so the device always finds the completion once it
    // has consumed the event.
    if let Err(e) = notifier.write(1) {
        error!("Failed signaling offloaded block request completion: {e}");
    }
}

fn worker_loop(
    mut file: File,
    receiver: mpsc::Receiver<Message>,
    run: BlockingOpFn,
    completions: &CompletionList,
    notifier: &EventFd,
    stop: &AtomicBool,
) {
    // Set when the thread init failed: operations then fail rather than run
    // without the restrictions the init was meant to apply.
    let mut failed = false;
    for message in receiver {
        let job = match message {
            Message::Init(init) => {
                if let Err(e) = init() {
                    error!("Failed to initialize block offload worker: {e}");
                    failed = true;
                }
                continue;
            }
            Message::Job(job) => job,
        };
        if stop.load(Ordering::Acquire) {
            break;
        }
        let result = if failed {
            Err(eio())
        } else {
            panic::catch_unwind(AssertUnwindSafe(|| {
                run(&mut file, job.op, job.offset, job.length)
            }))
            .unwrap_or_else(|_| {
                error!("Offloaded block {:?} request panicked", job.op);
                Err(eio())
            })
        };
        complete(completions, notifier, job.user_data, result);
    }
}

/// Worker thread running [`BlockingOp`]s for one async I/O object.
pub(crate) struct BlockingOffload {
    sender: Option<SyncSender<Message>>,
    completions: CompletionList,
    notifier: EventFd,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    // Operations submitted whose completion has not been returned yet.
    in_flight: usize,
    depth: usize,
}

impl BlockingOffload {
    /// Spawns the worker thread.
    ///
    /// The worker owns `file`, which must refer to the same disk as the
    /// backend, and signals `notifier`, the backend's completion eventfd. At
    /// most `depth` operations are accepted in flight; see [`Self::submit`].
    pub(crate) fn new(
        file: File,
        notifier: &EventFd,
        depth: usize,
        run: BlockingOpFn,
    ) -> io::Result<Self> {
        #[cfg(test)]
        if FAIL_NEXT_SPAWN.with(|fail| fail.replace(false)) {
            return Err(io::Error::other("injected spawn failure"));
        }
        let notifier = notifier.try_clone()?;
        let worker_notifier = notifier.try_clone()?;
        // Room for every operation in flight and the thread init.
        let (sender, receiver) = mpsc::sync_channel::<Message>(depth + 1);
        let completions = CompletionList::default();
        let worker_completions = Arc::clone(&completions);
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);

        // Until set_thread_init() is called, the thread runs with the seccomp
        // filter of the thread creating the async I/O object.
        let worker = thread::Builder::new()
            .name("blk_offload".to_string())
            .spawn(move || {
                worker_loop(
                    file,
                    receiver,
                    run,
                    &worker_completions,
                    &worker_notifier,
                    &worker_stop,
                );
            })?;

        Ok(BlockingOffload {
            sender: Some(sender),
            completions,
            notifier,
            stop,
            worker: Some(worker),
            in_flight: 0,
            depth,
        })
    }

    /// Has the worker run `init` before any operation submitted after this
    /// call, for instance to apply a seccomp filter. If `init` fails, the
    /// worker fails every operation with `EIO`.
    pub(crate) fn set_thread_init(&mut self, init: WorkerThreadInit) {
        let sent = self
            .sender
            .as_ref()
            .map(|sender| sender.try_send(Message::Init(init)));
        if !matches!(sent, Some(Ok(()))) {
            error!("Failed to pass the thread init to the block offload worker");
        }
    }

    /// Returns whether another operation can be submitted.
    #[cfg(test)]
    fn has_capacity(&self) -> bool {
        self.in_flight < self.depth
    }

    /// Submits `op` and reports its completion through the completion list.
    ///
    /// If the worker is full, because the caller submitted more than `depth`
    /// operations whose completion it has not taken, or gone, the operation
    /// is not run and completes with `EIO`.
    pub(crate) fn submit(&mut self, op: BlockingOp, offset: u64, length: u64, user_data: u64) {
        let job = Job {
            op,
            offset,
            length,
            user_data,
        };
        let full = self.in_flight >= self.depth;
        self.in_flight += 1;
        let sent = match &self.sender {
            Some(_) if full => Err(TrySendError::Full(Message::Job(job))),
            Some(sender) => sender.try_send(Message::Job(job)),
            None => unreachable!("sender is only taken on drop"),
        };
        match sent {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                warn!("Block offload worker full, failing {op:?} request");
                complete(&self.completions, &self.notifier, user_data, Err(eio()));
            }
            Err(TrySendError::Disconnected(_)) => {
                error!("Block offload worker gone, failing {op:?} request");
                complete(&self.completions, &self.notifier, user_data, Err(eio()));
            }
        }
    }

    /// Returns the next completed offloaded operation, if any.
    pub(crate) fn next_completion(&mut self) -> Option<AsyncIoCompletion> {
        let completion = self.completions.lock().unwrap().pop_front();
        if completion.is_some() {
            self.in_flight = self.in_flight.saturating_sub(1);
        }
        completion
    }
}

impl Drop for BlockingOffload {
    fn drop(&mut self) {
        // Skip queued operations; only wait for the one in progress, if any.
        self.stop.store(true, Ordering::Release);
        self.sender.take();
        if let Some(worker) = self.worker.take()
            && worker.join().is_err()
        {
            error!("Block offload worker thread panicked");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;
    use std::time::{Duration, Instant};

    use vmm_sys_util::eventfd::EFD_NONBLOCK;
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::sparse::discard_result;

    const SLOW: Duration = Duration::from_millis(300);

    fn temp_file() -> File {
        TempFile::new().unwrap().into_file()
    }

    fn offload(depth: usize, run: BlockingOpFn) -> (BlockingOffload, EventFd) {
        let notifier = EventFd::new(EFD_NONBLOCK).unwrap();
        let offload = BlockingOffload::new(temp_file(), &notifier, depth, run).unwrap();
        (offload, notifier)
    }

    fn wait_completion(offload: &mut BlockingOffload, timeout: Duration) -> AsyncIoCompletion {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(completion) = offload.next_completion() {
                return completion;
            }
            assert!(
                Instant::now() < deadline,
                "Timed out waiting for completion"
            );
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn enospc(_: &mut File, _: BlockingOp, _: u64, _: u64) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::ENOSPC))
    }

    fn other_error(_: &mut File, _: BlockingOp, _: u64, _: u64) -> io::Result<()> {
        Err(io::Error::other("no errno"))
    }

    fn unsupported_discard(_: &mut File, _: BlockingOp, _: u64, _: u64) -> io::Result<()> {
        discard_result(Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP)))
    }

    fn panics(_: &mut File, _: BlockingOp, _: u64, _: u64) -> io::Result<()> {
        panic!("offloaded operation panicked");
    }

    fn slow(_: &mut File, _: BlockingOp, _: u64, _: u64) -> io::Result<()> {
        thread::sleep(SLOW);
        Ok(())
    }

    static RUNS: AtomicUsize = AtomicUsize::new(0);

    fn counting_slow(_: &mut File, _: BlockingOp, _: u64, _: u64) -> io::Result<()> {
        RUNS.fetch_add(1, Ordering::SeqCst);
        thread::sleep(SLOW);
        Ok(())
    }

    #[test]
    fn offload_only_for_block_devices() {
        assert!(offload_fn(true).is_some());
        assert!(offload_fn(false).is_none());
    }

    #[test]
    fn spawn_offload_fails_instead_of_falling_back() {
        let notifier = EventFd::new(EFD_NONBLOCK).unwrap();
        let file = temp_file();
        assert!(spawn_offload(&file, &notifier, None).unwrap().is_none());
        assert!(
            spawn_offload(&file, &notifier, Some(slow))
                .unwrap()
                .is_some()
        );
        fail_next_spawn();
        assert!(spawn_offload(&file, &notifier, Some(slow)).is_err());
    }

    #[test]
    fn errors_reach_the_completion() {
        for (run, expected) in [
            (enospc as BlockingOpFn, -libc::ENOSPC),
            (other_error, -libc::EIO),
            (unsupported_discard, 0),
            // BLKDISCARD on a regular file fails with ENOTTY.
            (block_device_op, -libc::ENOTTY),
        ] {
            let (mut offload, notifier) = offload(OFFLOAD_DEPTH, run);
            offload.submit(BlockingOp::PunchHole, 0, 4096, 7);
            let completion = wait_completion(&mut offload, Duration::from_secs(5));
            assert_eq!((completion.user_data, completion.result), (7, expected));
            assert_eq!(notifier.read().unwrap(), 1);
        }
    }

    #[test]
    fn panic_completes_with_eio_and_worker_keeps_running() {
        let (mut offload, _notifier) = offload(OFFLOAD_DEPTH, panics);
        offload.submit(BlockingOp::PunchHole, 0, 4096, 1);
        offload.submit(BlockingOp::WriteZeroes, 0, 4096, 2);
        for user_data in [1, 2] {
            let completion = wait_completion(&mut offload, Duration::from_secs(5));
            assert_eq!(
                (completion.user_data, completion.result),
                (user_data, -libc::EIO)
            );
        }
        assert!(offload.has_capacity());
    }

    #[test]
    fn failed_thread_init_fails_requests() {
        let (mut offload, _notifier) = offload(OFFLOAD_DEPTH, slow);
        offload.set_thread_init(Box::new(|| Err(io::Error::other("init failed"))));
        offload.submit(BlockingOp::PunchHole, 0, 4096, 1);
        let start = Instant::now();
        let completion = wait_completion(&mut offload, Duration::from_secs(5));
        assert_eq!((completion.user_data, completion.result), (1, -libc::EIO));
        assert!(start.elapsed() < SLOW, "Operation ran after a failed init");
    }

    #[test]
    fn thread_init_runs_on_the_worker_before_operations() {
        let (mut offload, _notifier) = offload(OFFLOAD_DEPTH, slow);
        let ran_on = Arc::new(Mutex::new(None));
        let ran_on_worker = Arc::clone(&ran_on);
        offload.set_thread_init(Box::new(move || {
            *ran_on_worker.lock().unwrap() = thread::current().name().map(str::to_owned);
            Ok(())
        }));
        offload.submit(BlockingOp::PunchHole, 0, 4096, 1);
        let completion = wait_completion(&mut offload, Duration::from_secs(5));
        assert_eq!(completion.result, 0);
        assert_eq!(ran_on.lock().unwrap().as_deref(), Some("blk_offload"));
    }

    #[test]
    fn capacity_is_bounded_by_depth() {
        let (mut offload, _notifier) = offload(2, slow);
        assert!(offload.has_capacity());
        offload.submit(BlockingOp::PunchHole, 0, 4096, 1);
        assert!(offload.has_capacity());
        offload.submit(BlockingOp::PunchHole, 0, 4096, 2);
        assert!(!offload.has_capacity());
        // Capacity comes back only once a completion has been returned.
        wait_completion(&mut offload, Duration::from_secs(5));
        assert!(offload.has_capacity());
    }

    #[test]
    fn full_worker_fails_request_instead_of_running_it() {
        // Depth 1: with one job in flight, a second submission is refused.
        let (mut offload, _notifier) = offload(1, slow);
        offload.submit(BlockingOp::PunchHole, 0, 4096, 1);
        let start = Instant::now();
        offload.submit(BlockingOp::PunchHole, 0, 4096, 2);
        assert!(
            start.elapsed() < SLOW / 4,
            "Submission ran the operation inline"
        );
        let completion = wait_completion(&mut offload, Duration::from_secs(5));
        assert_eq!((completion.user_data, completion.result), (2, -libc::EIO));
        assert!(
            start.elapsed() < SLOW / 2,
            "Refused submission waited for the one in flight"
        );
    }

    #[test]
    fn disconnected_worker_fails_request() {
        let (mut offload, _notifier) = offload(OFFLOAD_DEPTH, slow);
        // Stop the worker as if it had died.
        offload.stop.store(true, Ordering::Release);
        offload.submit(BlockingOp::PunchHole, 0, 4096, 1);
        offload.worker.take().unwrap().join().unwrap();
        // Drain the completion of the skipped job: there is none.
        assert!(offload.next_completion().is_none());
        let start = Instant::now();
        offload.submit(BlockingOp::WriteZeroes, 0, 4096, 2);
        assert!(
            start.elapsed() < SLOW / 4,
            "Submission ran the operation inline"
        );
        let completion = wait_completion(&mut offload, Duration::from_secs(5));
        assert_eq!((completion.user_data, completion.result), (2, -libc::EIO));
    }

    #[test]
    fn drop_skips_queued_operations() {
        RUNS.store(0, Ordering::SeqCst);
        let (mut offload, _notifier) = offload(OFFLOAD_DEPTH, counting_slow);
        for user_data in 0..OFFLOAD_DEPTH as u64 {
            offload.submit(BlockingOp::PunchHole, 0, 4096, user_data);
        }
        // Let the worker start the first operation.
        thread::sleep(SLOW / 4);
        let start = Instant::now();
        drop(offload);
        let elapsed = start.elapsed();
        assert!(
            elapsed < SLOW,
            "Drop waited {elapsed:?} for queued operations"
        );
        assert_eq!(RUNS.load(Ordering::SeqCst), 1);
    }
}
