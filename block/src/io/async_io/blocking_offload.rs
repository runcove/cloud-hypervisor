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

use std::collections::VecDeque;
use std::fs::File;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use log::error;
use vmm_sys_util::eventfd::EventFd;

use super::AsyncIoCompletion;
use super::common::errno_result;
use crate::sparse::{punch_hole, write_zeroes};

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

struct Job {
    op: BlockingOp,
    offset: u64,
    length: u64,
    user_data: u64,
}

type CompletionList = Arc<Mutex<VecDeque<AsyncIoCompletion>>>;

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
        .push_back(AsyncIoCompletion::new(user_data, result, None));
    // Signal after queuing so the device always finds the completion once it
    // has consumed the event.
    if let Err(e) = notifier.write(1) {
        error!("Failed signaling offloaded block request completion: {e}");
    }
}

/// Worker thread running [`BlockingOp`]s for one async I/O object.
pub(crate) struct BlockingOffload {
    run: BlockingOpFn,
    sender: Option<SyncSender<Job>>,
    completions: CompletionList,
    notifier: EventFd,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl BlockingOffload {
    /// Spawns the worker thread.
    ///
    /// The worker owns `file`, which must refer to the same disk as the
    /// backend, and signals `notifier`, the backend's completion eventfd. At
    /// most `capacity` operations wait for the worker; the device cannot have
    /// more requests in flight than its queue size, so a capacity equal to the
    /// queue size is never exceeded by a compliant driver.
    pub(crate) fn new(
        file: File,
        notifier: &EventFd,
        capacity: usize,
        run: BlockingOpFn,
    ) -> io::Result<Self> {
        let notifier = notifier.try_clone()?;
        let worker_notifier = notifier.try_clone()?;
        let (sender, receiver) = mpsc::sync_channel::<Job>(capacity);
        let completions = CompletionList::default();
        let worker_completions = Arc::clone(&completions);
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);

        // The thread inherits the seccomp filter of the thread creating the
        // async I/O object, which already allows the block device ioctls.
        let worker = thread::Builder::new()
            .name("blk_offload".to_string())
            .spawn(move || {
                let mut file = file;
                for job in receiver {
                    if worker_stop.load(Ordering::Acquire) {
                        break;
                    }
                    let result = run(&mut file, job.op, job.offset, job.length);
                    complete(&worker_completions, &worker_notifier, job.user_data, result);
                }
            })?;

        Ok(BlockingOffload {
            run,
            sender: Some(sender),
            completions,
            notifier,
            stop,
            worker: Some(worker),
        })
    }

    /// Submits `op` and reports its completion through the completion list.
    ///
    /// When the worker is saturated, the operation runs synchronously on the
    /// calling thread using `file`. This bounds memory and applies
    /// backpressure: the queue thread stops taking new descriptors until the
    /// operation is done, as it did before offloading existed.
    pub(crate) fn submit(
        &mut self,
        file: &mut File,
        op: BlockingOp,
        offset: u64,
        length: u64,
        user_data: u64,
    ) {
        let job = Job {
            op,
            offset,
            length,
            user_data,
        };
        let job = match self.sender.as_ref().map(|sender| sender.try_send(job)) {
            Some(Ok(())) => return,
            Some(Err(TrySendError::Full(job) | TrySendError::Disconnected(job))) => job,
            None => unreachable!("sender is only taken on drop"),
        };
        let result = (self.run)(file, job.op, job.offset, job.length);
        complete(&self.completions, &self.notifier, job.user_data, result);
    }

    /// Returns the next completed offloaded operation, if any.
    pub(crate) fn next_completion(&mut self) -> Option<AsyncIoCompletion> {
        self.completions.lock().unwrap().pop_front()
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
