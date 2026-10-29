// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2020 Intel Corporation
//
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::cmp::max;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::num::Wrapping;
use std::ops::Deref;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};
use std::{io, mem, result, thread};

use anyhow::anyhow;
use block::async_io::{AsyncIo, AsyncIoCompletion, AsyncIoError, OFFLOAD_DEPTH};
use block::disk_file::AsyncFullDiskFile;
use block::error::BlockError;
use block::fcntl::{LockError, LockGranularity, LockGranularityChoice, LockType, get_lock_state};
use block::{
    ExecuteAsync, ExecuteError, MAX_DISCARD_WRITE_ZEROES_SEG, Request, RequestType,
    VirtioBlockConfig, build_serial, fcntl,
};
use event_monitor::event;
use log::{debug, error, info, warn};
use rate_limiter::TokenType;
use rate_limiter::group::{RateLimiterGroup, RateLimiterGroupHandle};
use seccompiler::{SeccompAction, apply_filter};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use virtio_bindings::virtio_blk::*;
use virtio_bindings::virtio_config::*;
use virtio_bindings::virtio_ring::{VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC};
use virtio_queue::{Queue, QueueOwnedT, QueueT};
use vm_memory::{ByteValued, Bytes, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryError};
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};
use vm_virtio::AccessPlatform;
use vmm_sys_util::eventfd::EventFd;

use super::{
    ActivateError, ActivateResult, EPOLL_HELPER_EVENT_LAST, EpollHelper, EpollHelperError,
    EpollHelperHandler, Error as DeviceError, VirtioCommon, VirtioDevice, VirtioDeviceType,
    VirtioInterruptType,
};
use crate::device::ActivationContext;
use crate::seccomp_filters::{Thread, get_seccomp_filter};
use crate::{GuestMemoryMmap, VirtioInterrupt};

const SECTOR_SHIFT: u8 = 9;
pub const SECTOR_SIZE: u64 = 0x01 << SECTOR_SHIFT;

// New descriptors are pending on the virtio queue.
const QUEUE_AVAIL_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 1;
// New completed tasks are pending on the completion ring.
const COMPLETION_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 2;
// New 'wake up' event from the rate limiter
const RATE_LIMITER_EVENT: u16 = EPOLL_HELPER_EVENT_LAST + 3;

// latency scale, for reduce precision loss in calculate.
const LATENCY_SCALE: u64 = 10000;

pub const MINIMUM_BLOCK_QUEUE_SIZE: u16 = 2;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to complete the request")]
    RequestCompleting(#[source] block::Error),
    #[error("Missing the expected entry in the list of requests")]
    MissingEntryRequestList,
    #[error("Failed synchronizing the file")]
    Fsync(#[source] AsyncIoError),
    #[error("Failed adding used index")]
    QueueAddUsed(#[source] virtio_queue::Error),
    #[error("Failed creating an iterator over the queue")]
    QueueIterator(#[source] virtio_queue::Error),
    #[error("Duplicated head index in the queue")]
    QueueDuplicatedHeadIndex,
    #[error("Failed to update request status")]
    RequestStatus(#[source] GuestMemoryError),
    #[error("Failed to enable notification")]
    QueueEnableNotification(#[source] virtio_queue::Error),
    #[error("Failed to get {lock_type:?} lock for disk image: {path}")]
    LockDiskImage {
        /// The underlying error.
        #[source]
        error: LockError,
        /// The requested lock type.
        lock_type: LockType,
        /// The path of the disk image.
        path: PathBuf,
    },
    #[error("Disk image size is not a multiple of {}", SECTOR_SIZE)]
    InvalidSize,
    #[error("Failed to pause worker thread")]
    Pause(#[source] MigratableError),
    #[error("Failed to resume worker thread")]
    Resume(#[source] MigratableError),
    #[error("Failed signal config interrupt")]
    ConfigChange(#[source] io::Error),
    #[error("Disk resize failed")]
    DiskResize(#[source] BlockError),
}

pub type Result<T> = result::Result<T, Error>;

// latency will be records as microseconds, average latency
// will be save as scaled value.
#[derive(Clone)]
pub struct BlockCounters {
    read_bytes: Arc<AtomicU64>,
    read_ops: Arc<AtomicU64>,
    read_latency_min: Arc<AtomicU64>,
    read_latency_max: Arc<AtomicU64>,
    read_latency_avg: Arc<AtomicU64>,
    write_bytes: Arc<AtomicU64>,
    write_ops: Arc<AtomicU64>,
    write_latency_min: Arc<AtomicU64>,
    write_latency_max: Arc<AtomicU64>,
    write_latency_avg: Arc<AtomicU64>,
}

impl Default for BlockCounters {
    fn default() -> Self {
        BlockCounters {
            read_bytes: Arc::new(AtomicU64::new(0)),
            read_ops: Arc::new(AtomicU64::new(0)),
            read_latency_min: Arc::new(AtomicU64::new(u64::MAX)),
            read_latency_max: Arc::new(AtomicU64::new(u64::MAX)),
            read_latency_avg: Arc::new(AtomicU64::new(u64::MAX)),
            write_bytes: Arc::new(AtomicU64::new(0)),
            write_ops: Arc::new(AtomicU64::new(0)),
            write_latency_min: Arc::new(AtomicU64::new(u64::MAX)),
            write_latency_max: Arc::new(AtomicU64::new(u64::MAX)),
            write_latency_avg: Arc::new(AtomicU64::new(u64::MAX)),
        }
    }
}

/// Releases one active request count when dropped.
struct ActiveRequestGuard {
    counter: Arc<AtomicUsize>,
}

impl ActiveRequestGuard {
    fn new(counter: &Arc<AtomicUsize>) -> Self {
        Self {
            counter: Arc::clone(counter),
        }
    }
}

impl Drop for ActiveRequestGuard {
    fn drop(&mut self) {
        let previous = self.counter.fetch_sub(1, Ordering::SeqCst);
        debug_assert!(previous > 0);
    }
}

/// Bounds the discard and write zeroes requests running on backend worker
/// threads across all queues of a device, so that a pause, which waits for
/// them, waits for at most `depth` of them however many queues there are.
struct OffloadBudget {
    in_flight: AtomicUsize,
    depth: usize,
    // Per queue, by position: whether the queue waits for a slot, and the
    // eventfd that makes it process its queue again.
    waiters: Vec<(AtomicBool, EventFd)>,
}

impl OffloadBudget {
    fn new(depth: usize, queue_evts: Vec<EventFd>) -> Self {
        OffloadBudget {
            in_flight: AtomicUsize::new(0),
            depth,
            waiters: queue_evts
                .into_iter()
                .map(|queue_evt| (AtomicBool::new(false), queue_evt))
                .collect(),
        }
    }

    fn take(&self) -> bool {
        let mut n = self.in_flight.load(Ordering::SeqCst);
        while n < self.depth {
            match self
                .in_flight
                .compare_exchange_weak(n, n + 1, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return true,
                Err(current) => n = current,
            }
        }
        false
    }

    /// Takes a slot for queue `queue`. Without one, the queue is woken
    /// through its eventfd once a slot is released.
    fn try_acquire(&self, queue: usize) -> bool {
        if self.take() {
            return true;
        }
        if let Some((waiting, _)) = self.waiters.get(queue) {
            waiting.store(true, Ordering::SeqCst);
        }
        // A slot released before the queue was marked waiting woke nobody.
        self.take()
    }

    fn release(&self) {
        let previous = self.in_flight.fetch_sub(1, Ordering::SeqCst);
        debug_assert!(previous > 0);
        for (waiting, queue_evt) in &self.waiters {
            if waiting.swap(false, Ordering::SeqCst)
                && let Err(e) = queue_evt.write(1)
            {
                error!("Failed to wake a block queue waiting for an offload slot: {e}");
            }
        }
    }
}

#[derive(Default)]
struct CompletionTotals {
    read_bytes: Wrapping<u64>,
    write_bytes: Wrapping<u64>,
    read_ops: Wrapping<u64>,
    write_ops: Wrapping<u64>,
}

struct BlockEpollHandler {
    queue_index: u16,
    queue: Queue,
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
    disk_image: Box<dyn AsyncIo>,
    disk_nsectors: Arc<AtomicU64>,
    interrupt_cb: Arc<dyn VirtioInterrupt>,
    serial: Box<[u8]>,
    kill_evt: EventFd,
    pause_evt: EventFd,
    writeback: Arc<AtomicBool>,
    counters: BlockCounters,
    queue_evt: EventFd,
    inflight_requests: VecDeque<(u16, Request)>,
    // Set when the backend runs discard and write zeroes on worker threads:
    // the device-wide bound on them.
    offload_budget: Option<Arc<OffloadBudget>>,
    // Discards taken off the queue while no offload slot was free, so the
    // requests behind them are not held up. Bounded by the queue size.
    parked_discards: VecDeque<(u16, Request)>,
    // The active count includes `inflight_requests` and `parked_discards`
    // plus requests in transition from the queue to inflight or inflight to
    // completion.
    active_request_count: Arc<AtomicUsize>,
    // True when draining before pause.
    draining_active_requests: Arc<AtomicBool>,
    rate_limiter: Option<RateLimiterGroupHandle>,
    access_platform: Option<Arc<dyn AccessPlatform>>,
    host_cpus: Option<Box<[usize]>>,
    acked_features: u64,
}

fn has_feature(features: u64, feature_flag: u64) -> bool {
    (features & (1u64 << feature_flag)) != 0
}

impl BlockEpollHandler {
    fn check_request(features: u64, request: &Request) -> result::Result<(), ExecuteError> {
        let request_type = request.request_type();
        if (has_feature(features, VIRTIO_BLK_F_RO.into()))
            && !(request_type == RequestType::In
                || request_type == RequestType::GetDeviceId
                || request_type == RequestType::Flush)
        {
            // For virtio spec compliance
            // "A device MUST set the status byte to VIRTIO_BLK_S_IOERR for a write request
            // if the VIRTIO_BLK_F_RO feature if offered, and MUST NOT write any data."
            warn!(
                "Rejecting block request {request_type:?}: device is read-only (VIRTIO_BLK_F_RO negotiated)"
            );
            return Err(ExecuteError::ReadOnly);
        }

        Ok(())
    }

    // A spec-compliant driver never reuses a virtqueue head_index while the
    // corresponding chain is still available (virtio 1.x §2.7.13.4).
    // Double check the guest driver is behaving.
    fn is_head_in_flight(
        inflight: &VecDeque<(u16, Request)>,
        parked: &VecDeque<(u16, Request)>,
        batch: &[(u16, Request)],
        head: u16,
    ) -> bool {
        batch.iter().any(|(h, _)| *h == head)
            || inflight.iter().any(|(h, _)| *h == head)
            || parked.iter().any(|(h, _)| *h == head)
    }

    fn process_queue_submit(&mut self) -> Result<()> {
        // Artificially bump the active counter while submitting so pause doesn't
        // race and read a zero.
        self.active_request_count.fetch_add(1, Ordering::SeqCst);
        let _active_request = ActiveRequestGuard::new(&self.active_request_count);
        // Clone the Arc so the `self.queue` mutable borrow is allowed.
        let draining_active_requests = Arc::clone(&self.draining_active_requests);
        if draining_active_requests.load(Ordering::SeqCst) {
            self.complete_parked_discards();
            return Ok(());
        }

        let queue = &mut self.queue;
        let queue_size = queue.size();
        let mut batch_requests = Vec::new();
        let mut batch_inflight_requests = Vec::new();
        let mut processed = 0;

        loop {
            // Cap a single drain at the virtqueue size. A compliant driver won't submit more that
            // queue_size, but a buggy or malicious one can keep adding as the VMM is reading.
            if processed >= queue_size {
                break;
            }
            if draining_active_requests.load(Ordering::SeqCst) {
                break;
            }
            processed += 1;
            let mut desc_chain = match queue
                .iter(self.mem.memory())
                .map_err(Error::QueueIterator)?
                .next()
            {
                Some(c) => c,
                None => break,
            };

            let head = desc_chain.head_index();
            if Self::is_head_in_flight(
                &self.inflight_requests,
                &self.parked_discards,
                &batch_inflight_requests,
                head,
            ) {
                warn!("Guest reused virtio-blk head_index {head} while the chain was used");
                return Err(Error::QueueDuplicatedHeadIndex);
            }

            let mut request = match Request::parse(&mut desc_chain, self.access_platform.as_deref())
            {
                Ok(r) => r,
                Err(e) => {
                    warn!("Failed to parse virtio-blk request at head {head}: {e}");
                    queue
                        .add_used(desc_chain.memory(), head, 0)
                        .map_err(Error::QueueAddUsed)?;
                    queue
                        .enable_notification(desc_chain.memory())
                        .map_err(Error::QueueEnableNotification)?;
                    continue;
                }
            };

            // For virtio spec compliance
            // "A device MUST set the status byte to VIRTIO_BLK_S_IOERR for a write request
            // if the VIRTIO_BLK_F_RO feature if offered, and MUST NOT write any data."
            if let Err(e) = Self::check_request(self.acked_features, &request) {
                warn!("Request check failed: {request:x?} {e:?}");
                desc_chain
                    .memory()
                    .write_obj(VIRTIO_BLK_S_IOERR, request.status_addr())
                    .map_err(Error::RequestStatus)?;

                // If no asynchronous operation has been submitted, we can
                // simply return the used descriptor.
                queue
                    .add_used(desc_chain.memory(), desc_chain.head_index(), 1)
                    .map_err(Error::QueueAddUsed)?;
                queue
                    .enable_notification(desc_chain.memory())
                    .map_err(Error::QueueEnableNotification)?;
                continue;
            }

            if let Some(rate_limiter) = &mut self.rate_limiter {
                // If limiter.consume() fails it means there is no more TokenType::Ops
                // budget and rate limiting is in effect.
                if !rate_limiter.consume(1, TokenType::Ops) {
                    // Stop processing the queue and return this descriptor chain to the
                    // avail ring, for later processing.
                    queue.go_to_previous_position();
                    break;
                }
                // Exercise the rate limiter only if this request is of data transfer type.
                if request.request_type() == RequestType::In
                    || request.request_type() == RequestType::Out
                {
                    let mut bytes = Wrapping(0);
                    for (_, data_len) in request.data_descriptors() {
                        bytes += Wrapping(*data_len as u64);
                    }

                    // If limiter.consume() fails it means there is no more TokenType::Bytes
                    // budget and rate limiting is in effect.
                    if !rate_limiter.consume(bytes.0, TokenType::Bytes) {
                        // Revert the OPS consume().
                        rate_limiter.manual_replenish(1, TokenType::Ops);
                        // Stop processing the queue and return this descriptor chain to the
                        // avail ring, for later processing.
                        queue.go_to_previous_position();
                        break;
                    }
                }
            }

            // Discard and write zeroes running on the backend's worker threads
            // each take one of the device's offload slots.
            let offload_budget = self.offload_budget.as_deref().filter(|_| {
                matches!(
                    request.request_type(),
                    RequestType::Discard | RequestType::WriteZeroes
                )
            });
            if let Some(budget) = offload_budget {
                let queue_index = usize::from(self.queue_index);
                if request.request_type() == RequestType::Discard {
                    // Without a slot, or behind discards already waiting for
                    // one, take the discard off the queue anyway and park it,
                    // so that the reads and writes behind it go on.
                    if !self.parked_discards.is_empty() || !budget.try_acquire(queue_index) {
                        let status = match request.check_discard(
                            desc_chain.memory(),
                            self.disk_nsectors.load(Ordering::SeqCst),
                        ) {
                            Ok(()) => {
                                self.parked_discards.push_back((head, request));
                                self.active_request_count.fetch_add(1, Ordering::SeqCst);
                                continue;
                            }
                            Err(e) => {
                                warn!("Request failed: {request:x?} {e:?}");
                                e.status()
                            }
                        };
                        desc_chain
                            .memory()
                            .write_obj(status, request.status_addr())
                            .map_err(Error::RequestStatus)?;
                        queue
                            .add_used(desc_chain.memory(), head, 1)
                            .map_err(Error::QueueAddUsed)?;
                        queue
                            .enable_notification(desc_chain.memory())
                            .map_err(Error::QueueEnableNotification)?;
                        continue;
                    }
                } else if !budget.try_acquire(queue_index) {
                    // Write zeroes must have run once it completes, and a
                    // pause cannot wait for an unbounded number of them, so
                    // it is not parked: leave it and the requests behind it
                    // on the queue until a slot is released, which processes
                    // the queue again.
                    if let Some(rate_limiter) = &mut self.rate_limiter {
                        rate_limiter.manual_replenish(1, TokenType::Ops);
                    }
                    queue.go_to_previous_position();
                    break;
                }
            }
            let holds_offload_slot = offload_budget.is_some();

            request.writeback = self.writeback.load(Ordering::Acquire);

            let result = request.execute_async(
                self.mem.memory().into_inner(),
                self.disk_nsectors.load(Ordering::SeqCst),
                self.disk_image.as_mut(),
                &self.serial,
                desc_chain.head_index() as u64,
            );

            if let Ok(ExecuteAsync {
                async_complete: true,
                batch_request,
            }) = result
            {
                if let Some(batch_request) = batch_request {
                    batch_requests.push(batch_request);
                    batch_inflight_requests.push((desc_chain.head_index(), request));
                } else {
                    self.inflight_requests
                        .push_back((desc_chain.head_index(), request));
                    self.active_request_count.fetch_add(1, Ordering::SeqCst);
                }
            } else {
                if holds_offload_slot && let Some(budget) = &self.offload_budget {
                    budget.release();
                }
                let status = match result {
                    Ok(_) => VIRTIO_BLK_S_OK,
                    Err(e) => {
                        warn!("Request failed: {request:x?} {e:?}");
                        e.status() as u32
                    }
                };

                desc_chain
                    .memory()
                    .write_obj(status as u8, request.status_addr())
                    .map_err(Error::RequestStatus)?;

                let len = if status == VIRTIO_BLK_S_OK
                    && request.request_type() == RequestType::GetDeviceId
                {
                    self.serial.len() as u32 + 1
                } else {
                    1
                };
                // If no asynchronous operation has been submitted, we can
                // simply return the used descriptor.
                queue
                    .add_used(desc_chain.memory(), desc_chain.head_index(), len)
                    .map_err(Error::QueueAddUsed)?;
                queue
                    .enable_notification(desc_chain.memory())
                    .map_err(Error::QueueEnableNotification)?;
            }
        }

        if !batch_requests.is_empty() {
            match self.disk_image.submit_batch_requests(batch_requests) {
                Ok(()) => {
                    let batch_len = batch_inflight_requests.len();
                    self.inflight_requests.extend(batch_inflight_requests);
                    self.active_request_count
                        .fetch_add(batch_len, Ordering::SeqCst);
                }
                Err(e) => {
                    // If batch submission fails, report VIRTIO_BLK_S_IOERR for all requests.
                    for (user_data, request) in batch_inflight_requests {
                        warn!("Request failed with batch submission: {request:x?} {e:?}");
                        let desc_index = user_data;
                        let mem = self.mem.memory();
                        mem.write_obj(VIRTIO_BLK_S_IOERR as u8, request.status_addr())
                            .map_err(Error::RequestStatus)?;
                        queue
                            .add_used(mem.deref(), desc_index, 1)
                            .map_err(Error::QueueAddUsed)?;
                        queue
                            .enable_notification(mem.deref())
                            .map_err(Error::QueueEnableNotification)?;
                    }
                }
            }
        }

        if draining_active_requests.load(Ordering::SeqCst) {
            self.complete_parked_discards();
        } else {
            self.submit_parked_discards()?;
        }

        Ok(())
    }

    /// Submits parked discards, oldest first, while offload slots are free.
    fn submit_parked_discards(&mut self) -> Result<()> {
        let Some(budget) = self.offload_budget.clone() else {
            return Ok(());
        };
        while !self.parked_discards.is_empty() && budget.try_acquire(usize::from(self.queue_index))
        {
            let (head, mut request) = self.parked_discards.pop_front().unwrap();
            let result = request.execute_async(
                self.mem.memory().into_inner(),
                self.disk_nsectors.load(Ordering::SeqCst),
                self.disk_image.as_mut(),
                &self.serial,
                u64::from(head),
            );
            if let Ok(ExecuteAsync {
                async_complete: true,
                batch_request: None,
            }) = result
            {
                // Already counted as active while parked.
                self.inflight_requests.push_back((head, request));
                continue;
            }
            budget.release();
            let _active_request = ActiveRequestGuard::new(&self.active_request_count);
            let status = match result {
                Ok(_) => VIRTIO_BLK_S_OK as u8,
                Err(e) => {
                    warn!("Request failed: {request:x?} {e:?}");
                    e.status()
                }
            };
            self.return_parked_discard(head, &request, status)?;
        }
        Ok(())
    }

    fn return_parked_discard(&mut self, head: u16, request: &Request, status: u8) -> Result<()> {
        let mem = self.mem.memory();
        mem.write_obj(status, request.status_addr())
            .map_err(Error::RequestStatus)?;
        self.queue
            .add_used(mem.deref(), head, 1)
            .map_err(Error::QueueAddUsed)?;
        self.queue
            .enable_notification(mem.deref())
            .map_err(Error::QueueEnableNotification)?;
        Ok(())
    }

    /// Completes the parked discards without running them, so that a pause
    /// waits only for the offloaded requests in flight. A discard only
    /// allows the device to deallocate the range ("the device MAY
    /// deallocate", virtio 1.2 5.2.6.2), so leaving it undone is valid.
    fn complete_parked_discards(&mut self) {
        while let Some((head, request)) = self.parked_discards.pop_front() {
            let _active_request = ActiveRequestGuard::new(&self.active_request_count);
            if let Err(e) = self.return_parked_discard(head, &request, VIRTIO_BLK_S_OK as u8) {
                warn!("Failed to complete parked discard at head {head}: {e}");
            }
        }
    }

    fn try_signal_used_queue(&mut self) -> result::Result<(), EpollHelperError> {
        if self
            .queue
            .needs_notification(self.mem.memory().deref())
            .map_err(|e| {
                EpollHelperError::HandleEvent(anyhow!("Failed to check needs_notification: {e:?}"))
            })?
        {
            self.signal_used_queue().map_err(|e| {
                EpollHelperError::HandleEvent(anyhow!("Failed to signal used queue: {e:?}"))
            })?;
        }

        Ok(())
    }

    fn process_queue_submit_and_signal(&mut self) -> result::Result<(), EpollHelperError> {
        match self.process_queue_submit() {
            Ok(()) => {}
            Err(e @ (Error::QueueIterator(_) | Error::QueueDuplicatedHeadIndex)) => {
                // Virtqueue is corrupted or guest driver is misbehaving; exit
                // the worker so spawn_worker marks the device NEEDS_RESET.
                return Err(EpollHelperError::HandleEvent(anyhow!(
                    "Failed to process queue (submit): {e}"
                )));
            }
            Err(e) => {
                // Per-request errors are logged but non-device fatal.
                warn!("Failed to process queue (submit): {e}");
            }
        }

        self.try_signal_used_queue()
    }

    #[inline]
    fn find_inflight_request(&mut self, completed_head: u16) -> Result<Request> {
        // This loop neatly handles the fast path where the completions are
        // in order (it turns into just a pop_front()) and the 1% of the time
        // (analysis during boot) where slight out of ordering has been
        // observed e.g.
        // Submissions: 1 2 3 4 5 6 7
        // Completions: 2 1 3 5 4 7 6
        // In this case find the corresponding item and swap it with the front
        // This is a O(1) operation and is prepared for the future as it it likely
        // the next completion would be for the one that was skipped which will
        // now be the new front.
        for (i, (head, _)) in self.inflight_requests.iter().enumerate() {
            if head == &completed_head {
                return Ok(self.inflight_requests.swap_remove_front(i).unwrap().1);
            }
        }

        Err(Error::MissingEntryRequestList)
    }

    fn process_queue_complete(&mut self) -> Result<()> {
        let mut totals = CompletionTotals::default();
        let mut result = Ok(());

        // Take every completion even after one fails: the event announcing
        // them has been consumed, so any left behind would wait, holding
        // their offload slots, for an unrelated completion.
        while let Some(completion) = self.disk_image.next_completed_request() {
            if let Err(e) = self.complete_request(completion, &mut totals) {
                if result.is_ok() {
                    result = Err(e);
                } else {
                    warn!("Failed to process queue (complete): {e:?}");
                }
            }
        }

        self.counters
            .write_bytes
            .fetch_add(totals.write_bytes.0, Ordering::AcqRel);
        self.counters
            .write_ops
            .fetch_add(totals.write_ops.0, Ordering::AcqRel);

        self.counters
            .read_bytes
            .fetch_add(totals.read_bytes.0, Ordering::AcqRel);
        self.counters
            .read_ops
            .fetch_add(totals.read_ops.0, Ordering::AcqRel);

        result
    }

    fn complete_request(
        &mut self,
        mut completion: AsyncIoCompletion,
        totals: &mut CompletionTotals,
    ) -> Result<()> {
        let mem = self.mem.memory();
        let result = completion.result;
        let desc_index = completion.user_data as u16;

        let mut request = self.find_inflight_request(desc_index)?;
        let _active_request = ActiveRequestGuard::new(&self.active_request_count);
        if let Some(budget) = &self.offload_budget
            && matches!(
                request.request_type(),
                RequestType::Discard | RequestType::WriteZeroes
            )
        {
            budget.release();
        }

        request
            .complete_async(&mem, &mut completion)
            .map_err(Error::RequestCompleting)?;

        let latency = request.start().elapsed().as_micros() as u64;
        let read_ops_last = self.counters.read_ops.load(Ordering::Relaxed);
        let write_ops_last = self.counters.write_ops.load(Ordering::Relaxed);
        let read_max = self.counters.read_latency_max.load(Ordering::Relaxed);
        let write_max = self.counters.write_latency_max.load(Ordering::Relaxed);
        let mut read_avg = self.counters.read_latency_avg.load(Ordering::Relaxed);
        let mut write_avg = self.counters.write_latency_avg.load(Ordering::Relaxed);
        let (status, len) = if result >= 0 {
            match request.request_type() {
                RequestType::In => {
                    for (_, data_len) in request.data_descriptors() {
                        totals.read_bytes += Wrapping(*data_len as u64);
                    }
                    totals.read_ops += Wrapping(1);
                    if latency < self.counters.read_latency_min.load(Ordering::Relaxed) {
                        self.counters
                            .read_latency_min
                            .store(latency, Ordering::Relaxed);
                    }
                    if latency > read_max || read_max == u64::MAX {
                        self.counters
                            .read_latency_max
                            .store(latency, Ordering::Relaxed);
                    }

                    // Special case the first real latency report
                    read_avg = if read_avg == u64::MAX {
                        latency * LATENCY_SCALE
                    } else {
                        // Cumulative average is guaranteed to be
                        // positive if being calculated properly
                        (read_avg as i64
                            + ((latency * LATENCY_SCALE) as i64 - read_avg as i64)
                                / (read_ops_last + totals.read_ops.0) as i64)
                            .try_into()
                            .unwrap()
                    };
                }
                RequestType::Out => {
                    if !request.writeback {
                        self.disk_image.fsync(None).map_err(Error::Fsync)?;
                    }
                    for (_, data_len) in request.data_descriptors() {
                        totals.write_bytes += Wrapping(*data_len as u64);
                    }
                    totals.write_ops += Wrapping(1);
                    if latency < self.counters.write_latency_min.load(Ordering::Relaxed) {
                        self.counters
                            .write_latency_min
                            .store(latency, Ordering::Relaxed);
                    }
                    if latency > write_max || write_max == u64::MAX {
                        self.counters
                            .write_latency_max
                            .store(latency, Ordering::Relaxed);
                    }

                    // Special case the first real latency report
                    write_avg = if write_avg == u64::MAX {
                        latency * LATENCY_SCALE
                    } else {
                        // Cumulative average is guaranteed to be
                        // positive if being calculated properly
                        (write_avg as i64
                            + ((latency * LATENCY_SCALE) as i64 - write_avg as i64)
                                / (write_ops_last + totals.write_ops.0) as i64)
                            .try_into()
                            .unwrap()
                    }
                }
                _ => {}
            }

            self.counters
                .read_latency_avg
                .store(read_avg, Ordering::Relaxed);

            self.counters
                .write_latency_avg
                .store(write_avg, Ordering::Relaxed);

            let len = if request.request_type() == RequestType::In {
                result as u32 + 1
            } else {
                1
            };
            (VIRTIO_BLK_S_OK as u8, len)
        } else {
            warn!(
                "Request failed: {:x?} {:?}",
                request,
                io::Error::from_raw_os_error(-result)
            );
            (VIRTIO_BLK_S_IOERR as u8, 1)
        };

        mem.write_obj(status, request.status_addr())
            .map_err(Error::RequestStatus)?;

        let queue = &mut self.queue;

        queue
            .add_used(mem.deref(), desc_index, len)
            .map_err(Error::QueueAddUsed)?;
        queue
            .enable_notification(mem.deref())
            .map_err(Error::QueueEnableNotification)?;

        Ok(())
    }

    fn signal_used_queue(&self) -> result::Result<(), DeviceError> {
        self.interrupt_cb
            .trigger(VirtioInterruptType::Queue(self.queue_index))
            .map_err(|e| {
                error!("Failed to signal used queue: {e:?}");
                DeviceError::FailedSignalingUsedQueue(e)
            })
    }

    fn set_queue_thread_affinity(&self) {
        // Prepare the CPU set the current queue thread is expected to run onto.
        let cpuset = self.host_cpus.as_ref().map(|host_cpus| {
            // SAFETY: all zeros is a valid pattern
            let mut cpuset: libc::cpu_set_t = unsafe { mem::zeroed() };
            // SAFETY: FFI call, trivially safe
            unsafe { libc::CPU_ZERO(&mut cpuset) };
            for host_cpu in host_cpus {
                // SAFETY: FFI call, trivially safe
                unsafe { libc::CPU_SET(*host_cpu, &mut cpuset) };
            }
            cpuset
        });

        // Schedule the thread to run on the expected CPU set
        if let Some(cpuset) = cpuset.as_ref() {
            let cpuset: *const libc::cpu_set_t = cpuset;
            // SAFETY: FFI call with correct arguments
            let ret = unsafe { libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), cpuset) };

            if ret != 0 {
                error!(
                    "Failed scheduling the virtqueue thread {} on the expected CPU set: {}",
                    self.queue_index,
                    io::Error::last_os_error()
                );
            }
        }
    }

    fn run(
        &mut self,
        paused: &AtomicBool,
        paused_sync: &Barrier,
    ) -> result::Result<(), EpollHelperError> {
        let mut helper = EpollHelper::new(&self.kill_evt, &self.pause_evt)?;
        helper.add_event(self.queue_evt.as_raw_fd(), QUEUE_AVAIL_EVENT)?;
        helper.add_event(self.disk_image.notifier().as_raw_fd(), COMPLETION_EVENT)?;
        if let Some(rate_limiter) = &self.rate_limiter {
            helper.add_event(rate_limiter.as_raw_fd(), RATE_LIMITER_EVENT)?;
        }
        self.set_queue_thread_affinity();
        helper.run(paused, paused_sync, self)?;

        Ok(())
    }
}

impl EpollHelperHandler for BlockEpollHandler {
    fn handle_event(
        &mut self,
        _helper: &mut EpollHelper,
        event: &epoll::Event,
    ) -> result::Result<(), EpollHelperError> {
        let ev_type = event.data as u16;
        match ev_type {
            QUEUE_AVAIL_EVENT => {
                self.queue_evt.read().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!("Failed to get queue event: {e:?}"))
                })?;

                let rate_limit_reached = self.rate_limiter.as_ref().is_some_and(|r| r.is_blocked());

                // Process the queue only when the rate limit is not reached,
                // or to complete parked discards for a pause.
                if !rate_limit_reached || self.draining_active_requests.load(Ordering::SeqCst) {
                    self.process_queue_submit_and_signal()?;
                }
            }
            COMPLETION_EVENT => {
                self.disk_image.notifier().read().map_err(|e| {
                    EpollHelperError::HandleEvent(anyhow!("Failed to get queue event: {e:?}"))
                })?;

                if let Err(e) = self.process_queue_complete() {
                    warn!("Failed to process queue (complete): {e:?}");
                }

                self.try_signal_used_queue()?;

                let rate_limit_reached = self.rate_limiter.as_ref().is_some_and(|r| r.is_blocked());

                // Process the queue only when the rate limit is not reached,
                // or to complete parked discards for a pause.
                if !rate_limit_reached || self.draining_active_requests.load(Ordering::SeqCst) {
                    self.process_queue_submit_and_signal()?;
                }
            }
            RATE_LIMITER_EVENT => {
                if let Some(rate_limiter) = &mut self.rate_limiter {
                    // Upon rate limiter event, call the rate limiter handler
                    // and restart processing the queue.
                    rate_limiter.event_handler().map_err(|e| {
                        EpollHelperError::HandleEvent(anyhow!(
                            "Failed to process rate limiter event: {e:?}"
                        ))
                    })?;

                    self.process_queue_submit_and_signal()?;
                } else {
                    return Err(EpollHelperError::HandleEvent(anyhow!(
                        "Unexpected 'RATE_LIMITER_EVENT' when rate_limiter is not enabled."
                    )));
                }
            }
            _ => {
                return Err(EpollHelperError::HandleEvent(anyhow!(
                    "Unexpected event: {ev_type}"
                )));
            }
        }
        Ok(())
    }
}

/// Makes every queue process its virtqueue.
fn kick_queues(queue_evts: &[EventFd]) {
    for queue_evt in queue_evts {
        if let Err(e) = queue_evt.write(1) {
            error!("Failed to kick block queue: {e}");
        }
    }
}

/// Runs `pause` with the queues draining: they take no new request, and
/// complete their parked discards without running them.
///
/// If `pause` fails, the queues stop draining and process the requests that
/// were left on their virtqueues meanwhile.
fn drain_for_pause(
    draining_active_requests: &AtomicBool,
    queue_evts: &[EventFd],
    pause: impl FnOnce() -> result::Result<(), MigratableError>,
) -> result::Result<(), MigratableError> {
    draining_active_requests.store(true, Ordering::SeqCst);
    // Wake every queue so it completes its parked discards, which count as
    // active requests.
    kick_queues(queue_evts);
    let result = pause();
    draining_active_requests.store(false, Ordering::SeqCst);
    if result.is_err() {
        // A queue that saw a request while draining left it on the
        // virtqueue, and may not be notified of it again.
        kick_queues(queue_evts);
    }
    result
}

/// Virtio device for exposing block level read/write operations on a host file.
pub struct Block {
    common: VirtioCommon,
    id: String,
    disk_image: Box<dyn AsyncFullDiskFile>,
    disk_path: PathBuf,
    disk_nsectors: Arc<AtomicU64>,
    config: VirtioBlockConfig,
    writeback: Arc<AtomicBool>,
    counters: BlockCounters,
    seccomp_action: SeccompAction,
    rate_limiter: Option<Arc<RateLimiterGroup>>,
    exit_evt: EventFd,
    serial: Box<[u8]>,
    queue_affinity: BTreeMap<u16, Box<[usize]>>,
    lock_granularity_choice: LockGranularityChoice,
    device_status: Arc<AtomicU8>,
    active_request_count: Arc<AtomicUsize>,
    draining_active_requests: Arc<AtomicBool>,
    // Clones of the activated queues' eventfds, to make them process their
    // virtqueue.
    queue_evts: Vec<EventFd>,
}

#[derive(Serialize, Deserialize)]
pub struct BlockState {
    pub disk_path: String,
    pub disk_nsectors: u64,
    pub avail_features: u64,
    pub acked_features: u64,
    pub config: VirtioBlockConfig,
}

impl Block {
    /// Create a new virtio block device that operates on the given file.
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        disk_image: Box<dyn AsyncFullDiskFile>,
        disk_path: PathBuf,
        read_only: bool,
        access_platform_enabled: bool,
        num_queues: usize,
        queue_size: u16,
        serial: Option<String>,
        seccomp_action: SeccompAction,
        rate_limiter: Option<Arc<RateLimiterGroup>>,
        exit_evt: EventFd,
        state: Option<BlockState>,
        queue_affinity: BTreeMap<u16, Box<[usize]>>,
        sparse: bool,
        lock_granularity: LockGranularityChoice,
        guest_block_size: Option<u32>,
    ) -> io::Result<Self> {
        let (disk_nsectors, avail_features, acked_features, config, paused) =
            if let Some(state) = state {
                info!("Restoring virtio-block {id}");
                (
                    state.disk_nsectors,
                    state.avail_features,
                    state.acked_features,
                    state.config,
                    true,
                )
            } else {
                let disk_size = disk_image
                    .logical_size()
                    .map_err(|e| io::Error::other(format!("Failed getting disk size: {e}")))?;
                if disk_size % SECTOR_SIZE != 0 {
                    warn!(
                        "Disk size {disk_size} is not a multiple of sector size {SECTOR_SIZE}; \
                 the remainder will not be visible to the guest."
                    );
                }

                let mut avail_features = (1u64 << VIRTIO_F_VERSION_1)
                    | (1u64 << VIRTIO_BLK_F_FLUSH)
                    | (1u64 << VIRTIO_BLK_F_CONFIG_WCE)
                    | (1u64 << VIRTIO_BLK_F_BLK_SIZE)
                    | (1u64 << VIRTIO_BLK_F_TOPOLOGY)
                    | (1u64 << VIRTIO_BLK_F_SEG_MAX)
                    | (1u64 << VIRTIO_RING_F_EVENT_IDX)
                    | (1u64 << VIRTIO_RING_F_INDIRECT_DESC);

                // When backend supports sparse operations:
                // - Always advertise WRITE_ZEROES (safe for all drivers)
                // - Advertise DISCARD only when sparse=true, since DISCARD
                //   deallocates space via punch_hole and should require
                //   explicit user opt in.
                let mut discard_supported = false;
                if disk_image.supports_sparse_operations() {
                    avail_features |= 1u64 << VIRTIO_BLK_F_WRITE_ZEROES;
                    if sparse {
                        avail_features |= 1u64 << VIRTIO_BLK_F_DISCARD;
                        discard_supported = true;
                    }
                } else if sparse {
                    warn!("sparse=on requested but backend does not support sparse operations");
                }

                if access_platform_enabled {
                    avail_features |= 1u64 << VIRTIO_F_ACCESS_PLATFORM;
                }

                if read_only {
                    avail_features |= 1u64 << VIRTIO_BLK_F_RO;
                }

                let mut topology = disk_image.topology();
                if let Some(block_size) = guest_block_size {
                    topology = topology.with_block_size(block_size as u64);
                }
                info!("Disk topology: {topology:?}");

                let logical_block_size = if topology.logical_block_size > 512 {
                    topology.logical_block_size
                } else {
                    512
                };

                // Calculate the exponent that maps physical block to logical block
                let mut physical_block_exp = 0;
                let mut size = logical_block_size;
                while size < topology.physical_block_size {
                    physical_block_exp += 1;
                    size <<= 1;
                }

                let disk_nsectors = disk_size / SECTOR_SIZE;
                let mut config = VirtioBlockConfig {
                    capacity: disk_nsectors,
                    writeback: 1,
                    blk_size: topology.logical_block_size as u32,
                    physical_block_exp,
                    min_io_size: (topology.minimum_io_size / logical_block_size) as u16,
                    opt_io_size: (topology.optimal_io_size / logical_block_size) as u32,
                    seg_max: (queue_size - MINIMUM_BLOCK_QUEUE_SIZE) as u32,
                    ..Default::default()
                };

                if avail_features & (1u64 << VIRTIO_BLK_F_WRITE_ZEROES) != 0 {
                    config.max_write_zeroes_sectors = u32::MAX;
                    config.max_write_zeroes_seg = MAX_DISCARD_WRITE_ZEROES_SEG;
                    config.write_zeroes_may_unmap = if discard_supported { 1 } else { 0 };
                }
                if avail_features & (1u64 << VIRTIO_BLK_F_DISCARD) != 0 {
                    config.max_discard_sectors = u32::MAX;
                    config.max_discard_seg = MAX_DISCARD_WRITE_ZEROES_SEG;
                    config.discard_sector_alignment = (logical_block_size / SECTOR_SIZE) as u32;
                }

                if num_queues > 1 {
                    avail_features |= 1u64 << VIRTIO_BLK_F_MQ;
                    config.num_queues = num_queues as u16;
                }

                (disk_nsectors, avail_features, 0, config, false)
            };

        let serial = serial
            .map_or_else(|| build_serial(&disk_path), Vec::from)
            .into_boxed_slice();

        Ok(Block {
            common: VirtioCommon {
                device_type: VirtioDeviceType::Block as u32,
                avail_features,
                acked_features,
                paused_sync: Some(Arc::new(Barrier::new(num_queues + 1))),
                queue_sizes: vec![queue_size; num_queues],
                min_queues: 1,
                paused: Arc::new(AtomicBool::new(paused)),
                ..Default::default()
            },
            id,
            disk_image,
            disk_path,
            disk_nsectors: Arc::new(AtomicU64::new(disk_nsectors)),
            config,
            writeback: Arc::new(AtomicBool::new(true)),
            counters: BlockCounters::default(),
            seccomp_action,
            rate_limiter,
            exit_evt,
            serial,
            queue_affinity,
            lock_granularity_choice: lock_granularity,
            device_status: Arc::new(AtomicU8::new(0)),
            active_request_count: Arc::new(AtomicUsize::new(0)),
            draining_active_requests: Arc::new(AtomicBool::new(false)),
            queue_evts: Vec::new(),
        })
    }

    fn wait_for_active_requests(
        active_request_count: &AtomicUsize,
    ) -> result::Result<(), anyhow::Error> {
        const BLOCK_PAUSE_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);
        const BLOCK_PAUSE_FIRST_DRAIN_WARNING: Duration = Duration::from_secs(1);
        const BLOCK_PAUSE_DRAIN_WARNING_INTERVAL: Duration = Duration::from_secs(5);

        let started = Instant::now();
        let mut next_warning = BLOCK_PAUSE_FIRST_DRAIN_WARNING;

        loop {
            let active = active_request_count.load(Ordering::SeqCst);
            if active == 0 {
                return Ok(());
            }

            let elapsed = started.elapsed();
            if elapsed >= BLOCK_PAUSE_DRAIN_TIMEOUT {
                return Err(anyhow!("timed out draining block requests"));
            }

            if elapsed >= next_warning {
                warn!("pause: still waiting for {active} active block requests after {elapsed:?}");
                next_warning += BLOCK_PAUSE_DRAIN_WARNING_INTERVAL;
            }

            thread::yield_now();
        }
    }

    fn read_only(&self) -> bool {
        has_feature(self.features(), VIRTIO_BLK_F_RO.into())
    }

    /// Returns the granularity for the advisory lock for this disk.
    fn lock_granularity(&mut self) -> LockGranularity {
        match self.lock_granularity_choice {
            LockGranularityChoice::Full => LockGranularity::WholeFile,
            LockGranularityChoice::ByteRange => {
                // Byte range lock covering [0, max(logical, physical))
                // logical > physical for sparse files, physical > logical
                // for small dense files due to filesystem block rounding.
                let logical = self.disk_image.logical_size();
                let physical = self.disk_image.physical_size();
                match (logical, physical) {
                    (Ok(l), Ok(p)) => LockGranularity::ByteRange(0, max(l, p)),
                    (Ok(l), Err(_)) => LockGranularity::ByteRange(0, l),
                    (Err(_), Ok(p)) => LockGranularity::ByteRange(0, p),
                    (Err(e), Err(_)) => {
                        let fallback = LockGranularity::WholeFile;
                        warn!(
                            "Can't get disk size for id={},path={}, falling back to {:?}: error: {e}",
                            self.id,
                            self.disk_path.display(),
                            fallback
                        );
                        fallback
                    }
                }
            }
        }
    }

    /// Tries to set an advisory lock for the corresponding disk image.
    pub fn try_lock_image(&mut self) -> Result<()> {
        let lock_type = match self.read_only() {
            true => LockType::Read,
            false => LockType::Write,
        };
        let granularity = self.lock_granularity();
        debug!(
            "Attempting to acquire {lock_type:?} lock for disk image: id={},path={},granularity={granularity:?}",
            self.id,
            self.disk_path.display()
        );
        let fd = self.disk_image.fd();
        fcntl::try_acquire_lock(&fd, lock_type, granularity).map_err(|error| {
            let current_lock = get_lock_state(&fd, granularity);
            // Don't propagate the error to the outside, as it is not useful at all. Instead,
            // we try to log additional help to the user.
            if let Ok(current_lock) = current_lock {
                error!("Can't get {lock_type:?} lock for {} as there is already a {current_lock:?} lock", self.disk_path.display());
            } else {
                error!("Can't get {lock_type:?} lock for {}, but also can't determine the current lock state", self.disk_path.display());
            }
            Error::LockDiskImage {
                path: self.disk_path.clone(),
                error,
                lock_type,
            }
        })?;
        info!(
            "Acquired {lock_type:?} lock for disk image id={},path={}",
            self.id,
            self.disk_path.display()
        );
        Ok(())
    }

    /// Releases the advisory lock held for the corresponding disk image.
    pub fn unlock_image(&mut self) -> Result<()> {
        let granularity = self.lock_granularity();

        // It is very unlikely that this fails;
        // Should we remove the Result to simplify the error propagation on
        // higher levels?
        let fd = self.disk_image.fd();
        fcntl::clear_lock(&fd, granularity).map_err(|error| Error::LockDiskImage {
            path: self.disk_path.clone(),
            error,
            lock_type: LockType::Unlock,
        })
    }

    fn state(&self) -> BlockState {
        BlockState {
            disk_path: self.disk_path.to_str().unwrap().to_owned(),
            disk_nsectors: self.disk_nsectors.load(Ordering::SeqCst),
            avail_features: self.common.avail_features,
            acked_features: self.common.acked_features,
            config: self.config,
        }
    }

    /// The virtio v1.2 spec says "If VIRTIO_BLK_F_CONFIG_WCE was not
    /// negotiated but VIRTIO_BLK_F_FLUSH was, the driver SHOULD assume
    /// presence of a writeback cache." It also says "If
    /// VIRTIO_BLK_F_CONFIG_WCE is negotiated but VIRTIO_BLK_F_FLUSH is not,
    /// the device MUST initialize writeback to 0."
    fn is_writeback_enabled(&self, desired: bool) -> bool {
        let flush = self.common.feature_acked(VIRTIO_BLK_F_FLUSH.into());
        let wce = self.common.feature_acked(VIRTIO_BLK_F_CONFIG_WCE.into());
        if wce { flush && desired } else { flush }
    }

    fn set_writeback_mode(&mut self, enabled: bool) {
        self.config.writeback = enabled as u8;
        self.writeback.store(enabled, Ordering::Release);
        info!(
            "Changing cache mode to {}",
            if enabled { "writeback" } else { "writethrough" }
        );
    }

    pub fn resize(&mut self, new_size: u64) -> Result<()> {
        if !new_size.is_multiple_of(SECTOR_SIZE) {
            return Err(Error::InvalidSize);
        }

        self.disk_image
            .resize(new_size)
            .map_err(Error::DiskResize)?;

        let nsectors = new_size / SECTOR_SIZE;

        let was_paused = self.common.paused.load(Ordering::SeqCst);
        self.common.pause().map_err(Error::Pause)?;

        self.disk_nsectors.store(nsectors, Ordering::SeqCst);
        self.config.capacity = nsectors;
        self.state().disk_nsectors = nsectors;

        if !was_paused {
            self.common.resume().map_err(Error::Resume)?;
        }

        self.common
            .trigger_interrupt(VirtioInterruptType::Config)
            .map_err(Error::ConfigChange)
    }

    #[cfg(fuzzing)]
    pub fn wait_for_epoll_threads(&mut self) {
        self.common.wait_for_epoll_threads();
    }
}

impl VirtioDevice for Block {
    fn device_type(&self) -> u32 {
        self.common.device_type
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.common.queue_sizes
    }

    fn features(&self) -> u64 {
        self.common.avail_features
    }

    fn ack_features(&mut self, value: u64) {
        self.common.ack_features(value);
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        self.read_config_from_slice(self.config.as_slice(), offset, data);
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        // The "writeback" field is the only mutable field
        let writeback_offset =
            (&raw const self.config.writeback as u64) - (&raw const self.config as u64);
        if offset != writeback_offset || data.len() != size_of_val(&self.config.writeback) {
            error!(
                "Attempt to write to read-only field: offset {:x} length {}",
                offset,
                data.len()
            );
            return;
        }

        let writeback = self.is_writeback_enabled(data[0] == 1);
        self.set_writeback_mode(writeback);
    }

    fn activate(&mut self, context: ActivationContext) -> ActivateResult {
        let ActivationContext {
            mem,
            interrupt_cb,
            mut queues,
            device_status,
        } = context;
        self.device_status = device_status;
        // See if the guest didn't ack the device being read-only.
        // If so, warn and pretend it did.
        let original_acked_features = self.common.acked_features;
        self.common.acked_features |= self.common.avail_features & (1u64 << VIRTIO_BLK_F_RO);
        if original_acked_features != self.common.acked_features {
            warn!("Guest did not acknowledge that device is read-only, acting as if it did!");
        }
        self.common.activate(&queues, Arc::clone(&interrupt_cb))?;

        // Recompute the barrier size from the queues that are actually activated.
        self.common.paused_sync = Some(Arc::new(Barrier::new(queues.len() + 1)));

        let writeback = self.is_writeback_enabled(self.config.writeback == 1);
        self.set_writeback_mode(writeback);

        let event_idx = self.common.feature_acked(VIRTIO_RING_F_EVENT_IDX.into());

        let clone_queue_evts = || {
            self.common
                .queue_evts
                .iter()
                .map(|(_, queue_evt)| queue_evt.try_clone())
                .collect::<io::Result<Vec<_>>>()
                .map_err(|e| {
                    error!("Failed cloning queue EventFd: {e}");
                    ActivateError::BadActivate
                })
        };
        // One budget for all queues: a pause waits for the offloaded requests
        // of every queue.
        let offload_budget = Arc::new(OffloadBudget::new(OFFLOAD_DEPTH, clone_queue_evts()?));
        self.queue_evts = clone_queue_evts()?;

        for i in 0..queues.len() {
            let (_, mut queue, queue_evt) = queues.remove(0);
            queue.set_event_idx(event_idx);

            let queue_size = queue.size();
            let (kill_evt, pause_evt) = self.common.dup_eventfds()?;
            let queue_idx = i as u16;

            let mut disk_image =
                self.disk_image
                    .create_async_io(queue_size as u32)
                    .map_err(|e| {
                        error!("failed to create new AsyncIo: {e}");
                        ActivateError::BadActivate
                    })?;
            // Worker threads the backend spawns for this queue get the same
            // seccomp filter as the queue thread.
            let seccomp_filter = get_seccomp_filter(&self.seccomp_action, Thread::VirtioBlock)
                .map_err(ActivateError::CreateSeccompFilter)?;
            disk_image.set_worker_thread_init(Box::new(move || {
                if seccomp_filter.is_empty() {
                    return Ok(());
                }
                apply_filter(&seccomp_filter).map_err(io::Error::other)
            }));

            let offload_budget = disk_image
                .offloads_punch_hole_or_write_zeroes()
                .then(|| Arc::clone(&offload_budget));

            let mut handler = BlockEpollHandler {
                queue_index: queue_idx,
                queue,
                mem: mem.clone(),
                disk_image,
                disk_nsectors: Arc::clone(&self.disk_nsectors),
                interrupt_cb: Arc::clone(&interrupt_cb),
                serial: self.serial.clone(),
                kill_evt,
                pause_evt,
                writeback: Arc::clone(&self.writeback),
                counters: self.counters.clone(),
                queue_evt,
                // Analysis during boot shows around ~40 maximum requests
                // This gives head room for systems with slower I/O without
                // compromising the cost of the reallocation or memory overhead
                inflight_requests: VecDeque::with_capacity(64),
                offload_budget,
                parked_discards: VecDeque::new(),
                rate_limiter: self
                    .rate_limiter
                    .as_ref()
                    .map(|r| r.new_handle())
                    .transpose()
                    .unwrap(),
                access_platform: self.common.access_platform(),
                host_cpus: self.queue_affinity.get(&queue_idx).cloned(),
                acked_features: self.common.acked_features,
                active_request_count: Arc::clone(&self.active_request_count),
                draining_active_requests: Arc::clone(&self.draining_active_requests),
            };

            let paused = Arc::clone(&self.common.paused);
            let paused_sync = self.common.paused_sync.clone();

            self.common.spawn_worker(
                &format!("{}_q{}", self.id.clone(), i),
                &self.seccomp_action,
                Thread::VirtioBlock,
                &self.exit_evt,
                Arc::clone(&self.device_status),
                Arc::clone(&interrupt_cb),
                move || handler.run(&paused, paused_sync.as_ref().unwrap()),
            )?;
        }

        event!("virtio-device", "activated", "id", &self.id);

        Ok(())
    }

    fn reset(&mut self) {
        self.common.reset();
        self.queue_evts.clear();
        self.draining_active_requests.store(false, Ordering::SeqCst);
        self.active_request_count.store(0, Ordering::SeqCst);
        self.set_writeback_mode(true);
        event!("virtio-device", "reset", "id", &self.id);
    }

    fn shutdown(&mut self) {
        self.common.wait_for_epoll_threads();
    }

    fn counters(&self) -> Option<HashMap<&'static str, Wrapping<u64>>> {
        let mut counters = HashMap::new();

        let read_ops = self.counters.read_ops.load(Ordering::Acquire);
        let write_ops = self.counters.write_ops.load(Ordering::Acquire);

        counters.insert(
            "read_bytes",
            Wrapping(self.counters.read_bytes.load(Ordering::Acquire)),
        );
        counters.insert(
            "write_bytes",
            Wrapping(self.counters.write_bytes.load(Ordering::Acquire)),
        );
        counters.insert("read_ops", Wrapping(read_ops));
        counters.insert("write_ops", Wrapping(write_ops));

        // Don't publish read/write operations counters until the first operation
        if write_ops > 0 {
            counters.insert(
                "write_latency_min",
                Wrapping(self.counters.write_latency_min.load(Ordering::Acquire)),
            );
            counters.insert(
                "write_latency_max",
                Wrapping(self.counters.write_latency_max.load(Ordering::Acquire)),
            );
            counters.insert(
                "write_latency_avg",
                Wrapping(self.counters.write_latency_avg.load(Ordering::Acquire) / LATENCY_SCALE),
            );
        }
        if read_ops > 0 {
            counters.insert(
                "read_latency_min",
                Wrapping(self.counters.read_latency_min.load(Ordering::Acquire)),
            );
            counters.insert(
                "read_latency_max",
                Wrapping(self.counters.read_latency_max.load(Ordering::Acquire)),
            );
            counters.insert(
                "read_latency_avg",
                Wrapping(self.counters.read_latency_avg.load(Ordering::Acquire) / LATENCY_SCALE),
            );
        }

        Some(counters)
    }

    fn set_access_platform(&mut self, access_platform: Arc<dyn AccessPlatform>) {
        self.common.set_access_platform(access_platform);
    }

    fn access_platform(&self) -> Option<Arc<dyn AccessPlatform>> {
        self.common.access_platform()
    }
}

impl Pausable for Block {
    fn pause(&mut self) -> result::Result<(), MigratableError> {
        // Drain before parking the worker threads: the workers are what
        // complete in-flight I/O, so they must keep running until the count
        // reaches zero.
        drain_for_pause(&self.draining_active_requests, &self.queue_evts, || {
            Block::wait_for_active_requests(&self.active_request_count)
                .map_err(MigratableError::Pause)?;
            // Flush cached format metadata (e.g. qcow2 L2/refcount tables) so
            // the on-disk image is self-consistent while paused: snapshot
            // copies and migration disk-lock handoff read the file directly.
            self.disk_image.sync_metadata().map_err(|e| {
                MigratableError::Pause(anyhow::Error::new(e).context("sync disk metadata"))
            })?;
            self.common.pause()
        })
    }

    fn resume(&mut self) -> result::Result<(), MigratableError> {
        self.draining_active_requests.store(false, Ordering::SeqCst);
        self.common.resume()
    }
}

impl Snapshottable for Block {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> result::Result<Snapshot, MigratableError> {
        Snapshot::new_from_state(&self.state())
    }
}
impl Transportable for Block {}
impl Migratable for Block {
    fn notify_started_migration(&mut self) -> result::Result<(), MigratableError> {
        if let Err(e) = self.disk_image.sync_metadata() {
            warn!("Failed to flush disk {} before migration: {e}", self.id);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Result as IoResult;
    use std::panic;
    use std::sync::Mutex;
    use std::sync::mpsc::{self, Sender};

    use block::async_io::{AsyncIoOperation, AsyncIoResult};
    use block::{BLKDISCARD, BLKZEROOUT};
    use hypervisor::Vm;
    use virtio_bindings::virtio_ring::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};
    use vm_memory::GuestAddress;
    use vm_virtio::queue::testing::VirtQueue as GuestQ;
    use vmm_sys_util::eventfd::EFD_NONBLOCK;
    use vmm_sys_util::tempfile::TempFile;

    use super::*;

    struct Noop(EventFd);
    impl VirtioInterrupt for Noop {
        fn trigger(&self, _: VirtioInterruptType) -> IoResult<()> {
            Ok(())
        }
        fn set_notifier(&self, _: u32, _: Option<EventFd>, _: &dyn Vm) -> IoResult<()> {
            Ok(())
        }
    }
    impl AsyncIo for Noop {
        fn notifier(&self) -> &EventFd {
            &self.0
        }
        fn submit_data_operation(&mut self, _: AsyncIoOperation) -> AsyncIoResult<()> {
            unreachable!()
        }
        fn fsync(&mut self, _: Option<u64>) -> AsyncIoResult<()> {
            unreachable!()
        }
        fn punch_hole(&mut self, _: u64, _: u64, _: u64) -> AsyncIoResult<()> {
            unreachable!()
        }
        fn write_zeroes(&mut self, _: u64, _: u64, _: u64) -> AsyncIoResult<()> {
            unreachable!()
        }
        fn next_completed_request(&mut self) -> Option<AsyncIoCompletion> {
            None
        }
    }

    #[test]
    fn parse_failure_reclaims_head() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let vq = GuestQ::new(GuestAddress(0x1000), &mem, 4);
        vq.dtable[0].set(0x2000, 16, 0, 0);
        vq.avail.ring[0].set(0);
        vq.avail.idx.set(1);

        let evt = || EventFd::new(EFD_NONBLOCK).unwrap();
        let mut handler = BlockEpollHandler {
            queue_index: 0,
            queue: vq.create_queue(),
            mem: GuestMemoryAtomic::new(mem.clone()),
            disk_image: Box::new(Noop(evt())),
            disk_nsectors: Arc::new(AtomicU64::new(0)),
            interrupt_cb: Arc::new(Noop(evt())),
            serial: Box::default(),
            kill_evt: evt(),
            pause_evt: evt(),
            writeback: Arc::new(AtomicBool::new(false)),
            counters: BlockCounters::default(),
            queue_evt: evt(),
            inflight_requests: VecDeque::new(),
            offload_budget: None,
            parked_discards: VecDeque::new(),
            active_request_count: Arc::new(AtomicUsize::new(0)),
            draining_active_requests: Arc::new(AtomicBool::new(false)),
            rate_limiter: None,
            access_platform: None,
            host_cpus: None,
            acked_features: 0,
        };

        handler.process_queue_submit().unwrap();

        assert_eq!(vq.used.idx.get(), 1);
    }

    const SLOW_DEPTH: usize = 4;
    const SLOW_LATENCY: Duration = Duration::from_millis(200);

    /// A backend whose discards take `SLOW_LATENCY` each, one at a time on a
    /// worker thread, with at most `SLOW_DEPTH` accepted at once.
    struct SlowDiscards {
        notifier: EventFd,
        jobs: Sender<u64>,
        completions: Arc<Mutex<VecDeque<AsyncIoCompletion>>>,
        in_flight: usize,
        max_in_flight: Arc<AtomicUsize>,
    }

    impl SlowDiscards {
        fn new() -> Self {
            let notifier = EventFd::new(0).unwrap();
            let worker_notifier = notifier.try_clone().unwrap();
            let completions = Arc::new(Mutex::new(VecDeque::new()));
            let worker_completions = Arc::clone(&completions);
            let (jobs, receiver) = mpsc::channel::<u64>();
            thread::spawn(move || {
                for user_data in receiver {
                    thread::sleep(SLOW_LATENCY);
                    worker_completions
                        .lock()
                        .unwrap()
                        .push_back(AsyncIoCompletion::new(user_data, 0, None));
                    worker_notifier.write(1).unwrap();
                }
            });
            SlowDiscards {
                notifier,
                jobs,
                completions,
                in_flight: 0,
                max_in_flight: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl AsyncIo for SlowDiscards {
        fn notifier(&self) -> &EventFd {
            &self.notifier
        }
        fn submit_data_operation(&mut self, _: AsyncIoOperation) -> AsyncIoResult<()> {
            unreachable!()
        }
        fn fsync(&mut self, _: Option<u64>) -> AsyncIoResult<()> {
            unreachable!()
        }
        fn punch_hole(&mut self, _: u64, _: u64, user_data: u64) -> AsyncIoResult<()> {
            // Record rather than refuse, so a test sees how far the bound is
            // exceeded.
            self.in_flight += 1;
            self.max_in_flight
                .fetch_max(self.in_flight, Ordering::SeqCst);
            self.jobs.send(user_data).unwrap();
            Ok(())
        }
        fn write_zeroes(&mut self, _: u64, _: u64, _: u64) -> AsyncIoResult<()> {
            unreachable!()
        }
        fn offloads_punch_hole_or_write_zeroes(&self) -> bool {
            true
        }
        fn next_completed_request(&mut self) -> Option<AsyncIoCompletion> {
            let completion = self.completions.lock().unwrap().pop_front();
            if completion.is_some() {
                self.in_flight -= 1;
            }
            completion
        }
    }

    const DISCARDS: u16 = 12;

    /// Builds a handler whose queue holds `DISCARDS` discard requests.
    fn slow_discard_handler<'a>(
        mem: &'a GuestMemoryMmap,
        max_in_flight: &mut Arc<AtomicUsize>,
    ) -> (BlockEpollHandler, GuestQ<'a>) {
        let vq = GuestQ::new(GuestAddress(0x1000), mem, 64);
        for i in 0..DISCARDS {
            let base = 0x8000 + u64::from(i) * 0x100;
            // Header: type, reserved, sector.
            mem.write_obj(VIRTIO_BLK_T_DISCARD, GuestAddress(base))
                .unwrap();
            // Segment: sector 0, 8 sectors, no flags.
            mem.write_obj(8u32, GuestAddress(base + 0x28)).unwrap();
            let desc = i * 3;
            let next = VRING_DESC_F_NEXT as u16;
            vq.dtable[desc as usize].set(base, 16, next, desc + 1);
            vq.dtable[desc as usize + 1].set(base + 0x20, 16, next, desc + 2);
            vq.dtable[desc as usize + 2].set(base + 0x40, 1, VRING_DESC_F_WRITE as u16, 0);
            vq.avail.ring[i as usize].set(desc);
        }
        vq.avail.idx.set(DISCARDS);

        let disk_image = SlowDiscards::new();
        *max_in_flight = Arc::clone(&disk_image.max_in_flight);
        let evt = || EventFd::new(EFD_NONBLOCK).unwrap();
        let handler = BlockEpollHandler {
            queue_index: 0,
            queue: vq.create_queue(),
            mem: GuestMemoryAtomic::new(mem.clone()),
            disk_image: Box::new(disk_image),
            disk_nsectors: Arc::new(AtomicU64::new(1 << 20)),
            interrupt_cb: Arc::new(Noop(evt())),
            serial: Box::default(),
            kill_evt: evt(),
            pause_evt: evt(),
            writeback: Arc::new(AtomicBool::new(false)),
            counters: BlockCounters::default(),
            queue_evt: evt(),
            inflight_requests: VecDeque::new(),
            offload_budget: Some(Arc::new(OffloadBudget::new(OFFLOAD_DEPTH, Vec::new()))),
            parked_discards: VecDeque::new(),
            active_request_count: Arc::new(AtomicUsize::new(0)),
            draining_active_requests: Arc::new(AtomicBool::new(false)),
            rate_limiter: None,
            access_platform: None,
            host_cpus: None,
            acked_features: 0,
        };
        (handler, vq)
    }

    /// Waits for the backend's next completion event and handles it, as the
    /// queue thread does.
    fn handle_completion_event(handler: &mut BlockEpollHandler, helper: &mut EpollHelper) {
        // The backend's notifier is blocking: wait until it is signaled
        // without consuming the event, which handle_event() reads.
        let mut pollfd = libc::pollfd {
            fd: handler.disk_image.notifier().as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pollfd is a valid pollfd for the duration of the call.
        let ret = unsafe { libc::poll(&mut pollfd, 1, 10_000) };
        assert_eq!(ret, 1, "Timed out waiting for a completion");
        let event = epoll::Event::new(epoll::Events::EPOLLIN, u64::from(COMPLETION_EVENT));
        handler.handle_event(helper, &event).unwrap();
    }

    #[test]
    fn slow_discards_in_flight_are_bounded_by_backend() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let mut max_in_flight = Arc::default();
        let (mut handler, vq) = slow_discard_handler(&mem, &mut max_in_flight);
        let kill_evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let pause_evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let mut helper = EpollHelper::new(&kill_evt, &pause_evt).unwrap();

        handler.process_queue_submit().unwrap();
        // The discards beyond the budget are parked, off the queue.
        assert_eq!(handler.inflight_requests.len(), SLOW_DEPTH);
        assert_eq!(
            handler.parked_discards.len(),
            usize::from(DISCARDS) - SLOW_DEPTH
        );
        assert_eq!(
            handler.active_request_count.load(Ordering::SeqCst),
            usize::from(DISCARDS)
        );

        // Each completion lets the queue thread take the next discard.
        while vq.used.idx.get() < DISCARDS {
            handle_completion_event(&mut handler, &mut helper);
        }
        assert_eq!(max_in_flight.load(Ordering::SeqCst), SLOW_DEPTH);
        assert_eq!(handler.active_request_count.load(Ordering::SeqCst), 0);
        for i in 0..DISCARDS {
            let status: u8 = mem
                .read_obj(GuestAddress(0x8000 + u64::from(i) * 0x100 + 0x40))
                .unwrap();
            assert_eq!(status, VIRTIO_BLK_S_OK as u8);
        }
    }

    #[test]
    fn drain_waits_only_for_bounded_slow_discards() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let mut max_in_flight = Arc::default();
        let (mut handler, vq) = slow_discard_handler(&mem, &mut max_in_flight);
        let kill_evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let pause_evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let mut helper = EpollHelper::new(&kill_evt, &pause_evt).unwrap();

        handler.process_queue_submit().unwrap();
        // Pause: stop taking requests and wait for the ones in flight.
        let start = Instant::now();
        handler
            .draining_active_requests
            .store(true, Ordering::SeqCst);
        while handler.active_request_count.load(Ordering::SeqCst) > 0 {
            handle_completion_event(&mut handler, &mut helper);
        }
        let elapsed = start.elapsed();

        // Parked discards are completed without running.
        assert_eq!(vq.used.idx.get(), DISCARDS);
        assert_eq!(max_in_flight.load(Ordering::SeqCst), SLOW_DEPTH);
        assert!(
            elapsed < SLOW_LATENCY * (SLOW_DEPTH as u32 + 1),
            "Drain took {elapsed:?} for {SLOW_DEPTH} discards of {SLOW_LATENCY:?}"
        );
    }

    /// Runs what the block offload worker does on a thread under the
    /// virtio-block seccomp filter, applied the way activate() has the
    /// backend apply it. A syscall the filter does not allow raises SIGSYS
    /// and kills the test binary.
    #[test]
    fn virtio_block_filter_allows_offload_worker() {
        let filter = get_seccomp_filter(&SeccompAction::Trap, Thread::VirtioBlock).unwrap();
        let notifier = EventFd::new(EFD_NONBLOCK).unwrap();
        let worker_notifier = notifier.try_clone().unwrap();
        let file = TempFile::new().unwrap().into_file();
        let (sender, receiver) = mpsc::sync_channel::<u64>(1);
        let worker = thread::spawn(move || {
            apply_filter(&filter).unwrap();
            let completions = Mutex::new(VecDeque::new());
            for user_data in receiver {
                let range = [0u64, 4096];
                for request in [BLKDISCARD, BLKZEROOUT] {
                    // SAFETY: range is a valid [u64; 2] for the ioctl. On a
                    // regular file it fails with ENOTTY, after the filter
                    // has checked it.
                    let ret = unsafe { libc::ioctl(file.as_raw_fd(), request as _, &range) };
                    assert_eq!(ret, -1);
                    assert_eq!(
                        io::Error::last_os_error().raw_os_error(),
                        Some(libc::ENOTTY)
                    );
                }
                // A panic in an operation is caught and logged.
                let caught = panic::catch_unwind(|| panic!("offloaded operation panicked"));
                assert!(caught.is_err());
                completions
                    .lock()
                    .unwrap()
                    .push_back(AsyncIoCompletion::new(user_data, -libc::EIO, None));
                worker_notifier.write(1).unwrap();
            }
            completions.into_inner().unwrap().len()
        });
        sender.send(1).unwrap();
        sender.send(2).unwrap();
        drop(sender);
        assert_eq!(worker.join().unwrap(), 2);
        assert_eq!(notifier.read().unwrap(), 2);
    }
}
